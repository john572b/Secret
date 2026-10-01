// secret.boi.lu — point d'entrée Cloudflare Workers.
// Même rôle que server/ : servir l'interface, créer/consulter des sessions,
// relayer des blobs chiffrés. Chaque salle vit dans un Durable Object (mémoire
// + état minimal), jamais dans une base de données de conversations.

import { isRoomId } from '../server/validate.js';
import { buildSecurityHeaders, originAllowed, sanitizeHost } from '../server/headers.js';
import { ROOM_DEFAULTS } from './room.js';

export { Room } from './room.js';

const VERSION = '0.1.0';
const MAX_BODY = 4096;
const MAX_FILE_BYTES = 8 * 1024 * 1024;
const MAX_PAYLOAD_BYTES = 1024 * 1024;

function withHeaders(res, base) {
  const h = new Headers(res.headers);
  for (const [k, v] of Object.entries(base)) h.set(k, v);
  return new Response(res.body, { status: res.status, statusText: res.statusText, headers: h });
}

function json(status, obj, base) {
  return new Response(JSON.stringify(obj), { status, headers: { ...base, 'Content-Type': 'application/json; charset=utf-8', 'Cache-Control': 'no-store' } });
}

function sameOrigin(req, host) {
  return originAllowed({ host, origin: req.headers.get('origin'), secFetchSite: req.headers.get('sec-fetch-site') });
}

async function limited(limiter, key) {
  if (!limiter) return false;
  try {
    const { success } = await limiter.limit({ key });
    return !success;
  } catch {
    return false; // le limiteur est indisponible : on ne bloque pas le service
  }
}

function clientIp(req) {
  return req.headers.get('cf-connecting-ip') || 'unknown';
}

function roomStub(env, roomId) {
  return env.ROOMS.get(env.ROOMS.idFromName(roomId));
}

async function newRoomId() {
  const b = new Uint8Array(16);
  crypto.getRandomValues(b);
  return btoa(String.fromCharCode(...b)).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

export default {
  async fetch(req, env) {
    const url = new URL(req.url);
    const host = sanitizeHost(req.headers.get('host')) || url.host;
    const base = buildSecurityHeaders({ host, requireHttps: url.protocol === 'https:' });

    // --- API ---------------------------------------------------------------------------------
    if (url.pathname === '/api/rooms' && req.method === 'POST') {
      if (!sameOrigin(req, host)) return json(403, { error: 'forbidden_origin' }, base);
      if (!(req.headers.get('content-type') || '').startsWith('application/json')) return json(415, { error: 'unsupported_media_type' }, base);
      if (await limited(env.CREATE_LIMITER, clientIp(req))) return json(429, { error: 'rate_limited' }, base);
      const raw = await req.text();
      if (raw.length > MAX_BODY) return json(413, { error: 'payload_too_large' }, base);
      let body;
      try { body = JSON.parse(raw); } catch { return json(400, { error: 'bad_request' }, base); }
      if (body === null || typeof body !== 'object') return json(400, { error: 'bad_request' }, base);
      const max = Number(body.maxParticipants);
      if (!Number.isInteger(max) || max < 2 || max > ROOM_DEFAULTS.maxParticipantsLimit) return json(400, { error: 'invalid_max_participants' }, base);
      const roomId = await newRoomId();
      const res = await roomStub(env, roomId).fetch('https://room/init', { method: 'POST', body: JSON.stringify({ roomId, maxParticipants: max }) });
      if (!res.ok) return json(500, { error: 'internal' }, base);
      return json(201, await res.json(), base);
    }

    if (url.pathname.startsWith('/api/rooms/') && req.method === 'GET') {
      const id = url.pathname.slice('/api/rooms/'.length);
      if (!isRoomId(id)) return json(400, { error: 'bad_request' }, base);
      if (await limited(env.LOOKUP_LIMITER, clientIp(req))) return json(429, { error: 'rate_limited' }, base);
      const res = await roomStub(env, id).fetch('https://room/info');
      return withHeaders(res, { ...base, 'Cache-Control': 'no-store' });
    }

    if (url.pathname === '/api/info' && req.method === 'GET') {
      return json(200, {
        version: VERSION,
        platform: 'cloudflare-workers',
        limits: {
          maxParticipants: ROOM_DEFAULTS.maxParticipantsLimit,
          maxFileBytes: MAX_FILE_BYTES,
          maxPayloadBytes: MAX_PAYLOAD_BYTES,
          roomMaxAgeMs: ROOM_DEFAULTS.maxAgeMs,
          roomEmptyTtlMs: ROOM_DEFAULTS.emptyTtlMs,
          roomIdleTtlMs: ROOM_DEFAULTS.idleTtlMs,
        },
      }, base);
    }

    if (url.pathname.startsWith('/api/')) return json(404, { error: 'not_found' }, base);

    // --- WebSocket ---------------------------------------------------------------------------
    if (url.pathname === '/ws') {
      if ((req.headers.get('upgrade') || '').toLowerCase() !== 'websocket') return new Response('Expected websocket', { status: 426, headers: base });
      if (!sameOrigin(req, host)) return new Response('Forbidden', { status: 403, headers: base });
      if (await limited(env.CONNECT_LIMITER, clientIp(req))) return new Response('Too Many Requests', { status: 429, headers: base });
      // La salle n'est connue qu'au message `join` : on l'exige dès l'ouverture
      // via le paramètre ?room=… pour router vers le bon objet durable.
      const roomId = url.searchParams.get('room');
      if (!isRoomId(roomId)) return new Response('Bad request', { status: 400, headers: base });
      return roomStub(env, roomId).fetch(req);
    }

    // --- Fichiers statiques -----------------------------------------------------------------
    if (req.method !== 'GET' && req.method !== 'HEAD') return new Response('Method not allowed', { status: 405, headers: { ...base, Allow: 'GET, HEAD' } });
    let assetPath = url.pathname;
    if (assetPath === '/' || /^\/c\/[A-Za-z0-9_-]{22}$/.test(assetPath)) assetPath = '/index.html';
    else if (assetPath === '/security' || assetPath === '/securite') assetPath = '/security.html';
    else if (!/^\/(css|js)\/[A-Za-z0-9_.-]+$|^\/favicon\.svg$|^\/robots\.txt$/.test(assetPath)) return new Response('Not found', { status: 404, headers: base });
    const res = await env.ASSETS.fetch(new Request(new URL(assetPath, url.origin), { method: req.method, headers: req.headers }));
    if (res.status === 404) return new Response('Not found', { status: 404, headers: base });
    return withHeaders(res, { ...base, 'Cache-Control': assetPath.endsWith('.html') ? 'no-store' : 'no-cache' });
  },
};
