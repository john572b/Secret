// Couche HTTP : fichiers statiques, API minimale et en-têtes de sécurité.
// Aucun cookie, aucune session serveur, aucune journalisation des requêtes.

import { readFile } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { isRoomId } from './validate.js';
import { buildSecurityHeaders, sanitizeHost, originAllowed } from './headers.js';

const PUBLIC_DIR = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..', 'public');

const MIME = {
  '.html': 'text/html; charset=utf-8',
  '.js': 'text/javascript; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
  '.svg': 'image/svg+xml',
  '.png': 'image/png',
  '.ico': 'image/x-icon',
  '.webmanifest': 'application/manifest+json',
  '.txt': 'text/plain; charset=utf-8',
};

const MAX_BODY = 4096;

export function securityHeaders(req, { requireHttps }) {
  return buildSecurityHeaders({ host: req.headers.host, requireHttps });
}

function isHttps(req, trustProxy) {
  if (req.socket.encrypted) return true;
  if (trustProxy) {
    const proto = String(req.headers['x-forwarded-proto'] || '').split(',')[0].trim();
    return proto === 'https';
  }
  return false;
}

export function clientIp(req, trustProxy) {
  if (trustProxy) {
    const xff = req.headers['x-forwarded-for'];
    if (typeof xff === 'string' && xff.length) return xff.split(',')[0].trim().slice(0, 64);
  }
  return req.socket.remoteAddress || 'unknown';
}

export function isSameOrigin(req) {
  return originAllowed({ host: req.headers.host, origin: req.headers.origin, secFetchSite: req.headers['sec-fetch-site'] });
}

function send(res, status, headers, body) {
  res.writeHead(status, headers);
  res.end(body);
}

function json(res, status, obj, baseHeaders) {
  send(res, status, { ...baseHeaders, 'Content-Type': 'application/json; charset=utf-8', 'Cache-Control': 'no-store' }, JSON.stringify(obj));
}

function readBody(req, max) {
  return new Promise((resolve, reject) => {
    let size = 0;
    const chunks = [];
    req.on('data', (c) => {
      size += c.length;
      if (size > max) { chunks.length = 0; req.removeAllListeners('data'); req.resume(); reject(new Error('too_large')); return; }
      chunks.push(c);
    });
    req.on('end', () => resolve(Buffer.concat(chunks).toString('utf8')));
    req.on('error', reject);
  });
}

export function createHttpHandler(ctx) {
  const { store, limiters, config } = ctx;

  async function serveStatic(res, relPath, baseHeaders) {
    const abs = path.resolve(PUBLIC_DIR, '.' + relPath);
    if (!abs.startsWith(PUBLIC_DIR + path.sep) && abs !== PUBLIC_DIR) return send(res, 404, baseHeaders, 'Not found');
    const ext = path.extname(abs);
    const mime = MIME[ext];
    if (!mime) return send(res, 404, baseHeaders, 'Not found');
    try {
      const data = await readFile(abs);
      send(res, 200, {
        ...baseHeaders,
        'Content-Type': mime,
        'Content-Length': data.length,
        'Cache-Control': ext === '.html' ? 'no-store' : 'no-cache',
      }, data);
    } catch {
      send(res, 404, baseHeaders, 'Not found');
    }
  }

  async function handleApi(req, res, url, baseHeaders, ip) {
    if (req.method === 'POST' && url.pathname === '/api/rooms') {
      if (!isSameOrigin(req)) return json(res, 403, { error: 'forbidden_origin' }, baseHeaders);
      if (!String(req.headers['content-type'] || '').startsWith('application/json')) {
        return json(res, 415, { error: 'unsupported_media_type' }, baseHeaders);
      }
      if (!limiters.create.take(ip)) return json(res, 429, { error: 'rate_limited' }, baseHeaders);
      let raw;
      try { raw = await readBody(req, MAX_BODY); } catch (e) { return json(res, e.message === 'too_large' ? 413 : 400, { error: e.message === 'too_large' ? 'payload_too_large' : 'bad_request' }, baseHeaders); }
      let body;
      try { body = raw.trim() ? JSON.parse(raw) : {}; } catch { return json(res, 400, { error: 'bad_request' }, baseHeaders); }
      if (body === null || typeof body !== 'object') return json(res, 400, { error: 'bad_request' }, baseHeaders);
      // Pas de nombre choisi par l'utilisateur : la salle accepte tout le monde jusqu'au
      // verrouillage, dans la limite d'un plafond technique (protection contre les abus).
      let created;
      try { created = store.create({ maxParticipants: store.opts.maxParticipantsLimit }); } catch { return json(res, 500, { error: 'internal' }, baseHeaders); }
      const { room, ownerToken } = created;
      return json(res, 201, { roomId: room.id, ownerToken, maxParticipants: room.maxParticipants, expiresAt: room.expiresAt }, baseHeaders);
    }

    if (req.method === 'GET' && url.pathname.startsWith('/api/rooms/')) {
      const id = url.pathname.slice('/api/rooms/'.length);
      if (!isRoomId(id)) return json(res, 400, { error: 'bad_request' }, baseHeaders);
      if (!limiters.lookup.take(ip)) return json(res, 429, { error: 'rate_limited' }, baseHeaders);
      const room = store.get(id);
      if (!room) return json(res, 404, { error: 'not_found' }, baseHeaders);
      return json(res, 200, { roomId: room.id, locked: room.locked, participants: room.members.size, maxParticipants: room.maxParticipants, expiresAt: room.expiresAt }, baseHeaders);
    }

    if (req.method === 'GET' && url.pathname === '/api/info') {
      return json(res, 200, {
        version: config.version,
        limits: {
          maxParticipants: store.opts.maxParticipantsLimit,
          maxFileBytes: config.maxFileBytes,
          maxPayloadBytes: config.maxPayloadBytes,
          roomMaxAgeMs: store.opts.maxAgeMs,
          roomEmptyTtlMs: store.opts.emptyTtlMs,
          roomIdleTtlMs: store.opts.idleTtlMs,
          rateLimitIdleMs: limiters.create.idleMs,
        },
      }, baseHeaders);
    }

    return json(res, 404, { error: 'not_found' }, baseHeaders);
  }

  return async function handler(req, res) {
    const baseHeaders = securityHeaders(req, config);
    let url;
    try {
      url = new URL(req.url, 'http://localhost');
    } catch {
      return send(res, 400, baseHeaders, 'Bad request');
    }

    if (config.requireHttps && !isHttps(req, config.trustProxy)) {
      const host = sanitizeHost(req.headers.host);
      if (!host) return send(res, 400, baseHeaders, 'Bad request');
      return send(res, 301, { ...baseHeaders, Location: `https://${host}${url.pathname}${url.search}` }, '');
    }

    if (url.pathname.startsWith('/api/')) {
      try {
        return await handleApi(req, res, url, baseHeaders, clientIp(req, config.trustProxy));
      } catch {
        return json(res, 500, { error: 'internal' }, baseHeaders);
      }
    }

    if (req.method !== 'GET' && req.method !== 'HEAD') return send(res, 405, { ...baseHeaders, Allow: 'GET, HEAD' }, 'Method not allowed');

    if (url.pathname === '/' || /^\/c\/[A-Za-z0-9_-]{22}$/.test(url.pathname)) return serveStatic(res, '/index.html', baseHeaders);
    if (url.pathname === '/security' || url.pathname === '/securite') return serveStatic(res, '/security.html', baseHeaders);
    return serveStatic(res, url.pathname, baseHeaders);
  };
}
