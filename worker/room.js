// Durable Object « Room » : une instance par session de chat.
//
// État conservé (stockage de l'objet, effacé à la destruction) : métadonnées
// de la salle uniquement — haché du jeton propriétaire, nombre maximal,
// verrouillage, horodatages, compteur d'ordre d'arrivée. Les participants sont
// portés par les WebSockets eux-mêmes (attachements, survivent à l'hibernation).
// Aucun message n'est jamais écrit : les blobs chiffrés sont relayés puis oubliés.

import { DurableObject } from 'cloudflare:workers';
import { isRoomId, isMemberId, isOwnerToken, isPubKey, isMac, isRelayData, parseJson } from '../server/validate.js';

export const ROOM_DEFAULTS = Object.freeze({
  maxAgeMs: 24 * 60 * 60 * 1000,
  emptyTtlMs: 10 * 60 * 1000,
  maxParticipantsLimit: 50,
});

const MAX_PAYLOAD_BYTES = 1024 * 1024;
const MAX_CT_LEN = Math.ceil(MAX_PAYLOAD_BYTES / 3) * 4;
const CLOSE_POLICY = 1008;
const CLOSE_NORMAL = 1000;
const MSG_BUCKET = { capacity: 40, refillPerSec: 20 };
const BYTE_BUCKET = { capacity: 64 * 1024 * 1024, refillPerSec: 2 * 1024 * 1024 };

async function sha256b64(text) {
  const h = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(text));
  return btoa(String.fromCharCode(...new Uint8Array(h)));
}

function randomToken(n = 32) {
  const b = new Uint8Array(n);
  crypto.getRandomValues(b);
  return btoa(String.fromCharCode(...b)).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

function timingSafeEqualStr(a, b) {
  if (typeof a !== 'string' || typeof b !== 'string' || a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return diff === 0;
}

function safeSend(ws, obj) {
  try { ws.send(JSON.stringify(obj)); } catch { /* socket fermée */ }
}

function take(bucket, cfg, cost, now) {
  const elapsed = Math.max(0, now - bucket.updated) / 1000;
  bucket.tokens = Math.min(cfg.capacity, bucket.tokens + elapsed * cfg.refillPerSec);
  bucket.updated = now;
  if (bucket.tokens >= cost) { bucket.tokens -= cost; return true; }
  return false;
}

export class Room extends DurableObject {
  constructor(ctx, env) {
    super(ctx, env);
    this.buckets = new WeakMap(); // ws -> { msg, bytes } (en mémoire : au mieux après hibernation)
    // Réponse automatique aux pings applicatifs sans réveiller l'objet.
    this.ctx.setWebSocketAutoResponse(new WebSocketRequestResponsePair('{"t":"ping"}', '{"t":"pong"}'));
  }

  // --- Métadonnées ---------------------------------------------------------------------------

  async #meta() { return (await this.ctx.storage.get('meta')) || null; }
  async #saveMeta(meta) { await this.ctx.storage.put('meta', meta); }

  #members() {
    const out = [];
    for (const ws of this.ctx.getWebSockets()) {
      const a = ws.deserializeAttachment();
      if (a?.memberId) out.push({ ws, ...a });
    }
    return out;
  }

  async #isExpired(meta, now = Date.now()) {
    if (now >= meta.expiresAt) return true;
    if (meta.emptySince != null && this.#members().length === 0 && now - meta.emptySince >= ROOM_DEFAULTS.emptyTtlMs) return true;
    return false;
  }

  async #scheduleAlarm(meta) {
    let at = meta.expiresAt;
    if (meta.emptySince != null) at = Math.min(at, meta.emptySince + ROOM_DEFAULTS.emptyTtlMs);
    await this.ctx.storage.setAlarm(at);
  }

  // --- Requêtes HTTP internes et upgrade WebSocket ------------------------------------------

  async fetch(req) {
    const url = new URL(req.url);

    if (url.pathname === '/init' && req.method === 'POST') {
      if (await this.#meta()) return new Response('exists', { status: 409 });
      const { roomId, maxParticipants } = await req.json();
      if (!isRoomId(roomId)) return new Response('bad', { status: 400 });
      const ownerToken = randomToken(32);
      const now = Date.now();
      const meta = {
        roomId,
        ownerHash: await sha256b64(ownerToken),
        maxParticipants,
        locked: false,
        createdAt: now,
        expiresAt: now + ROOM_DEFAULTS.maxAgeMs,
        emptySince: now,
        nextIndex: 1,
      };
      await this.#saveMeta(meta);
      await this.#scheduleAlarm(meta);
      return Response.json({ roomId, ownerToken, maxParticipants, expiresAt: meta.expiresAt });
    }

    if (url.pathname === '/info') {
      const meta = await this.#meta();
      if (!meta || (await this.#isExpired(meta))) { if (meta) await this.#destroy('expired'); return Response.json({ error: 'not_found' }, { status: 404 }); }
      return Response.json({ roomId: meta.roomId, locked: meta.locked, participants: this.#members().length, maxParticipants: meta.maxParticipants, expiresAt: meta.expiresAt });
    }

    if (url.pathname === '/ws') {
      if ((req.headers.get('upgrade') || '').toLowerCase() !== 'websocket') return new Response('Expected websocket', { status: 426 });
      const pair = new WebSocketPair();
      const [client, server] = Object.values(pair);
      this.ctx.acceptWebSocket(server);
      server.serializeAttachment({ joined: false });
      return new Response(null, { status: 101, webSocket: client });
    }

    return new Response('not found', { status: 404 });
  }

  // --- Messages ------------------------------------------------------------------------------

  async webSocketMessage(ws, message) {
    const fail = (code, closeCode = CLOSE_POLICY) => { safeSend(ws, { t: 'error', code }); try { ws.close(closeCode, code); } catch { /* ignore */ } };
    const refuse = (code) => safeSend(ws, { t: 'error', code });

    if (typeof message !== 'string') return fail('binary_not_allowed');
    const now = Date.now();
    let b = this.buckets.get(ws);
    if (!b) { b = { msg: { tokens: MSG_BUCKET.capacity, updated: now }, bytes: { tokens: BYTE_BUCKET.capacity, updated: now } }; this.buckets.set(ws, b); }
    if (!take(b.msg, MSG_BUCKET, 1, now) || !take(b.bytes, BYTE_BUCKET, message.length, now)) return fail('rate_limited');
    const msg = parseJson(message, MAX_PAYLOAD_BYTES);
    if (!msg || typeof msg.t !== 'string') return fail('bad_message');

    const att = ws.deserializeAttachment() || {};
    switch (msg.t) {
      case 'ping': return safeSend(ws, { t: 'pong' });
      case 'join': return this.#join(ws, att, msg, fail);
      case 'relay': return this.#relay(ws, att, msg, fail);
      case 'lock':
      case 'unlock': return this.#lock(ws, att, msg.t === 'lock', fail, refuse);
      case 'destroy': return this.#destroyRequest(att, fail);
      default: return fail('unknown_type');
    }
  }

  async #join(ws, att, msg, fail) {
    if (att.joined) return fail('already_joined');
    if (!isRoomId(msg.roomId) || !isMemberId(msg.memberId) || !isPubKey(msg.pubKey) || !isMac(msg.mac)) return fail('bad_join');
    if (msg.ownerToken !== undefined && !isOwnerToken(msg.ownerToken)) return fail('bad_join');
    const meta = await this.#meta();
    if (!meta || meta.roomId !== msg.roomId) return fail('not_found', CLOSE_NORMAL);
    if (await this.#isExpired(meta)) { await this.#destroy('expired'); return fail('not_found', CLOSE_NORMAL); }
    if (meta.locked) return fail('locked', CLOSE_NORMAL);
    const members = this.#members();
    if (members.length >= meta.maxParticipants) return fail('full', CLOSE_NORMAL);
    if (members.some((m) => m.memberId === msg.memberId)) return fail('duplicate', CLOSE_NORMAL);

    const owner = msg.ownerToken !== undefined && timingSafeEqualStr(await sha256b64(msg.ownerToken), meta.ownerHash);
    const index = meta.nextIndex++;
    meta.emptySince = null;
    await this.#saveMeta(meta);
    await this.#scheduleAlarm(meta);
    const me = { joined: true, memberId: msg.memberId, index, pubKey: msg.pubKey, mac: msg.mac, owner };
    ws.serializeAttachment(me);

    safeSend(ws, {
      t: 'welcome',
      memberId: me.memberId,
      index,
      owner,
      locked: meta.locked,
      maxParticipants: meta.maxParticipants,
      expiresAt: meta.expiresAt,
      members: members.map(({ memberId, index: i, pubKey, mac }) => ({ memberId, index: i, pubKey, mac })),
    });
    const announce = { t: 'joined', member: { memberId: me.memberId, index, pubKey: me.pubKey, mac: me.mac } };
    for (const m of members) safeSend(m.ws, announce);
  }

  #relay(ws, att, msg, fail) {
    if (!att.joined) return fail('not_joined');
    if (!isRelayData(msg.data, { maxCtLen: MAX_CT_LEN })) return fail('bad_relay');
    const out = { t: 'relay', from: att.memberId, data: msg.data };
    const members = this.#members();
    if (msg.to !== undefined) {
      if (!isMemberId(msg.to) || msg.to === att.memberId) return fail('bad_relay');
      const target = members.find((m) => m.memberId === msg.to);
      if (target) safeSend(target.ws, out);
      return;
    }
    for (const m of members) if (m.memberId !== att.memberId) safeSend(m.ws, out);
  }

  async #lock(ws, att, locked, fail, refuse) {
    if (!att.joined) return fail('not_joined');
    if (!att.owner) return refuse('not_owner');
    const meta = await this.#meta();
    if (!meta) return fail('not_found', CLOSE_NORMAL);
    meta.locked = locked;
    await this.#saveMeta(meta);
    for (const m of this.#members()) safeSend(m.ws, { t: 'state', locked });
  }

  // Tout participant connecté peut détruire la session (sécurité avant tout).
  async #destroyRequest(att, fail) {
    if (!att.joined) return fail('not_joined');
    await this.#destroy('participant', att.index);
  }

  async #destroy(reason, by = null) {
    for (const ws of this.ctx.getWebSockets()) {
      safeSend(ws, { t: 'destroyed', reason, by });
      try { ws.close(CLOSE_NORMAL, 'destroyed'); } catch { /* ignore */ }
    }
    await this.ctx.storage.deleteAlarm();
    await this.ctx.storage.deleteAll();
  }

  // --- Départs et expiration -----------------------------------------------------------------

  async webSocketClose(ws) { await this.#leave(ws); }
  async webSocketError(ws) { await this.#leave(ws); }

  async #leave(ws) {
    const att = ws.deserializeAttachment();
    try { ws.close(CLOSE_NORMAL, 'bye'); } catch { /* déjà fermée */ }
    if (!att?.joined) return;
    ws.serializeAttachment({ joined: false });
    const meta = await this.#meta();
    const remaining = this.#members().filter((m) => m.ws !== ws);
    for (const m of remaining) safeSend(m.ws, { t: 'left', memberId: att.memberId });
    if (meta && remaining.length === 0) {
      meta.emptySince = Date.now();
      await this.#saveMeta(meta);
      await this.#scheduleAlarm(meta);
    }
  }

  async alarm() {
    const meta = await this.#meta();
    if (!meta) return;
    if (await this.#isExpired(meta)) await this.#destroy('expired');
    else await this.#scheduleAlarm(meta);
  }
}
