// Relais WebSocket. Le serveur ne comprend pas le contenu des champs `data` :
// il vérifie leur forme, les attribue à un expéditeur et les transmet.

import { WebSocketServer } from 'ws';
import { RateLimiter } from './ratelimit.js';
import { clientIp, isSameOrigin } from './http.js';
import { isRoomId, isMemberId, isOwnerToken, isPubKey, isMac, isRelayData, parseJson } from './validate.js';

const CLOSE_POLICY = 1008;      // violation de protocole / non autorisé
const CLOSE_NORMAL = 1000;
const CLOSE_TOO_BIG = 1009;

function safeSend(ws, obj) {
  if (ws.readyState === ws.OPEN) {
    try { ws.send(JSON.stringify(obj)); } catch { /* socket en cours de fermeture */ }
  }
}

function publicMember(m) {
  return { memberId: m.memberId, index: m.index, pubKey: m.pubKey, mac: m.mac };
}

export function attachWebSocket(httpServer, ctx) {
  const { store, limiters, config } = ctx;
  const wss = new WebSocketServer({ noServer: true, maxPayload: config.maxPayloadBytes, perMessageDeflate: false });
  const maxCtLen = Math.ceil(config.maxPayloadBytes / 3) * 4;

  function broadcast(room, obj, exceptId = null) {
    for (const m of room.members.values()) {
      if (m.memberId !== exceptId) safeSend(m.ws, obj);
    }
  }

  // Appelé par le magasin avant l'effacement d'une session.
  store.onDestroy = (room, reason, by = null) => {
    for (const m of room.members.values()) {
      safeSend(m.ws, { t: 'destroyed', reason, by });
      m.ws.state = null;
      try { m.ws.close(CLOSE_NORMAL, 'destroyed'); } catch { /* déjà fermé */ }
    }
  };

  httpServer.on('upgrade', (req, socket, head) => {
    let pathname;
    try { pathname = new URL(req.url, 'http://localhost').pathname; } catch { socket.destroy(); return; }
    if (pathname !== '/ws') { socket.destroy(); return; }
    if (!isSameOrigin(req)) { socket.write('HTTP/1.1 403 Forbidden\r\n\r\n'); socket.destroy(); return; }
    const ip = clientIp(req, config.trustProxy);
    if (!limiters.connect.take(ip)) { socket.write('HTTP/1.1 429 Too Many Requests\r\n\r\n'); socket.destroy(); return; }
    wss.handleUpgrade(req, socket, head, (ws) => wss.emit('connection', ws, req));
  });

  wss.on('connection', (ws) => {
    ws.isAlive = true;
    ws.state = null; // { room, memberId }
    const msgBucket = new RateLimiter({ capacity: 40, refillPerSec: 20 });
    const byteBucket = new RateLimiter({ capacity: 64 * 1024 * 1024, refillPerSec: 2 * 1024 * 1024 });

    const fail = (code, closeCode = CLOSE_POLICY) => {
      safeSend(ws, { t: 'error', code });
      try { ws.close(closeCode, code); } catch { /* ignore */ }
    };
    // Refus sans fermeture : la connexion reste valide (ex. action réservée au propriétaire).
    const refuse = (code) => safeSend(ws, { t: 'error', code });

    ws.on('pong', () => { ws.isAlive = true; });

    ws.on('message', (raw, isBinary) => {
      if (isBinary) return fail('binary_not_allowed');
      const size = raw.length;
      if (!msgBucket.take('m') || !byteBucket.take('b', size)) return fail('rate_limited');
      const msg = parseJson(raw.toString('utf8'), config.maxPayloadBytes);
      if (!msg || typeof msg.t !== 'string') return fail('bad_message');

      switch (msg.t) {
        case 'ping':
          return safeSend(ws, { t: 'pong' });
        case 'join':
          return handleJoin(ws, msg, fail);
        case 'relay':
          return handleRelay(ws, msg, fail);
        case 'lock':
        case 'unlock':
          return handleLock(ws, msg.t === 'lock', fail, refuse);
        case 'destroy':
          return handleDestroy(ws, fail);
        default:
          return fail('unknown_type');
      }
    });

    ws.on('close', () => leave(ws));
    ws.on('error', () => leave(ws));
  });

  function handleJoin(ws, msg, fail) {
    if (ws.state) return fail('already_joined');
    if (!isRoomId(msg.roomId) || !isMemberId(msg.memberId) || !isPubKey(msg.pubKey) || !isMac(msg.mac)) return fail('bad_join');
    if (msg.ownerToken !== undefined && !isOwnerToken(msg.ownerToken)) return fail('bad_join');

    const room = store.get(msg.roomId);
    if (!room) return fail('not_found', CLOSE_NORMAL);
    const member = { memberId: msg.memberId, pubKey: msg.pubKey, mac: msg.mac, ws, index: 0 };
    try {
      store.addMember(room, member);
    } catch (e) {
      return fail(e.message, CLOSE_NORMAL); // locked | full | duplicate | destroyed
    }
    const owner = msg.ownerToken !== undefined && store.isOwner(room, msg.ownerToken);
    ws.state = { room, memberId: member.memberId, owner };

    const others = [...room.members.values()].filter((m) => m !== member).map(publicMember);
    safeSend(ws, {
      t: 'welcome',
      memberId: member.memberId,
      index: member.index,
      owner,
      locked: room.locked,
      maxParticipants: room.maxParticipants,
      expiresAt: room.expiresAt,
      members: others,
    });
    broadcast(room, { t: 'joined', member: publicMember(member) }, member.memberId);
  }

  function handleRelay(ws, msg, fail) {
    const st = ws.state;
    if (!st) return fail('not_joined');
    if (!isRelayData(msg.data, { maxCtLen })) return fail('bad_relay');
    const { room, memberId } = st;
    store.touch(room);
    const out = { t: 'relay', from: memberId, data: msg.data };
    if (msg.to !== undefined) {
      if (!isMemberId(msg.to) || msg.to === memberId) return fail('bad_relay');
      const target = room.members.get(msg.to);
      if (target) safeSend(target.ws, out); // cible partie entre-temps : on ignore
      return;
    }
    broadcast(room, out, memberId);
  }

  function handleLock(ws, locked, fail, refuse) {
    const st = ws.state;
    if (!st) return fail('not_joined');
    if (!st.owner) return refuse('not_owner');
    st.room.locked = locked;
    broadcast(st.room, { t: 'state', locked });
  }

  // Tout participant connecté peut détruire la session (sécurité avant tout).
  function handleDestroy(ws, fail) {
    const st = ws.state;
    if (!st) return fail('not_joined');
    const index = st.room.members.get(st.memberId)?.index ?? null;
    store.destroy(st.room.id, 'participant', index);
  }

  function leave(ws) {
    const st = ws.state;
    if (!st) return;
    ws.state = null;
    const { room, memberId } = st;
    if (room.destroyed) return;
    if (store.removeMember(room, memberId)) broadcast(room, { t: 'left', memberId });
  }

  // Détection des connexions mortes.
  const heartbeat = setInterval(() => {
    for (const ws of wss.clients) {
      if (!ws.isAlive) { ws.terminate(); continue; }
      ws.isAlive = false;
      try { ws.ping(); } catch { /* ignore */ }
    }
  }, config.heartbeatMs);
  heartbeat.unref();

  return {
    wss,
    async close() {
      clearInterval(heartbeat);
      // Laisse partir les trames « destroyed » avant de couper les connexions restantes.
      await new Promise((r) => setTimeout(r, 200));
      for (const ws of wss.clients) { try { ws.terminate(); } catch { /* ignore */ } }
      wss.close();
    },
  };
}
