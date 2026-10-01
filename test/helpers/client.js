// Outils de test : serveur réel + vrais modules client (crypto, protocol, transport).

import { createApp } from '../../server/index.js';
import * as C from '../../public/js/crypto.js';
import { Session, Status } from '../../public/js/protocol.js';
import { Transport, wireSession } from '../../public/js/transport.js';

export { C, Session, Status, Transport };

// E2E_BASE=http://127.0.0.1:8787 : exécute les scénarios contre un serveur externe (Worker local).
export const EXTERNAL_BASE = process.env.E2E_BASE || null;
const openClients = new Set();

export async function startApp(overrides = {}) {
  if (EXTERNAL_BASE) {
    const base = EXTERNAL_BASE.replace(/\/$/, '');
    return {
      app: null, base, wsUrl: base.replace(/^http/, 'ws') + '/ws', external: true,
      // Sans serveur local à arrêter, on ferme les clients restés ouverts pour libérer la boucle d'événements.
      close: async () => { for (const c of openClients) c.close(); openClients.clear(); },
    };
  }
  const app = createApp({
    requireHttps: false,
    store: { maxAgeMs: 60_000, emptyTtlMs: 60_000, maxParticipantsLimit: 10, sweepIntervalMs: 50 },
    limits: {
      create: { capacity: 1000, refillPerSec: 1000 },
      lookup: { capacity: 1000, refillPerSec: 1000 },
      connect: { capacity: 1000, refillPerSec: 1000 },
    },
    heartbeatMs: 1000,
    ...overrides,
  });
  const addr = await app.listen(0, '127.0.0.1');
  const base = `http://127.0.0.1:${addr.port}`;
  return { app, base, wsUrl: `ws://127.0.0.1:${addr.port}/ws`, close: async () => { await app.close(); for (const c of openClients) c.close(); openClients.clear(); } };
}

export async function createRoom(base, maxParticipants = 5, headers = {}) {
  const res = await fetch(`${base}/api/rooms`, {
    method: 'POST',
    headers: { 'content-type': 'application/json', ...headers },
    body: JSON.stringify({ maxParticipants }),
  });
  return { status: res.status, body: await res.json().catch(() => null) };
}

export async function deriveRoot({ roomId, secret, code = '', passphrase = null }) {
  const S = passphrase ? await C.secretFromPassphrase(passphrase, roomId) : secret;
  const salt = await C.saltFromCode(code, roomId);
  return C.deriveRoot(S, salt);
}

// Client complet. `wire` enregistre tout ce qui transite sur le câble (= ce que voit le serveur).
export async function makeClient({ wsUrl, roomId, secret, code = '', passphrase = null, ownerToken, name = 'client' }) {
  const root = await deriveRoot({ roomId, secret, code, passphrase });
  const state = {
    name,
    messages: [],
    members: [],
    statuses: [],
    notices: [],
    wire: { out: [], in: [] },
    welcome: null,
    locked: null,
    destroyedReason: null,
    error: null,
    closeInfo: null,
  };
  const session = new Session({
    roomId,
    root,
    send: () => {},
    on: {
      status: (s) => state.statuses.push(s),
      message: (m) => state.messages.push(m),
      members: (l) => { state.members = l; },
      notice: (k, info) => state.notices.push({ k, info }),
    },
  });
  const transport = new Transport(`${wsUrl}?room=${encodeURIComponent(roomId)}`, {});
  wireSession(transport, session, {
    onWelcome: (w) => { state.welcome = w; state.locked = w.locked; },
    onState: (s) => { state.locked = s.locked; },
    onDestroyed: (r) => { state.destroyedReason = r; },
    onError: (c) => { state.error = c; },
    onClose: (i) => { state.closeInfo = i; },
  });
  const ann = await session.init();
  await transport.connect();
  const rawSend = transport.ws.send.bind(transport.ws);
  transport.ws.send = (d) => { state.wire.out.push(String(d)); rawSend(d); };
  transport.ws.addEventListener('message', (ev) => state.wire.in.push(String(ev.data)));
  transport.join({ roomId, ...ann, ownerToken });

  const client = {
    state,
    session,
    transport,
    root,
    async waitStatus(target, timeout = 5000) {
      await waitFor(() => session.status === target, timeout, `${name}: statut ${target} attendu, obtenu ${session.status}`);
    },
    async waitMessages(n, timeout = 5000) {
      await waitFor(() => state.messages.length >= n, timeout, `${name}: ${n} message(s) attendu(s), reçu(s) ${state.messages.length}`);
    },
    async waitMembers(n, timeout = 5000) {
      await waitFor(() => state.members.length === n, timeout, `${name}: ${n} membre(s) attendu(s), vu(s) ${state.members.length}`);
    },
    close() { openClients.delete(client); transport.close(); },
  };
  openClients.add(client);
  // Les champs d'état sont lus à la demande (ils évoluent après la création).
  for (const k of Object.keys(state)) Object.defineProperty(client, k, { get: () => state[k], enumerable: true });
  return client;
}

export function waitFor(pred, timeout = 5000, label = 'condition') {
  return new Promise((resolve, reject) => {
    const start = Date.now();
    const tick = () => {
      if (pred()) return resolve();
      if (Date.now() - start > timeout) return reject(new Error(`timeout: ${label}`));
      setTimeout(tick, 15);
    };
    tick();
  });
}

export const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

export function textOf(m) { return m.header.text; }
