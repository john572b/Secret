// Tests du serveur : sessions, expiration, participants, validation, limitation de débit.
import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import WebSocket from 'ws';
import { RoomStore } from '../server/rooms.js';
import { RateLimiter } from '../server/ratelimit.js';
import { startApp, createRoom, makeClient, waitFor, sleep, C, Status } from './helpers/client.js';

let env;
before(async () => { env = await startApp(); });
after(async () => { await env.close(); });

function rawClient(wsUrl, headers = {}) {
  return new Promise((resolve, reject) => {
    const ws = new WebSocket(wsUrl, { headers });
    const got = [];
    ws.on('message', (d) => got.push(JSON.parse(d.toString())));
    ws.on('open', () => resolve({ ws, got, send: (o) => ws.send(JSON.stringify(o)) }));
    ws.on('error', reject);
    ws.on('unexpected-response', (_, res) => reject(new Error('http_' + res.statusCode)));
  });
}

async function validJoin(roomId, extra = {}) {
  const id = await C.generateIdentity();
  return { t: 'join', roomId, memberId: C.newMemberId(), pubKey: id.publicKeyB64, mac: C.toB64(C.randomBytes(32)), ...extra };
}

test('création : identifiant aléatoire de 128 bits, jeton propriétaire jamais stocké en clair', async () => {
  const { status, body } = await createRoom(env.base, 3);
  assert.equal(status, 201);
  assert.match(body.roomId, /^[A-Za-z0-9_-]{22}$/);
  assert.match(body.ownerToken, /^[A-Za-z0-9_-]{43}$/);
  const room = env.app.store.get(body.roomId);
  assert.ok(room);
  assert.ok(!JSON.stringify({ ...room, members: [] }).includes(body.ownerToken));
  const { body: b2 } = await createRoom(env.base, 3);
  assert.notEqual(body.roomId, b2.roomId);
  // Fixation de session : l'identifiant ne peut pas être choisi par le client.
  const res = await fetch(`${env.base}/api/rooms`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ maxParticipants: 3, roomId: 'AAAAAAAAAAAAAAAAAAAAAA' }) });
  const b3 = await res.json();
  assert.notEqual(b3.roomId, 'AAAAAAAAAAAAAAAAAAAAAA');
});

test('création : validation stricte du nombre de participants et du corps', async () => {
  for (const bad of [1, 0, -1, 999, 'deux', null, 2.5]) {
    const { status } = await createRoom(env.base, bad);
    assert.equal(status, 400, `maxParticipants=${bad}`);
  }
  const r = await fetch(`${env.base}/api/rooms`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: '{not json' });
  assert.equal(r.status, 400);
  const r2 = await fetch(`${env.base}/api/rooms`, { method: 'POST', headers: { 'content-type': 'text/plain' }, body: '{}' });
  assert.equal(r2.status, 415);
  const r3 = await fetch(`${env.base}/api/rooms`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: 'x'.repeat(10_000) });
  assert.equal(r3.status, 413);
});

test('consultation : 404 pour une session inconnue, 400 pour un identifiant mal formé', async () => {
  assert.equal((await fetch(`${env.base}/api/rooms/BBBBBBBBBBBBBBBBBBBBBB`)).status, 404);
  assert.ok([400, 404].includes((await fetch(`${env.base}/api/rooms/../etc`)).status));
  assert.equal((await fetch(`${env.base}/api/rooms/'%20OR%201=1`)).status, 400);
  assert.equal((await fetch(`${env.base}/api/rooms/${'A'.repeat(22)}%00`)).status, 400);
});

test('expiration : salle vide détruite après le délai, salle expirée après la durée max', async () => {
  const store = new RoomStore({ maxAgeMs: 1000, emptyTtlMs: 200 });
  const destroyed = [];
  store.onDestroy = (room, reason) => destroyed.push(reason);
  const { room } = store.create({ maxParticipants: 2 });
  const now = Date.now();
  assert.equal(store.isExpired(room, now + 100), false);
  assert.equal(store.isExpired(room, now + 250), true, 'vide depuis plus de emptyTtlMs');
  store.addMember(room, { memberId: 'm1' });
  assert.equal(store.isExpired(room, now + 900), false, 'occupée : pas d\'expiration par vacuité');
  assert.equal(store.isExpired(room, now + 1001), true, 'durée de vie maximale atteinte');
  store.removeMember(room, 'm1');
  assert.equal(store.sweep(Date.now() + 250), 1);
  assert.deepEqual(destroyed, ['expired']);
  assert.equal(store.get(room.id), null);
});

test('inactivité : expiration sans trafic, remise à zéro à chaque relais', () => {
  const store = new RoomStore({ maxAgeMs: 100_000, emptyTtlMs: 100_000, idleTtlMs: 1000 });
  const { room } = store.create({ maxParticipants: 2 });
  store.addMember(room, { memberId: 'm1' });
  const now = Date.now();
  assert.equal(store.expiryReason(room, now + 900), null);
  assert.equal(store.expiryReason(room, now + 1001), 'inactive');
  store.touch(room, now + 900);
  assert.equal(store.expiryReason(room, now + 1500), null, 'le trafic repousse l\'échéance');
  assert.equal(store.expiryReason(room, now + 1901), 'inactive');
});

test('expiration réelle : les clients connectés sont notifiés et la session disparaît', async () => {
  const short = await startApp({ store: { maxAgeMs: 400, emptyTtlMs: 10_000, maxParticipantsLimit: 10, sweepIntervalMs: 50 } });
  try {
    const { body } = await createRoom(short.base, 3);
    const a = await makeClient({ wsUrl: short.wsUrl, roomId: body.roomId, secret: C.newRoomSecret(), name: 'A' });
    await a.waitStatus(Status.SECURE);
    await waitFor(() => a.destroyedReason === 'expired', 3000, 'expiration notifiée');
    assert.equal(short.app.store.size, 0);
  } finally { await short.close(); }
});

test('participants : nombre maximal respecté, identifiants dupliqués refusés', async () => {
  const { body } = await createRoom(env.base, 2);
  const secret = C.newRoomSecret();
  const a = await makeClient({ wsUrl: env.wsUrl, roomId: body.roomId, secret, name: 'A' });
  const b = await makeClient({ wsUrl: env.wsUrl, roomId: body.roomId, secret, name: 'B' });
  await a.waitStatus(Status.SECURE); await b.waitStatus(Status.SECURE);
  const c = await makeClient({ wsUrl: env.wsUrl, roomId: body.roomId, secret, name: 'C' });
  await waitFor(() => c.error === 'full', 2000);
  const dup = await rawClient(env.wsUrl);
  dup.send(await validJoin(body.roomId, { memberId: a.session.memberId }));
  await waitFor(() => dup.got.some((m) => m.t === 'error' && (m.code === 'duplicate' || m.code === 'full')), 2000);
  a.close(); b.close();
});

test('messages WebSocket mal formés : connexion fermée avec code 1008', async () => {
  const { body } = await createRoom(env.base, 3);
  const cases = [
    'pas du json',
    JSON.stringify([]),
    JSON.stringify({ t: 'inconnu' }),
    JSON.stringify({ t: 'relay', data: {} }),
    JSON.stringify({ t: 'lock' }),
    JSON.stringify({ t: 'join', roomId: '../../', memberId: 'x', pubKey: 'y', mac: 'z' }),
    JSON.stringify({ t: 'join', roomId: body.roomId, memberId: C.newMemberId(), pubKey: '<script>', mac: 'z' }),
  ];
  for (const payload of cases) {
    const c = await rawClient(env.wsUrl);
    const closed = new Promise((r) => c.ws.on('close', (code) => r(code)));
    c.ws.send(payload);
    assert.equal(await closed, 1008, payload.slice(0, 40));
  }
  const bin = await rawClient(env.wsUrl);
  const closedBin = new Promise((r) => bin.ws.on('close', (code) => r(code)));
  bin.ws.send(Buffer.from([1, 2, 3]));
  assert.equal(await closedBin, 1008);
});

test('relais : la forme des blobs est vérifiée mais pas leur contenu ; cible inexistante ignorée', async () => {
  const { body } = await createRoom(env.base, 3);
  const c = await rawClient(env.wsUrl);
  c.send(await validJoin(body.roomId));
  await waitFor(() => c.got.some((m) => m.t === 'welcome'), 2000);
  const closed = new Promise((r) => c.ws.on('close', (code) => r(code)));
  c.send({ t: 'relay', data: { k: 'msg', epochId: 'e', seq: 0, iv: C.toB64(C.randomBytes(12)), ct: C.toB64(C.randomBytes(40)) } });
  c.send({ t: 'relay', to: C.newMemberId(), data: { k: 'key', epochId: 'e', iv: C.toB64(C.randomBytes(12)), ct: C.toB64(C.randomBytes(40)) } });
  await sleep(100);
  assert.equal(c.ws.readyState, WebSocket.OPEN, 'blobs bien formés acceptés');
  c.send({ t: 'relay', data: { k: 'msg', epochId: 'e', seq: 0, iv: 'court', ct: 'x', extra: 'champ interdit' } });
  assert.equal(await closed, 1008);
});

test('limitation de débit : création de sessions et connexions WebSocket', async () => {
  const limited = await startApp({ limits: { create: { capacity: 3, refillPerSec: 0 }, lookup: { capacity: 100, refillPerSec: 0 }, connect: { capacity: 2, refillPerSec: 0 } } });
  try {
    const statuses = [];
    for (let i = 0; i < 5; i++) statuses.push((await createRoom(limited.base, 3)).status);
    assert.deepEqual(statuses, [201, 201, 201, 429, 429]);
    await rawClient(limited.wsUrl); await rawClient(limited.wsUrl);
    await assert.rejects(() => rawClient(limited.wsUrl), /http_429/);
  } finally { await limited.close(); }
});

test('limitation de débit par connexion : rafale de messages fermée', async () => {
  const { body } = await createRoom(env.base, 3);
  const c = await rawClient(env.wsUrl);
  c.send(await validJoin(body.roomId));
  await waitFor(() => c.got.some((m) => m.t === 'welcome'), 2000);
  const closed = new Promise((r) => c.ws.on('close', (code) => r(code)));
  for (let i = 0; i < 100; i++) c.send({ t: 'ping' });
  assert.equal(await closed, 1008);
  assert.ok(c.got.some((m) => m.t === 'error' && m.code === 'rate_limited'));
});

test('force brute sur le code : le serveur ne vérifie aucun code (rien à forcer) et PBKDF2 ralentit la dérivation', async () => {
  // Le serveur n'a jamais connaissance du code : aucun point de terminaison ne permet de le tester.
  const t0 = Date.now();
  await C.saltFromCode('0000', 'AAAAAAAAAAAAAAAAAAAAAA');
  const ms = Date.now() - t0;
  assert.ok(ms > 20, `PBKDF2 doit coûter un temps non négligeable (mesuré ${ms} ms)`);
  const limiter = new RateLimiter({ capacity: 5, refillPerSec: 1 });
  let ok = 0;
  for (let i = 0; i < 20; i++) if (limiter.take('ip')) ok++;
  assert.equal(ok, 5);
  assert.equal(limiter.take('ip', 1, Date.now() + 2000), true, 'recharge dans le temps');
  limiter.sweep(Date.now() + 11 * 60 * 1000);
  assert.equal(limiter.size, 0, 'les clés (IP) sont purgées');
});

test('arrêt du serveur : toutes les sessions sont détruites et les clients prévenus', async () => {
  const tmp = await startApp();
  const { body } = await createRoom(tmp.base, 3);
  const a = await makeClient({ wsUrl: tmp.wsUrl, roomId: body.roomId, secret: C.newRoomSecret(), name: 'A' });
  await a.waitStatus(Status.SECURE);
  await tmp.close();
  await waitFor(() => a.destroyedReason === 'shutdown', 2000);
  assert.equal(tmp.app.store.size, 0);
});
