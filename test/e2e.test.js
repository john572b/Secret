// Tests de bout en bout : vrais clients (crypto + protocole + transport) à travers le vrai serveur.
import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { startApp, createRoom, makeClient, waitFor, sleep, textOf, C, Status } from './helpers/client.js';

let env;
before(async () => { env = await startApp(); });
after(async () => { await env.close(); });

async function newRoom() {
  const { body } = await createRoom(env.base);
  return { roomId: body.roomId, ownerToken: body.ownerToken, secret: C.newRoomSecret() };
}

test('deux participants établissent le chiffrement et échangent des messages que le serveur ne peut pas lire', async () => {
  const r = await newRoom();
  const a = await makeClient({ wsUrl: env.wsUrl, ...r, name: 'A' });
  await a.waitStatus(Status.SECURE);
  const b = await makeClient({ wsUrl: env.wsUrl, roomId: r.roomId, secret: r.secret, name: 'B' });
  await b.waitStatus(Status.SECURE);
  await a.waitMembers(2); await b.waitMembers(2);

  const SECRET_TEXT = 'Rendez-vous à minuit sous le pont — ' + C.toHex(C.randomBytes(8));
  await a.session.sendText(SECRET_TEXT);
  await b.waitMessages(1);
  assert.equal(textOf(b.messages[0]), SECRET_TEXT);
  assert.equal(b.messages[0].index, a.welcome.index);

  await b.session.sendText('réponse ' + SECRET_TEXT);
  await a.waitMessages(1);
  assert.equal(textOf(a.messages[0]), 'réponse ' + SECRET_TEXT);

  // Tout ce qui a circulé sur le câble, dans les deux sens, pour les deux clients.
  const wire = [...a.wire.out, ...a.wire.in, ...b.wire.out, ...b.wire.in].join('\n');
  assert.ok(!wire.includes(SECRET_TEXT), 'le texte en clair ne doit jamais transiter');
  assert.ok(!wire.includes('minuit'));
  assert.ok(!wire.includes(C.toB64(r.secret)) && !wire.includes(C.toB64url(r.secret)) && !wire.includes(C.toHex(r.secret)), 'le secret de session ne transite jamais');
  assert.ok(!wire.includes(C.toB64(a.root)) && !wire.includes(C.toHex(a.root)), 'la racine ne transite jamais');
  for (const frame of [...a.wire.out, ...b.wire.out]) {
    const m = JSON.parse(frame);
    if (m.t === 'relay') assert.deepEqual(Object.keys(m.data).sort(), m.data.k === 'msg' ? ['ct', 'epochId', 'iv', 'k', 'seq'] : ['ct', 'epochId', 'iv', 'k']);
  }
  a.close(); b.close();
});

test('mauvais code de chiffrement : rejoint le réseau mais ne déchiffre rien et apparaît non vérifié', async () => {
  const r = await newRoom();
  const a = await makeClient({ wsUrl: env.wsUrl, ...r, code: 'bon-code', name: 'A' });
  await a.waitStatus(Status.SECURE);
  const evil = await makeClient({ wsUrl: env.wsUrl, roomId: r.roomId, secret: r.secret, code: 'mauvais-code', name: 'Evil' });
  await evil.waitStatus(Status.MISMATCH);
  await a.waitMembers(2);
  assert.equal(a.members.find((m) => !m.self).verified, false, 'vu comme non vérifié par A');

  await a.session.sendText('confidentiel');
  await sleep(200);
  assert.equal(evil.messages.length, 0);
  assert.equal(evil.session.epochs.size, 0, 'aucune clé d\'époque reçue');
  await assert.rejects(() => evil.session.sendText('tentative'), /not_secure/);

  // Un troisième participant avec le bon code fonctionne normalement.
  const b = await makeClient({ wsUrl: env.wsUrl, roomId: r.roomId, secret: r.secret, code: 'bon-code', name: 'B' });
  await b.waitStatus(Status.SECURE);
  await a.session.sendText('pour B');
  await b.waitMessages(1);
  assert.equal(textOf(b.messages[0]), 'pour B');
  assert.equal(evil.messages.length, 0);
  a.close(); b.close(); evil.close();
});

test('fichier : chiffré de bout en bout, octets identiques à l\'arrivée, jamais en clair sur le câble', async () => {
  const r = await newRoom();
  const a = await makeClient({ wsUrl: env.wsUrl, ...r, name: 'A' });
  await a.waitStatus(Status.SECURE);
  const b = await makeClient({ wsUrl: env.wsUrl, roomId: r.roomId, secret: r.secret, name: 'B' });
  await b.waitStatus(Status.SECURE);
  const marker = C.utf8.encode('MARQUEUR-FICHIER-EN-CLAIR-' + C.toHex(C.randomBytes(8)));
  const bytes = new Uint8Array(300_000);
  bytes.set(C.randomBytes(bytes.length)); bytes.set(marker, 1000);
  await a.session.sendFile({ name: 'photo.png', type: 'image/png', size: bytes.length }, bytes);
  await b.waitMessages(1);
  const f = b.messages[0];
  assert.equal(f.kind, 'file');
  assert.equal(f.header.name, 'photo.png');
  assert.deepEqual(f.body, bytes);
  const wire = [...a.wire.out, ...b.wire.in].join('\n');
  assert.ok(!wire.includes(C.utf8.decode(marker)));
  assert.ok(!wire.includes(C.toB64(bytes.subarray(0, 300))));
  await assert.rejects(() => a.session.sendFile({ name: 'big' }, new Uint8Array(9 * 1024 * 1024)), RangeError);
  a.close(); b.close();
});

test('fichier volumineux : découpé en trames < 1 Mio, réassemblé à l\'identique, morceau manquant = rien', async () => {
  const r = await newRoom();
  const a = await makeClient({ wsUrl: env.wsUrl, ...r, name: 'A' });
  await a.waitStatus(Status.SECURE);
  const b = await makeClient({ wsUrl: env.wsUrl, roomId: r.roomId, secret: r.secret, name: 'B' });
  await b.waitStatus(Status.SECURE);
  const bytes = C.randomBytes(1_300_000);
  const sent = a.wire.out.length;
  const { parts } = await a.session.sendFile({ name: 'gros.bin', type: 'application/octet-stream' }, bytes);
  assert.equal(parts, 3);
  const frames = a.wire.out.slice(sent);
  assert.equal(frames.length, 3);
  for (const f of frames) assert.ok(f.length < 1024 * 1024, `trame de ${f.length} octets`);
  await b.waitMessages(1, 10000);
  assert.equal(b.messages[0].kind, 'file');
  assert.equal(b.messages[0].header.name, 'gros.bin');
  assert.equal(b.messages[0].header.parts, undefined);
  assert.deepEqual(b.messages[0].body, bytes);
  // Un serveur malveillant qui supprime un morceau : le fichier n'est jamais émis.
  const parsed = frames.map((f) => JSON.parse(f).data);
  b.session.received.clear();
  await b.session.handleRelay(a.session.memberId, { ...parsed[0], seq: 100 });
  await b.session.handleRelay(a.session.memberId, { ...parsed[2], seq: 102 });
  await sleep(100);
  assert.equal(b.messages.length, 1);
  a.close(); b.close();
});

test('départ d\'un participant : rotation de clé, l\'ancienne clé ne déchiffre pas la suite', async () => {
  const r = await newRoom();
  const a = await makeClient({ wsUrl: env.wsUrl, ...r, name: 'A' });
  await a.waitStatus(Status.SECURE);
  const b = await makeClient({ wsUrl: env.wsUrl, roomId: r.roomId, secret: r.secret, name: 'B' });
  const c = await makeClient({ wsUrl: env.wsUrl, roomId: r.roomId, secret: r.secret, name: 'C' });
  await b.waitStatus(Status.SECURE); await c.waitStatus(Status.SECURE);
  await a.waitMembers(3);
  const epochBefore = a.session.currentEpochId;
  const oldKey = a.session.epochs.get(epochBefore).key;

  c.close();
  await a.waitMembers(2); await b.waitMembers(2);
  await waitFor(() => a.session.currentEpochId !== epochBefore, 3000, 'rotation après départ');
  await waitFor(() => b.session.currentEpochId === a.session.currentEpochId, 3000, 'B reçoit la nouvelle époque');

  await a.session.sendText('après le départ de C');
  await b.waitMessages(1);
  assert.equal(textOf(b.messages[0]), 'après le départ de C');
  const frame = JSON.parse(a.wire.out.filter((f) => f.includes('"k":"msg"')).pop());
  assert.notEqual(frame.data.epochId, epochBefore);
  await assert.rejects(() => C.decrypt(oldKey, frame.data.iv, frame.data.ct, `secret.boi.lu/v1/msg|${r.roomId}|${a.session.memberId}|${frame.data.epochId}|${frame.data.seq}`));
  a.close(); b.close();
});

test('départ du meneur : le suivant prend le relais et effectue une rotation', async () => {
  const r = await newRoom();
  const a = await makeClient({ wsUrl: env.wsUrl, ...r, name: 'A' });
  await a.waitStatus(Status.SECURE);
  const b = await makeClient({ wsUrl: env.wsUrl, roomId: r.roomId, secret: r.secret, name: 'B' });
  const c = await makeClient({ wsUrl: env.wsUrl, roomId: r.roomId, secret: r.secret, name: 'C' });
  await b.waitStatus(Status.SECURE); await c.waitStatus(Status.SECURE);
  await b.waitMembers(3);
  const before = b.session.currentEpochId;
  a.close();
  await waitFor(() => b.session.isLeader && b.session.currentEpochId !== before, 3000, 'B devient meneur');
  await waitFor(() => c.session.currentEpochId === b.session.currentEpochId, 3000, 'C reçoit la clé de B');
  await c.session.sendText('toujours là');
  await b.waitMessages(1);
  assert.equal(textOf(b.messages[0]), 'toujours là');
  b.close(); c.close();
});

test('rejeu : un message relayé deux fois n\'est accepté qu\'une fois ; réattribution impossible', async () => {
  const r = await newRoom();
  const a = await makeClient({ wsUrl: env.wsUrl, ...r, name: 'A' });
  await a.waitStatus(Status.SECURE);
  const b = await makeClient({ wsUrl: env.wsUrl, roomId: r.roomId, secret: r.secret, name: 'B' });
  await b.waitStatus(Status.SECURE);
  await a.session.sendText('unique');
  await b.waitMessages(1);
  const frame = JSON.parse(a.wire.out.filter((f) => f.includes('"k":"msg"')).pop());
  // Rejeu par le « serveur » : on réinjecte le même blob chez B.
  await b.session.handleRelay(a.session.memberId, frame.data);
  await sleep(50);
  assert.equal(b.messages.length, 1);
  assert.ok(b.notices.some((n) => n.k === 'replay_dropped'));
  // Réattribution à un autre expéditeur : l'AAD ne correspond plus.
  const c = await makeClient({ wsUrl: env.wsUrl, roomId: r.roomId, secret: r.secret, name: 'C' });
  await c.waitStatus(Status.SECURE);
  await b.waitMembers(3);
  await b.session.handleRelay(c.session.memberId, { ...frame.data, seq: 999 });
  await sleep(50);
  assert.equal(b.messages.length, 1);
  a.close(); b.close(); c.close();
});

test('verrouillage : refuse les nouveaux, garde les présents ; déverrouillage ; non-propriétaire refusé', async () => {
  const r = await newRoom();
  const a = await makeClient({ wsUrl: env.wsUrl, ...r, name: 'A' });
  await a.waitStatus(Status.SECURE);
  assert.equal(a.welcome.owner, true);
  const b = await makeClient({ wsUrl: env.wsUrl, roomId: r.roomId, secret: r.secret, name: 'B' });
  await b.waitStatus(Status.SECURE);
  assert.equal(b.welcome.owner, false);

  b.transport.lock();
  await waitFor(() => b.error === 'not_owner', 2000, 'refus non-propriétaire');

  a.transport.lock();
  await waitFor(() => a.locked === true && a.session.locked === true, 2000, 'état verrouillé diffusé');
  const c = await makeClient({ wsUrl: env.wsUrl, roomId: r.roomId, secret: r.secret, name: 'C' });
  await waitFor(() => c.error === 'locked', 2000, 'nouveau participant refusé');
  const info = await (await fetch(`${env.base}/api/rooms/${r.roomId}`)).json();
  assert.equal(info.locked, true);
  assert.equal(info.participants, 2);

  a.transport.unlock();
  await waitFor(() => a.locked === false, 2000);
  const d = await makeClient({ wsUrl: env.wsUrl, roomId: r.roomId, secret: r.secret, name: 'D' });
  await d.waitStatus(Status.SECURE);
  a.close(); d.close();
});

test('destruction par n\'importe quel participant : clients notifiés et déconnectés, session inexistante, clés client effacées', async () => {
  const r = await newRoom();
  const a = await makeClient({ wsUrl: env.wsUrl, ...r, name: 'A' });
  await a.waitStatus(Status.SECURE);
  const b = await makeClient({ wsUrl: env.wsUrl, roomId: r.roomId, secret: r.secret, name: 'B' });
  await b.waitStatus(Status.SECURE);
  assert.equal(b.welcome.owner, false);
  // B n'est pas propriétaire : il peut quand même détruire le chat.
  b.transport.destroy();
  await waitFor(() => a.destroyedReason === 'participant' && b.destroyedReason === 'participant', 2000, 'notification de destruction');
  await waitFor(() => a.closeInfo && b.closeInfo, 2000, 'sockets fermées');
  assert.equal(a.session.status, Status.DESTROYED);
  assert.equal(a.session.epochs.size, 0);
  assert.equal(a.session.root, null);
  assert.equal(a.session.identity, null);
  assert.ok(a.root.every((x) => x === 0), 'racine remise à zéro');
  if (env.app) assert.equal(env.app.store.get(r.roomId), null);
  const res = await fetch(`${env.base}/api/rooms/${r.roomId}`);
  assert.equal(res.status, 404);
  const again = await makeClient({ wsUrl: env.wsUrl, roomId: r.roomId, secret: r.secret, name: 'late' });
  await waitFor(() => again.error === 'not_found', 2000);
});

test('un message chiffré sous une époque reçu avant sa clé est mis en attente puis déchiffré', async () => {
  const r = await newRoom();
  const a = await makeClient({ wsUrl: env.wsUrl, ...r, name: 'A' });
  await a.waitStatus(Status.SECURE);
  const b = await makeClient({ wsUrl: env.wsUrl, roomId: r.roomId, secret: r.secret, name: 'B' });
  await b.waitStatus(Status.SECURE);
  await a.waitMembers(2);
  // Simule le serveur livrant un message avant la clé : B oublie l'époque courante.
  const epochId = a.session.currentEpochId;
  await a.session.sendText('en avance');
  await b.waitMessages(1);
  const frame = JSON.parse(a.wire.out.filter((f) => f.includes('"k":"msg"')).pop());
  const keyFrame = JSON.parse(a.wire.out.find((f) => f.includes('"k":"key"') && f.includes(epochId)));
  b.session.epochs.delete(epochId); b.session.currentEpochId = null;
  b.session.received.clear();
  await b.session.handleRelay(a.session.memberId, frame.data);
  assert.equal(b.session.pending.length, 1);
  await b.session.handleRelay(a.session.memberId, keyFrame.data);
  await b.waitMessages(2);
  assert.equal(textOf(b.messages[1]), 'en avance');
  a.close(); b.close();
});

test('pseudos : annoncés chiffrés, visibles des autres, jamais en clair sur le câble', async () => {
  const r = await newRoom();
  const a = await makeClient({ wsUrl: env.wsUrl, ...r, name: 'A', nickname: 'Alice Dupont' });
  await a.waitStatus(Status.SECURE);
  const b = await makeClient({ wsUrl: env.wsUrl, roomId: r.roomId, secret: r.secret, name: 'B', nickname: '  Bob\u0000<script>  ' });
  await b.waitStatus(Status.SECURE);
  await waitFor(() => a.members.find((m) => !m.self)?.name === 'Bob<script>', 5000, 'A connaît le pseudo de B (nettoyé)');
  await waitFor(() => b.members.find((m) => !m.self)?.name === 'Alice Dupont', 5000, 'B connaît le pseudo de A');
  assert.equal(a.members.find((m) => m.self).name, 'Alice Dupont');
  await a.session.sendText('salut');
  await b.waitMessages(1);
  assert.equal(b.messages[0].name, 'Alice Dupont');
  const wire = [...a.wire.out, ...a.wire.in, ...b.wire.out, ...b.wire.in].join('\n');
  assert.ok(!wire.includes('Alice') && !wire.includes('Bob'), 'les pseudos ne transitent jamais en clair');
  // Un troisième arrivant apprend les pseudos existants.
  const c = await makeClient({ wsUrl: env.wsUrl, roomId: r.roomId, secret: r.secret, name: 'C' });
  await c.waitStatus(Status.SECURE);
  await waitFor(() => c.members.filter((m) => m.name).length === 2, 5000, 'C reçoit les deux pseudos');
  a.close(); b.close(); c.close();
});

test('inactivité : une salle sans message est détruite, clients prévenus', { skip: !!process.env.E2E_BASE }, async () => {
  const idle = await startApp({ store: { maxAgeMs: 60_000, emptyTtlMs: 60_000, idleTtlMs: 700, maxParticipantsLimit: 10, sweepIntervalMs: 50 } });
  try {
    const { body } = await createRoom(idle.base);
    const secret = C.newRoomSecret();
    const a = await makeClient({ wsUrl: idle.wsUrl, roomId: body.roomId, secret, name: 'A' });
    const b = await makeClient({ wsUrl: idle.wsUrl, roomId: body.roomId, secret, name: 'B' });
    await a.waitStatus(Status.SECURE); await b.waitStatus(Status.SECURE);
    // Des messages réguliers maintiennent la salle en vie.
    for (let i = 0; i < 4; i++) { await a.session.sendText('ping ' + i); await sleep(250); }
    assert.ok(idle.app.store.get(body.roomId), 'salle vivante tant qu\'il y a du trafic');
    await waitFor(() => a.destroyedReason === 'inactive' && b.destroyedReason === 'inactive', 3000, 'destruction pour inactivité');
    assert.equal(idle.app.store.size, 0);
  } finally { await idle.close(); }
});

test('événement de capture : transmis chiffré aux autres participants', async () => {
  const r = await newRoom();
  const a = await makeClient({ wsUrl: env.wsUrl, ...r, name: 'A' });
  await a.waitStatus(Status.SECURE);
  const b = await makeClient({ wsUrl: env.wsUrl, roomId: r.roomId, secret: r.secret, name: 'B' });
  await b.waitStatus(Status.SECURE);
  await a.session.sendCaptureEvent();
  await b.waitMessages(1);
  assert.equal(b.messages[0].kind, 'capture');
  assert.ok(!a.wire.out.join('').includes('capture'));
  a.close(); b.close();
});
