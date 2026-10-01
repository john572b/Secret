import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as C from '../public/js/crypto.js';
import { encodePayload, decodePayload } from '../public/js/protocol.js';

const roomId = 'AAAAAAAAAAAAAAAAAAAAAA';

test('base64 et hex : aller-retour, y compris sur de grands tampons', () => {
  const big = C.randomBytes(100_000);
  assert.deepEqual(C.fromB64(C.toB64(big)), big);
  assert.deepEqual(C.fromB64url(C.toB64url(big)), big);
  assert.equal(C.toHex(new Uint8Array([0, 255, 16])), '00ff10');
});

test('PBKDF2 : 600 000 itérations minimum, résultat déterministe, sels distincts', async () => {
  assert.ok(C.PBKDF2_ITERATIONS >= 600_000);
  const a = await C.secretFromPassphrase('phrase-secrète', roomId);
  const b = await C.secretFromPassphrase('phrase-secrète', roomId);
  const c = await C.secretFromPassphrase('phrase-secrète', 'BBBBBBBBBBBBBBBBBBBBBB');
  assert.deepEqual(a, b);
  assert.notDeepEqual(a, c);
  const code = await C.saltFromCode('phrase-secrète', roomId);
  assert.notDeepEqual(code, a, 'les étiquettes de domaine séparent clé personnelle et code');
});

test('clé personnelle : longueur 8 à 52 caractères imposée', async () => {
  assert.equal(C.isValidPassphrase('1234567'), false);
  assert.equal(C.isValidPassphrase('12345678'), true);
  assert.equal(C.isValidPassphrase('x'.repeat(52)), true);
  assert.equal(C.isValidPassphrase('x'.repeat(53)), false);
  await assert.rejects(() => C.secretFromPassphrase('court', roomId), RangeError);
});

test('racine : un code différent donne une racine différente, absence de code = sel nul', async () => {
  const S = C.newRoomSecret();
  const r1 = await C.deriveRoot(S, await C.saltFromCode('', roomId));
  const r2 = await C.deriveRoot(S, await C.saltFromCode('code-1', roomId));
  const r3 = await C.deriveRoot(S, await C.saltFromCode('code-2', roomId));
  assert.notDeepEqual(r1, r2);
  assert.notDeepEqual(r2, r3);
  assert.deepEqual(await C.saltFromCode('', roomId), new Uint8Array(32));
});

test('AES-GCM : chiffrement/déchiffrement, mauvaise clé, AAD ou ciphertext altéré rejetés', async () => {
  const k1 = await C.importAesKey(C.generateEpochKeyRaw());
  const k2 = await C.importAesKey(C.generateEpochKeyRaw());
  const pt = C.utf8.encode('message confidentiel');
  const { iv, ct } = await C.encrypt(k1, pt, 'aad|1');
  assert.deepEqual(await C.decrypt(k1, iv, ct, 'aad|1'), pt);
  await assert.rejects(() => C.decrypt(k2, iv, ct, 'aad|1'));
  await assert.rejects(() => C.decrypt(k1, iv, ct, 'aad|2'));
  const tampered = C.fromB64(ct); tampered[0] ^= 1;
  await assert.rejects(() => C.decrypt(k1, iv, C.toB64(tampered), 'aad|1'));
  const ivs = new Set();
  for (let i = 0; i < 50; i++) ivs.add((await C.encrypt(k1, pt, 'x')).iv);
  assert.equal(ivs.size, 50, 'IV aléatoire à chaque chiffrement');
});

test('HMAC : vérification des annonces de clé publique', async () => {
  const root = await C.deriveRoot(C.newRoomSecret(), new Uint8Array(32));
  const auth = await C.deriveAuthKey(root);
  const other = await C.deriveAuthKey(await C.deriveRoot(C.newRoomSecret(), new Uint8Array(32)));
  const id = await C.generateIdentity();
  const binding = C.memberBinding(roomId, C.newMemberId(), id.publicKeyB64);
  const mac = await C.sign(auth, binding);
  assert.equal(await C.verify(auth, binding, mac), true);
  assert.equal(await C.verify(other, binding, mac), false);
  assert.equal(await C.verify(auth, binding + 'x', mac), false);
  assert.equal(await C.verify(auth, binding, 'pas-du-base64!!'), false);
});

test('ECDH + HKDF : clé d\'enveloppe symétrique, liée à la racine et aux identifiants', async () => {
  const root = await C.deriveRoot(C.newRoomSecret(), new Uint8Array(32));
  const rootB = await C.deriveRoot(C.newRoomSecret(), new Uint8Array(32));
  const a = await C.generateIdentity();
  const b = await C.generateIdentity();
  const aPub = await C.importPublicKey(a.publicKeyB64);
  const bPub = await C.importPublicKey(b.publicKeyB64);
  const kab = await C.deriveWrapKey(a.privateKey, bPub, root, 'a', 'b');
  const kba = await C.deriveWrapKey(b.privateKey, aPub, root, 'b', 'a');
  const kBadRoot = await C.deriveWrapKey(b.privateKey, aPub, rootB, 'b', 'a');
  const kBadIds = await C.deriveWrapKey(b.privateKey, aPub, root, 'b', 'c');
  const epoch = C.generateEpochKeyRaw();
  const { iv, ct } = await C.encrypt(kab, epoch, 'key');
  assert.deepEqual(await C.decrypt(kba, iv, ct, 'key'), epoch);
  await assert.rejects(() => C.decrypt(kBadRoot, iv, ct, 'key'), 'sans la racine, ECDH seul ne suffit pas');
  await assert.rejects(() => C.decrypt(kBadIds, iv, ct, 'key'));
});

test('clé privée ECDH non exportable', async () => {
  const id = await C.generateIdentity();
  assert.equal(id.privateKey.extractable, false);
  await assert.rejects(() => globalThis.crypto.subtle.exportKey('jwk', id.privateKey));
});

test('encodage des charges utiles : en-tête + corps binaire, rejet des en-têtes corrompus', () => {
  const body = C.randomBytes(1000);
  const bytes = encodePayload({ kind: 'file', name: 'a.bin' }, body);
  const d = decodePayload(bytes);
  assert.equal(d.header.name, 'a.bin');
  assert.deepEqual(d.body, body);
  assert.equal(decodePayload(encodePayload({ kind: 'text', text: 'x' })).body, null);
  const broken = new Uint8Array(bytes); new DataView(broken.buffer).setUint32(0, 10_000_000);
  assert.throws(() => decodePayload(broken));
  assert.throws(() => decodePayload(new Uint8Array(2)));
});

test('wipe remet les tampons à zéro', () => {
  const s = C.newRoomSecret();
  C.wipe(s);
  assert.ok(s.every((b) => b === 0));
});
