// secret.boi.lu — enveloppe minimale autour de la Web Crypto API.
// Aucune primitive maison : PBKDF2, HKDF, HMAC, ECDH P-256, AES-256-GCM, SHA-256.
// Ce module s'exécute à l'identique dans le navigateur et sous Node.js (tests).

const subtle = globalThis.crypto.subtle;
const te = new TextEncoder();
const td = new TextDecoder();

export const PBKDF2_ITERATIONS = 600_000;
export const CURVE = 'P-256';
export const ALGORITHMS = Object.freeze({
  kdf: `PBKDF2-HMAC-SHA-256 (${PBKDF2_ITERATIONS.toLocaleString('fr-FR')} itérations)`,
  derive: 'HKDF-SHA-256',
  auth: 'HMAC-SHA-256',
  exchange: `ECDH ${CURVE} (clés éphémères)`,
  cipher: 'AES-256-GCM',
});

export const utf8 = {
  encode: (s) => te.encode(s),
  decode: (b) => td.decode(b),
};

export function randomBytes(n) {
  const b = new Uint8Array(n);
  // getRandomValues est limité à 65 536 octets par appel.
  for (let i = 0; i < n; i += 65_536) globalThis.crypto.getRandomValues(b.subarray(i, Math.min(n, i + 65_536)));
  return b;
}

export function toB64(bytes) {
  let s = '';
  const CHUNK = 0x8000;
  for (let i = 0; i < bytes.length; i += CHUNK) s += String.fromCharCode.apply(null, bytes.subarray(i, i + CHUNK));
  return btoa(s);
}

export function fromB64(s) {
  const bin = atob(s);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

export const toB64url = (bytes) => toB64(bytes).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
export function fromB64url(s) {
  const b = s.replace(/-/g, '+').replace(/_/g, '/');
  return fromB64(b + '='.repeat((4 - (b.length % 4)) % 4));
}

export function toHex(bytes) {
  return Array.from(bytes, (b) => b.toString(16).padStart(2, '0')).join('');
}

// Remise à zéro (au mieux) des secrets bruts.
export function wipe(...arrays) {
  for (const a of arrays) if (a && typeof a.fill === 'function') a.fill(0);
}

export function newMemberId() { return toHex(randomBytes(16)); }
export function newRoomSecret() { return randomBytes(32); }

// --- Dérivation depuis des secrets humains -------------------------------------------------

async function pbkdf2(secret, saltLabel) {
  const km = await subtle.importKey('raw', utf8.encode(secret.normalize('NFKC')), 'PBKDF2', false, ['deriveBits']);
  const bits = await subtle.deriveBits(
    { name: 'PBKDF2', hash: 'SHA-256', salt: utf8.encode(saltLabel), iterations: PBKDF2_ITERATIONS },
    km,
    256,
  );
  return new Uint8Array(bits);
}

export const PASSPHRASE_MIN = 8;
export const PASSPHRASE_MAX = 52;
export function isValidPassphrase(p) {
  return typeof p === 'string' && [...p].length >= PASSPHRASE_MIN && [...p].length <= PASSPHRASE_MAX;
}

// Mode « clé personnelle » : le secret de session est dérivé de la phrase.
export async function secretFromPassphrase(passphrase, roomId) {
  if (!isValidPassphrase(passphrase)) throw new RangeError('invalid_passphrase');
  return pbkdf2(passphrase, `secret.boi.lu/v1/passphrase/${roomId}`);
}

// Code supplémentaire : devient le sel de la dérivation racine (32 zéros si absent).
export function saltFromCode(code, roomId) {
  if (!code) return Promise.resolve(new Uint8Array(32));
  return pbkdf2(code, `secret.boi.lu/v1/code/${roomId}`);
}

// --- HKDF ----------------------------------------------------------------------------------

async function hkdf(ikm, salt, info, lengthBytes = 32) {
  const k = await subtle.importKey('raw', ikm, 'HKDF', false, ['deriveBits']);
  const bits = await subtle.deriveBits({ name: 'HKDF', hash: 'SHA-256', salt, info: utf8.encode(info) }, k, lengthBytes * 8);
  return new Uint8Array(bits);
}

export function deriveRoot(secret, codeSalt) {
  return hkdf(secret, codeSalt, 'secret.boi.lu/v1/root');
}

export async function deriveAuthKey(root) {
  const raw = await hkdf(root, new Uint8Array(32), 'secret.boi.lu/v1/auth');
  const key = await subtle.importKey('raw', raw, { name: 'HMAC', hash: 'SHA-256' }, false, ['sign', 'verify']);
  wipe(raw);
  return key;
}

// --- Authentification des annonces de clé publique -----------------------------------------

export function memberBinding(roomId, memberId, pubKeyB64) {
  return `secret.boi.lu/v1/member|${roomId}|${memberId}|${pubKeyB64}`;
}

export async function sign(authKey, text) {
  return toB64(new Uint8Array(await subtle.sign('HMAC', authKey, utf8.encode(text))));
}

export async function verify(authKey, text, macB64) {
  try {
    return await subtle.verify('HMAC', authKey, fromB64(macB64), utf8.encode(text));
  } catch {
    return false;
  }
}

// --- Identité éphémère (ECDH) --------------------------------------------------------------

export async function generateIdentity() {
  const kp = await subtle.generateKey({ name: 'ECDH', namedCurve: CURVE }, false, ['deriveBits']);
  const raw = new Uint8Array(await subtle.exportKey('raw', kp.publicKey));
  return { privateKey: kp.privateKey, publicKeyB64: toB64(raw) };
}

export function importPublicKey(b64) {
  return subtle.importKey('raw', fromB64(b64), { name: 'ECDH', namedCurve: CURVE }, false, []);
}

// Clé d'enveloppe pairwise : ECDH + HKDF salé par la racine (liaison au secret de session).
export async function deriveWrapKey(privateKey, theirPublicKey, root, idA, idB) {
  const shared = new Uint8Array(await subtle.deriveBits({ name: 'ECDH', public: theirPublicKey }, privateKey, 256));
  const ids = [idA, idB].sort().join('|');
  const raw = await hkdf(shared, root, `secret.boi.lu/v1/wrap|${ids}`);
  wipe(shared);
  const key = await subtle.importKey('raw', raw, 'AES-GCM', false, ['encrypt', 'decrypt']);
  wipe(raw);
  return key;
}

// --- Clés d'époque et chiffrement authentifié ----------------------------------------------

export function generateEpochKeyRaw() { return randomBytes(32); }

export function importAesKey(raw) {
  return subtle.importKey('raw', raw, 'AES-GCM', false, ['encrypt', 'decrypt']);
}

export async function encrypt(key, plaintext, aad) {
  const iv = randomBytes(12);
  const ct = new Uint8Array(await subtle.encrypt({ name: 'AES-GCM', iv, additionalData: utf8.encode(aad) }, key, plaintext));
  return { iv: toB64(iv), ct: toB64(ct) };
}

export async function decrypt(key, ivB64, ctB64, aad) {
  const pt = await subtle.decrypt({ name: 'AES-GCM', iv: fromB64(ivB64), additionalData: utf8.encode(aad) }, key, fromB64(ctB64));
  return new Uint8Array(pt);
}

export async function fingerprint(pubKeyB64) {
  const h = new Uint8Array(await subtle.digest('SHA-256', fromB64(pubKeyB64)));
  return toHex(h.subarray(0, 8)).match(/.{4}/g).join(' ');
}
