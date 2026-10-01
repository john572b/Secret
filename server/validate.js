// Validation stricte des entrées. Tout ce qui vient du réseau passe par ici.

const ROOM_ID = /^[A-Za-z0-9_-]{22}$/;          // 16 octets en base64url
const MEMBER_ID = /^[0-9a-f]{32}$/;              // 16 octets en hexadécimal
const OWNER_TOKEN = /^[A-Za-z0-9_-]{43}$/;       // 32 octets en base64url
const B64 = /^[A-Za-z0-9+/]+={0,2}$/;

export const isRoomId = (v) => typeof v === 'string' && ROOM_ID.test(v);
export const isMemberId = (v) => typeof v === 'string' && MEMBER_ID.test(v);
export const isOwnerToken = (v) => typeof v === 'string' && OWNER_TOKEN.test(v);

export function isB64(v, { min = 1, max = Infinity } = {}) {
  return typeof v === 'string' && v.length >= min && v.length <= max && B64.test(v);
}

// Clé publique ECDH P-256 brute non compressée : 65 octets → 88 caractères base64.
export const isPubKey = (v) => isB64(v, { min: 88, max: 88 });
// HMAC-SHA-256 : 32 octets → 44 caractères base64.
export const isMac = (v) => isB64(v, { min: 44, max: 44 });

export function isPlainObject(v) {
  return v !== null && typeof v === 'object' && !Array.isArray(v);
}

// Payload opaque de bout en bout : on ne vérifie que la forme, jamais le sens.
export function isRelayData(v, { maxCtLen }) {
  if (!isPlainObject(v)) return false;
  if (v.k !== 'key' && v.k !== 'msg') return false;
  if (typeof v.epochId !== 'string' || v.epochId.length < 1 || v.epochId.length > 96) return false;
  if (!isB64(v.iv, { min: 16, max: 16 })) return false;       // 12 octets
  if (!isB64(v.ct, { min: 24, max: maxCtLen })) return false;  // ≥ tag GCM 16 octets
  if (v.k === 'msg' && !(Number.isInteger(v.seq) && v.seq >= 0 && v.seq <= Number.MAX_SAFE_INTEGER)) return false;
  for (const key of Object.keys(v)) {
    if (!['k', 'epochId', 'iv', 'ct', 'seq'].includes(key)) return false;
  }
  return true;
}

export function parseJson(text, maxLen) {
  if (typeof text !== 'string' || text.length > maxLen) return undefined;
  try {
    const v = JSON.parse(text);
    return isPlainObject(v) ? v : undefined;
  } catch {
    return undefined;
  }
}
