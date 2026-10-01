// secret.boi.lu — gestion de session de bout en bout (clé de groupe par époque).
// Ce module ne connaît pas le DOM ni le WebSocket : il reçoit des événements de
// présence et des blobs relayés, et émet des blobs à relayer. Il est testé tel
// quel sous Node.js, à travers le vrai serveur.

import * as C from './crypto.js';

export const Status = Object.freeze({
  INIT: 'init',                 // identité générée, pas encore dans la salle
  WAITING_KEY: 'waiting_key',   // dans la salle, en attente de la clé de groupe
  SECURE: 'secure',             // clé de groupe établie : chiffrement E2E actif
  MISMATCH: 'secret_mismatch',  // aucun autre participant ne reconnaît notre secret
  DESTROYED: 'destroyed',
});

const MAX_EPOCHS_KEPT = 4;          // époques conservées pour les messages en transit
const MAX_PENDING = 64;             // messages en attente d'une clé d'époque
const HEADER_LEN_BYTES = 4;

export const MAX_FILE_BYTES = 8 * 1024 * 1024;
// Les relais (dont Cloudflare) limitent une trame WebSocket à 1 Mio : les
// fichiers sont découpés en morceaux chiffrés indépendamment, puis réassemblés.
export const FILE_CHUNK_BYTES = 512 * 1024;
export const MAX_RELAY_BYTES = 1024 * 1024;
const MAX_ASSEMBLIES = 8;
const ASSEMBLY_TTL_MS = 2 * 60 * 1000;

const msgAad = (roomId, from, epochId, seq) => `secret.boi.lu/v1/msg|${roomId}|${from}|${epochId}|${seq}`;
const keyAad = (roomId, from, to, epochId) => `secret.boi.lu/v1/key|${roomId}|${from}|${to}|${epochId}`;

export function encodePayload(header, body) {
  const h = C.utf8.encode(JSON.stringify(header));
  const out = new Uint8Array(HEADER_LEN_BYTES + h.length + (body ? body.length : 0));
  new DataView(out.buffer).setUint32(0, h.length);
  out.set(h, HEADER_LEN_BYTES);
  if (body) out.set(body, HEADER_LEN_BYTES + h.length);
  return out;
}

export function decodePayload(bytes) {
  if (bytes.length < HEADER_LEN_BYTES) throw new Error('payload_too_short');
  const hl = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength).getUint32(0);
  if (hl > bytes.length - HEADER_LEN_BYTES || hl > 64 * 1024) throw new Error('bad_header');
  const header = JSON.parse(C.utf8.decode(bytes.subarray(HEADER_LEN_BYTES, HEADER_LEN_BYTES + hl)));
  if (header === null || typeof header !== 'object') throw new Error('bad_header');
  const body = bytes.subarray(HEADER_LEN_BYTES + hl);
  return { header, body: body.length ? body : null };
}

export class Session {
  /**
   * @param {object} o
   * @param {string} o.roomId
   * @param {Uint8Array} o.root   secret racine dérivé (voir crypto.deriveRoot)
   * @param {(to: string|null, data: object) => void} o.send   relais vers le serveur
   * @param {object} [o.on]  { status(status), message(msg), members(list), notice(kind, info) }
   */
  constructor({ roomId, root, send, on = {}, memberId = C.newMemberId() }) {
    this.roomId = roomId;
    this.memberId = memberId;
    this.root = root;
    this.sendRelay = send;
    this.on = on;
    this.index = null;
    this.members = new Map();     // memberId -> { memberId, index, pubKey, mac, verified, publicKey, wrapKey }
    this.epochs = new Map();      // epochId -> { key, raw|null, createdAt }
    this.currentEpochId = null;
    this.epochCounter = 0;
    this.seq = 0;
    this.received = new Map();    // `${from}|${epochId}` -> dernier seq accepté
    this.pending = [];            // messages dont l'époque est encore inconnue
    this.assemblies = new Map();  // `${from}|${fileId}` -> fichier en cours de réassemblage
    this.status = Status.INIT;
    this.locked = false;
  }

  // Génère l'identité éphémère et l'annonce authentifiée.
  async init() {
    this.identity = await C.generateIdentity();
    this.authKey = await C.deriveAuthKey(this.root);
    this.pubKey = this.identity.publicKeyB64;
    this.mac = await C.sign(this.authKey, C.memberBinding(this.roomId, this.memberId, this.pubKey));
    return { memberId: this.memberId, pubKey: this.pubKey, mac: this.mac };
  }

  // --- Présence (événements du serveur) ----------------------------------------------------

  async welcome({ index, members, locked }) {
    this.index = index;
    this.locked = !!locked;
    for (const m of members) await this.#addMember(m);
    this.#emitMembers();
    await this.#ensureEpoch();
    this.#updateStatus();
  }

  async memberJoined(m) {
    const member = await this.#addMember(m);
    this.#emitMembers();
    await this.#ensureEpoch();
    if (this.isLeader && member.verified && this.currentEpochId) await this.#sendKey(member.memberId);
    this.#updateStatus();
  }

  async memberLeft(memberId) {
    const m = this.members.get(memberId);
    if (!m) return;
    this.members.delete(memberId);
    this.#emitMembers();
    // Rotation : le participant parti ne doit pas pouvoir lire la suite.
    if (this.isLeader) await this.#rotate();
    else await this.#ensureEpoch();
    this.#updateStatus();
  }

  setLocked(locked) { this.locked = !!locked; }

  // Meneur : le participant vérifié le plus ancien. Un participant qui ne
  // reconnaît aucun autre membre (secret différent) ne se proclame pas meneur :
  // il n'établirait qu'une clé que personne ne partage.
  get isLeader() {
    if (this.index == null) return false;
    let anyVerified = this.members.size === 0;
    for (const m of this.members.values()) {
      if (!m.verified) continue;
      anyVerified = true;
      if (m.index < this.index) return false;
    }
    return anyVerified;
  }

  get leaderId() {
    let best = { index: this.index, memberId: this.memberId };
    for (const m of this.members.values()) if (m.verified && m.index < best.index) best = m;
    return best.memberId;
  }

  memberList() {
    const list = [...this.members.values()].map((m) => ({ memberId: m.memberId, index: m.index, verified: m.verified, self: false }));
    if (this.index != null) list.push({ memberId: this.memberId, index: this.index, verified: true, self: true });
    return list.sort((a, b) => a.index - b.index);
  }

  get verifiedCount() { return this.memberList().filter((m) => m.verified).length; }

  // --- Relais entrant ------------------------------------------------------------------------

  async handleRelay(from, data) {
    if (this.status === Status.DESTROYED) return;
    const m = this.members.get(from);
    if (!m || !m.verified) return; // expéditeur inconnu ou non authentifié : ignoré
    if (data.k === 'key') return this.#handleKey(m, data);
    if (data.k === 'msg') return this.#handleMessage(m, data);
  }

  async #handleKey(m, { epochId, iv, ct }) {
    if (this.epochs.has(epochId)) return;
    let raw;
    try {
      const wrapKey = await this.#wrapKeyFor(m);
      raw = await C.decrypt(wrapKey, iv, ct, keyAad(this.roomId, m.memberId, this.memberId, epochId));
    } catch {
      this.on.notice?.('key_rejected');
      return;
    }
    if (raw.length !== 32) { C.wipe(raw); return; }
    await this.#installEpoch(epochId, raw, { keepRaw: false });
    this.seq = 0;
    this.#updateStatus();
    await this.#flushPending(epochId);
  }

  async #handleMessage(m, data) {
    const ep = this.epochs.get(data.epochId);
    if (!ep) {
      if (this.pending.length < MAX_PENDING) this.pending.push({ from: m.memberId, data });
      return;
    }
    const k = `${m.memberId}|${data.epochId}`;
    const last = this.received.get(k);
    if (last !== undefined && data.seq <= last) { this.on.notice?.('replay_dropped'); return; }
    let bytes;
    try {
      bytes = await C.decrypt(ep.key, data.iv, data.ct, msgAad(this.roomId, m.memberId, data.epochId, data.seq));
    } catch {
      this.on.notice?.('decrypt_failed');
      return;
    }
    this.received.set(k, data.seq);
    let decoded;
    try { decoded = decodePayload(bytes); } catch { return; }
    const { header, body } = decoded;
    if (!['text', 'file', 'capture'].includes(header.kind)) return;
    if (header.kind === 'file') return this.#assemble(m, header, body, data.epochId);
    this.on.message?.({ from: m.memberId, index: m.index, kind: header.kind, header, body, epochId: data.epochId });
  }

  // Réassemblage des fichiers découpés. Chaque morceau est authentifié séparément ;
  // la cohérence (taille, nombre de parties) est vérifiée avant émission.
  #assemble(m, header, body, epochId) {
    const { fileId, part, parts, size } = header;
    const maxParts = Math.ceil(MAX_FILE_BYTES / FILE_CHUNK_BYTES);
    if (typeof fileId !== 'string' || fileId.length > 32 || !Number.isInteger(parts) || parts < 1 || parts > maxParts) return;
    if (!Number.isInteger(part) || part < 0 || part >= parts || !Number.isInteger(size) || size < 0 || size > MAX_FILE_BYTES) return;
    if (!body && size > 0) return;
    const chunk = body || new Uint8Array(0);
    if (chunk.length > FILE_CHUNK_BYTES) return;
    const now = Date.now();
    for (const [k, a] of this.assemblies) if (now - a.startedAt > ASSEMBLY_TTL_MS) this.assemblies.delete(k);
    const key = `${m.memberId}|${fileId}`;
    let a = this.assemblies.get(key);
    if (!a) {
      if (this.assemblies.size >= MAX_ASSEMBLIES) return;
      a = { header, chunks: new Array(parts), received: 0, total: 0, startedAt: now };
      this.assemblies.set(key, a);
    }
    if (a.chunks[part] || a.header.parts !== parts || a.header.size !== size) return;
    a.chunks[part] = chunk;
    a.received++;
    a.total += chunk.length;
    if (a.total > size) { this.assemblies.delete(key); return; }
    if (a.received < parts) return;
    this.assemblies.delete(key);
    if (a.total !== size) return;
    const out = new Uint8Array(size);
    let off = 0;
    for (const c of a.chunks) { out.set(c, off); off += c.length; }
    const { fileId: _id, part: _p, parts: _n, ...clean } = a.header;
    this.on.message?.({ from: m.memberId, index: m.index, kind: 'file', header: clean, body: out, epochId });
  }

  async #flushPending(epochId) {
    const ready = this.pending.filter((p) => p.data.epochId === epochId);
    this.pending = this.pending.filter((p) => p.data.epochId !== epochId);
    for (const p of ready) {
      const m = this.members.get(p.from);
      if (m) await this.#handleMessage(m, p.data);
    }
  }

  // --- Envoi ---------------------------------------------------------------------------------

  async #sendPayload(header, body) {
    if (this.status !== Status.SECURE) throw new Error('not_secure');
    const ep = this.epochs.get(this.currentEpochId);
    const seq = this.seq++;
    const { iv, ct } = await C.encrypt(ep.key, encodePayload(header, body), msgAad(this.roomId, this.memberId, this.currentEpochId, seq));
    this.sendRelay(null, { k: 'msg', epochId: this.currentEpochId, seq, iv, ct });
    return { header, body, epochId: this.currentEpochId, seq };
  }

  async sendText(text) {
    if (typeof text !== 'string' || !text.length) throw new Error('empty');
    return this.#sendPayload({ kind: 'text', text, ts: Date.now() });
  }

  async sendFile({ name, type }, bytes) {
    if (!(bytes instanceof Uint8Array)) throw new TypeError('bytes');
    if (bytes.length > MAX_FILE_BYTES) throw new RangeError('file_too_large');
    if (this.status !== Status.SECURE) throw new Error('not_secure');
    const base = { kind: 'file', name: String(name).slice(0, 255), type: String(type || '').slice(0, 100), size: bytes.length, ts: Date.now() };
    const fileId = C.toHex(C.randomBytes(8));
    const parts = Math.max(1, Math.ceil(bytes.length / FILE_CHUNK_BYTES));
    for (let part = 0; part < parts; part++) {
      await this.#sendPayload({ ...base, fileId, part, parts }, bytes.subarray(part * FILE_CHUNK_BYTES, (part + 1) * FILE_CHUNK_BYTES));
    }
    return { header: base, body: bytes, parts };
  }

  async sendCaptureEvent() {
    return this.#sendPayload({ kind: 'capture', ts: Date.now() });
  }

  // --- Gestion des époques -------------------------------------------------------------------

  async #ensureEpoch() {
    if (!this.currentEpochId && this.isLeader) await this.#rotate();
  }

  async #rotate() {
    const raw = C.generateEpochKeyRaw();
    const epochId = `${this.memberId.slice(0, 8)}:${++this.epochCounter}:${C.toHex(C.randomBytes(4))}`;
    await this.#installEpoch(epochId, raw, { keepRaw: true });
    this.seq = 0;
    for (const m of this.members.values()) if (m.verified) await this.#sendKey(m.memberId);
    this.on.notice?.('epoch_rotated', { epochId });
  }

  async #installEpoch(epochId, raw, { keepRaw }) {
    const key = await C.importAesKey(raw);
    if (!keepRaw) C.wipe(raw);
    // L'ancienne époque courante ne sert plus à envelopper : on efface sa clé brute.
    const prev = this.epochs.get(this.currentEpochId);
    if (prev?.raw) { C.wipe(prev.raw); prev.raw = null; }
    this.epochs.set(epochId, { key, raw: keepRaw ? raw : null, createdAt: Date.now() });
    this.currentEpochId = epochId;
    while (this.epochs.size > MAX_EPOCHS_KEPT) {
      const oldest = this.epochs.keys().next().value;
      const e = this.epochs.get(oldest);
      if (e.raw) C.wipe(e.raw);
      this.epochs.delete(oldest);
      for (const k of [...this.received.keys()]) if (k.endsWith(`|${oldest}`)) this.received.delete(k);
    }
  }

  async #sendKey(toId) {
    const m = this.members.get(toId);
    const epochId = this.currentEpochId;
    const ep = this.epochs.get(epochId);
    if (!m?.verified || !ep?.raw) return;
    // Copie locale : une rotation concurrente peut effacer ep.raw pendant les attentes.
    const raw = ep.raw.slice();
    try {
      const wrapKey = await this.#wrapKeyFor(m);
      if (!this.members.has(toId) || this.status === Status.DESTROYED) return;
      const { iv, ct } = await C.encrypt(wrapKey, raw, keyAad(this.roomId, this.memberId, toId, epochId));
      this.sendRelay(toId, { k: 'key', epochId, iv, ct });
    } finally {
      C.wipe(raw);
    }
  }

  async #wrapKeyFor(m) {
    if (!m.wrapKey) {
      if (!m.publicKey) m.publicKey = await C.importPublicKey(m.pubKey);
      m.wrapKey = await C.deriveWrapKey(this.identity.privateKey, m.publicKey, this.root, this.memberId, m.memberId);
    }
    return m.wrapKey;
  }

  // --- Membres -------------------------------------------------------------------------------

  async #addMember({ memberId, index, pubKey, mac }) {
    const verified = await C.verify(this.authKey, C.memberBinding(this.roomId, memberId, pubKey), mac);
    const member = { memberId, index, pubKey, mac, verified, publicKey: null, wrapKey: null };
    this.members.set(memberId, member);
    return member;
  }

  #emitMembers() { this.on.members?.(this.memberList()); }

  #updateStatus() {
    let next;
    if (this.status === Status.DESTROYED) return;
    if (this.currentEpochId) next = Status.SECURE;
    else if (this.members.size > 0 && [...this.members.values()].every((m) => !m.verified)) next = Status.MISMATCH;
    else next = Status.WAITING_KEY;
    if (next !== this.status) { this.status = next; this.on.status?.(next); }
  }

  // --- Informations de sécurité (affichage) ------------------------------------------------

  async securityInfo() {
    return {
      algorithms: C.ALGORITHMS,
      fingerprint: this.pubKey ? await C.fingerprint(this.pubKey) : null,
      epochId: this.currentEpochId,
      epochsKept: this.epochs.size,
      leaderId: this.leaderId,
      isLeader: this.isLeader,
      verified: this.verifiedCount,
      total: this.memberList().length,
      status: this.status,
    };
  }

  // --- Destruction ---------------------------------------------------------------------------

  destroy() {
    for (const e of this.epochs.values()) if (e.raw) C.wipe(e.raw);
    this.epochs.clear();
    this.currentEpochId = null;
    C.wipe(this.root);
    this.root = null;
    this.identity = null;
    this.authKey = null;
    for (const m of this.members.values()) { m.wrapKey = null; m.publicKey = null; }
    this.members.clear();
    this.received.clear();
    this.pending.length = 0;
    this.assemblies.clear();
    this.status = Status.DESTROYED;
    this.on.status?.(Status.DESTROYED);
  }
}
