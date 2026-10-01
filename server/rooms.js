// Magasin de sessions, uniquement en mémoire.
// Une session (« room ») n'existe que pendant sa durée de vie : aucune base de
// données, aucun fichier, aucune persistance entre redémarrages.

import { randomBytes, createHash, timingSafeEqual } from 'node:crypto';

export const DEFAULTS = {
  maxAgeMs: 24 * 60 * 60 * 1000,      // durée de vie maximale d'une session
  emptyTtlMs: 10 * 60 * 1000,         // destruction si la salle reste vide
  maxParticipantsLimit: 50,           // plafond absolu du nombre de participants
  sweepIntervalMs: 15 * 1000,
};

function hashToken(token) {
  return createHash('sha256').update(token, 'utf8').digest();
}

export class RoomStore {
  constructor(opts = {}) {
    // Les options `undefined` (variables d'environnement absentes) n'écrasent pas les valeurs par défaut.
    this.opts = { ...DEFAULTS, ...Object.fromEntries(Object.entries(opts).filter(([, v]) => v !== undefined)) };
    this.rooms = new Map();
    this.timer = null;
    this.onDestroy = null; // (room, reason) => void — appelé avant l'effacement
  }

  start() {
    if (this.timer) return;
    this.timer = setInterval(() => this.sweep(), this.opts.sweepIntervalMs);
    this.timer.unref();
  }

  stop() {
    if (this.timer) clearInterval(this.timer);
    this.timer = null;
  }

  get size() { return this.rooms.size; }

  create({ maxParticipants }) {
    const max = Number(maxParticipants);
    if (!Number.isInteger(max) || max < 2 || max > this.opts.maxParticipantsLimit) {
      throw new RangeError('invalid_max_participants');
    }
    const id = randomBytes(16).toString('base64url');        // 128 bits
    const ownerToken = randomBytes(32).toString('base64url'); // 256 bits, jamais stocké en clair
    const now = Date.now();
    const room = {
      id,
      ownerHash: hashToken(ownerToken),
      maxParticipants: max,
      locked: false,
      createdAt: now,
      expiresAt: now + this.opts.maxAgeMs,
      emptySince: now,
      members: new Map(),
      nextIndex: 1,
      destroyed: false,
    };
    this.rooms.set(id, room);
    return { room, ownerToken };
  }

  isExpired(room, now = Date.now()) {
    if (now >= room.expiresAt) return true;
    if (room.members.size === 0 && room.emptySince != null && now - room.emptySince >= this.opts.emptyTtlMs) return true;
    return false;
  }

  get(id) {
    const room = this.rooms.get(id);
    if (!room) return null;
    if (this.isExpired(room)) {
      this.destroy(id, 'expired');
      return null;
    }
    return room;
  }

  isOwner(room, token) {
    if (typeof token !== 'string' || token.length < 16 || token.length > 128) return false;
    const h = hashToken(token);
    return h.length === room.ownerHash.length && timingSafeEqual(h, room.ownerHash);
  }

  addMember(room, member) {
    if (room.destroyed) throw new Error('destroyed');
    if (room.locked) throw new Error('locked');
    if (room.members.size >= room.maxParticipants) throw new Error('full');
    if (room.members.has(member.memberId)) throw new Error('duplicate');
    member.index = room.nextIndex++;
    room.members.set(member.memberId, member);
    room.emptySince = null;
    return member;
  }

  removeMember(room, memberId) {
    const existed = room.members.delete(memberId);
    if (room.members.size === 0) room.emptySince = Date.now();
    return existed;
  }

  destroy(id, reason = 'participant', by = null) {
    const room = this.rooms.get(id);
    if (!room) return false;
    this.rooms.delete(id);
    room.destroyed = true;
    try { this.onDestroy?.(room, reason, by); } finally { wipeRoom(room); }
    return true;
  }

  sweep(now = Date.now()) {
    let n = 0;
    for (const [id, room] of this.rooms) {
      if (this.isExpired(room, now)) { this.destroy(id, 'expired'); n++; }
    }
    return n;
  }

  destroyAll(reason = 'shutdown') {
    for (const id of [...this.rooms.keys()]) this.destroy(id, reason);
  }
}

// Efface les structures de la session. L'effacement mémoire en JavaScript est
// au mieux (ramasse-miettes), mais on supprime toute référence utile.
function wipeRoom(room) {
  for (const m of room.members.values()) {
    m.pubKey = null; m.mac = null; m.ws = null;
  }
  room.members.clear();
  room.ownerHash.fill(0);
  room.id = null;
}
