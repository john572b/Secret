// Limiteur de débit « seau à jetons », en mémoire.
// Les clés (adresses IP) ne sont conservées que le temps de la fenêtre et
// purgées ensuite ; elles ne sont jamais écrites ailleurs.

export class RateLimiter {
  constructor({ capacity, refillPerSec, idleMs = 10 * 60 * 1000 }) {
    this.capacity = capacity;
    this.refillPerSec = refillPerSec;
    this.idleMs = idleMs;
    this.buckets = new Map();
  }

  take(key, cost = 1, now = Date.now()) {
    let b = this.buckets.get(key);
    if (!b) {
      b = { tokens: this.capacity, updated: now };
      this.buckets.set(key, b);
    } else {
      const elapsed = Math.max(0, now - b.updated) / 1000;
      b.tokens = Math.min(this.capacity, b.tokens + elapsed * this.refillPerSec);
      b.updated = now;
    }
    if (b.tokens >= cost) { b.tokens -= cost; return true; }
    return false;
  }

  sweep(now = Date.now()) {
    for (const [k, b] of this.buckets) {
      if (now - b.updated > this.idleMs) this.buckets.delete(k);
    }
  }

  get size() { return this.buckets.size; }
}
