// secret.boi.lu — transport WebSocket vers le serveur de relais.
// Utilise le WebSocket natif (navigateur et Node.js ≥ 22), sans dépendance.

export class Transport {
  /**
   * @param {string} url  ws(s)://hôte/ws
   * @param {object} handlers { welcome, joined, left, relay, state, destroyed, error, close, open }
   */
  constructor(url, handlers = {}) {
    this.url = url;
    this.h = handlers;
    this.ws = null;
    this.closedByUs = false;
  }

  connect() {
    return new Promise((resolve, reject) => {
      const ws = new WebSocket(this.url);
      this.ws = ws;
      let opened = false;
      ws.addEventListener('open', () => { opened = true; this.h.open?.(); resolve(); });
      ws.addEventListener('message', (ev) => this.#onMessage(ev.data));
      ws.addEventListener('error', () => { if (!opened) reject(new Error('connect_failed')); });
      ws.addEventListener('close', (ev) => {
        this.h.close?.({ code: ev.code, reason: ev.reason, byUs: this.closedByUs });
        if (!opened) reject(new Error('connect_failed'));
      });
    });
  }

  #onMessage(data) {
    if (typeof data !== 'string') return;
    let msg;
    try { msg = JSON.parse(data); } catch { return; }
    if (!msg || typeof msg.t !== 'string') return;
    switch (msg.t) {
      case 'welcome': return this.h.welcome?.(msg);
      case 'joined': return this.h.joined?.(msg.member);
      case 'left': return this.h.left?.(msg.memberId);
      case 'relay': return this.h.relay?.(msg.from, msg.data);
      case 'state': return this.h.state?.(msg);
      case 'destroyed': return this.h.destroyed?.(msg.reason, msg.by ?? null);
      case 'error': return this.h.error?.(msg.code);
      case 'pong': return;
      default: return;
    }
  }

  send(obj) {
    if (this.ws && this.ws.readyState === WebSocket.OPEN) this.ws.send(JSON.stringify(obj));
  }

  join({ roomId, memberId, pubKey, mac, ownerToken }) {
    const msg = { t: 'join', roomId, memberId, pubKey, mac };
    if (ownerToken) msg.ownerToken = ownerToken;
    this.send(msg);
  }

  relay(to, data) {
    const msg = { t: 'relay', data };
    if (to) msg.to = to;
    this.send(msg);
  }

  lock() { this.send({ t: 'lock' }); }
  unlock() { this.send({ t: 'unlock' }); }
  destroy() { this.send({ t: 'destroy' }); }
  ping() { this.send({ t: 'ping' }); }

  close() {
    this.closedByUs = true;
    try { this.ws?.close(1000, 'bye'); } catch { /* ignore */ }
  }
}

// Assemble un client complet : transport + session, pour l'interface et les tests.
export function wireSession(transport, session, extra = {}) {
  transport.h.welcome = async (w) => { extra.onWelcome?.(w); await session.welcome(w); };
  transport.h.joined = (m) => session.memberJoined(m);
  transport.h.left = (id) => session.memberLeft(id);
  transport.h.relay = (from, data) => session.handleRelay(from, data);
  transport.h.state = (s) => { session.setLocked(s.locked); extra.onState?.(s); };
  transport.h.destroyed = (reason, by) => { extra.onDestroyed?.(reason, by); session.destroy(); };
  transport.h.error = (code) => extra.onError?.(code);
  transport.h.close = (info) => extra.onClose?.(info);
  session.sendRelay = (to, data) => transport.relay(to, data);
}
