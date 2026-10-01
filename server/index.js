// Point d'entrée du serveur secret.boi.lu.
// Rôle : servir l'interface, créer/détruire des sessions, relayer des blobs
// chiffrés. Il ne possède aucune clé permettant de lire une conversation.

import http from 'node:http';
import { pathToFileURL } from 'node:url';
import { RoomStore } from './rooms.js';
import { RateLimiter } from './ratelimit.js';
import { createHttpHandler } from './http.js';
import { attachWebSocket } from './ws.js';
import { log } from './log.js';

export const VERSION = '0.1.0';

export function createApp(overrides = {}) {
  const env = process.env;
  const config = {
    version: VERSION,
    requireHttps: overrides.requireHttps ?? (env.REQUIRE_HTTPS === '1' || (env.NODE_ENV === 'production' && env.REQUIRE_HTTPS !== '0')),
    trustProxy: overrides.trustProxy ?? env.TRUST_PROXY === '1',
    maxFileBytes: overrides.maxFileBytes ?? 8 * 1024 * 1024,
    maxPayloadBytes: overrides.maxPayloadBytes ?? 12 * 1024 * 1024,
    heartbeatMs: overrides.heartbeatMs ?? 30 * 1000,
  };

  const store = new RoomStore(overrides.store ?? {
    maxAgeMs: Number(env.ROOM_MAX_AGE_MS) || undefined,
    emptyTtlMs: Number(env.ROOM_EMPTY_TTL_MS) || undefined,
    maxParticipantsLimit: Number(env.MAX_PARTICIPANTS) || undefined,
  });

  const limiters = {
    create: new RateLimiter(overrides.limits?.create ?? { capacity: 10, refillPerSec: 10 / 60 }),
    lookup: new RateLimiter(overrides.limits?.lookup ?? { capacity: 60, refillPerSec: 1 }),
    connect: new RateLimiter(overrides.limits?.connect ?? { capacity: 30, refillPerSec: 0.5 }),
  };

  const ctx = { store, limiters, config };
  const server = http.createServer(createHttpHandler(ctx));
  server.headersTimeout = 10_000;
  server.requestTimeout = 30_000;
  const wsLayer = attachWebSocket(server, ctx);

  const sweeper = setInterval(() => { for (const l of Object.values(limiters)) l.sweep(); }, 60_000);
  sweeper.unref();

  return {
    server,
    store,
    config,
    limiters,
    listen(port = 0, host = '0.0.0.0') {
      return new Promise((resolve, reject) => {
        server.once('error', reject);
        server.listen(port, host, () => {
          store.start();
          resolve(server.address());
        });
      });
    },
    close() {
      clearInterval(sweeper);
      store.stop();
      store.destroyAll('shutdown');
      wsLayer.close();
      return new Promise((resolve) => server.close(() => resolve()));
    },
  };
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  const app = createApp();
  const port = Number(process.env.PORT) || 8080;
  const host = process.env.HOST || '0.0.0.0';
  app.listen(port, host).then((addr) => {
    log.info('serveur démarré', 'port', addr.port, 'https_obligatoire', String(app.config.requireHttps));
  }).catch((e) => {
    log.error('échec du démarrage', e?.code || 'unknown');
    process.exit(1);
  });
  const shutdown = () => {
    log.info('arrêt : destruction de toutes les sessions', app.store.size);
    app.close().then(() => process.exit(0));
    setTimeout(() => process.exit(0), 2000).unref();
  };
  process.on('SIGINT', shutdown);
  process.on('SIGTERM', shutdown);
}
