var __defProp = Object.defineProperty;
var __name = (target, value) => __defProp(target, "name", { value, configurable: true });

// server/validate.js
var ROOM_ID = /^[A-Za-z0-9_-]{22}$/;
var MEMBER_ID = /^[0-9a-f]{32}$/;
var OWNER_TOKEN = /^[A-Za-z0-9_-]{43}$/;
var B64 = /^[A-Za-z0-9+/]+={0,2}$/;
var isRoomId = /* @__PURE__ */ __name((v) => typeof v === "string" && ROOM_ID.test(v), "isRoomId");
var isMemberId = /* @__PURE__ */ __name((v) => typeof v === "string" && MEMBER_ID.test(v), "isMemberId");
var isOwnerToken = /* @__PURE__ */ __name((v) => typeof v === "string" && OWNER_TOKEN.test(v), "isOwnerToken");
function isB64(v, { min = 1, max = Infinity } = {}) {
  return typeof v === "string" && v.length >= min && v.length <= max && B64.test(v);
}
__name(isB64, "isB64");
var isPubKey = /* @__PURE__ */ __name((v) => isB64(v, { min: 88, max: 88 }), "isPubKey");
var isMac = /* @__PURE__ */ __name((v) => isB64(v, { min: 44, max: 44 }), "isMac");
function isPlainObject(v) {
  return v !== null && typeof v === "object" && !Array.isArray(v);
}
__name(isPlainObject, "isPlainObject");
function isRelayData(v, { maxCtLen }) {
  if (!isPlainObject(v)) return false;
  if (v.k !== "key" && v.k !== "msg") return false;
  if (typeof v.epochId !== "string" || v.epochId.length < 1 || v.epochId.length > 96) return false;
  if (!isB64(v.iv, { min: 16, max: 16 })) return false;
  if (!isB64(v.ct, { min: 24, max: maxCtLen })) return false;
  if (v.k === "msg" && !(Number.isInteger(v.seq) && v.seq >= 0 && v.seq <= Number.MAX_SAFE_INTEGER)) return false;
  for (const key of Object.keys(v)) {
    if (!["k", "epochId", "iv", "ct", "seq"].includes(key)) return false;
  }
  return true;
}
__name(isRelayData, "isRelayData");
function parseJson(text, maxLen) {
  if (typeof text !== "string" || text.length > maxLen) return void 0;
  try {
    const v = JSON.parse(text);
    return isPlainObject(v) ? v : void 0;
  } catch {
    return void 0;
  }
}
__name(parseJson, "parseJson");

// server/headers.js
function sanitizeHost(host) {
  if (typeof host !== "string" || host.length > 255) return null;
  return /^[A-Za-z0-9.\-:[\]]+$/.test(host) ? host : null;
}
__name(sanitizeHost, "sanitizeHost");
function buildSecurityHeaders({ host, requireHttps }) {
  const safeHost = sanitizeHost(host);
  const wsSources = safeHost ? ` wss://${safeHost}${requireHttps ? "" : ` ws://${safeHost}`}` : "";
  const csp = [
    "default-src 'none'",
    "script-src 'self'",
    "style-src 'self'",
    "img-src 'self' blob:",
    `connect-src 'self'${wsSources}`,
    "font-src 'self'",
    "manifest-src 'self'",
    "base-uri 'none'",
    "form-action 'self'",
    "frame-ancestors 'none'",
    "object-src 'none'",
    ...requireHttps ? ["upgrade-insecure-requests"] : []
  ].join("; ");
  return {
    "Content-Security-Policy": csp,
    "Strict-Transport-Security": "max-age=63072000; includeSubDomains; preload",
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
    "Permissions-Policy": "camera=(), microphone=(), geolocation=(), payment=(), usb=(), interest-cohort=()",
    "Cross-Origin-Opener-Policy": "same-origin",
    "Cross-Origin-Resource-Policy": "same-origin",
    "X-Permitted-Cross-Domain-Policies": "none"
  };
}
__name(buildSecurityHeaders, "buildSecurityHeaders");
function originAllowed({ host, origin, secFetchSite }) {
  if (typeof origin === "string" && origin !== "null") {
    try {
      return new URL(origin).host === host;
    } catch {
      return false;
    }
  }
  if (typeof secFetchSite === "string") return secFetchSite === "same-origin" || secFetchSite === "none";
  return true;
}
__name(originAllowed, "originAllowed");

// worker/room.js
import { DurableObject } from "cloudflare:workers";
var ROOM_DEFAULTS = Object.freeze({
  maxAgeMs: 24 * 60 * 60 * 1e3,
  emptyTtlMs: 10 * 60 * 1e3,
  maxParticipantsLimit: 50
});
var MAX_PAYLOAD_BYTES = 1024 * 1024;
var MAX_CT_LEN = Math.ceil(MAX_PAYLOAD_BYTES / 3) * 4;
var CLOSE_POLICY = 1008;
var CLOSE_NORMAL = 1e3;
var MSG_BUCKET = { capacity: 40, refillPerSec: 20 };
var BYTE_BUCKET = { capacity: 64 * 1024 * 1024, refillPerSec: 2 * 1024 * 1024 };
async function sha256b64(text) {
  const h = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(text));
  return btoa(String.fromCharCode(...new Uint8Array(h)));
}
__name(sha256b64, "sha256b64");
function randomToken(n = 32) {
  const b = new Uint8Array(n);
  crypto.getRandomValues(b);
  return btoa(String.fromCharCode(...b)).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}
__name(randomToken, "randomToken");
function timingSafeEqualStr(a, b) {
  if (typeof a !== "string" || typeof b !== "string" || a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return diff === 0;
}
__name(timingSafeEqualStr, "timingSafeEqualStr");
function safeSend(ws, obj) {
  try {
    ws.send(JSON.stringify(obj));
  } catch {
  }
}
__name(safeSend, "safeSend");
function take(bucket, cfg, cost, now) {
  const elapsed = Math.max(0, now - bucket.updated) / 1e3;
  bucket.tokens = Math.min(cfg.capacity, bucket.tokens + elapsed * cfg.refillPerSec);
  bucket.updated = now;
  if (bucket.tokens >= cost) {
    bucket.tokens -= cost;
    return true;
  }
  return false;
}
__name(take, "take");
var Room = class extends DurableObject {
  static {
    __name(this, "Room");
  }
  constructor(ctx, env) {
    super(ctx, env);
    this.buckets = /* @__PURE__ */ new WeakMap();
    this.ctx.setWebSocketAutoResponse(new WebSocketRequestResponsePair('{"t":"ping"}', '{"t":"pong"}'));
  }
  // --- Métadonnées ---------------------------------------------------------------------------
  async #meta() {
    return await this.ctx.storage.get("meta") || null;
  }
  async #saveMeta(meta) {
    await this.ctx.storage.put("meta", meta);
  }
  #members() {
    const out = [];
    for (const ws of this.ctx.getWebSockets()) {
      const a = ws.deserializeAttachment();
      if (a?.memberId) out.push({ ws, ...a });
    }
    return out;
  }
  async #isExpired(meta, now = Date.now()) {
    if (now >= meta.expiresAt) return true;
    if (meta.emptySince != null && this.#members().length === 0 && now - meta.emptySince >= ROOM_DEFAULTS.emptyTtlMs) return true;
    return false;
  }
  async #scheduleAlarm(meta) {
    let at = meta.expiresAt;
    if (meta.emptySince != null) at = Math.min(at, meta.emptySince + ROOM_DEFAULTS.emptyTtlMs);
    await this.ctx.storage.setAlarm(at);
  }
  // --- Requêtes HTTP internes et upgrade WebSocket ------------------------------------------
  async fetch(req) {
    const url = new URL(req.url);
    if (url.pathname === "/init" && req.method === "POST") {
      if (await this.#meta()) return new Response("exists", { status: 409 });
      const { roomId, maxParticipants } = await req.json();
      if (!isRoomId(roomId)) return new Response("bad", { status: 400 });
      const ownerToken = randomToken(32);
      const now = Date.now();
      const meta = {
        roomId,
        ownerHash: await sha256b64(ownerToken),
        maxParticipants,
        locked: false,
        createdAt: now,
        expiresAt: now + ROOM_DEFAULTS.maxAgeMs,
        emptySince: now,
        nextIndex: 1
      };
      await this.#saveMeta(meta);
      await this.#scheduleAlarm(meta);
      return Response.json({ roomId, ownerToken, maxParticipants, expiresAt: meta.expiresAt });
    }
    if (url.pathname === "/info") {
      const meta = await this.#meta();
      if (!meta || await this.#isExpired(meta)) {
        if (meta) await this.#destroy("expired");
        return Response.json({ error: "not_found" }, { status: 404 });
      }
      return Response.json({ roomId: meta.roomId, locked: meta.locked, participants: this.#members().length, maxParticipants: meta.maxParticipants, expiresAt: meta.expiresAt });
    }
    if (url.pathname === "/ws") {
      if ((req.headers.get("upgrade") || "").toLowerCase() !== "websocket") return new Response("Expected websocket", { status: 426 });
      const pair = new WebSocketPair();
      const [client, server] = Object.values(pair);
      this.ctx.acceptWebSocket(server);
      server.serializeAttachment({ joined: false });
      return new Response(null, { status: 101, webSocket: client });
    }
    return new Response("not found", { status: 404 });
  }
  // --- Messages ------------------------------------------------------------------------------
  async webSocketMessage(ws, message) {
    const fail = /* @__PURE__ */ __name((code, closeCode = CLOSE_POLICY) => {
      safeSend(ws, { t: "error", code });
      try {
        ws.close(closeCode, code);
      } catch {
      }
    }, "fail");
    const refuse = /* @__PURE__ */ __name((code) => safeSend(ws, { t: "error", code }), "refuse");
    if (typeof message !== "string") return fail("binary_not_allowed");
    const now = Date.now();
    let b = this.buckets.get(ws);
    if (!b) {
      b = { msg: { tokens: MSG_BUCKET.capacity, updated: now }, bytes: { tokens: BYTE_BUCKET.capacity, updated: now } };
      this.buckets.set(ws, b);
    }
    if (!take(b.msg, MSG_BUCKET, 1, now) || !take(b.bytes, BYTE_BUCKET, message.length, now)) return fail("rate_limited");
    const msg = parseJson(message, MAX_PAYLOAD_BYTES);
    if (!msg || typeof msg.t !== "string") return fail("bad_message");
    const att = ws.deserializeAttachment() || {};
    switch (msg.t) {
      case "ping":
        return safeSend(ws, { t: "pong" });
      case "join":
        return this.#join(ws, att, msg, fail);
      case "relay":
        return this.#relay(ws, att, msg, fail);
      case "lock":
      case "unlock":
        return this.#lock(ws, att, msg.t === "lock", fail, refuse);
      case "destroy":
        return this.#destroyRequest(att, fail, refuse);
      default:
        return fail("unknown_type");
    }
  }
  async #join(ws, att, msg, fail) {
    if (att.joined) return fail("already_joined");
    if (!isRoomId(msg.roomId) || !isMemberId(msg.memberId) || !isPubKey(msg.pubKey) || !isMac(msg.mac)) return fail("bad_join");
    if (msg.ownerToken !== void 0 && !isOwnerToken(msg.ownerToken)) return fail("bad_join");
    const meta = await this.#meta();
    if (!meta || meta.roomId !== msg.roomId) return fail("not_found", CLOSE_NORMAL);
    if (await this.#isExpired(meta)) {
      await this.#destroy("expired");
      return fail("not_found", CLOSE_NORMAL);
    }
    if (meta.locked) return fail("locked", CLOSE_NORMAL);
    const members = this.#members();
    if (members.length >= meta.maxParticipants) return fail("full", CLOSE_NORMAL);
    if (members.some((m) => m.memberId === msg.memberId)) return fail("duplicate", CLOSE_NORMAL);
    const owner = msg.ownerToken !== void 0 && timingSafeEqualStr(await sha256b64(msg.ownerToken), meta.ownerHash);
    const index = meta.nextIndex++;
    meta.emptySince = null;
    await this.#saveMeta(meta);
    await this.#scheduleAlarm(meta);
    const me = { joined: true, memberId: msg.memberId, index, pubKey: msg.pubKey, mac: msg.mac, owner };
    ws.serializeAttachment(me);
    safeSend(ws, {
      t: "welcome",
      memberId: me.memberId,
      index,
      owner,
      locked: meta.locked,
      maxParticipants: meta.maxParticipants,
      expiresAt: meta.expiresAt,
      members: members.map(({ memberId, index: i, pubKey, mac }) => ({ memberId, index: i, pubKey, mac }))
    });
    const announce = { t: "joined", member: { memberId: me.memberId, index, pubKey: me.pubKey, mac: me.mac } };
    for (const m of members) safeSend(m.ws, announce);
  }
  #relay(ws, att, msg, fail) {
    if (!att.joined) return fail("not_joined");
    if (!isRelayData(msg.data, { maxCtLen: MAX_CT_LEN })) return fail("bad_relay");
    const out = { t: "relay", from: att.memberId, data: msg.data };
    const members = this.#members();
    if (msg.to !== void 0) {
      if (!isMemberId(msg.to) || msg.to === att.memberId) return fail("bad_relay");
      const target = members.find((m) => m.memberId === msg.to);
      if (target) safeSend(target.ws, out);
      return;
    }
    for (const m of members) if (m.memberId !== att.memberId) safeSend(m.ws, out);
  }
  async #lock(ws, att, locked, fail, refuse) {
    if (!att.joined) return fail("not_joined");
    if (!att.owner) return refuse("not_owner");
    const meta = await this.#meta();
    if (!meta) return fail("not_found", CLOSE_NORMAL);
    meta.locked = locked;
    await this.#saveMeta(meta);
    for (const m of this.#members()) safeSend(m.ws, { t: "state", locked });
  }
  async #destroyRequest(att, fail, refuse) {
    if (!att.joined) return fail("not_joined");
    if (!att.owner) return refuse("not_owner");
    await this.#destroy("owner");
  }
  async #destroy(reason) {
    for (const ws of this.ctx.getWebSockets()) {
      safeSend(ws, { t: "destroyed", reason });
      try {
        ws.close(CLOSE_NORMAL, "destroyed");
      } catch {
      }
    }
    await this.ctx.storage.deleteAlarm();
    await this.ctx.storage.deleteAll();
  }
  // --- Départs et expiration -----------------------------------------------------------------
  async webSocketClose(ws) {
    await this.#leave(ws);
  }
  async webSocketError(ws) {
    await this.#leave(ws);
  }
  async #leave(ws) {
    const att = ws.deserializeAttachment();
    try {
      ws.close(CLOSE_NORMAL, "bye");
    } catch {
    }
    if (!att?.joined) return;
    ws.serializeAttachment({ joined: false });
    const meta = await this.#meta();
    const remaining = this.#members().filter((m) => m.ws !== ws);
    for (const m of remaining) safeSend(m.ws, { t: "left", memberId: att.memberId });
    if (meta && remaining.length === 0) {
      meta.emptySince = Date.now();
      await this.#saveMeta(meta);
      await this.#scheduleAlarm(meta);
    }
  }
  async alarm() {
    const meta = await this.#meta();
    if (!meta) return;
    if (await this.#isExpired(meta)) await this.#destroy("expired");
    else await this.#scheduleAlarm(meta);
  }
};

// worker/index.js
var VERSION = "0.1.0";
var MAX_BODY = 4096;
var MAX_FILE_BYTES = 8 * 1024 * 1024;
var MAX_PAYLOAD_BYTES2 = 1024 * 1024;
function withHeaders(res, base) {
  const h = new Headers(res.headers);
  for (const [k, v] of Object.entries(base)) h.set(k, v);
  return new Response(res.body, { status: res.status, statusText: res.statusText, headers: h });
}
__name(withHeaders, "withHeaders");
function json(status, obj, base) {
  return new Response(JSON.stringify(obj), { status, headers: { ...base, "Content-Type": "application/json; charset=utf-8", "Cache-Control": "no-store" } });
}
__name(json, "json");
function sameOrigin(req, host) {
  return originAllowed({ host, origin: req.headers.get("origin"), secFetchSite: req.headers.get("sec-fetch-site") });
}
__name(sameOrigin, "sameOrigin");
async function limited(limiter, key) {
  if (!limiter) return false;
  try {
    const { success } = await limiter.limit({ key });
    return !success;
  } catch {
    return false;
  }
}
__name(limited, "limited");
function clientIp(req) {
  return req.headers.get("cf-connecting-ip") || "unknown";
}
__name(clientIp, "clientIp");
function roomStub(env, roomId) {
  return env.ROOMS.get(env.ROOMS.idFromName(roomId));
}
__name(roomStub, "roomStub");
async function newRoomId() {
  const b = new Uint8Array(16);
  crypto.getRandomValues(b);
  return btoa(String.fromCharCode(...b)).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}
__name(newRoomId, "newRoomId");
var worker_default = {
  async fetch(req, env) {
    const url = new URL(req.url);
    const host = sanitizeHost(req.headers.get("host")) || url.host;
    const base = buildSecurityHeaders({ host, requireHttps: url.protocol === "https:" });
    if (url.pathname === "/api/rooms" && req.method === "POST") {
      if (!sameOrigin(req, host)) return json(403, { error: "forbidden_origin" }, base);
      if (!(req.headers.get("content-type") || "").startsWith("application/json")) return json(415, { error: "unsupported_media_type" }, base);
      if (await limited(env.CREATE_LIMITER, clientIp(req))) return json(429, { error: "rate_limited" }, base);
      const raw = await req.text();
      if (raw.length > MAX_BODY) return json(413, { error: "payload_too_large" }, base);
      let body;
      try {
        body = JSON.parse(raw);
      } catch {
        return json(400, { error: "bad_request" }, base);
      }
      if (body === null || typeof body !== "object") return json(400, { error: "bad_request" }, base);
      const max = Number(body.maxParticipants);
      if (!Number.isInteger(max) || max < 2 || max > ROOM_DEFAULTS.maxParticipantsLimit) return json(400, { error: "invalid_max_participants" }, base);
      const roomId = await newRoomId();
      const res2 = await roomStub(env, roomId).fetch("https://room/init", { method: "POST", body: JSON.stringify({ roomId, maxParticipants: max }) });
      if (!res2.ok) return json(500, { error: "internal" }, base);
      return json(201, await res2.json(), base);
    }
    if (url.pathname.startsWith("/api/rooms/") && req.method === "GET") {
      const id = url.pathname.slice("/api/rooms/".length);
      if (!isRoomId(id)) return json(400, { error: "bad_request" }, base);
      if (await limited(env.LOOKUP_LIMITER, clientIp(req))) return json(429, { error: "rate_limited" }, base);
      const res2 = await roomStub(env, id).fetch("https://room/info");
      return withHeaders(res2, { ...base, "Cache-Control": "no-store" });
    }
    if (url.pathname === "/api/info" && req.method === "GET") {
      return json(200, {
        version: VERSION,
        platform: "cloudflare-workers",
        limits: {
          maxParticipants: ROOM_DEFAULTS.maxParticipantsLimit,
          maxFileBytes: MAX_FILE_BYTES,
          maxPayloadBytes: MAX_PAYLOAD_BYTES2,
          roomMaxAgeMs: ROOM_DEFAULTS.maxAgeMs,
          roomEmptyTtlMs: ROOM_DEFAULTS.emptyTtlMs
        }
      }, base);
    }
    if (url.pathname.startsWith("/api/")) return json(404, { error: "not_found" }, base);
    if (url.pathname === "/ws") {
      if ((req.headers.get("upgrade") || "").toLowerCase() !== "websocket") return new Response("Expected websocket", { status: 426, headers: base });
      if (!sameOrigin(req, host)) return new Response("Forbidden", { status: 403, headers: base });
      if (await limited(env.CONNECT_LIMITER, clientIp(req))) return new Response("Too Many Requests", { status: 429, headers: base });
      const roomId = url.searchParams.get("room");
      if (!isRoomId(roomId)) return new Response("Bad request", { status: 400, headers: base });
      return roomStub(env, roomId).fetch(req);
    }
    if (req.method !== "GET" && req.method !== "HEAD") return new Response("Method not allowed", { status: 405, headers: { ...base, Allow: "GET, HEAD" } });
    let assetPath = url.pathname;
    if (assetPath === "/" || /^\/c\/[A-Za-z0-9_-]{22}$/.test(assetPath)) assetPath = "/index.html";
    else if (assetPath === "/security" || assetPath === "/securite") assetPath = "/security.html";
    else if (!/^\/(css|js)\/[A-Za-z0-9_.-]+$|^\/favicon\.svg$|^\/robots\.txt$/.test(assetPath)) return new Response("Not found", { status: 404, headers: base });
    const res = await env.ASSETS.fetch(new Request(new URL(assetPath, url.origin), { method: req.method, headers: req.headers }));
    if (res.status === 404) return new Response("Not found", { status: 404, headers: base });
    return withHeaders(res, { ...base, "Cache-Control": assetPath.endsWith(".html") ? "no-store" : "no-cache" });
  }
};

// node_modules/wrangler/templates/middleware/middleware-ensure-req-body-drained.ts
var drainBody = /* @__PURE__ */ __name(async (request, env, _ctx, middlewareCtx) => {
  try {
    return await middlewareCtx.next(request, env);
  } finally {
    try {
      if (request.body !== null && !request.bodyUsed) {
        const reader = request.body.getReader();
        while (!(await reader.read()).done) {
        }
      }
    } catch (e) {
      console.error("Failed to drain the unused request body.", e);
    }
  }
}, "drainBody");
var middleware_ensure_req_body_drained_default = drainBody;

// node_modules/wrangler/templates/middleware/middleware-miniflare3-json-error.ts
function reduceError(e) {
  return {
    name: e?.name,
    message: e?.message ?? String(e),
    stack: e?.stack,
    cause: e?.cause === void 0 ? void 0 : reduceError(e.cause)
  };
}
__name(reduceError, "reduceError");
var jsonError = /* @__PURE__ */ __name(async (request, env, _ctx, middlewareCtx) => {
  try {
    return await middlewareCtx.next(request, env);
  } catch (e) {
    const error = reduceError(e);
    const body = JSON.stringify(error);
    const headers = {
      "Content-Type": "application/json",
      "MF-Experimental-Error-Stack": "true"
    };
    const encoded = encodeURIComponent(body);
    if (encoded.length <= 8192) {
      headers["MF-Experimental-Error-Stack-Payload"] = encoded;
    }
    return new Response(body, { status: 500, headers });
  }
}, "jsonError");
var middleware_miniflare3_json_error_default = jsonError;

// .wrangler/tmp/bundle-PEIopQ/middleware-insertion-facade.js
var __INTERNAL_WRANGLER_MIDDLEWARE__ = [
  middleware_ensure_req_body_drained_default,
  middleware_miniflare3_json_error_default
];
var middleware_insertion_facade_default = worker_default;

// node_modules/wrangler/templates/middleware/common.ts
var __facade_middleware__ = [];
function __facade_register__(...args) {
  __facade_middleware__.push(...args.flat());
}
__name(__facade_register__, "__facade_register__");
function __facade_invokeChain__(request, env, ctx, dispatch, middlewareChain) {
  const [head, ...tail] = middlewareChain;
  const middlewareCtx = {
    dispatch,
    next(newRequest, newEnv) {
      return __facade_invokeChain__(newRequest, newEnv, ctx, dispatch, tail);
    }
  };
  return head(request, env, ctx, middlewareCtx);
}
__name(__facade_invokeChain__, "__facade_invokeChain__");
function __facade_invoke__(request, env, ctx, dispatch, finalMiddleware) {
  return __facade_invokeChain__(request, env, ctx, dispatch, [
    ...__facade_middleware__,
    finalMiddleware
  ]);
}
__name(__facade_invoke__, "__facade_invoke__");

// .wrangler/tmp/bundle-PEIopQ/middleware-loader.entry.ts
var __Facade_ScheduledController__ = class ___Facade_ScheduledController__ {
  constructor(scheduledTime, cron, noRetry) {
    this.scheduledTime = scheduledTime;
    this.cron = cron;
    this.#noRetry = noRetry;
  }
  scheduledTime;
  cron;
  static {
    __name(this, "__Facade_ScheduledController__");
  }
  #noRetry;
  noRetry() {
    if (!(this instanceof ___Facade_ScheduledController__)) {
      throw new TypeError("Illegal invocation");
    }
    this.#noRetry();
  }
};
function wrapExportedHandler(worker) {
  if (__INTERNAL_WRANGLER_MIDDLEWARE__ === void 0 || __INTERNAL_WRANGLER_MIDDLEWARE__.length === 0) {
    return worker;
  }
  for (const middleware of __INTERNAL_WRANGLER_MIDDLEWARE__) {
    __facade_register__(middleware);
  }
  const fetchDispatcher = /* @__PURE__ */ __name(function(request, env, ctx) {
    if (worker.fetch === void 0) {
      throw new Error("Handler does not export a fetch() function.");
    }
    return worker.fetch(request, env, ctx);
  }, "fetchDispatcher");
  return {
    ...worker,
    fetch(request, env, ctx) {
      const dispatcher = /* @__PURE__ */ __name(function(type, init) {
        if (type === "scheduled" && worker.scheduled !== void 0) {
          const controller = new __Facade_ScheduledController__(
            Date.now(),
            init.cron ?? "",
            () => {
            }
          );
          return worker.scheduled(controller, env, ctx);
        }
      }, "dispatcher");
      return __facade_invoke__(request, env, ctx, dispatcher, fetchDispatcher);
    }
  };
}
__name(wrapExportedHandler, "wrapExportedHandler");
function wrapWorkerEntrypoint(klass) {
  if (__INTERNAL_WRANGLER_MIDDLEWARE__ === void 0 || __INTERNAL_WRANGLER_MIDDLEWARE__.length === 0) {
    return klass;
  }
  for (const middleware of __INTERNAL_WRANGLER_MIDDLEWARE__) {
    __facade_register__(middleware);
  }
  return class extends klass {
    #fetchDispatcher = /* @__PURE__ */ __name((request, env, ctx) => {
      this.env = env;
      this.ctx = ctx;
      if (super.fetch === void 0) {
        throw new Error("Entrypoint class does not define a fetch() function.");
      }
      return super.fetch(request);
    }, "#fetchDispatcher");
    #dispatcher = /* @__PURE__ */ __name((type, init) => {
      if (type === "scheduled" && super.scheduled !== void 0) {
        const controller = new __Facade_ScheduledController__(
          Date.now(),
          init.cron ?? "",
          () => {
          }
        );
        return super.scheduled(controller);
      }
    }, "#dispatcher");
    fetch(request) {
      return __facade_invoke__(
        request,
        this.env,
        this.ctx,
        this.#dispatcher,
        this.#fetchDispatcher
      );
    }
  };
}
__name(wrapWorkerEntrypoint, "wrapWorkerEntrypoint");
var WRAPPED_ENTRY;
if (typeof middleware_insertion_facade_default === "object") {
  WRAPPED_ENTRY = wrapExportedHandler(middleware_insertion_facade_default);
} else if (typeof middleware_insertion_facade_default === "function") {
  WRAPPED_ENTRY = wrapWorkerEntrypoint(middleware_insertion_facade_default);
}
var middleware_loader_entry_default = WRAPPED_ENTRY;
export {
  Room,
  __INTERNAL_WRANGLER_MIDDLEWARE__,
  middleware_loader_entry_default as default
};
//# sourceMappingURL=index.js.map
