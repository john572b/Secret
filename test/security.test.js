// Tests de sécurité : en-têtes, CSP, CSRF/CSWSH, XSS (rendu sans innerHTML), journaux sans fuite.
import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { readFile, readdir } from 'node:fs/promises';
import { spawn } from 'node:child_process';
import path from 'node:path';
import WebSocket from 'ws';
import { startApp, createRoom, makeClient, waitFor, C, Status } from './helpers/client.js';

let env;
before(async () => { env = await startApp(); });
after(async () => { await env.close(); });

test('en-têtes de sécurité modernes présents sur toutes les réponses', async () => {
  for (const p of ['/', '/security', '/api/info', '/api/rooms/BBBBBBBBBBBBBBBBBBBBBB', '/inexistant']) {
    const res = await fetch(env.base + p);
    const h = res.headers;
    const csp = h.get('content-security-policy');
    assert.ok(csp, p);
    assert.match(csp, /default-src 'none'/);
    assert.match(csp, /script-src 'self'/);
    assert.ok(!csp.includes('unsafe-inline') && !csp.includes('unsafe-eval'));
    assert.match(csp, /frame-ancestors 'none'/);
    assert.match(csp, /base-uri 'none'/);
    assert.match(h.get('strict-transport-security'), /max-age=\d{8,}/);
    assert.equal(h.get('x-content-type-options'), 'nosniff');
    assert.equal(h.get('referrer-policy'), 'no-referrer');
    assert.equal(h.get('x-frame-options'), 'DENY');
    assert.equal(h.get('cross-origin-opener-policy'), 'same-origin');
    assert.ok(h.get('permissions-policy'));
    assert.ok(!h.get('set-cookie'), 'aucun cookie');
  }
  const html = await fetch(env.base + '/');
  assert.equal(html.headers.get('cache-control'), 'no-store');
});

test('HTTPS obligatoire : redirection 301 en mode production', async () => {
  const prod = await startApp({ requireHttps: true });
  try {
    const res = await fetch(prod.base + '/c/AAAAAAAAAAAAAAAAAAAAAA?x=1', { redirect: 'manual' });
    assert.equal(res.status, 301);
    assert.match(res.headers.get('location'), /^https:\/\/127\.0\.0\.1:\d+\/c\/AAAAAAAAAAAAAAAAAAAAAA\?x=1$/);
    assert.match(res.headers.get('content-security-policy'), /upgrade-insecure-requests/);
  } finally { await prod.close(); }
});

test('CSRF : création refusée depuis une origine étrangère, acceptée depuis la même origine', async () => {
  const { status } = await createRoom(env.base, 3, { origin: 'https://attaquant.example' });
  assert.equal(status, 403);
  const { status: s2 } = await createRoom(env.base, 3, { 'sec-fetch-site': 'cross-site' });
  assert.equal(s2, 403);
  const { status: s3 } = await createRoom(env.base, 3, { origin: env.base });
  assert.equal(s3, 201);
  const { status: s4 } = await createRoom(env.base, 3, { 'sec-fetch-site': 'same-origin' });
  assert.equal(s4, 201);
});

test('CSWSH : WebSocket refusé depuis une origine étrangère', async () => {
  const attempt = (headers) => new Promise((resolve) => {
    const ws = new WebSocket(env.wsUrl, { headers });
    ws.on('open', () => { ws.close(); resolve('open'); });
    ws.on('unexpected-response', (_, res) => resolve('http_' + res.statusCode));
    ws.on('error', () => resolve('error'));
  });
  assert.equal(await attempt({ origin: 'https://attaquant.example' }), 'http_403');
  assert.equal(await attempt({ origin: env.base }), 'open');
  const other = new Promise((resolve) => {
    const ws = new WebSocket(env.base.replace('http', 'ws') + '/autre');
    ws.on('open', () => resolve('open'));
    ws.on('error', () => resolve('error'));
    ws.on('unexpected-response', () => resolve('rejected'));
  });
  assert.notEqual(await other, 'open');
});

test('traversée de répertoires et types de fichiers non servis', async () => {
  for (const p of ['/../package.json', '/..%2fpackage.json', '/js/../../server/index.js', '/package.json', '/server/index.js', '/.git/config']) {
    const res = await fetch(env.base + p);
    assert.equal(res.status, 404, p);
  }
  assert.equal((await fetch(env.base + '/js/crypto.js')).status, 200);
  assert.equal((await fetch(env.base + '/', { method: 'POST' })).status, 405);
});

test('XSS : le code client ne rend jamais de données via innerHTML/outerHTML/insertAdjacentHTML/eval', async () => {
  const dir = path.resolve('public/js');
  const files = (await readdir(dir)).filter((f) => f.endsWith('.js'));
  assert.ok(files.length >= 3);
  for (const f of files) {
    const src = await readFile(path.join(dir, f), 'utf8');
    for (const bad of ['innerHTML', 'outerHTML', 'insertAdjacentHTML', 'document.write', 'eval(', 'new Function', 'javascript:']) {
      assert.ok(!src.includes(bad), `${f} contient ${bad}`);
    }
  }
  const html = await readFile(path.resolve('public/index.html'), 'utf8');
  assert.ok(!/<script(?![^>]*\bsrc=)/i.test(html), 'aucun script inline (CSP)');
  assert.ok(!/\son[a-z]+\s*=/i.test(html), 'aucun gestionnaire inline');
  assert.ok(!/<style/i.test(html), 'aucun style inline');
});

test('injection : un contenu hostile transite et ressort intact (texte), sans toucher le serveur', async () => {
  const { body } = await createRoom(env.base, 3);
  const secret = C.newRoomSecret();
  const a = await makeClient({ wsUrl: env.wsUrl, roomId: body.roomId, secret, name: 'A' });
  await a.waitStatus(Status.SECURE);
  const b = await makeClient({ wsUrl: env.wsUrl, roomId: body.roomId, secret, name: 'B' });
  await b.waitStatus(Status.SECURE);
  const hostile = `<img src=x onerror=alert(1)>'; DROP TABLE rooms; -- {"t":"destroy"} \u0000 ${'é'.repeat(10)}`;
  await a.session.sendText(hostile);
  await b.waitMessages(1);
  assert.equal(b.messages[0].header.text, hostile);
  assert.ok(env.app.store.get(body.roomId), 'la session existe toujours');
  a.close(); b.close();
});

test('journaux : aucun secret, message, identifiant ou IP sur la sortie du serveur (LOG_LEVEL=info)', async () => {
  const child = spawn(process.execPath, ['server/index.js'], {
    env: { ...process.env, PORT: '0', HOST: '127.0.0.1', LOG_LEVEL: 'info', NODE_ENV: 'test', REQUIRE_HTTPS: '0' },
    stdio: ['ignore', 'pipe', 'pipe'],
  });
  let out = '';
  child.stdout.on('data', (d) => { out += d; });
  child.stderr.on('data', (d) => { out += d; });
  try {
    await waitFor(() => /port \d+/.test(out), 5000, 'démarrage');
    const port = Number(out.match(/port (\d+)/)[1]);
    const base = `http://127.0.0.1:${port}`;
    const wsUrl = `ws://127.0.0.1:${port}/ws`;
    const { body } = await createRoom(base, 3);
    const secret = C.newRoomSecret();
    const code = 'code-ultra-secret';
    const a = await makeClient({ wsUrl, roomId: body.roomId, secret, code, ownerToken: body.ownerToken, name: 'A' });
    await a.waitStatus(Status.SECURE);
    const b = await makeClient({ wsUrl, roomId: body.roomId, secret, code, name: 'B' });
    await b.waitStatus(Status.SECURE);
    const text = 'phrase-en-clair-' + C.toHex(C.randomBytes(8));
    await a.session.sendText(text);
    await b.waitMessages(1);
    // Déclenche aussi des erreurs de protocole pour vérifier qu'elles ne journalisent rien de sensible.
    const bad = new WebSocket(wsUrl); await new Promise((r) => bad.on('open', r)); bad.send('garbage'); await new Promise((r) => bad.on('close', r));
    a.transport.destroy();
    await waitFor(() => a.destroyedReason === 'owner', 2000);
    child.kill('SIGTERM');
    await new Promise((r) => child.on('exit', r));
    for (const forbidden of [text, code, body.roomId, body.ownerToken, a.session.memberId, C.toB64(secret), C.toHex(secret), '127.0.0.1', a.session.pubKey]) {
      assert.ok(!out.includes(forbidden), `journal contient : ${forbidden.slice(0, 30)}`);
    }
  } finally { if (child.exitCode === null) child.kill('SIGKILL'); }
});
