// secret.boi.lu — point d'entrée de l'interface (accueil, création, invitation, rejoindre).
// Les secrets (secret de session, code de chiffrement) ne vivent qu'en mémoire
// et dans le fragment d'URL (#…), que le navigateur n'envoie jamais au serveur.

import * as C from './crypto.js';
import { $, $$, showView, toast, copyText, setError } from './ui.js';
import { ChatView } from './chat.js';
import { sanitizeName } from './protocol.js';

const ROOM_RE = /^[A-Za-z0-9_-]{22}$/;
let chat = null;

// --- Navigation ------------------------------------------------------------------------------

function go(view, { url } = {}) {
  if (url !== undefined) history.replaceState(null, '', url);
  showView(view);
}

for (const b of $$('[data-nav="home"]')) b.addEventListener('click', () => go('view-home', { url: '/' }));
$('#btn-go-create').addEventListener('click', () => go('view-create', { url: '/' }));
$('#btn-go-join').addEventListener('click', () => { resetJoinForm(); go('view-join', { url: '/' }); });

function showHomeBanner(message, kind = '') {
  const b = $('#home-banner');
  b.textContent = message || '';
  b.className = `banner ${kind}`;
  b.hidden = !message;
}

// --- Analyse d'un lien / identifiant ---------------------------------------------------------

export function parseInvite(input) {
  const s = String(input || '').trim();
  if (ROOM_RE.test(s)) return { roomId: s, secret: null };
  try {
    const u = new URL(s, location.origin);
    const m = u.pathname.match(/^\/c\/([A-Za-z0-9_-]{22})$/);
    if (!m) return null;
    return { roomId: m[1], secret: secretFromHash(u.hash) };
  } catch {
    return null;
  }
}

function secretFromHash(hash) {
  const m = String(hash || '').match(/^#s=([A-Za-z0-9_-]{43})$/);
  if (!m) return null;
  try { return C.fromB64url(m[1]); } catch { return null; }
}

// --- Entrée dans le chat ---------------------------------------------------------------------

async function enterChat({ roomId, secret, code, ownerToken, isCreator, name = null }) {
  // Dérivations locales (PBKDF2 peut prendre ~1 s sur mobile).
  const codeSalt = await C.saltFromCode(code, roomId);
  const root = await C.deriveRoot(secret, codeSalt);
  C.wipe(codeSalt);

  const url = `/c/${roomId}#s=${C.toB64url(secret)}`;
  go('view-chat', { url });
  chat?.dispose();
  chat = new ChatView({
    roomId,
    root,
    ownerToken,
    inviteUrl: `${location.origin}${url}`,
    hasCode: !!code,
    isCreator,
    name: sanitizeName(name),
    onExit: (reason) => {
      chat = null;
      go('view-home', { url: '/' });
      if (reason === 'destroyed' || reason?.startsWith('destroyed:')) {
        const who = reason.includes(':') ? ` par ${reason.split(':')[1]}` : '';
        showHomeBanner(`💥 Ce chat a été détruit${who}. Les clés et l'historique local ont été effacés.`, 'danger');
      }
      else if (reason === 'expired') showHomeBanner('⏳ Cette session a expiré et a été détruite.', '');
      else if (reason === 'inactive') showHomeBanner('💤 Cette session a été détruite pour inactivité (aucun message depuis trop longtemps).', '');
      else if (reason === 'left') showHomeBanner('Vous avez quitté le chat. Les clés locales ont été effacées.', 'ok');
      else if (reason) showHomeBanner(reason, 'danger');
    },
  });
  await chat.start();
}

// --- Création --------------------------------------------------------------------------------

$('#form-create').addEventListener('submit', async (e) => {
  e.preventDefault();
  const errNode = $('#create-error');
  setError(errNode, '');
  const code = $('#create-code').value;
  const name = $('#create-name').value;
  if (code && code.length < 4) return setError(errNode, 'Le code de chiffrement doit contenir au moins 4 caractères.');

  const btn = $('#btn-create');
  btn.disabled = true;
  try {
    const res = await fetch('/api/rooms', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({}),
    });
    if (res.status === 429) return setError(errNode, 'Trop de créations récentes. Réessayez dans une minute.');
    if (!res.ok) return setError(errNode, 'Le serveur a refusé la création du chat.');
    const { roomId, ownerToken } = await res.json();
    const secret = C.newRoomSecret();
    try { sessionStorage.setItem(`owner:${roomId}`, ownerToken); } catch { /* stockage indisponible */ }
    showInvite({ roomId, secret, code: code || null, ownerToken, name });
    $('#create-code').value = '';
  } catch {
    setError(errNode, 'Impossible de joindre le serveur.');
  } finally {
    btn.disabled = false;
  }
});

function showInvite({ roomId, secret, code, ownerToken, name }) {
  const link = `${location.origin}/c/${roomId}#s=${C.toB64url(secret)}`;
  $('#invite-link').value = link;
  $('#invite-link-hint').textContent = 'Le secret de chiffrement est dans la partie « #… » du lien : le navigateur ne l\'envoie jamais au serveur.';
  const notes = $('#invite-notes');
  notes.replaceChildren();
  const add = (t) => { const li = document.createElement('li'); li.textContent = t; notes.append(li); };
  if (code) add('Code de chiffrement défini : transmettez-le par un autre canal sécurisé que le lien (de vive voix, par exemple). Sans lui, le lien ne permet pas de déchiffrer.');
  else add('Aucun code de chiffrement : toute personne disposant du lien pourra lire la conversation. Partagez-le avec soin.');
  add('Les participants n\'auront accès qu\'aux messages échangés après leur arrivée : rien n\'est conservé sur le serveur.');
  add('Toute personne disposant du lien (et du code) peut rejoindre, jusqu\'à ce que vous verrouilliez le chat. Tout participant peut le détruire.');

  $('#btn-copy-link').onclick = async () => toast((await copyText(link)) ? 'Lien copié.' : 'Copie impossible : sélectionnez le lien manuellement.');
  $('#btn-enter').onclick = async () => {
    $('#btn-enter').disabled = true;
    try { await enterChat({ roomId, secret, code, ownerToken, isCreator: true, name }); }
    finally { $('#btn-enter').disabled = false; }
  };
  go('view-invite', { url: '/' });
}

// --- Rejoindre -------------------------------------------------------------------------------

let pendingInvite = null; // { roomId, secret } lorsqu'on arrive par un lien

function resetJoinForm() {
  pendingInvite = null;
  $('#join-field-link').hidden = false;
  $('#join-session').hidden = true;
  $('#join-link').value = '';
  $('#join-name').value = '';
  $('#join-code').value = '';
  setError($('#join-error'), '');
}

function prepareJoinFromLink({ roomId, secret }) {
  resetJoinForm();
  pendingInvite = { roomId, secret };
  $('#join-field-link').hidden = true;
  const s = $('#join-session');
  s.textContent = secret
    ? `Session ${roomId.slice(0, 6)}… — le lien contient le secret de chiffrement.`
    : `Session ${roomId.slice(0, 6)}… — ce lien est incomplet (il manque la partie « #s=… »). Demandez le lien complet au créateur.`;
  s.hidden = false;
  go('view-join');
}

$('#form-join').addEventListener('submit', async (e) => {
  e.preventDefault();
  const errNode = $('#join-error');
  setError(errNode, '');
  const parsed = pendingInvite || parseInvite($('#join-link').value);
  if (!parsed) return setError(errNode, 'Lien ou identifiant invalide.');
  const code = $('#join-code').value;
  if (!parsed.secret) return setError(errNode, 'Il manque le secret : collez le lien d\'invitation complet (avec la partie « #s=… »).');

  const btn = $('#btn-join');
  btn.disabled = true;
  try {
    const res = await fetch(`/api/rooms/${parsed.roomId}`);
    if (res.status === 404) return setError(errNode, 'Ce chat n\'existe pas ou a été détruit.');
    if (res.status === 429) return setError(errNode, 'Trop de tentatives. Réessayez dans un instant.');
    if (!res.ok) return setError(errNode, 'Le serveur est indisponible.');
    const info = await res.json();
    if (info.locked) return setError(errNode, '🔒 Ce chat est verrouillé : les nouvelles connexions sont bloquées.');
    if (info.participants >= info.maxParticipants) return setError(errNode, 'Ce chat a atteint sa capacité technique.');
    let ownerToken = null;
    try { ownerToken = sessionStorage.getItem(`owner:${parsed.roomId}`); } catch { /* ignore */ }
    await enterChat({ roomId: parsed.roomId, secret: parsed.secret, code: code || null, ownerToken, isCreator: false, name: $('#join-name').value });
    $('#join-code').value = '';
  } catch {
    setError(errNode, 'Impossible de joindre le serveur.');
  } finally {
    btn.disabled = false;
  }
});

// --- Démarrage -------------------------------------------------------------------------------

function boot() {
  if (!globalThis.crypto?.subtle || !globalThis.isSecureContext) {
    showView('view-home');
    showHomeBanner('Ce navigateur n\'expose pas la Web Crypto API dans un contexte sécurisé (HTTPS requis). Le chiffrement de bout en bout est impossible.', 'danger');
    for (const b of $$('#view-home button')) b.disabled = true;
    return;
  }
  const m = location.pathname.match(/^\/c\/([A-Za-z0-9_-]{22})$/);
  if (m) {
    prepareJoinFromLink({ roomId: m[1], secret: secretFromHash(location.hash) });
    return;
  }
  showView('view-home');
}

boot();
