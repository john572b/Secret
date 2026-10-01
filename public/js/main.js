// secret.boi.lu — point d'entrée de l'interface (accueil, création, invitation, rejoindre).
// Les secrets (secret de session, code, clé personnelle) ne vivent qu'en mémoire
// et dans le fragment d'URL (#…), que le navigateur n'envoie jamais au serveur.

import * as C from './crypto.js';
import { $, $$, showView, toast, copyText, setError } from './ui.js';
import { ChatView } from './chat.js';

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

async function enterChat({ roomId, secret, passphrase, code, ownerToken, isCreator }) {
  // Dérivations locales (PBKDF2 peut prendre ~1 s sur mobile).
  const S = passphrase ? await C.secretFromPassphrase(passphrase, roomId) : secret;
  const codeSalt = await C.saltFromCode(code, roomId);
  const root = await C.deriveRoot(S, codeSalt);
  if (passphrase) C.wipe(S);
  C.wipe(codeSalt);

  const url = `/c/${roomId}${secret ? `#s=${C.toB64url(secret)}` : ''}`;
  go('view-chat', { url });
  chat?.dispose();
  chat = new ChatView({
    roomId,
    root,
    ownerToken,
    inviteUrl: `${location.origin}${url}`,
    hasCode: !!code,
    passphraseMode: !!passphrase,
    isCreator,
    onExit: (reason) => {
      chat = null;
      go('view-home', { url: '/' });
      if (reason === 'destroyed' || reason?.startsWith('destroyed:')) {
        const who = reason.includes(':') ? ` par ${reason.split(':')[1]}` : '';
        showHomeBanner(`💥 Ce chat a été détruit${who}. Les clés et l'historique local ont été effacés.`, 'danger');
      }
      else if (reason === 'expired') showHomeBanner('⏳ Cette session a expiré et a été détruite.', '');
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
  const max = Number($('#create-max').value);
  const code = $('#create-code').value;
  const pass = $('#create-pass').value;
  if (!Number.isInteger(max) || max < 2 || max > 50) return setError(errNode, 'Le nombre de participants doit être compris entre 2 et 50.');
  if (pass && !C.isValidPassphrase(pass)) return setError(errNode, 'La clé personnelle doit contenir entre 8 et 52 caractères.');
  if (code && code.length < 4) return setError(errNode, 'Le code supplémentaire doit contenir au moins 4 caractères.');

  const btn = $('#btn-create');
  btn.disabled = true;
  try {
    const res = await fetch('/api/rooms', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ maxParticipants: max }),
    });
    if (res.status === 429) return setError(errNode, 'Trop de créations récentes. Réessayez dans une minute.');
    if (!res.ok) return setError(errNode, 'Le serveur a refusé la création du chat.');
    const { roomId, ownerToken } = await res.json();
    const secret = pass ? null : C.newRoomSecret();
    try { sessionStorage.setItem(`owner:${roomId}`, ownerToken); } catch { /* stockage indisponible */ }
    showInvite({ roomId, secret, passphrase: pass || null, code: code || null, ownerToken });
    $('#create-code').value = '';
    $('#create-pass').value = '';
  } catch {
    setError(errNode, 'Impossible de joindre le serveur.');
  } finally {
    btn.disabled = false;
  }
});

function showInvite({ roomId, secret, passphrase, code, ownerToken }) {
  const link = `${location.origin}/c/${roomId}${secret ? `#s=${C.toB64url(secret)}` : ''}`;
  $('#invite-link').value = link;
  $('#invite-id').value = roomId;
  $('#invite-link-hint').textContent = secret
    ? 'Le secret de chiffrement est dans la partie « #… » du lien : le navigateur ne l\'envoie jamais au serveur.'
    : 'Ce lien ne contient aucun secret : les participants devront saisir la clé personnelle.';
  const notes = $('#invite-notes');
  notes.replaceChildren();
  const add = (t) => { const li = document.createElement('li'); li.textContent = t; notes.append(li); };
  if (code) add('Code supplémentaire défini : transmettez-le par un autre canal que le lien (ex. de vive voix). Sans lui, le lien ne permet pas de déchiffrer.');
  if (passphrase) add('Clé personnelle définie : elle n\'est pas dans le lien. Communiquez-la séparément aux participants.');
  add('Les participants n\'auront accès qu\'aux messages échangés après leur arrivée : rien n\'est conservé sur le serveur.');
  add('Vous pourrez verrouiller le chat pour bloquer les nouvelles connexions, puis le détruire.');

  $('#btn-copy-link').onclick = async () => toast((await copyText(link)) ? 'Lien copié.' : 'Copie impossible : sélectionnez le lien manuellement.');
  $('#btn-copy-id').onclick = async () => toast((await copyText(roomId)) ? 'Identifiant copié.' : 'Copie impossible.');
  $('#btn-enter').onclick = async () => {
    $('#btn-enter').disabled = true;
    try { await enterChat({ roomId, secret, passphrase, code, ownerToken, isCreator: true }); }
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
  $('#join-field-pass').hidden = false;
  $('#join-link').value = '';
  $('#join-pass').value = '';
  $('#join-code').value = '';
  setError($('#join-error'), '');
}

function prepareJoinFromLink({ roomId, secret }) {
  resetJoinForm();
  pendingInvite = { roomId, secret };
  $('#join-field-link').hidden = true;
  const s = $('#join-session');
  s.textContent = `Session ${roomId.slice(0, 6)}… — ${secret ? 'le lien contient le secret de chiffrement.' : 'ce lien ne contient pas de secret : saisissez la clé personnelle.'}`;
  s.hidden = false;
  $('#join-field-pass').hidden = !!secret;
  go('view-join');
}

$('#form-join').addEventListener('submit', async (e) => {
  e.preventDefault();
  const errNode = $('#join-error');
  setError(errNode, '');
  const parsed = pendingInvite || parseInvite($('#join-link').value);
  if (!parsed) return setError(errNode, 'Lien ou identifiant invalide.');
  const pass = $('#join-pass').value;
  const code = $('#join-code').value;
  if (!parsed.secret && !pass) return setError(errNode, 'Il manque le secret : collez le lien d\'invitation complet, ou saisissez la clé personnelle.');
  if (!parsed.secret && !C.isValidPassphrase(pass)) return setError(errNode, 'La clé personnelle doit contenir entre 8 et 52 caractères.');

  const btn = $('#btn-join');
  btn.disabled = true;
  try {
    const res = await fetch(`/api/rooms/${parsed.roomId}`);
    if (res.status === 404) return setError(errNode, 'Ce chat n\'existe pas ou a été détruit.');
    if (res.status === 429) return setError(errNode, 'Trop de tentatives. Réessayez dans un instant.');
    if (!res.ok) return setError(errNode, 'Le serveur est indisponible.');
    const info = await res.json();
    if (info.locked) return setError(errNode, '🔒 Ce chat est verrouillé : les nouvelles connexions sont bloquées.');
    if (info.participants >= info.maxParticipants) return setError(errNode, 'Ce chat est complet.');
    let ownerToken = null;
    try { ownerToken = sessionStorage.getItem(`owner:${parsed.roomId}`); } catch { /* ignore */ }
    await enterChat({ roomId: parsed.roomId, secret: parsed.secret ? parsed.secret : null, passphrase: parsed.secret ? null : pass, code: code || null, ownerToken, isCreator: false });
    $('#join-pass').value = '';
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
