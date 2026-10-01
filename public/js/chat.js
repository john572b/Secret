// secret.boi.lu — vue du chat. Relie transport, session E2E et interface.
// Tout contenu utilisateur est rendu via textContent ; les fichiers reçus sont
// servis depuis des URL blob: locales, jamais interprétés.

import * as C from './crypto.js';
import { Session, Status, MAX_FILE_BYTES } from './protocol.js';
import { Transport, wireSession } from './transport.js';
import { watchCaptureEvents } from './capture.js';
import { showWatermark } from './watermark.js';
import { $, el, toast, copyText, formatBytes, formatTime, safeFileName, IMAGE_TYPES } from './ui.js';

const pseudonym = (index) => `Participant-${index}`;

export class ChatView {
  constructor({ roomId, root, ownerToken, inviteUrl, hasCode, passphraseMode, isCreator, onExit }) {
    this.roomId = roomId;
    this.root = root;
    this.ownerToken = ownerToken || null;
    this.inviteUrl = inviteUrl;
    this.hasCode = hasCode;
    this.passphraseMode = passphraseMode;
    this.isCreator = isCreator;
    this.onExit = onExit;
    this.owner = false;
    this.locked = false;
    this.blobUrls = [];
    this.stopCapture = null;
    this.stopWatermark = null;
    this.listeners = [];
    this.ended = false;
  }

  // --- Démarrage / connexion ----------------------------------------------------------------

  async start() {
    this.#bindUi();
    $('#messages').replaceChildren();
    $('#chat-session').textContent = `· ${this.roomId.slice(0, 6)}…`;
    this.sessionCode = (await this.#sessionCode());
    await this.#connect();
  }

  async #connect() {
    this.session = new Session({
      roomId: this.roomId,
      root: this.root,
      send: () => {},
      on: {
        status: (s) => this.#onStatus(s),
        message: (m) => this.#onMessage(m),
        members: (l) => this.#onMembers(l),
        notice: (k, info) => this.#onNotice(k, info),
      },
    });
    const proto = location.protocol === 'https:' ? 'wss' : 'ws';
    this.transport = new Transport(`${proto}://${location.host}/ws`, {});
    wireSession(this.transport, this.session, {
      onWelcome: (w) => this.#onWelcome(w),
      onState: (s) => this.#onLockState(s.locked),
      onDestroyed: (reason) => this.#onDestroyed(reason),
      onError: (code) => this.#onServerError(code),
      onClose: (info) => this.#onClose(info),
    });
    this.#setConn('⏳ Connexion…', 'quiet');
    const ann = await this.session.init();
    try {
      await this.transport.connect();
    } catch {
      this.#setConn('🔴 Déconnecté', 'danger');
      this.#banner('Impossible de joindre le serveur.', 'danger', { retry: true });
      return;
    }
    this.transport.join({ roomId: this.roomId, ...ann, ownerToken: this.ownerToken || undefined });
    this.pingTimer = setInterval(() => this.transport.ping(), 25_000);
  }

  #onWelcome(w) {
    this.owner = !!w.owner;
    this.#setConn('🟢 Connecté', 'secure');
    this.#onLockState(w.locked, { silent: true });
    $('#btn-lock').hidden = !this.owner;
    $('#btn-destroy').hidden = !this.owner;
    this.pseudonym = pseudonym(w.index);
    this.stopWatermark?.();
    this.stopWatermark = showWatermark({ pseudonym: this.pseudonym, sessionCode: this.sessionCode });
    this.#system(`Vous êtes ${this.pseudonym}. ${this.owner ? 'Vous êtes le propriétaire de ce chat.' : ''}`);
    if (!this.stopCapture) {
      this.stopCapture = watchCaptureEvents(() => {
        // Notification envoyée (chiffrée) aux autres participants uniquement.
        if (this.session?.status === Status.SECURE) this.session.sendCaptureEvent().catch(() => {});
      });
    }
    if (w.expiresAt) {
      const h = Math.max(1, Math.round((w.expiresAt - Date.now()) / 3600_000));
      this.#system(`Cette session sera détruite automatiquement dans environ ${h} h, ou dès que le propriétaire la détruit.`);
    }
  }

  // --- État du chiffrement -------------------------------------------------------------------

  #onStatus(status) {
    const pill = $('#btn-security');
    const composerOn = status === Status.SECURE;
    for (const id of ['#input-message', '#btn-file', '#btn-send']) $(id).disabled = !composerOn;
    pill.className = 'pill';
    switch (status) {
      case Status.SECURE:
        pill.textContent = '🟢 Chiffré de bout en bout';
        pill.classList.add('secure');
        this.#banner('');
        break;
      case Status.WAITING_KEY:
        pill.textContent = '🟡 En attente de la clé de session…';
        break;
      case Status.MISMATCH:
        pill.textContent = '🔴 Secret non reconnu';
        pill.classList.add('danger');
        this.#banner(`Aucun participant ne reconnaît votre ${this.passphraseMode ? 'clé personnelle' : 'lien'}${this.hasCode ? ' / code supplémentaire' : ' ou code supplémentaire'}. Vous êtes connecté au réseau mais vous ne recevrez aucune clé : la conversation reste indéchiffrable. Vérifiez le code et rejoignez à nouveau.`, 'danger');
        break;
      case Status.DESTROYED:
        pill.textContent = '⚫ Session terminée';
        break;
      default:
        pill.textContent = '🟡 Établissement du chiffrement…';
    }
  }

  #onNotice(kind, info) {
    if (kind === 'epoch_rotated' && info?.epochId) this.#system('🔑 Nouvelle clé de session distribuée aux participants vérifiés.');
    else if (kind === 'key_rejected') this.#system('⚠️ Une clé reçue n\'a pas pu être vérifiée et a été ignorée.', 'warn');
  }

  // --- Participants --------------------------------------------------------------------------

  #onMembers(list) {
    const n = list.length;
    const unverified = list.filter((m) => !m.verified).length;
    const btn = $('#btn-participants');
    btn.textContent = `🟢 ${n} participant${n > 1 ? 's' : ''} connecté${n > 1 ? 's' : ''}${unverified ? ` (${unverified} non vérifié${unverified > 1 ? 's' : ''})` : ''}`;
    const ul = $('#participants-list');
    ul.replaceChildren(...list.map((m) => el('li', {}, [
      el('span', { text: pseudonym(m.index) }),
      m.self ? el('span', { class: 'tag', text: '(vous)' }) : null,
      el('span', { class: m.verified ? 'tag' : 'tag bad', text: m.verified ? '✓ vérifié' : '⚠ non vérifié — secret différent' }),
    ])));
    const previous = this.memberIds || new Set();
    const current = new Set(list.map((m) => m.memberId));
    for (const m of list) if (!previous.has(m.memberId) && !m.self && previous.size) this.#system(`${pseudonym(m.index)} a rejoint le chat${m.verified ? '' : ' (non vérifié : secret différent)'}.`);
    for (const id of previous) if (!current.has(id)) this.#system(`${this.memberNames?.get(id) || 'Un participant'} a quitté le chat.`);
    this.memberIds = current;
    this.memberNames = new Map(list.map((m) => [m.memberId, pseudonym(m.index)]));
  }

  // --- Messages ------------------------------------------------------------------------------

  #onMessage({ index, kind, header, body }) {
    if (kind === 'capture') return this.#system('⚠️ Un événement de capture d\'écran ou d\'enregistrement a été détecté chez un participant.', 'warn');
    this.#render({ mine: false, name: pseudonym(index), header, body });
  }

  #render({ mine, name, header, body }) {
    const meta = el('div', { class: 'meta' }, [el('span', { text: mine ? `${this.pseudonym} (vous)` : name }), el('span', { text: formatTime(header.ts) })]);
    const node = el('article', { class: `msg${mine ? ' mine' : ''}` }, [meta]);
    if (header.kind === 'text') {
      node.append(el('div', { class: 'text', text: String(header.text ?? '') }));
    } else if (header.kind === 'file' && body) {
      const name = safeFileName(header.name);
      const isImage = IMAGE_TYPES.has(header.type);
      // Les fichiers non-image sont servis en octet-stream : jamais rendus par le navigateur.
      const blob = new Blob([body], { type: isImage ? header.type : 'application/octet-stream' });
      const url = URL.createObjectURL(blob);
      this.blobUrls.push(url);
      if (isImage) node.append(el('img', { src: url, alt: `Image : ${name}` }));
      node.append(el('a', { class: 'file', href: url, download: name }, [el('span', { text: '📎' }), el('span', { text: `${name} (${formatBytes(body.length)})` })]));
    } else {
      return;
    }
    this.#append(node);
  }

  #system(text, kind = '') {
    this.#append(el('div', { class: `sys${kind ? ` ${kind}` : ''}`, text }));
  }

  #append(node) {
    const box = $('#messages');
    const stick = box.scrollTop + box.clientHeight >= box.scrollHeight - 40;
    box.append(node);
    if (stick) box.scrollTop = box.scrollHeight;
  }

  async #sendText() {
    const input = $('#input-message');
    const text = input.value.trim();
    if (!text || this.session?.status !== Status.SECURE) return;
    if (text.length > 20_000) return toast('Message trop long (20 000 caractères max).');
    try {
      const { header } = await this.session.sendText(text);
      this.#render({ mine: true, header });
      input.value = '';
      input.style.height = 'auto';
    } catch {
      toast('Envoi impossible : chiffrement non établi.');
    }
  }

  async #sendFiles(files) {
    for (const file of files) {
      if (file.size > MAX_FILE_BYTES) { toast(`« ${safeFileName(file.name)} » dépasse ${formatBytes(MAX_FILE_BYTES)}.`); continue; }
      if (this.session?.status !== Status.SECURE) return toast('Chiffrement non établi.');
      try {
        const bytes = new Uint8Array(await file.arrayBuffer());
        const { header, body } = await this.session.sendFile({ name: file.name, type: file.type }, bytes);
        this.#render({ mine: true, header, body });
      } catch {
        toast('Envoi du fichier impossible.');
      }
    }
  }

  // --- Verrouillage / destruction / fin ------------------------------------------------------

  #onLockState(locked, { silent = false } = {}) {
    this.locked = !!locked;
    $('#pill-lock').hidden = !this.locked;
    $('#btn-invite').hidden = this.locked;
    $('#btn-lock').textContent = this.locked ? '🔓 Déverrouiller' : '🔒 Verrouiller le chat';
    if (!silent) this.#system(this.locked ? '🔒 Le chat est verrouillé : les nouvelles connexions sont bloquées.' : '🔓 Le chat est déverrouillé : de nouveaux participants peuvent rejoindre.');
  }

  #onDestroyed(reason) {
    if (this.ended) return;
    this.#end(reason === 'expired' ? 'expired' : 'destroyed');
  }

  #onServerError(code) {
    const messages = {
      not_found: 'Ce chat n\'existe pas ou a été détruit.',
      locked: '🔒 Ce chat est verrouillé : les nouvelles connexions sont bloquées.',
      full: 'Ce chat est complet.',
      duplicate: 'Identifiant déjà utilisé : rechargez la page.',
      rate_limited: 'Trop de messages envoyés : connexion interrompue.',
      not_owner: 'Action réservée au propriétaire du chat.',
    };
    const text = messages[code] || `Erreur de protocole (${String(code).slice(0, 32)}).`;
    if (code === 'not_owner') return toast(text);
    if (['not_found', 'locked', 'full', 'duplicate'].includes(code)) return this.#end(text);
    this.#banner(text, 'danger');
  }

  #onClose(info) {
    clearInterval(this.pingTimer);
    if (this.ended || info.byUs) return;
    this.#setConn('🔴 Déconnecté', 'danger');
    this.#onStatus(Status.WAITING_KEY);
    this.#banner('Connexion perdue. Les messages ne peuvent plus être échangés.', 'danger', { retry: true });
  }

  async #reconnect() {
    this.#banner('');
    this.session?.destroy();
    $('#messages').replaceChildren();
    await this.#connect();
  }

  leave() { this.#end('left'); }

  #end(reason) {
    if (this.ended) return;
    this.ended = true;
    clearInterval(this.pingTimer);
    try { this.transport?.close(); } catch { /* ignore */ }
    this.dispose();
    this.onExit?.(reason);
  }

  // Suppression des clés, de l'historique local et des ressources.
  dispose() {
    clearInterval(this.pingTimer);
    this.stopCapture?.(); this.stopCapture = null;
    this.stopWatermark?.(); this.stopWatermark = null;
    for (const u of this.blobUrls) URL.revokeObjectURL(u);
    this.blobUrls = [];
    $('#messages').replaceChildren();
    $('#participants-list').replaceChildren();
    $('#security-info').replaceChildren();
    $('#input-message').value = '';
    try { sessionStorage.removeItem(`owner:${this.roomId}`); } catch { /* ignore */ }
    this.session?.destroy();
    this.session = null;
    this.ownerToken = null;
    for (const [target, type, fn] of this.listeners) target.removeEventListener(type, fn);
    this.listeners = [];
    for (const d of ['#panel-participants', '#panel-security', '#dlg-destroy']) { const dlg = $(d); if (dlg.open) dlg.close(); }
  }

  // --- Interface -----------------------------------------------------------------------------

  #on(target, type, fn) { target.addEventListener(type, fn); this.listeners.push([target, type, fn]); }

  #setConn(text, cls) { const p = $('#pill-conn'); p.textContent = text; p.className = `pill quiet ${cls}`; }

  #banner(text, kind = '', { retry = false } = {}) {
    const b = $('#chat-banner');
    b.replaceChildren();
    if (!text) { b.hidden = true; return; }
    b.className = `banner ${kind}`;
    b.append(document.createTextNode(text + ' '));
    if (retry) b.append(el('button', { type: 'button', class: 'btn small', text: 'Reconnecter', onclick: () => this.#reconnect() }));
    b.hidden = false;
  }

  async #sessionCode() {
    const h = new Uint8Array(await crypto.subtle.digest('SHA-256', C.utf8.encode(this.roomId)));
    return C.toHex(h.subarray(0, 2)).toUpperCase();
  }

  async #showSecurity() {
    const dl = $('#security-info');
    const info = await this.session?.securityInfo();
    const rows = info ? [
      ['État', info.status === Status.SECURE ? '🟢 Chiffré de bout en bout' : info.status === Status.MISMATCH ? '🔴 Secret non reconnu' : '🟡 En cours d\'établissement'],
      ['Transport', `${location.protocol === 'https:' ? 'TLS (wss)' : '⚠️ non chiffré (ws) — développement'} + chiffrement applicatif indépendant`],
      ['Chiffrement', info.algorithms.cipher],
      ['Échange de clés', info.algorithms.exchange],
      ['Dérivation', `${info.algorithms.derive} ; secrets humains : ${info.algorithms.kdf}`],
      ['Authentification', `${info.algorithms.auth} des clés publiques, dérivée du secret partagé`],
      ['Votre empreinte', info.fingerprint || '—'],
      ['Clé de session', info.epochId ? `époque ${info.epochId.split(':')[1]} (${info.epochsKept} conservée${info.epochsKept > 1 ? 's' : ''})` : 'non établie'],
      ['Meneur', info.isLeader ? 'vous (distribution des clés)' : (this.memberNames?.get(info.leaderId) || '—')],
      ['Participants vérifiés', `${info.verified} / ${info.total}`],
      ['Code supplémentaire', this.hasCode ? 'utilisé (jamais transmis au serveur)' : 'non utilisé'],
      ['Serveur', 'relais de blobs chiffrés ; ne possède ni secret ni clé'],
    ] : [];
    dl.replaceChildren(...rows.flatMap(([k, v]) => [el('dt', { text: k }), el('dd', { text: v })]));
    $('#panel-security').showModal();
  }

  #bindUi() {
    const input = $('#input-message');
    this.#on($('#composer'), 'submit', (e) => { e.preventDefault(); this.#sendText(); });
    this.#on(input, 'keydown', (e) => { if (e.key === 'Enter' && !e.shiftKey) { e.preventDefault(); this.#sendText(); } });
    this.#on(input, 'input', () => { input.style.height = 'auto'; input.style.height = `${Math.min(160, input.scrollHeight)}px`; });
    this.#on($('#btn-file'), 'click', () => $('#input-file').click());
    this.#on($('#input-file'), 'change', (e) => { this.#sendFiles([...e.target.files]); e.target.value = ''; });

    const dz = $('#dropzone');
    let dragDepth = 0;
    this.#on(document, 'dragenter', (e) => { if (e.dataTransfer?.types?.includes('Files')) { dragDepth++; dz.hidden = false; } });
    this.#on(document, 'dragleave', () => { if (--dragDepth <= 0) { dragDepth = 0; dz.hidden = true; } });
    this.#on(document, 'dragover', (e) => e.preventDefault());
    this.#on(document, 'drop', (e) => { e.preventDefault(); dragDepth = 0; dz.hidden = true; if (e.dataTransfer?.files?.length) this.#sendFiles([...e.dataTransfer.files]); });

    this.#on($('#btn-participants'), 'click', () => $('#panel-participants').showModal());
    this.#on($('#btn-security'), 'click', () => this.#showSecurity());
    for (const b of document.querySelectorAll('.panel [data-close]')) this.#on(b, 'click', (e) => e.target.closest('dialog').close());

    this.#on($('#btn-invite'), 'click', async () => {
      const ok = await copyText(this.inviteUrl);
      toast(ok ? `Lien d'invitation copié.${this.hasCode ? ' N\'oubliez pas de transmettre le code séparément.' : ''}` : 'Copie impossible.');
    });
    this.#on($('#btn-lock'), 'click', () => { if (this.locked) this.transport.unlock(); else this.transport.lock(); });
    this.#on($('#btn-destroy'), 'click', () => $('#dlg-destroy').showModal());
    this.#on($('#btn-destroy-confirm'), 'click', () => { $('#dlg-destroy').close(); this.transport.destroy(); });
    this.#on($('#btn-leave'), 'click', () => this.leave());
    this.#on(window, 'pagehide', () => { this.session?.destroy(); });
  }
}
