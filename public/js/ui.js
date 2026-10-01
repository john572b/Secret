// Petits utilitaires DOM. Tout texte provenant d'un utilisateur passe par
// textContent : aucune insertion de HTML dynamique.

export const $ = (sel, root = document) => root.querySelector(sel);
export const $$ = (sel, root = document) => [...root.querySelectorAll(sel)];

export function el(tag, attrs = {}, children = []) {
  const node = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs)) {
    if (v === undefined || v === null || v === false) continue;
    if (k === 'class') node.className = v;
    else if (k === 'text') node.textContent = v;
    else if (k === 'dataset') Object.assign(node.dataset, v);
    else if (k.startsWith('on') && typeof v === 'function') node.addEventListener(k.slice(2), v);
    else node.setAttribute(k, v === true ? '' : String(v));
  }
  for (const c of [].concat(children)) {
    if (c === null || c === undefined) continue;
    node.append(typeof c === 'string' ? document.createTextNode(c) : c);
  }
  return node;
}

export function showView(id) {
  for (const v of $$('.view')) v.hidden = v.id !== id;
  const view = document.getElementById(id);
  const focusTarget = view?.querySelector('h1, h2, [autofocus]');
  if (focusTarget) { focusTarget.setAttribute('tabindex', '-1'); focusTarget.focus({ preventScroll: true }); }
  window.scrollTo(0, 0);
}

export function toast(message, ms = 3500) {
  const box = $('#toasts');
  const t = el('div', { class: 'toast', text: message });
  box.append(t);
  setTimeout(() => t.remove(), ms);
}

export async function copyText(text) {
  try {
    await navigator.clipboard.writeText(text);
    return true;
  } catch {
    return false;
  }
}

export function setError(node, message) {
  node.textContent = message || '';
  node.hidden = !message;
}

export function formatBytes(n) {
  if (n < 1024) return `${n} o`;
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} Kio`;
  return `${(n / (1024 * 1024)).toFixed(2)} Mio`;
}

export function formatTime(ts) {
  try { return new Date(ts).toLocaleTimeString('fr-FR', { hour: '2-digit', minute: '2-digit' }); } catch { return ''; }
}

// Nom de fichier affiché/téléchargé : jamais interprété, toujours assaini.
export function safeFileName(name) {
  const cleaned = String(name || 'fichier').replace(/[\\/:*?"<>|\u0000-\u001f]/g, '_').replace(/^\.+/, '').slice(0, 120);
  return cleaned || 'fichier';
}

export const IMAGE_TYPES = new Set(['image/png', 'image/jpeg', 'image/gif', 'image/webp']);
