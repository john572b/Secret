// Détection (au mieux) des événements de capture d'écran exposés par le navigateur.
//
// Limites assumées : aucun navigateur n'expose d'API fiable pour savoir qu'une
// capture ou un enregistrement a eu lieu. On ne signale que ce qui est
// réellement observable, pour ne jamais produire de fausse notification :
//   - touche « Impr. écran » (Windows / Linux), reçue au keyup ;
//   - raccourcis macOS ⌘⇧3 / ⌘⇧4 / ⌘⇧5 / ⌘⇧6 lorsque le système les laisse parvenir à la page ;
//   - démarrage d'un partage/enregistrement d'écran initié *par cette page* (getDisplayMedia),
//     ce que l'application ne fait jamais : s'il se produit, une extension ou un script l'a déclenché.
// Les photos prises avec un autre appareil sont indétectables.

export function watchCaptureEvents(onDetected, { cooldownMs = 4000 } = {}) {
  let last = 0;
  const fire = (kind) => {
    const now = Date.now();
    if (now - last < cooldownMs) return;
    last = now;
    try { onDetected(kind); } catch { /* ne jamais casser l'interface */ }
  };

  const onKeyUp = (e) => { if (e.key === 'PrintScreen') fire('printscreen'); };
  const onKeyDown = (e) => {
    if (e.key === 'PrintScreen') fire('printscreen');
    else if (e.metaKey && e.shiftKey && ['3', '4', '5', '6'].includes(e.key)) fire('macos-shortcut');
  };
  window.addEventListener('keyup', onKeyUp, true);
  window.addEventListener('keydown', onKeyDown, true);

  // getDisplayMedia n'est jamais appelé par l'application ; on l'instrumente pour
  // détecter un appel par un tiers (extension) dans le contexte de la page.
  let restoreGdm = null;
  const md = navigator.mediaDevices;
  if (md && typeof md.getDisplayMedia === 'function') {
    const original = md.getDisplayMedia.bind(md);
    md.getDisplayMedia = async function patched(...args) {
      fire('display-media');
      return original(...args);
    };
    restoreGdm = () => { md.getDisplayMedia = original; };
  }

  return () => {
    window.removeEventListener('keyup', onKeyUp, true);
    window.removeEventListener('keydown', onKeyDown, true);
    restoreGdm?.();
  };
}

export const CAPTURE_SUPPORT_NOTE =
  'Les captures d\'écran ne peuvent pas être totalement empêchées ni toujours détectées par un site web. ' +
  'Seuls les événements exposés par le navigateur (touche Impr. écran, raccourcis macOS) sont signalés aux autres participants.';
