// Filigrane de confidentialité : discret, individuel, légèrement mobile.
// Il ne contient jamais de donnée personnelle : seulement le site, le
// pseudonyme temporaire et un code court de session.

const TILES = 16;

export function showWatermark({ pseudonym, sessionCode }) {
  const root = document.getElementById('watermark');
  if (!root) return () => {};
  const text = `SECRET.BOI.LU • ${pseudonym} • Session ${sessionCode}`;
  root.replaceChildren();
  for (let i = 0; i < TILES; i++) {
    const span = document.createElement('span');
    span.textContent = text;
    // Décalage pseudo-aléatoire par tuile, différent pour chaque participant.
    span.style.transform = `translate(${(Math.random() * 60 - 30).toFixed(0)}px, ${(Math.random() * 40 - 20).toFixed(0)}px)`;
    root.append(span);
  }
  root.style.setProperty('--wm-dx', `${(Math.random() * 80 - 40).toFixed(0)}px`);
  root.style.setProperty('--wm-dy', `${(Math.random() * 80 + 20).toFixed(0)}px`);
  root.hidden = false;

  // Si un script tiers retire le filigrane, on le remet (dissuasion, pas garantie).
  const observer = new MutationObserver(() => {
    if (!document.body.contains(root) || root.hidden || root.childElementCount === 0) {
      if (!document.body.contains(root)) document.body.append(root);
      root.hidden = false;
      if (root.childElementCount === 0) showWatermark({ pseudonym, sessionCode });
    }
  });
  observer.observe(document.body, { childList: true, subtree: false });
  observer.observe(root, { childList: true, attributes: true });

  return () => {
    observer.disconnect();
    root.replaceChildren();
    root.hidden = true;
  };
}
