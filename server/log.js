// Journalisation volontairement minimaliste.
// Politique : aucun identifiant de session, aucun identifiant de participant,
// aucune adresse IP, aucun contenu de message, aucune clé ne doit transiter ici.
// Les appelants ne passent que des libellés fixes et des compteurs.

const LEVELS = { silent: 0, error: 1, warn: 2, info: 3 };

function levelFromEnv() {
  const name = (process.env.LOG_LEVEL || 'warn').toLowerCase();
  return LEVELS[name] ?? LEVELS.warn;
}

let level = levelFromEnv();

function emit(kind, args) {
  // Garde-fou : on refuse les objets pour éviter qu'une structure contenant
  // des données de session ne soit sérialisée par inadvertance.
  const safe = args.map((a) => (typeof a === 'string' || typeof a === 'number' || typeof a === 'boolean' ? a : `[${typeof a}]`));
  const line = `${new Date().toISOString()} ${kind} ${safe.join(' ')}`;
  if (kind === 'error') process.stderr.write(line + '\n');
  else process.stdout.write(line + '\n');
}

export const log = {
  setLevel(name) { level = LEVELS[name] ?? level; },
  info: (...a) => { if (level >= LEVELS.info) emit('info', a); },
  warn: (...a) => { if (level >= LEVELS.warn) emit('warn', a); },
  error: (...a) => { if (level >= LEVELS.error) emit('error', a); },
};
