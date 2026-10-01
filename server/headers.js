// En-têtes de sécurité, partagés par le serveur Node.js et le Worker Cloudflare.

export function sanitizeHost(host) {
  if (typeof host !== 'string' || host.length > 255) return null;
  return /^[A-Za-z0-9.\-:[\]]+$/.test(host) ? host : null;
}

export function buildSecurityHeaders({ host, requireHttps }) {
  const safeHost = sanitizeHost(host);
  // 'self' couvre les WebSockets de même origine dans les navigateurs récents ;
  // on ajoute l'hôte explicitement pour les moteurs plus anciens.
  const wsSources = safeHost ? ` wss://${safeHost}${requireHttps ? '' : ` ws://${safeHost}`}` : '';
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
    ...(requireHttps ? ['upgrade-insecure-requests'] : []),
  ].join('; ');
  return {
    'Content-Security-Policy': csp,
    'Strict-Transport-Security': 'max-age=63072000; includeSubDomains; preload',
    'X-Content-Type-Options': 'nosniff',
    'X-Frame-Options': 'DENY',
    'Referrer-Policy': 'no-referrer',
    'Permissions-Policy': 'camera=(), microphone=(), geolocation=(), payment=(), usb=(), interest-cohort=()',
    'Cross-Origin-Opener-Policy': 'same-origin',
    'Cross-Origin-Resource-Policy': 'same-origin',
    'X-Permitted-Cross-Domain-Policies': 'none',
  };
}

// Protection CSRF/CSWSH : sans cookies il n'y a pas d'ambient authority, mais on
// refuse quand même les origines étrangères pour les requêtes d'écriture.
export function originAllowed({ host, origin, secFetchSite }) {
  if (typeof origin === 'string' && origin !== 'null') {
    try {
      return new URL(origin).host === host;
    } catch {
      return false;
    }
  }
  if (typeof secFetchSite === 'string') return secFetchSite === 'same-origin' || secFetchSite === 'none';
  return true; // clients non-navigateur : pas de risque CSRF
}
