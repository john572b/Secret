# secret.boi.lu

Messagerie privée et éphémère, chiffrée de bout en bout dans le navigateur.
**Le serveur transporte les données, il ne peut pas lire la conversation.**

- Chiffrement de bout en bout (Web Crypto API : ECDH P‑256, HKDF, AES‑256‑GCM, HMAC, PBKDF2), aucune cryptographie maison.
- Aucun stockage : sessions en mémoire, détruites à la demande, à l'expiration ou lorsqu'elles restent vides.
- Code de chiffrement supplémentaire et clé personnelle optionnels, jamais transmis au serveur.
- Verrouillage des nouvelles connexions, destruction immédiate, rotation de clé à chaque départ.
- Notification des événements de capture réellement détectables, sans fausse promesse.
- Indicateur « 🟢 Chiffré de bout en bout » affiché uniquement lorsque la clé de groupe est établie.

Documentation : [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) (protocole, hypothèses, limites) et la page publique `/security`.

## Démarrer

```bash
npm install
npm start            # http://localhost:8080
LOG_LEVEL=info npm start
npm test             # tests unitaires, bout en bout et sécurité (Node ≥ 22)
```

Pour utiliser le chiffrement, le navigateur exige un contexte sécurisé : `http://localhost` convient en développement ; en production, HTTPS est obligatoire.

## Déploiement sur Cloudflare (production : secret.boi.lu)

Le site est hébergé sur Cloudflare Workers : le Worker (`worker/index.js`) sert
l'interface et l'API, et chaque salle vit dans un Durable Object (`worker/room.js`)
qui relaie les blobs chiffrés entre WebSockets. Le code client et la cryptographie
sont identiques à la version Node.js ; seul le relais change.

- État conservé par salle : métadonnées uniquement (haché du jeton propriétaire,
  nombre maximal, verrouillage, horodatages), effacées à la destruction ou à
  l'expiration (alarme). Les participants sont portés par les WebSockets
  (attachements). Aucun message n'est jamais écrit.
- Limites de débit par adresse IP via les bindings Rate Limiting (jamais journalisées).
- Trames WebSocket limitées à 1 Mio : les fichiers sont découpés côté client en
  morceaux chiffrés indépendamment puis réassemblés (voir `protocol.js`).

```bash
npm run dev:worker        # Worker local (workerd) sur http://127.0.0.1:8787
npm run test:worker       # scénarios de bout en bout contre le Worker local
CLOUDFLARE_API_TOKEN=… CLOUDFLARE_ACCOUNT_ID=… npm run deploy
```

Le jeton d'API doit avoir les droits Workers Scripts, Workers Routes et Zone (pour
le domaine personnalisé). Ne le stockez jamais dans le dépôt.

## Déploiement autonome (Node.js)

Le serveur écoute en HTTP et se place derrière un terminateur TLS (Caddy, nginx, Traefik…).

| Variable | Défaut | Rôle |
|---|---|---|
| `PORT` | `8080` | port d'écoute |
| `HOST` | `0.0.0.0` | interface d'écoute |
| `NODE_ENV=production` | — | active la redirection HTTPS (`REQUIRE_HTTPS=1` pour forcer, `0` pour désactiver) |
| `TRUST_PROXY=1` | désactivé | lit `X-Forwarded-Proto` / `X-Forwarded-For` (uniquement derrière un proxy de confiance) |
| `ROOM_MAX_AGE_MS` | 24 h | durée de vie maximale d'une session |
| `ROOM_EMPTY_TTL_MS` | 10 min | destruction d'une session vide |
| `MAX_PARTICIPANTS` | 50 | plafond du nombre de participants |
| `LOG_LEVEL` | `warn` | `silent`, `error`, `warn`, `info` — jamais de contenu, de clé ni d'identifiant |

Exemple avec Caddy :

```caddyfile
secret.boi.lu {
    reverse_proxy 127.0.0.1:8080
}
```

```bash
docker build -t secret-boi-lu .
docker run --rm -p 8080:8080 -e NODE_ENV=production -e TRUST_PROXY=1 secret-boi-lu
```

Le serveur doit tourner en **une seule instance** (état en mémoire). Un redémarrage détruit toutes les sessions, par conception.

## Structure

```
server/      relais Node.js : sessions en mémoire, API, WebSocket, limitation de débit, en-têtes
worker/      relais Cloudflare Workers + Durable Objects (même protocole, mêmes validations)
public/js/   crypto.js (primitives), protocol.js (clés de groupe), transport.js, chat.js, main.js
public/      index.html (application), security.html (documentation publique)
docs/        ARCHITECTURE.md
test/        crypto, bout en bout (vrais clients via le vrai serveur), serveur, sécurité
```

## Ce que ce projet ne promet pas

- Empêcher ou détecter toutes les captures d'écran : impossible pour un site web.
- Effacer des copies déjà faites par des participants.
- Protéger contre un participant légitime malveillant ou un appareil compromis.
