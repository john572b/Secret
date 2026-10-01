# secret.boi.lu

Messagerie privée et éphémère, chiffrée de bout en bout dans le navigateur.
**Le serveur transporte les données, il ne peut pas lire la conversation.**

- Chiffrement de bout en bout (Web Crypto API : ECDH P‑256, HKDF, AES‑256‑GCM, HMAC, PBKDF2), aucune cryptographie maison.
- Aucun stockage : sessions en mémoire, détruites à la demande, à l'expiration ou lorsqu'elles restent vides.
- Code de chiffrement supplémentaire et clé personnelle optionnels, jamais transmis au serveur.
- Verrouillage des nouvelles connexions, destruction immédiate, rotation de clé à chaque départ.
- Filigrane individuel, notification des événements de capture réellement détectables.
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

## Déploiement

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
server/      relais : sessions en mémoire, API, WebSocket, limitation de débit, en-têtes
public/js/   crypto.js (primitives), protocol.js (clés de groupe), transport.js, chat.js, main.js
public/      index.html (application), security.html (documentation publique)
docs/        ARCHITECTURE.md
test/        crypto, bout en bout (vrais clients via le vrai serveur), serveur, sécurité
```

## Ce que ce projet ne promet pas

- Empêcher ou détecter toutes les captures d'écran : impossible pour un site web.
- Effacer des copies déjà faites par des participants.
- Protéger contre un participant légitime malveillant ou un appareil compromis.
