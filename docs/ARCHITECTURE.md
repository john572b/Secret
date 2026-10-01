# secret.boi.lu — Architecture cryptographique et modèle de menace

Version 1 — document de référence, rédigé avant l'implémentation.

Ce document décrit précisément le protocole retenu, les hypothèses de sécurité
et les limites du système. Il ne décrit **aucune cryptographie maison** : le
protocole est une composition de primitives standard exposées par la
Web Crypto API du navigateur, assemblées selon un schéma classique
(échange de clés Diffie‑Hellman éphémère authentifié par un secret partagé,
puis chiffrement authentifié d'une clé de groupe par époque).

---

## 1. Objectif et principe fondamental

> Le serveur transporte les données, mais ne doit pas pouvoir lire la conversation.

- Les messages et fichiers sont chiffrés **dans le navigateur** avant de quitter
  l'appareil, et déchiffrés uniquement dans le navigateur des destinataires.
- Le serveur ne reçoit que des blobs chiffrés (AES‑256‑GCM) et les métadonnées
  strictement nécessaires au relais.
- Rien n'est stocké durablement : toute la session vit en mémoire vive du
  serveur et disparaît à la destruction ou à l'expiration.

## 2. Primitives utilisées (toutes natives, Web Crypto API)

| Usage | Primitive | Paramètres |
|---|---|---|
| Secret de session aléatoire | `crypto.getRandomValues` | 256 bits |
| Dérivation depuis une phrase secrète / un code | PBKDF2‑HMAC‑SHA‑256 | 600 000 itérations, sel = identifiant de session + étiquette de domaine |
| Dérivation de clés | HKDF‑SHA‑256 | étiquettes `secret.boi.lu/v1/…` distinctes par usage |
| Authentification des clés publiques | HMAC‑SHA‑256 | clé dérivée du secret racine |
| Échange de clés entre participants | ECDH P‑256 (clés éphémères) | une paire par participant et par connexion |
| Chiffrement authentifié (messages, fichiers, clés d'époque) | AES‑256‑GCM | IV aléatoire 96 bits, AAD liant salle/émetteur/époque/numéro |
| Empreintes | SHA‑256 | affichage d'empreinte de clé publique |

Pourquoi pas Argon2 ? Le navigateur n'expose pas nativement Argon2 ; l'intégrer
exigerait une bibliothèque tierce (WASM), ce qui agrandit la surface de code
cryptographique. PBKDF2 avec 600 000 itérations (recommandation OWASP 2023 pour
SHA‑256) est la meilleure option native. Le code supplémentaire reste un
*second facteur* : le secret principal de la session est, par défaut, 256 bits
aléatoires, et non une phrase humaine.

Pourquoi P‑256 et pas X25519 ? P‑256 est disponible dans tous les navigateurs
courants via Web Crypto ; X25519 l'est devenu récemment. Les deux offrent un
niveau de sécurité équivalent (~128 bits). Le code isole ce choix dans une
seule fonction pour permettre une migration.

Pourquoi pas RSA 4096 ? RSA n'apporte rien ici : les clés sont éphémères, et
ECDH est plus rapide et plus petit pour une sécurité équivalente. Il n'existe
aucune « clé SSL 4096 bits créée à la volée » dans ce système. TLS protège le
transport navigateur ↔ serveur ; le chiffrement de bout en bout en est
indépendant.

## 3. Secrets et dérivation

```text
roomId      : 128 bits aléatoires, générés par le serveur (identifiant de session, non secret)
S           : secret de session
              - mode lien : 256 bits aléatoires, placés dans le fragment (#) du lien d'invitation
              - mode clé personnelle : PBKDF2(clé personnelle, sel = "secret.boi.lu/v1/passphrase/" + roomId)
Cw          : PBKDF2(code supplémentaire, sel = "secret.boi.lu/v1/code/" + roomId)   (32 octets nuls si aucun code)
root        : HKDF-SHA256(ikm = S, salt = Cw, info = "secret.boi.lu/v1/root")
authKey     : HKDF-SHA256(ikm = root, info = "secret.boi.lu/v1/auth")         → clé HMAC
```

- Le fragment d'URL (`#…`) n'est **jamais envoyé** par le navigateur au serveur.
- La clé personnelle (8 à 52 caractères) et le code supplémentaire ne quittent
  jamais le navigateur ; seuls des dérivés en sont utilisés localement.
  Ils ne sont jamais stockés (ni `localStorage`, ni cookie).
- Un participant qui possède le lien mais pas le bon code obtient un `root`
  différent, donc une `authKey` différente : ses clés publiques ne sont pas
  reconnues par les autres, il ne reçoit jamais la clé de groupe, et il ne peut
  rien déchiffrer. Le serveur, lui, ne connaît ni S, ni le code, ni `root`.

## 4. Identités et authentification des participants

À chaque connexion, le navigateur génère :

- `memberId` : 128 bits aléatoires (identifiant temporaire, choisi côté client,
  vérifié unique par le serveur) ;
- une paire **ECDH P‑256 éphémère** (clé privée non exportable, détruite à la
  fermeture de l'onglet).

Il annonce au serveur `{ memberId, pubKey, mac }` avec :

```text
mac = HMAC-SHA256(authKey, "secret.boi.lu/v1/member|" + roomId + "|" + memberId + "|" + pubKey)
```

Chaque participant vérifie le `mac` des autres avec sa propre `authKey`.
Seuls les participants **vérifiés** (bon secret, bon code) reçoivent la clé de
groupe. Un participant non vérifié apparaît dans la liste avec un avertissement
visible par tous : il est connecté au réseau, mais hors de la conversation.

Le serveur ne peut pas forger un `mac` (il n'a pas `authKey`) : il ne peut donc
pas s'insérer comme participant ni substituer une clé publique (attaque de
l'homme du milieu). De plus la clé d'enveloppe (section 5) mélange `root` à la
clé ECDH, ce qui rend inutile toute substitution même si le `mac` était ignoré.

Les pseudonymes affichés (« Participant‑N ») dérivent de l'ordre d'arrivée
attribué par le serveur. Aucune donnée personnelle n'est demandée.

## 5. Clé de groupe par époque

Le chiffrement des messages utilise une **clé de groupe AES‑256 par époque**.

- Le **meneur** est le participant vérifié ayant le plus petit ordre d'arrivée
  (le créateur au départ ; en cas de départ, le suivant prend le relais).
- Le meneur génère une clé d'époque `K_e` (256 bits aléatoires) et un
  identifiant d'époque `epochId` unique.
- Pour chaque participant vérifié `P`, le meneur dérive une **clé d'enveloppe**
  pairwise :

```text
shared  = ECDH(meneur.priv, P.pub)
wrapKey = HKDF-SHA256(ikm = shared, salt = root, info = "secret.boi.lu/v1/wrap|" + ids triés)
```

  puis envoie `AES-256-GCM(wrapKey, K_e, AAD = roomId|meneur|P|epochId)` au
  participant, via le serveur, qui ne voit qu'un blob chiffré.

- Chaque **arrivée** d'un participant vérifié : le meneur lui envoie la clé
  d'époque courante (enveloppée pour lui seul). Il ne reçoit **pas** l'historique :
  le serveur n'en conserve aucun.
- Chaque **départ** : le meneur génère une nouvelle époque et la distribue aux
  membres restants. Le participant parti ne peut pas lire la suite. Les clients
  conservent brièvement les dernières époques (en mémoire) pour déchiffrer les
  messages en transit, puis les effacent.
- Changement de meneur : si le meneur part, le nouveau meneur effectue
  immédiatement une rotation.

Ce schéma est la forme la plus simple d'une distribution de clé de groupe par
canaux pairwise (schéma classique « sender key distribution », utilisé par
exemple dans les groupes Signal/WhatsApp pour distribuer les clés de groupe).
Il n'est pas MLS (RFC 9420) : MLS serait le choix idéal pour de grands groupes
avec forward secrecy fine‑grain et post‑compromise security, mais sa complexité
est disproportionnée pour un chat éphémère de quelques personnes, et aucune
implémentation native navigateur n'existe. Ce point est documenté comme
évolution possible.

## 6. Messages et fichiers

```text
plaintext   = [longueur en‑tête (4 octets)] [en‑tête JSON UTF‑8] [corps binaire optionnel]
en‑tête     = { kind: "text" | "file" | "capture", text?, name?, type?, size?, ts }
AAD         = roomId | émetteur | epochId | seq
chiffré     = AES-256-GCM(K_e, IV aléatoire 96 bits, plaintext, AAD)
relais      = { k: "msg", epochId, seq, iv, ct }     ← seul contenu vu par le serveur
```

- `seq` est un compteur strictement croissant par émetteur et par époque ;
  un destinataire rejette tout `seq` déjà vu (**protection contre le rejeu**).
- L'AAD lie le message à la salle, à l'émetteur et à l'époque : le serveur ne
  peut pas réattribuer un message à un autre participant ni le rejouer dans une
  autre salle.
- Les fichiers suivent exactement le même chemin : chiffrés entièrement côté
  client (limite 8 Mio), relayés en un seul message, déchiffrés localement et
  proposés en téléchargement via une URL `blob:` locale. Les images sont
  affichées en ligne uniquement si leur type MIME est `image/*`. Les noms de
  fichiers sont assainis avant affichage et jamais interprétés.

## 7. Rôle exact du serveur

Le serveur est **non fiable pour le contenu** et **fiable uniquement pour la
disponibilité et la présence** (il peut couper la session ou mentir sur qui est
connecté, mais pas lire ni forger).

Il est responsable de :

- créer une session (`roomId` aléatoire 128 bits, jeton de propriétaire 256 bits
  dont seul le haché SHA‑256 est conservé) ;
- accepter / refuser les connexions (session inexistante, pleine, verrouillée) ;
- relayer des blobs opaques entre participants (diffusion ou ciblé) ;
- diffuser les événements de présence (arrivée, départ, verrouillage) ;
- détruire la session (sur ordre du propriétaire, à l'expiration, ou lorsque la
  salle reste vide).

### Données visibles par le serveur (et durée)

| Donnée | Pourquoi | Durée |
|---|---|---|
| `roomId`, état verrouillé, nombre max | fonctionnement de la session | mémoire, jusqu'à destruction/expiration |
| haché SHA‑256 du jeton propriétaire | vérifier lock/unlock/destroy | idem |
| `memberId`, ordre d'arrivée, clé publique ECDH, `mac` | relais et présence | durée de la connexion |
| blobs chiffrés (`iv`, `ct`, `epochId`, `seq`), tailles et horodatage implicite | relais | **jamais conservés** : transmis puis libérés |
| adresse IP source | limitation de débit | compteur en mémoire, purgé après 10 min d'inactivité ; **jamais journalisée** |

### Données jamais accessibles au serveur

- messages et fichiers en clair ;
- secret de session `S`, code supplémentaire, clé personnelle, `root`, `authKey` ;
- clés privées ECDH, clés d'enveloppe, clés d'époque ;
- jeton propriétaire en clair (hors de la requête de vérification, en transit TLS).

### Politique de journaux

- Aucun message, clé, code, `roomId`, `memberId` ou adresse IP n'est écrit dans
  les journaux. Les journaux (niveau `warn` par défaut) ne contiennent que des
  événements génériques sans identifiant (démarrage, erreurs internes, compteurs).
- Les tests automatisés vérifient qu'aucun secret ni contenu de message
  n'apparaît sur la sortie standard du serveur.

### Hébergement Cloudflare Workers

En production, le relais est un Worker Cloudflare et chaque salle un Durable
Object. L'hébergeur occupe exactement la position du serveur décrite ci‑dessus :
il termine TLS et voit les mêmes blobs chiffrés, jamais le contenu. Différences
avec la version Node.js :

- les métadonnées de salle (haché du jeton propriétaire, nombre maximal,
  verrouillage, horodatages, compteur d'ordre) sont écrites dans le stockage de
  l'objet durable, car l'objet peut être évincé de la mémoire entre deux
  messages (hibernation des WebSockets). Elles sont effacées (`deleteAll`) à la
  destruction ou à l'expiration, déclenchée par une alarme ;
- les participants (identifiant, ordre, clé publique, HMAC) sont attachés aux
  WebSockets eux‑mêmes et disparaissent avec eux ;
- les messages ne sont jamais écrits : relayés puis oubliés ;
- la limitation de débit par IP utilise les bindings Rate Limiting de Cloudflare ;
- les trames WebSocket sont limitées à 1 Mio, d'où le découpage des fichiers en
  morceaux chiffrés indépendamment (`FILE_CHUNK_BYTES`), chacun authentifié et
  numéroté ; un morceau manquant ou altéré empêche simplement l'émission du
  fichier.

## 8. Cycle de vie

```text
Création (POST /api/rooms)
   ↓  roomId + ownerToken → créateur ; S généré/dérivé dans le navigateur
Session temporaire (mémoire)
   ↓  connexions WebSocket, annonces de clés publiques authentifiées
Échange de données chiffrées
   ↓  clé de groupe par époque, rotation à chaque départ
Destruction (propriétaire, expiration 24 h, salle vide > 10 min)
   ↓  clients notifiés et déconnectés, structures effacées, clés client détruites
Session inexistante
```

Destruction côté client : clés d'époque et secrets bruts remis à zéro
(`fill(0)`), références aux `CryptoKey` abandonnées, historique d'affichage
vidé, `sessionStorage` nettoyé, URL remplacée. Le navigateur ne garantit pas
l'effacement physique de la mémoire ; c'est une suppression au mieux.

Ce que la destruction **ne peut pas** faire : effacer des captures d'écran,
photos, enregistrements ou fichiers déjà téléchargés par des participants.

## 9. Sécurité du transport et du serveur

- HTTPS obligatoire en production (redirection), HSTS (2 ans, preload).
- CSP stricte : `default-src 'none'`, scripts et styles uniquement depuis
  l'origine, pas de scripts inline, `frame-ancestors 'none'`, `base-uri 'none'`.
- Pas de cookies : aucune session serveur, donc pas de fixation de session et
  surface CSRF nulle ; l'API vérifie en plus l'origine (`Origin` /
  `Sec-Fetch-Site`) et les connexions WebSocket refusent les origines étrangères.
- Validation stricte de tous les messages (types, tailles, formats) ; tout
  message non conforme ferme la connexion.
- Limitation de débit par IP (création de sessions, connexions) et par
  connexion (messages/s, octets/min).
- Taille maximale des trames WebSocket et des corps HTTP.
- Expiration automatique des sessions.
- En‑têtes : `X-Content-Type-Options`, `Referrer-Policy: no-referrer`,
  `Permissions-Policy`, `Cross-Origin-Opener-Policy`, `Cross-Origin-Resource-Policy`.

## 10. Modèle de menace

| Adversaire | Protégé ? | Remarque |
|---|---|---|
| Serveur honnête‑mais‑curieux | ✅ | ne voit que des blobs AES‑GCM |
| Serveur compromis (actif) | ✅ confidentialité / intégrité ; ❌ disponibilité | peut couper, retarder, mentir sur la présence ; ne peut ni lire ni injecter |
| Interception réseau | ✅ | TLS + E2E indépendant |
| Personne ayant le lien mais pas le code | ✅ | peut rejoindre le réseau, apparaît « non vérifié », ne déchiffre rien |
| Compromission ultérieure du lien/du code | ✅ pour le passé | les clés d'époque sont enveloppées avec des clés ECDH éphémères détruites : un enregistrement du trafic ne devient pas déchiffrable (forward secrecy vis‑à‑vis du secret partagé) |
| Participant légitime malveillant | ❌ | il peut tout lire et tout copier : c'est inhérent à toute messagerie |
| Capture d'écran / photo | ❌ | détection partielle au mieux, aucune dissuasion visuelle |
| Navigateur / appareil compromis | ❌ | hors périmètre |
| Force brute sur le code supplémentaire | ✅ partiel | PBKDF2 600 000 itérations ; limitation de débit ; mais un code court reste faible : le code est un second facteur, pas le secret principal |

## 11. Limites assumées

1. **Captures d'écran** : un site web ne peut pas empêcher ni détecter de façon
   fiable une capture. Seuls les événements exposés par le navigateur (touche
   Impr. écran, raccourcis macOS lorsqu'ils parviennent à la page) déclenchent
   une notification aux autres participants. Une photo prise avec un autre
   appareil est indétectable. Aucun filigrane n'est affiché (choix produit : il
   ne bloque rien et n'offre qu'une dissuasion symbolique).
2. **Pas d'historique** : un participant qui arrive après un message ne le
   recevra jamais. C'est une conséquence voulue de l'absence de stockage.
3. **Fragment d'URL** : le secret du lien reste dans l'historique du navigateur
   de chaque participant tant qu'il n'est pas effacé. Il est recommandé
   d'utiliser un code supplémentaire, transmis par un autre canal.
4. **Mémoire JavaScript** : l'effacement des clés est au mieux ; le ramasse‑miettes
   ne garantit rien.
5. **Présence** : le serveur est cru sur « qui est connecté ». Il ne peut
   toutefois pas faire accepter un faux participant par les autres (section 4).
6. **Pas de MLS** : la rotation de clé est déclenchée par les départs et les
   changements de meneur, pas à chaque message.

## 12. Vérifiabilité

- Le code cryptographique est concentré dans `public/js/crypto.js` (primitives)
  et `public/js/protocol.js` (gestion des époques), tous deux exécutables tels
  quels sous Node.js pour les tests.
- Les tests end‑to‑end font transiter de vrais clients par le vrai serveur et
  vérifient que le serveur n'observe jamais le texte en clair, qu'un mauvais
  code ne permet pas de déchiffrer, que les clés tournent au départ d'un membre,
  et que les messages rejoués sont rejetés.
