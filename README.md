# DNS Analyzer — Backend

Backend Node/Express du module DNS Analyzer de [cyberlab](https://github.com/AG69075), une webapp Flutter d'outils de reconnaissance réseau. Ce service expose des primitives DNS (`dig`, `sublist3r`) via une petite API HTTP.

## Architecture

```
Flutter webapp (navigateur)
        │  HTTPS, CORS ouvert
        ▼
Cloudflare Worker (cyberlab-dns-proxy)
        │  HTTPS + header X-Internal-Token
        ▼
Cloudflare Tunnel (cloudflared)
        │  réseau Docker interne
        ▼
Backend Node (ce repo) ── dig / sublist3r
```

Le backend n'expose **aucun port public**. `cloudflared` établit une connexion sortante vers Cloudflare depuis le conteneur Docker ; le Worker Cloudflare est le seul point d'entrée public, et c'est lui qui relaie les requêtes vers le backend en y attachant un token partagé. Rien n'écoute directement sur Internet côté NAS.

## Endpoints

| Méthode | Route | Description |
|---|---|---|
| `POST` | `/api/dns` | Requête DNS via `dig` (`domain`, `server`, `port`, `type`) |
| `POST` | `/api/subdomains/start` | Lance une énumération de sous-domaines (Sublist3r) en tâche de fond, retourne un `job_id` |
| `GET` | `/api/subdomains/status/:jobId` | Statut/résultat d'un job d'énumération (`pending` / `done` / `error`) |
| `GET` | `/health` | Health check (pas d'auth requise, utilisé par Docker `HEALTHCHECK`) |

Types d'enregistrement supportés : `A`, `AAAA`, `MX`, `TXT`, `CNAME`, `NS`, `PTR`, `AXFR`, `ANY`.

Toutes les routes `/api/*` requièrent le header `X-Internal-Token`, égal à la variable d'environnement `INTERNAL_API_TOKEN`. Sans correspondance : `401`.

## Variables d'environnement

| Variable | Requise | Description |
|---|---|---|
| `INTERNAL_API_TOKEN` | Oui | Secret partagé avec le Worker Cloudflare. Le serveur refuse de démarrer si absente (fail-closed). |
| `ALLOWED_ORIGINS` | Non | Liste d'origines autorisées en CORS, séparées par des virgules. Par défaut : l'origine du Worker `cyberlab-dns-proxy`. |

## Lancer en local

```bash
npm install
INTERNAL_API_TOKEN=$(openssl rand -hex 32) npm start
```

Nécessite `dig` (paquet `dnsutils`/`bind-tools`) et, pour l'énumération de sous-domaines, `python3` + `sublist3r` (`pip3 install sublist3r`) installés sur la machine.

## Déploiement (Docker Compose + Cloudflare Tunnel)

Le backend tourne dans un conteneur Docker, sans port publié. Un conteneur `cloudflared` sur le même réseau Docker route le trafic public vers le service via son nom (`dns-analyzer:4002`), configuré comme *Public Hostname* d'un tunnel Cloudflare Zero Trust.

```yaml
services:
  dns-analyzer:
    build:
      context: ./dns_analyzer
      dockerfile: Dockerfile
    image: dns-analyzer:latest
    container_name: dns_analyzer
    dns:
      - 8.8.8.8
      - 1.1.1.1
    env_file:
      - ./dns_analyzer/.env
    restart: unless-stopped
    deploy:
      resources:
        limits:
          memory: 512M

  cloudflared:
    image: cloudflare/cloudflared:latest
    container_name: cloudflared_dns_analyzer
    command: tunnel run
    env_file:
      - ./dns_analyzer/.env
    restart: unless-stopped
    depends_on:
      - dns-analyzer
```

`.env` (non versionné, voir `.gitignore`) :
```
INTERNAL_API_TOKEN=<secret partagé avec le Worker>
TUNNEL_TOKEN=<token du tunnel, généré dans le dashboard Cloudflare Zero Trust>
```

## Sécurité

Ce service exécute des commandes système (`dig`, `sublist3r`) à partir d'entrées utilisateur. Les protections en place :

- **Pas de shell** : `execFileSync`/`spawn` avec tableaux d'arguments, jamais de concaténation de chaîne shell.
- **Validation stricte** en entrée : hostname/IP (`net.isIP` + regex hostname), port (1-65535), type d'enregistrement en liste blanche.
- **Authentification** : token partagé requis sur `/api/*`, vérifié avant tout traitement.
- **Rate limiting** : 30 requêtes/min sur `/api/*`.
- **Plafond de jobs concurrents** : 3 scans Sublist3r simultanés max, pour éviter l'épuisement de ressources.
- **CORS restreint** à l'origine du Worker (configurable via `ALLOWED_ORIGINS`).
- **Aucune exposition réseau directe** : le port applicatif n'est jamais publié sur l'hôte, tout passe par le tunnel Cloudflare sortant.

`backup/` contient une version antérieure du backend, conservée à titre d'historique — elle ne doit pas être déployée (correctifs de sécurité absents).
