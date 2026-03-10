# KUBIOSEC SENTINEL — Deployment Guide

Complete guide for deploying SENTINEL via Docker Compose or Kubernetes, including authentication setup with GitHub and Google OAuth.

## Prerequisites

- Docker Engine 24+ (or Docker Desktop)
- An Anthropic API key (`sk-ant-...`) for the LLM-as-judge feature
- *(Optional)* GitHub and/or Google OAuth credentials for SSO login

## 1. Build the Image

```bash
git clone https://github.com/xxradar/aasa.git && cd aasa
docker build -t aasa:latest .
```

For remote registries:

```bash
docker tag aasa:latest ghcr.io/yourorg/aasa:v0.1.0
docker push ghcr.io/yourorg/aasa:v0.1.0
```

---

## 2a. Docker Compose

### Quick start

```bash
cp .env.example .env        # create from template
# edit .env — at minimum set AASA_ANTHROPIC_API_KEY
docker compose up -d
```

The UI is available at `http://localhost:6001`.

### Environment variables

All variables go in `.env` (or set them inline in `docker-compose.yml`). The `AASA_` prefix is required.

| Variable | Required | Default | Description |
|---|---|---|---|
| `AASA_ANTHROPIC_API_KEY` | Yes | — | Anthropic API key for LLM judge |
| `AASA_LLM_MODEL` | No | `claude-sonnet-4-5-20250929` | Claude model |
| `AASA_LLM_JUDGE_ENABLED` | No | `true` | Enable LLM analysis |
| `AASA_MAX_DEPTH` | No | `2` | Crawl depth |
| `AASA_MAX_PAGES` | No | `50` | Max pages per scan |
| `AASA_AUTH_ENABLED` | No | `true` | Enable authentication |
| `AASA_SECRET_KEY` | If auth | `change-me-...` | JWT signing key — generate with `openssl rand -hex 32` |
| `AASA_GITHUB_CLIENT_ID` | No | — | GitHub OAuth App Client ID |
| `AASA_GITHUB_CLIENT_SECRET` | No | — | GitHub OAuth App Client Secret |
| `AASA_GOOGLE_CLIENT_ID` | No | — | Google OAuth Client ID |
| `AASA_GOOGLE_CLIENT_SECRET` | No | — | Google OAuth Client Secret |

### Persistent storage

Scan results, user database, and auth logs are stored in `./results/` on the host (mounted to `/app/results` in the container). This directory survives `docker compose down`.

### Logs

```bash
# All logs
docker compose logs -f aasa

# Auth events only
docker compose exec aasa cat /app/results/auth.log
```

---

## 2b. Kubernetes

### Apply manifests

```bash
# 1. Namespace
kubectl apply -f k8s/namespace.yaml

# 2. Anthropic API key secret
kubectl create secret generic aasa-secret \
  --namespace aasa \
  --from-literal=AASA_ANTHROPIC_API_KEY='sk-ant-api03-YOUR-KEY'

# 3. ConfigMap, PVC, Deployment, Service
kubectl apply -f k8s/configmap.yaml
kubectl apply -f k8s/pvc.yaml
kubectl apply -f k8s/deployment.yaml
kubectl apply -f k8s/service.yaml

# 4. Check status
kubectl -n aasa get pods,svc,pvc
```

The UI is available at `http://localhost:30601` (NodePort).

### Enable authentication with OAuth

#### Create OAuth apps

**GitHub** — go to [Settings → Developer settings → OAuth Apps → New](https://github.com/settings/applications/new):

| Field | Value |
|---|---|
| Application name | `KUBIOSEC SENTINEL` |
| Homepage URL | `http://localhost:30601` |
| Authorization callback URL | `http://localhost:30601/auth/github/callback` |

Copy the Client ID and generate a Client Secret.

**Google** — go to [Cloud Console → Credentials](https://console.cloud.google.com/apis/credentials), then Create Credentials → OAuth client ID (Web application):

| Field | Value |
|---|---|
| Authorized JavaScript origins | `http://localhost:30601` |
| Authorized redirect URIs | `http://localhost:30601/auth/google/callback` |

Copy the Client ID and Client Secret. If prompted, configure the OAuth consent screen first (External, add `email`, `profile`, `openid` scopes).

#### Create the auth secret

```bash
kubectl create secret generic aasa-auth -n aasa \
  --from-literal=AASA_SECRET_KEY="$(openssl rand -hex 32)" \
  --from-literal=AASA_GITHUB_CLIENT_ID="Ov23li..." \
  --from-literal=AASA_GITHUB_CLIENT_SECRET="e45057..." \
  --from-literal=AASA_GOOGLE_CLIENT_ID="123456...apps.googleusercontent.com" \
  --from-literal=AASA_GOOGLE_CLIENT_SECRET="GOCSPX-..."
```

Always use `--from-literal` — do NOT pipe through `base64` manually (shell escaping causes issues).

#### Inject the secret into the deployment

```bash
kubectl patch deployment aasa -n aasa --type='json' -p='[
  {"op": "add", "path": "/spec/template/spec/containers/0/envFrom/-",
   "value": {"secretRef": {"name": "aasa-auth"}}}
]'
```

Or add it permanently in `k8s/deployment.yaml` under `envFrom`:

```yaml
envFrom:
  - configMapRef:
      name: aasa-config
  - secretRef:
      name: aasa-secret
  - secretRef:
      name: aasa-auth
```

#### Roll out and verify

```bash
kubectl rollout restart deployment/aasa -n aasa
kubectl rollout status deployment/aasa -n aasa --timeout=60s

# Verify providers
curl -s http://localhost:30601/auth/providers
# {"local":true,"github":true,"google":true}
```

### K8s persistent storage

A 1Gi PVC (`aasa-results`) is mounted at `/app/results`. It stores scan results, the user database (`users.db`), and auth logs (`auth.log`).

### K8s logs

```bash
# Application logs (stdout)
kubectl -n aasa logs -f deployment/aasa

# Auth events (persistent file on PVC)
kubectl exec deployment/aasa -n aasa -- cat /app/results/auth.log

# Auth events from stdout
kubectl -n aasa logs deployment/aasa | grep auth.events
```

### K8s configuration reference

Non-secret config is in the ConfigMap (`k8s/configmap.yaml`). Edit and restart:

```bash
kubectl -n aasa edit configmap aasa-config
kubectl -n aasa rollout restart deployment aasa
```

---

## 3. Authentication Flow

When `AASA_AUTH_ENABLED=true` (the default):

1. Unauthenticated browser requests redirect to `/login`
2. Unauthenticated API requests receive `401 Unauthorized`
3. Users sign in via email/password, GitHub, or Google
4. A JWT is issued as an HttpOnly cookie (`access_token`, 24h expiry)
5. Public endpoints that skip auth: `/api/v1/health`, `/docs`, `/openapi.json`

Auth events are logged to both stdout and `/app/results/auth.log` (rotated at 5MB, 3 backups).

To disable auth entirely, set `AASA_AUTH_ENABLED=false`.

---

## 4. Moving to Production

When deploying behind a real domain (e.g. `https://sentinel.kubiosec.com`):

1. Update callback URLs in both GitHub and Google OAuth app settings
2. Set `secure=True` for the cookie in `auth/routes.py`
3. Use a real `AASA_SECRET_KEY` (not the default)
4. Add a Kubernetes Ingress with TLS termination
5. Update `image:` in `deployment.yaml` to point to your registry
6. Consider using an external database instead of SQLite for multi-replica setups

---

## 5. Architecture Notes

- Single-replica deployment — scan state is partly in-memory and the PVC is `ReadWriteOnce`
- Recreate rollout strategy ensures the PVC is released before the new pod starts
- Container runs as non-root user `aasa` (UID 999)
- Health probes hit `/api/v1/health` (startup, liveness, readiness)
