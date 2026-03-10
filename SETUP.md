# KUBIOSEC SENTINEL — Kubernetes Auth Setup

Quick guide to deploy SENTINEL on Kubernetes with GitHub and Google OAuth.

## Prerequisites

- Kubernetes cluster with `kubectl` access
- Docker (to build the image)
- `aasa` namespace created: `kubectl create namespace aasa`

## 1. Build the Docker Image

```bash
docker build -t aasa:latest .
```

## 2. Create OAuth Apps

### GitHub

1. Go to **GitHub → Settings → Developer settings → OAuth Apps → New OAuth App**
   (https://github.com/settings/applications/new)

2. Fill in:
   - **Application name**: `KUBIOSEC SENTINEL`
   - **Homepage URL**: `http://localhost:30601`
   - **Authorization callback URL**: `http://localhost:30601/auth/github/callback`

3. Click **Register application**

4. Copy the **Client ID** (shown immediately)

5. Click **Generate a new client secret** and copy it

> **Note:** GitHub only allows one callback URL per OAuth App. Create separate apps for dev (`localhost`) and production (your domain).

### Google

1. Go to **Google Cloud Console → APIs & Services → Credentials**
   (https://console.cloud.google.com/apis/credentials)

2. Click **Create Credentials → OAuth client ID**

3. Select **Web application** as the type

4. Fill in:
   - **Name**: `KUBIOSEC SENTINEL`
   - **Authorized JavaScript origins**: `http://localhost:30601`
   - **Authorized redirect URIs**: `http://localhost:30601/auth/google/callback`

5. Click **Create** and copy the **Client ID** and **Client Secret**

> **Note:** If you haven't configured the OAuth consent screen yet, Google will prompt you. Select **External**, fill in the app name and support email, and add the `email`, `profile`, and `openid` scopes.

## 3. Create Kubernetes Secrets

```bash
kubectl create secret generic aasa-auth -n aasa \
  --from-literal=AASA_SECRET_KEY="$(openssl rand -hex 32)" \
  --from-literal=AASA_GITHUB_CLIENT_ID="your-github-client-id" \
  --from-literal=AASA_GITHUB_CLIENT_SECRET="your-github-client-secret" \
  --from-literal=AASA_GOOGLE_CLIENT_ID="your-google-client-id.apps.googleusercontent.com" \
  --from-literal=AASA_GOOGLE_CLIENT_SECRET="GOCSPX-your-google-secret"
```

Verify the values are correct (no stray characters):

```bash
kubectl get secret aasa-auth -n aasa -o jsonpath='{.data.AASA_GOOGLE_CLIENT_ID}' | base64 -d
```

## 4. Update the Deployment

Add the secret as an envFrom source to your existing deployment:

```bash
kubectl patch deployment aasa -n aasa --type='json' -p='[
  {"op": "add", "path": "/spec/template/spec/containers/0/envFrom/-",
   "value": {"secretRef": {"name": "aasa-auth"}}}
]'
```

Or add it directly in your deployment manifest under `spec.template.spec.containers[0]`:

```yaml
envFrom:
  - configMapRef:
      name: aasa-config
  - secretRef:
      name: aasa-auth
```

## 5. Roll Out

```bash
kubectl rollout restart deployment/aasa -n aasa
kubectl rollout status deployment/aasa -n aasa --timeout=60s
```

## 6. Verify

```bash
# Health (public, no auth required) → should return 200
curl -s http://localhost:30601/api/v1/health

# Root (should redirect 307 → /login)
curl -s -o /dev/null -w "%{http_code}" http://localhost:30601/

# Check providers are configured
curl -s http://localhost:30601/auth/providers
# Expected: {"local":true,"github":true,"google":true}
```

## Environment Variables Reference

| Variable | Required | Description |
|---|---|---|
| `AASA_AUTH_ENABLED` | No | Set `false` to disable auth entirely (default: `true`) |
| `AASA_SECRET_KEY` | Yes | Random string for JWT signing. Generate with `openssl rand -hex 32` |
| `AASA_JWT_EXPIRE_MINUTES` | No | Token expiry in minutes (default: `1440` = 24h) |
| `AASA_GITHUB_CLIENT_ID` | No | GitHub OAuth App Client ID |
| `AASA_GITHUB_CLIENT_SECRET` | No | GitHub OAuth App Client Secret |
| `AASA_GOOGLE_CLIENT_ID` | No | Google OAuth Client ID |
| `AASA_GOOGLE_CLIENT_SECRET` | No | Google OAuth Client Secret |
| `AASA_AUTH_DB_PATH` | No | SQLite user database path (default: `/app/results/users.db`) |

## Auth Flow

1. Unauthenticated user visits any page → redirected to `/login`
2. User signs in via email/password, GitHub, or Google
3. Server issues a JWT stored as an HttpOnly cookie (`access_token`)
4. All subsequent requests include the cookie automatically
5. API routes return `401` if the cookie is missing or expired
6. `/api/v1/health`, `/docs`, and `/openapi.json` remain public

## Moving to Production

When deploying behind a real domain (e.g. `https://sentinel.kubiosec.com`):

1. Update callback URLs in both GitHub and Google OAuth settings
2. Set `secure=True` for the cookie in `auth/routes.py`
3. Use a proper `AASA_SECRET_KEY` (not the default)
4. Consider adding an Ingress with TLS termination
