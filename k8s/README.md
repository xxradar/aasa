# AASA — Kubernetes Deployment

Deploy the AI Agent Attack Surface Analyzer on Kubernetes.

## Prerequisites

- Kubernetes cluster (1.24+)
- `kubectl` configured
- AASA Docker image built and available:
  ```bash
  docker build -t aasa:latest .
  ```
  For remote clusters, push to your registry:
  ```bash
  docker tag aasa:latest ghcr.io/yourorg/aasa:v0.1.0
  docker push ghcr.io/yourorg/aasa:v0.1.0
  ```
  Then update `image:` in `deployment.yaml` accordingly.

## Quick Start

```bash
# 1. Create the namespace
kubectl apply -f k8s/namespace.yaml

# 2. Create the API key secret (do NOT commit real keys to git)
kubectl create secret generic aasa-secret \
  --namespace aasa \
  --from-literal=AASA_ANTHROPIC_API_KEY='sk-ant-api03-YOUR-KEY-HERE'

# 3. Apply all remaining manifests
kubectl apply -f k8s/configmap.yaml
kubectl apply -f k8s/pvc.yaml
kubectl apply -f k8s/deployment.yaml
kubectl apply -f k8s/service.yaml

# 4. Check status
kubectl -n aasa get pods,svc,pvc
```

## Access the UI

NodePort is configured on **30601**:

```
http://<node-ip>:30601
```

For `minikube`:
```bash
minikube service aasa -n aasa
```

For `kind` / `k3s` / local clusters:
```
http://localhost:30601
```

## API Endpoints

| Endpoint | Description |
|----------|-------------|
| `GET  /api/v1/health` | Health check |
| `POST /api/v1/scan` | Start website scan (async) |
| `POST /api/v1/scan/pdf` | Start PDF scan (async) |
| `GET  /api/v1/scan/{id}` | Poll scan status / results |
| `GET  /api/v1/results` | List persisted scan results |
| `GET  /api/v1/rules` | List learned rules |
| `GET  /api/v1/usage` | LLM usage statistics |
| `GET  /docs` | OpenAPI / Swagger docs |

## Configuration

Non-secret configuration lives in `configmap.yaml`. Key settings:

| Variable | Default | Description |
|----------|---------|-------------|
| `AASA_LLM_MODEL` | `claude-sonnet-4-5-20250929` | Anthropic model for LLM judge |
| `AASA_LLM_JUDGE_ENABLED` | `true` | Enable/disable LLM analysis |
| `AASA_MAX_DEPTH` | `2` | Crawler depth |
| `AASA_MAX_PAGES` | `50` | Max pages per scan |
| `AASA_RULE_LEARNING_ENABLED` | `true` | Auto-extract rules from LLM findings |

Edit the ConfigMap and restart the pod to apply changes:
```bash
kubectl -n aasa edit configmap aasa-config
kubectl -n aasa rollout restart deployment aasa
```

## Storage

Scan results, learned rules, and LLM usage data persist in a 1Gi PVC
mounted at `/app/results`. Data survives pod restarts and redeployments.

To increase storage:
```bash
kubectl -n aasa edit pvc aasa-results   # if your StorageClass supports expansion
```

## Troubleshooting

```bash
# Pod logs
kubectl -n aasa logs -f deployment/aasa

# Describe pod (events, resource issues)
kubectl -n aasa describe pod -l app.kubernetes.io/name=aasa

# Shell into the pod
kubectl -n aasa exec -it deployment/aasa -- /bin/bash

# Check PVC binding
kubectl -n aasa get pvc
```

## Architecture Notes

- **Single replica** — scan state is partly in-memory; PVC is `ReadWriteOnce`
- **Recreate strategy** — ensures the PVC is released before the new pod mounts it
- **Startup probe** — gives the app up to 50s to initialize before liveness kicks in
- **Non-root** — container runs as user `aasa` (UID 1000)
