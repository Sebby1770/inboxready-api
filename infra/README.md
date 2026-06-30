# InboxReady Infrastructure

This folder contains the launch operations layer for InboxReady API.

## Local Staging

Run the API behind an Nginx proxy with rate limiting, static/OpenAPI caching, WebSocket upgrade
support, and request ID forwarding:

```bash
docker compose up --build
```

Open:

- Website: http://127.0.0.1:8080
- API docs: http://127.0.0.1:8080/docs
- Health: http://127.0.0.1:8080/healthz
- Metrics: http://127.0.0.1:8080/metrics

## Kubernetes

Apply the manifests after replacing secrets, domain names, image tags, and storage choices:

```bash
kubectl apply -f infra/kubernetes/namespace.yaml
kubectl apply -f infra/kubernetes/configmap.yaml
kubectl apply -f infra/kubernetes/secret.example.yaml
kubectl apply -f infra/kubernetes/deployment.yaml
kubectl apply -f infra/kubernetes/service.yaml
kubectl apply -f infra/kubernetes/ingress.yaml
kubectl apply -f infra/kubernetes/hpa.yaml
```

The launch app uses embedded SQLite. Keep one writer replica until storage is externalized to
Postgres, DynamoDB, or another managed database. The service, ingress, probes, and HPA are included
so the deployment path is ready once the storage layer is moved out of the container.

## CI/CD

GitHub Actions are configured to:

- install the Python package
- compile the app
- run tests
- build and publish a GHCR container image

Images publish to:

```text
ghcr.io/sebby1770/inboxready-api
```
