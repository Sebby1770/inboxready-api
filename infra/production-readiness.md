# Production Readiness Matrix

This maps the requested infrastructure checklist to the current InboxReady implementation. The goal
is a credible solo-founder launch: ship the reliability pieces that matter now, document the safe
upgrade path for heavier cloud primitives, and avoid maintenance-heavy services before customers
justify them.

| Checklist item | Implementation status |
| --- | --- |
| Kubernetes | Added `infra/kubernetes` namespace, config, secret example, deployment, service, ingress, and HPA manifests. Keep one writer replica while SQLite is embedded. |
| Docker staging | Added root `docker-compose.yml` that builds `API/Dockerfile`, persists local SQLite data, and runs Nginx in front of the API. |
| SQS | Implemented queue abstraction via persisted audit jobs and due-monitor runner. Use SQS as the external adapter when workers need to scale outside the API process. |
| S3 | Implemented local object-store archive for JSON/CSV audit-history exports. Use S3 for signed URLs and durable customer report delivery later. |
| Cherry pick | Use normal Git flow: `git cherry-pick COMMIT_SHA` for backporting fixes between `main`, staging, and release branches. |
| Containerisation | Existing `API/Dockerfile` plus new `.dockerignore`, Compose staging, and GHCR publishing workflow. |
| CI/CD | Added `.github/workflows/ci.yml` and `.github/workflows/container.yml` for tests, compile checks, and container publishing. |
| Cloud | Render config exists; Vercel Python Function config now supports preview/production deploys; Kubernetes and GHCR assets support a container migration path. |
| Encryption | App has secure password hashing, CSRF, defensive headers, webhook signature verification, optional secure cookies/HSTS, and TLS-ready ingress. |
| Firewall | Nginx rate limiting and private-network-only `/metrics` proxy rules are included. Add cloud WAF/IP allowlisting at the provider edge. |
| FTP | Intentionally not enabled. Plain FTP is unsafe for customer data; use HTTPS exports, S3, or SFTP if a customer contract requires file delivery. |
| WebSockets | Added `/ws/health` to stream live service metrics to internal dashboards or operators. |
| Tensor/ML serving | Not needed for the deterministic DNS scoring MVP. If scoring becomes ML-based, serve it behind the existing RPC/job boundary. |
| Kafka/RabbitMQ | Persisted audit jobs create the queue boundary now. Use Kafka/RabbitMQ only if monitor events, webhook retries, or notifications outgrow the local queue/SQS path. |
| Database optimisation | Existing storage uses bounded queries, normalized domains, account-level indexing patterns, and one-unit metering. Next step is Postgres indexes before horizontal writes. |
| Serverless/Lambda | Due-monitor execution and manual job-run endpoints can be called by cron or Lambda. The API itself stays simpler as a container first. |
| DynamoDB | Deferred storage option for high-volume audit jobs, audit history, export metadata, or monitor state. Current SQLite is intentionally small-launch friendly. |
| Deployments | Added Render config, Vercel config/workflows, Docker Compose staging, Kubernetes manifests, and GHCR image publishing. |
| Embedded database | SQLite remains the launch database for minimal ops. Do not run multi-writer replicas until moving to managed storage. |
| Rate limiting | Existing app-level usage limits plus Nginx public request limits. |
| Error logging | Added structured request/error logs with request IDs and recent error capture in `/v1/metrics/summary`. |
| QPS | Added `qps` in JSON metrics and `inboxready_qps` in Prometheus metrics. |
| Load balance | Nginx upstream and Kubernetes Service/Ingress are configured. True horizontal app scaling waits for externalized storage. |
| Caching proxy | Nginx caches static assets, docs, and OpenAPI responses for short windows. |
| Availability | Readiness/liveness probes, success-rate metrics, and health endpoints are included. |
| Throughput | Added `throughput_per_minute` in JSON metrics and Prometheus output. |
| RPC | Added `POST /v1/rpc` for health, metrics, providers, synchronous audits, and queued audits. |
| Long/short polling | Added `/v1/health/short-poll` and `/v1/health/long-poll`. |
| Sharding/partitioning | Documented future path: partition audit history by account/month or move high-volume history to DynamoDB/S3. |
| Git/GitHub | Repo uses a Codex feature branch, GitHub Actions, GHCR, and PR-based release flow. |
| PyCharm | No repo-specific IDE files are committed. Open the `API` folder as the project root and use `uvicorn --app-dir src inboxready_api.main:app --reload`. |

## Launch Steps

1. Merge the feature PR into `main` after CI passes.
2. Set production secrets: `INBOXREADY_SESSION_SECRET`, Stripe keys, and price IDs.
3. Choose the first hosting path. Render is fastest; Kubernetes is available once you have managed storage.
4. Point a domain at the deployment and enable HTTPS.
5. Run smoke checks: `/healthz`, `/readyz`, `/metrics`, `/docs`, `/app`, signup, dashboard, and one paid-plan checkout test.
6. Configure Stripe webhooks for `/v1/billing/webhook`.
7. Add uptime monitoring against `/readyz` and private metrics scraping against `/metrics`.
8. Keep SQLite and the local object store for design partners; move to Postgres plus S3 or DynamoDB before multi-region or multi-replica writes.
9. Start outbound with the public checker and API docs as the demo path.
10. Ship scheduled monitor workers only after design partners confirm they want drift alerts.
