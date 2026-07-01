# InboxReady API

InboxReady is a Python/FastAPI coding project for auditing whether customer domains are ready to send trustworthy email.

It checks MX, SPF, DMARC, DKIM, MTA-STS, TLS-RPT, and BIMI, detects likely sending providers, returns a weighted readiness score, and gives concrete remediation guidance. The project includes:

- A production-shaped FastAPI app in [`API/`](./API)
- A polished landing page and rate-limited public audit workspace
- Lovable-inspired visual system for the public site and operator dashboard
- Dashboard health insights with an action queue and domains-to-watch summary
- Saved-audit remediation playbooks with launch decisions, protocol coverage, and task owners
- Async audit jobs, object-style exports, due-monitor runs, and RPC-style commands for heavier integrations
- Runtime observability with request IDs, QPS, throughput, availability, `/metrics`, WebSocket health, and polling endpoints
- API-key protected single-domain and batch audit endpoints
- Canonical domain validation and concurrent batch execution
- SQLite-backed launch accounts, usage metering, rate limits, and audit history
- Audit history CSV exports, full saved-audit JSON detail views, and customer-ready playbook reports
- Account-level domain monitors with run-now checks and last-known status
- API-key listing and revocation for credential hygiene
- Stripe Checkout, Billing Portal, and webhook routes for paid plans
- Product release notes in [`CHANGELOG.md`](./CHANGELOG.md) and at `/changelog`
- A command-line interface via `inboxready`
- Tests for parsing, provider detection, batch summarization, and web routes
- Render deployment configuration in [`render.yaml`](./render.yaml)
- Docker Compose staging, Nginx proxy config, Kubernetes manifests, and CI/CD workflows in [`infra/`](./infra)
- Vercel Python Function deployment config in [`API/index.py`](./API/index.py), [`vercel.json`](./vercel.json), and [`infra/vercel-deployment.md`](./infra/vercel-deployment.md)

## Run Locally

```bash
cd API
python3 -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
uvicorn --app-dir src inboxready_api.main:app --reload
```

Open the workspace at [http://127.0.0.1:8000/app](http://127.0.0.1:8000/app).

Create a launch account at `/app#account` or call `POST /v1/accounts`, then use the returned
API key with `Authorization: Bearer $INBOXREADY_API_KEY`.

Release notes are tracked in [CHANGELOG.md](./CHANGELOG.md) and served inside the app at `/changelog`.

## Stage With Docker

```bash
docker compose up --build
```

Open the proxied staging site at [http://127.0.0.1:8080](http://127.0.0.1:8080).
The proxy includes rate limiting, short-lived docs/static caching, WebSocket upgrades, and request ID forwarding.

## Deploy With Vercel

InboxReady can also run as a Vercel Python Function for preview URLs and a low-ops launch lane:

```bash
npm install -g vercel
vercel link
vercel dev
vercel deploy
```

See [`infra/vercel-deployment.md`](./infra/vercel-deployment.md) for required Vercel/GitHub secrets,
environment variables, and the managed-storage caveat for production.

## Test

```bash
cd API
pytest
```

## Launch

Use [`infra/production-readiness.md`](./infra/production-readiness.md) for the implementation matrix
and launch steps covering Docker, Kubernetes, CI/CD, metrics, rate limiting, caching, cloud deployment,
Vercel, queue/object adapters, RPC, and storage-scaling decisions.
