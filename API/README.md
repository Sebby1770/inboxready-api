# InboxReady API

InboxReady is a practical API-as-a-Service MVP for one sticky B2B problem: verifying whether a customer domain is actually ready to send trustworthy email.

This folder includes:

- A founder-grade idea brief with six API businesses in [ideas.md](./ideas.md)
- A concrete launch checklist in [launch-plan.md](./launch-plan.md)
- A runnable FastAPI MVP for the strongest idea: `InboxReady API`

## Why This Idea

SaaS products that send email on behalf of customers keep hitting the same operational mess:

- support tickets about SPF, DKIM, and DMARC
- slow onboarding because DNS setups are wrong or incomplete
- lost deliverability because no one notices weak policies
- engineering teams rewriting the same DNS-check scripts in every product

InboxReady turns that into one API call.

## MVP Features

- Polished SaaS landing page at `/`
- Interactive public audit workspace at `/app`
- Lovable-inspired visual refresh with a cleaner operator dashboard and usage meter
- Session-based web accounts with signup, login, and logout
- Authenticated dashboard at `/dashboard`
- SQLite-backed launch accounts and API keys
- Per-key usage metering, rate limiting, and saved audit history
- Account-level domain monitors with run-now checks and last-known status
- Stripe Checkout, Billing Portal, and webhook endpoints for paid plans
- Support page plus launch-ready privacy and terms pages
- Public changelog page and repository-level release notes
- Audit history CSV export plus full saved-audit JSON detail views
- Audits MX, SPF, DMARC, DKIM, MTA-STS, TLS-RPT, and BIMI
- Detects likely sending providers from DNS evidence
- Scores domain readiness from 0-100
- Returns structured findings plus actionable remediation guidance
- Exposes a clean REST API with OpenAPI docs out of the box

## Endpoints

- `GET /`
- `GET /app`
- `GET /signup`
- `GET /login`
- `GET /dashboard`
- `GET /support`
- `GET /changelog`
- `GET /privacy`
- `GET /terms`
- `GET /api`
- `GET /healthz`
- `GET /readyz`
- `POST /demo/audit`
- `POST /v1/accounts`
- `GET /v1/account`
- `POST /v1/api-keys`
- `GET /v1/api-keys`
- `DELETE /v1/api-keys/{key_id}`
- `GET /v1/usage`
- `GET /v1/audit-history`
- `GET /v1/audit-history.csv`
- `GET /v1/audit-history/{audit_id}`
- `POST /v1/monitors`
- `GET /v1/monitors`
- `POST /v1/monitors/{monitor_id}/run`
- `DELETE /v1/monitors/{monitor_id}`
- `GET /v1/providers`
- `POST /v1/audits/email-domain`
- `POST /v1/audits/batch`
- `POST /v1/billing/checkout`
- `POST /v1/billing/portal`
- `POST /v1/billing/webhook`

## Quick Start

```bash
cd /Users/sebastianforbes/Desktop/CODE/API-as-a-Service/API
python3 -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
uvicorn --app-dir src inboxready_api.main:app --reload
```

Open:

- Website: [http://127.0.0.1:8000](http://127.0.0.1:8000)
- Workspace: [http://127.0.0.1:8000/app](http://127.0.0.1:8000/app)
- Dashboard: [http://127.0.0.1:8000/dashboard](http://127.0.0.1:8000/dashboard)
- API docs: [http://127.0.0.1:8000/docs](http://127.0.0.1:8000/docs)
- Health check: [http://127.0.0.1:8000/healthz](http://127.0.0.1:8000/healthz)
- Readiness check: [http://127.0.0.1:8000/readyz](http://127.0.0.1:8000/readyz)

## Example Request

Create an account and store the returned API key:

```bash
curl -X POST http://127.0.0.1:8000/v1/accounts \
  -H "Content-Type: application/json" \
  -d '{
    "email": "founder@example.com",
    "key_name": "Local dev"
  }'
```

Call the commercial API with `Authorization: Bearer`:

```bash
curl -X POST http://127.0.0.1:8000/v1/audits/email-domain \
  -H "Authorization: Bearer $INBOXREADY_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "domain": "example.com",
    "selectors": ["google", "selector1"]
  }'
```

## Batch Audits

Audit up to 10 customer domains in one request and get a portfolio-level summary:

```bash
curl -X POST http://127.0.0.1:8000/v1/audits/batch \
  -H "Authorization: Bearer $INBOXREADY_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "domains": ["example.com", "openai.com"],
    "selectors": ["google", "selector1"],
    "expected_providers": ["Google Workspace"]
  }'
```

The response includes every domain audit plus `summary.average_score`,
`summary.status_counts`, and the top repeated remediation patterns. Independent domain audits run
concurrently, capped by `INBOXREADY_BATCH_MAX_WORKERS` (default: 5), while response order remains
the same as request order.

## Public Demo Funnel

The browser forms on `/` and `/app` call `POST /demo/audit`. That endpoint is intentionally
unauthenticated but rate-limited by client IP with:

- `INBOXREADY_DEMO_RATE_LIMIT_PER_MINUTE`
- `INBOXREADY_DEMO_DAILY_LIMIT`

Use it as the public free checker. Keep `/v1/audits/*` for API-key customers.

## Web App Layer

The app now includes a simple but real SaaS account shell:

- `GET /signup` creates a free account, stores a hashed password, signs the user into a session, and reveals the first API key once
- `GET /login` signs the account holder back into the dashboard
- `GET /dashboard` shows current usage, audit history, billing entry points, and API key lifecycle controls
- `POST /dashboard/audit` runs an audit against the logged-in account and consumes real plan usage
- `POST /dashboard/monitors` adds customer domains to a persistent watchlist
- `POST /dashboard/monitors/{monitor_id}/run` refreshes a saved monitor and writes the result into audit history
- `GET /support`, `GET /privacy`, and `GET /terms` give the product expected commercial surfaces for early launch

## Accounts, Usage, History, and Monitors

API keys are stored hashed in SQLite. The plaintext key is only returned once during:

- `POST /v1/accounts`
- `POST /v1/api-keys`

List or revoke keys without exposing their plaintext values:

```bash
curl http://127.0.0.1:8000/v1/api-keys \
  -H "Authorization: Bearer $INBOXREADY_API_KEY"

curl -X DELETE http://127.0.0.1:8000/v1/api-keys/KEY_ID \
  -H "Authorization: Bearer $INBOXREADY_API_KEY"
```

Audit requests accept either a root domain or a URL and normalize it to an ASCII hostname. Invalid
hostnames, IP addresses, embedded credentials, and explicit ports are rejected before DNS or HTTP
lookups begin.

Browser sessions use signed, HTTP-only cookies. Every session-backed form and dashboard mutation is
protected by a per-session CSRF token, authentication rotates session contents, malformed password
hashes fail closed, and responses include CSP, frame, MIME-sniffing, referrer, and permissions
headers. Set `INBOXREADY_SESSION_HTTPS_ONLY=true` behind HTTPS to enable secure cookies and HSTS.

Usage is counted by audit unit. A single-domain audit costs 1 unit; a batch audit costs one
unit per normalized domain. Current launch limits are:

| Plan    | Monthly audits | Per-minute limit |
| ------- | -------------: | ---------------: |
| Free    |            100 |               15 |
| Starter |          2,500 |               60 |
| Growth  |         15,000 |              180 |
| Pro     |         75,000 |              600 |

Inspect usage and saved history:

```bash
curl http://127.0.0.1:8000/v1/usage \
  -H "Authorization: Bearer $INBOXREADY_API_KEY"

curl http://127.0.0.1:8000/v1/audit-history \
  -H "Authorization: Bearer $INBOXREADY_API_KEY"
```

Export saved history as CSV or open a full saved audit by ID:

```bash
curl http://127.0.0.1:8000/v1/audit-history.csv \
  -H "Authorization: Bearer $INBOXREADY_API_KEY"

curl http://127.0.0.1:8000/v1/audit-history/AUDIT_ID \
  -H "Authorization: Bearer $INBOXREADY_API_KEY"
```

Logged-in dashboard users can also download `/dashboard/audit-history.csv` and open
`/dashboard/audit-history/{audit_id}.json` from the history table.

Use monitors to keep customer domains on an account watchlist. A monitor stores cadence, selectors,
expected providers, and the latest score/status metadata. Running a monitor costs one audit unit and
also creates a saved audit history row:

```bash
curl -X POST http://127.0.0.1:8000/v1/monitors \
  -H "Authorization: Bearer $INBOXREADY_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "domain": "customer-example.com",
    "selectors": ["google"],
    "expected_providers": ["Google Workspace"],
    "cadence": "weekly"
  }'

curl http://127.0.0.1:8000/v1/monitors \
  -H "Authorization: Bearer $INBOXREADY_API_KEY"

curl -X POST http://127.0.0.1:8000/v1/monitors/MONITOR_ID/run \
  -H "Authorization: Bearer $INBOXREADY_API_KEY"
```

## Changelog

Release notes are tracked in the root [`CHANGELOG.md`](../CHANGELOG.md) and served in the web app
at `/changelog`.

## Billing

Stripe is optional in local development. To enable paid plans, set:

```bash
INBOXREADY_PUBLIC_BASE_URL=https://your-domain.example
INBOXREADY_STRIPE_SECRET_KEY=sk_live_...
INBOXREADY_STRIPE_WEBHOOK_SECRET=whsec_...
INBOXREADY_STRIPE_STARTER_PRICE_ID=price_...
INBOXREADY_STRIPE_GROWTH_PRICE_ID=price_...
INBOXREADY_STRIPE_PRO_PRICE_ID=price_...
```

Public account provisioning creates Free accounts by default. Keep
`INBOXREADY_ALLOW_UNPAID_PLAN_PROVISIONING=false` in production so paid plans are only applied
through Stripe webhooks.

Create a Checkout session:

```bash
curl -X POST http://127.0.0.1:8000/v1/billing/checkout \
  -H "Authorization: Bearer $INBOXREADY_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"plan":"growth"}'
```

Configure Stripe to send subscription events to `/v1/billing/webhook`. The handler verifies the
Stripe signature and upgrades or downgrades the account plan from Checkout and subscription events.

## CLI

The package also installs a small Python CLI:

```bash
inboxready providers
inboxready audit example.com --selectors google,selector1
inboxready audit example.com openai.com --json
```

## Example Response Shape

```json
{
  "domain": "example.com",
  "score": 74,
  "overall_status": "warn",
  "providers": [
    {
      "name": "Google Workspace",
      "confidence": 0.88,
      "evidence": ["include:_spf.google.com"]
    }
  ],
  "checks": {
    "mx": { "status": "pass" },
    "spf": { "status": "pass" },
    "dmarc": { "status": "warn" },
    "dkim": { "status": "warn" },
    "mta_sts": { "status": "info" },
    "tls_rpt": { "status": "info" },
    "bimi": { "status": "info" }
  },
  "recommendations": [
    {
      "severity": "medium",
      "code": "dmarc-monitoring-only",
      "message": "DMARC exists but is still set to monitoring mode."
    }
  ]
}
```

## Product Positioning

Initial positioning:

- API-first, not consultant-first
- onboarding and remediation, not full DMARC analytics
- white-label friendly for SaaS products and agencies
- low-friction pricing for startups that cannot justify enterprise security tooling

## Suggested Commercial Packaging

- Free: 100 audits/month, community docs only
- Starter: $49/month for 2,500 audits
- Growth: $149/month for 15,000 audits + webhooks + batch jobs
- Pro: $399/month for 75,000 audits + team accounts + SLA
- Overage: $0.01-$0.03 per audit depending on tier

## Local Development Note

The app source lives under `src/`, so local dev should use Uvicorn's `--app-dir src` flag:

```bash
uvicorn --app-dir src inboxready_api.main:app --reload
```

## Next Features After MVP

- Trendlines on top of the persisted audit history
- Webhooks for DNS changes and policy regressions
- Branded setup guides per provider
- Team workspaces and role-based access
- Batch audits for MSPs and ESPs
- Hosted DNS verification widgets for customer onboarding flows

## Files

- App entrypoint: [src/inboxready_api/main.py](./src/inboxready_api/main.py)
- Website copy/config: [src/inboxready_api/site_content.py](./src/inboxready_api/site_content.py)
- Security helpers: [src/inboxready_api/security.py](./src/inboxready_api/security.py)
- Storage/account layer: [src/inboxready_api/storage.py](./src/inboxready_api/storage.py)
- Audit engine: [src/inboxready_api/services/dns_audit.py](./src/inboxready_api/services/dns_audit.py)
- Provider heuristics: [src/inboxready_api/services/provider_detection.py](./src/inboxready_api/services/provider_detection.py)
- Templates: [src/inboxready_api/templates/base.html](./src/inboxready_api/templates/base.html)
- Frontend assets: [src/inboxready_api/static/css/site.css](./src/inboxready_api/static/css/site.css), [src/inboxready_api/static/js/app.js](./src/inboxready_api/static/js/app.js)
- Founder brief: [ideas.md](./ideas.md)
- Launch steps: [launch-plan.md](./launch-plan.md)
