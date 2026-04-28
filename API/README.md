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
- Interactive audit workspace at `/app`
- Audits MX, SPF, DMARC, DKIM, MTA-STS, TLS-RPT, and BIMI
- Detects likely sending providers from DNS evidence
- Scores domain readiness from 0-100
- Returns structured findings plus actionable remediation guidance
- Exposes a clean REST API with OpenAPI docs out of the box

## Endpoints

- `GET /`
- `GET /app`
- `GET /api`
- `GET /healthz`
- `GET /v1/providers`
- `POST /v1/audits/email-domain`
- `POST /v1/audits/batch`

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
- API docs: [http://127.0.0.1:8000/docs](http://127.0.0.1:8000/docs)
- Health check: [http://127.0.0.1:8000/healthz](http://127.0.0.1:8000/healthz)

## Example Request

```bash
curl -X POST http://127.0.0.1:8000/v1/audits/email-domain \
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
  -H "Content-Type: application/json" \
  -d '{
    "domains": ["example.com", "openai.com"],
    "selectors": ["google", "selector1"],
    "expected_providers": ["Google Workspace"]
  }'
```

The response includes every domain audit plus `summary.average_score`,
`summary.status_counts`, and the top repeated remediation patterns.

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

- Persistent audit history and trendlines
- Webhooks for DNS changes and policy regressions
- Branded setup guides per provider
- Team workspaces and API keys
- Batch audits for MSPs and ESPs
- Hosted DNS verification widgets for customer onboarding flows

## Files

- App entrypoint: [src/inboxready_api/main.py](./src/inboxready_api/main.py)
- Website copy/config: [src/inboxready_api/site_content.py](./src/inboxready_api/site_content.py)
- Audit engine: [src/inboxready_api/services/dns_audit.py](./src/inboxready_api/services/dns_audit.py)
- Provider heuristics: [src/inboxready_api/services/provider_detection.py](./src/inboxready_api/services/provider_detection.py)
- Templates: [src/inboxready_api/templates/base.html](./src/inboxready_api/templates/base.html)
- Frontend assets: [src/inboxready_api/static/css/site.css](./src/inboxready_api/static/css/site.css), [src/inboxready_api/static/js/app.js](./src/inboxready_api/static/js/app.js)
- Founder brief: [ideas.md](./ideas.md)
- Launch steps: [launch-plan.md](./launch-plan.md)
