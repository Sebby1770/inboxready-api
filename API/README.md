# InboxReady API

InboxReady is a practical API-as-a-Service for verifying whether a customer domain is ready to send trustworthy email.

**Version:** 0.2.0

## Why This Idea

SaaS products that send email on behalf of customers keep hitting the same operational mess:

- support tickets about SPF, DKIM, and DMARC
- slow onboarding because DNS setups are wrong or incomplete
- lost deliverability because no one notices weak policies
- engineering teams rewriting the same DNS-check scripts in every product

InboxReady turns that into one API call.

## Features

- Polished SaaS landing page at `/`
- Interactive audit workspace at `/app`
- Audits MX, SPF, DMARC, DKIM, MTA-STS, TLS-RPT, and BIMI
- Detects likely sending providers from DNS evidence
- Scores domain readiness from 0–100
- Structured findings + actionable remediation guidance
- Optional API keys (`X-API-Key`) and rate limiting
- TTL audit response cache (`X-Cache: HIT|MISS`)
- Markdown reports (`?format=markdown` or `/v1/audit/{domain}/report.md`)
- Domain compare (`POST /v1/compare`)
- Concurrent batch audits (up to 25 domains)
- Free / disposable mailbox domain warnings
- `/healthz` and `/readyz` with version
- CLI with formats, `--out`, `--timeout`, exit codes

## Endpoints

| Method | Path |
| --- | --- |
| `GET` | `/` |
| `GET` | `/app` |
| `GET` | `/api` |
| `GET` | `/healthz` |
| `GET` | `/readyz` |
| `GET` | `/v1/providers` |
| `POST` | `/v1/audits/email-domain` |
| `GET` | `/v1/audit/{domain}/report.md` |
| `POST` | `/v1/audits/batch` |
| `POST` | `/v1/compare` |
| `POST` | `/v1/cache/clear` |

## Quick Start

```bash
cd API
python3 -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
uvicorn --app-dir src inboxready_api.main:app --reload
```

Open:

- Website: http://127.0.0.1:8000
- Workspace: http://127.0.0.1:8000/app
- API docs: http://127.0.0.1:8000/docs
- Health: http://127.0.0.1:8000/healthz
- Ready: http://127.0.0.1:8000/readyz

## Environment

See [`.env.example`](./.env.example). Important production knobs:

```bash
INBOXREADY_API_KEYS=key1,key2
INBOXREADY_REQUIRE_API_KEY=false
INBOXREADY_RATE_LIMIT_PER_MINUTE=60
INBOXREADY_CACHE_TTL_SECONDS=300
```

When `INBOXREADY_API_KEYS` is non-empty (or `REQUIRE_API_KEY=true`), send `X-API-Key` on `/v1/*` routes. Missing/invalid keys return **401**; over-limit clients return **429**.

## Example Request

```bash
curl -X POST http://127.0.0.1:8000/v1/audits/email-domain \
  -H "Content-Type: application/json" \
  -d '{
    "domain": "example.com",
    "selectors": ["google", "selector1"]
  }'
```

Markdown:

```bash
curl -X POST "http://127.0.0.1:8000/v1/audits/email-domain?format=markdown" \
  -H "Content-Type: application/json" \
  -d '{"domain":"example.com"}'
```

## Batch Audits

Audit up to **25** domains concurrently:

```bash
curl -X POST http://127.0.0.1:8000/v1/audits/batch \
  -H "Content-Type: application/json" \
  -d '{
    "domains": ["example.com", "openai.com"],
    "selectors": ["google", "selector1"],
    "expected_providers": ["Google Workspace"]
  }'
```

## Compare

```bash
curl -X POST http://127.0.0.1:8000/v1/compare \
  -H "Content-Type: application/json" \
  -d '{"domains":["example.com","openai.com"]}'
```

## CLI

```bash
inboxready version
inboxready providers
inboxready audit example.com --selectors google,selector1
inboxready audit example.com --format md --out report.md
inboxready audit example.com openai.com --json
inboxready compare example.com openai.com
```

Exit codes: **0** pass, **1** fail overall, **2** error.

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

## Deploy Notes

- Cache and rate limits are in-memory per process.
- Point load balancer liveness at `/healthz` and readiness at `/readyz`.
- Set API keys before exposing a public production instance.

## Local Development Note

```bash
uvicorn --app-dir src inboxready_api.main:app --reload
pytest -q
```

## Files

- App entrypoint: [src/inboxready_api/main.py](./src/inboxready_api/main.py)
- Settings: [src/inboxready_api/settings.py](./src/inboxready_api/settings.py)
- Auth / rate limit: [src/inboxready_api/security.py](./src/inboxready_api/security.py)
- Cache: [src/inboxready_api/cache.py](./src/inboxready_api/cache.py)
- Audit engine: [src/inboxready_api/services/dns_audit.py](./src/inboxready_api/services/dns_audit.py)
- Batch / compare / report: [src/inboxready_api/services/](./src/inboxready_api/services/)
- CLI: [src/inboxready_api/cli.py](./src/inboxready_api/cli.py)
