# InboxReady API

InboxReady is a Python/FastAPI service that audits whether customer domains are ready to send trustworthy email.

**Version:** 0.3.0

It checks MX, SPF, DMARC, DKIM, MTA-STS, TLS-RPT, and BIMI; detects likely sending providers; returns a weighted readiness score and remediation guidance; and includes caching, optional API keys, rate limiting, domain compare, and markdown reports.

## Features (v0.3)

- Single-domain and concurrent batch audits (up to 25 domains)
- Provider fingerprint catalog
- Optional API keys (`X-API-Key`) and per-key/IP rate limiting
- TTL response cache with `X-Cache: HIT|MISS`
- Markdown / JSON audit reports
- Side-by-side domain compare
- Free / disposable mailbox domain warnings
- Liveness (`/healthz`) and readiness (`/readyz`) probes
- CLI: `inboxready` with formats, exit codes, and compare
- Landing page + interactive workspace
- GitHub Actions CI (Python 3.11+)

## Project layout

| Path | Purpose |
| --- | --- |
| [`API/`](./API) | FastAPI package, tests, Dockerfile |
| [`render.yaml`](./render.yaml) | Render.com deploy config |
| [`.github/workflows/ci.yml`](./.github/workflows/ci.yml) | pytest on 3.11 / 3.12 / 3.13 |

## Run locally

```bash
cd API
python3 -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
uvicorn --app-dir src inboxready_api.main:app --reload
```

- Site: http://127.0.0.1:8000  
- Workspace: http://127.0.0.1:8000/app  
- Docs: http://127.0.0.1:8000/docs  

## Environment variables

Copy [`API/.env.example`](./API/.env.example). All settings use the `INBOXREADY_` prefix:

| Variable | Default | Description |
| --- | --- | --- |
| `INBOXREADY_API_KEYS` | _(empty)_ | Comma-separated keys; when set, `X-API-Key` is required |
| `INBOXREADY_REQUIRE_API_KEY` | `false` | Force key auth even with empty key list |
| `INBOXREADY_RATE_LIMIT_PER_MINUTE` | `60` | Sliding window per key/IP (`0` disables) |
| `INBOXREADY_CACHE_TTL_SECONDS` | `300` | Audit result TTL (`0` disables) |
| `INBOXREADY_HTTP_TIMEOUT_SECONDS` | `5.0` | MTA-STS policy fetch timeout |
| `INBOXREADY_USER_AGENT` | `InboxReady/0.2 ...` | Outbound User-Agent |
| `INBOXREADY_BATCH_MAX_WORKERS` | `8` | Thread pool for batch audits |

## API overview

| Method | Path | Notes |
| --- | --- | --- |
| `GET` | `/healthz` | Liveness + version |
| `GET` | `/readyz` | DNS resolver constructible + version |
| `GET` | `/v1/providers` | Provider catalog |
| `POST` | `/v1/audits/email-domain` | Audit; `?format=json\|markdown` |
| `GET` | `/v1/audit/{domain}/report.md` | Markdown report |
| `POST` | `/v1/audits/batch` | Up to 25 domains, concurrent |
| `POST` | `/v1/compare` | Side-by-side scores + check diffs |
| `GET` | `/v1/history` | Recent audits |
| `GET` | `/v1/history/stats` | Aggregate history |
| `GET` | `/v1/history/export.csv` | CSV export |
| `GET` | `/v1/scoring` | Score weights |
| `POST` | `/v1/cache/clear` | Clear in-memory cache |

Auth (when keys configured or `REQUIRE_API_KEY=true`):

```bash
curl -H "X-API-Key: your-key" \
  -H "Content-Type: application/json" \
  -d '{"domain":"example.com"}' \
  http://127.0.0.1:8000/v1/audits/email-domain
```

## CLI

```bash
inboxready version
inboxready providers
inboxready audit example.com --format md --out report.md
inboxready audit example.com --json
inboxready audit a.com b.com --timeout 10
inboxready compare a.com b.com
```

Exit codes: `0` pass, `1` overall fail, `2` error.

## Test

```bash
cd API
pip install -e ".[dev]"
pytest -q
```

Unit tests mock DNS and do not require live internet.

## Deploy notes

- Prefer setting `INBOXREADY_API_KEYS` and a sensible `INBOXREADY_RATE_LIMIT_PER_MINUTE` in production.
- Cache and rate limits are **in-process** (per instance). Multi-instance deploys need sticky sessions or an external store for strict global limits.
- Health checks: liveness → `/healthz`, readiness → `/readyz`.
- Render: see [`render.yaml`](./render.yaml).

## License

See [LICENSE](./LICENSE).
