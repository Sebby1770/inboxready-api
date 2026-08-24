# InboxReady API

InboxReady is a Python/FastAPI service that audits whether customer domains are ready to send trustworthy email.

**Version:** 0.5.0 · **Site:** <https://sebby1770.github.io/inboxready-api/>

It checks MX, SPF, DMARC, DKIM, MTA-STS, TLS-RPT, and BIMI; detects likely sending providers; returns a weighted readiness score and remediation guidance; and includes caching, optional API keys, rate limiting, domain compare, and markdown reports.

It also ships the marketing site around the API — twelve pages, structured data, a sitemap, and a contact form — because an audit product with an unfinished front door is a hard sell.

## Features

### The API

- Single-domain and concurrent batch audits (up to 25 domains)
- Provider fingerprint catalog
- Optional API keys (`X-API-Key`) and per-key/IP rate limiting
- TTL response cache with `X-Cache: HIT|MISS`
- Markdown / JSON / HTML audit reports
- Side-by-side domain compare
- Audit history with stats and CSV export, optionally persisted
- Free / disposable mailbox domain warnings
- Liveness (`/healthz`) and readiness (`/readyz`) probes
- CLI: `inboxready` with formats, exit codes, and compare

### The site (v0.5)

- Twelve pages driven by a single page registry: product, case studies,
  pricing, FAQ, about, contact, workspace, thank-you, and three legal pages
- Full structured data: `Organization`, `ProfessionalService` (with geo and
  opening hours), `WebSite`, `BreadcrumbList`, `FAQPage`, `Article`
- `robots.txt` and `sitemap.xml`, both environment-aware
- Open Graph / Twitter cards with a 1200×630 social card
- Contact form with validation, a honeypot, and a bounded lead store
- Consent-gated GA4 that ships nothing at all unless configured
- Custom 404 for browsers, JSON 404 for API clients
- Security headers: CSP, `nosniff`, `X-Frame-Options`, `Referrer-Policy`,
  `Permissions-Policy`, HSTS
- Accessibility: skip link, focus rings, alt text everywhere, reduced-motion
- **Twenty conversion/SEO items, each guarded by a test** —
  see [`docs/growth-checklist.md`](./docs/growth-checklist.md)

## Project layout

| Path | Purpose |
| --- | --- |
| [`API/`](./API) | FastAPI package, tests, Dockerfile |
| [`API/src/inboxready_api/site/`](./API/src/inboxready_api/site) | Page registry, SEO, content, leads, site router |
| [`docs/growth-checklist.md`](./docs/growth-checklist.md) | Every checklist item, its code, and its test |
| [`docs/publishing.md`](./docs/publishing.md) | How the site is rendered to static files and published |
| [`API/scripts/build_static.py`](./API/scripts/build_static.py) | Renders the whole site for GitHub Pages |
| [`render.yaml`](./render.yaml) | Render.com deploy config |
| [`.github/workflows/ci.yml`](./.github/workflows/ci.yml) | ruff + pytest on 3.11 / 3.12 / 3.13 |
| [`.github/workflows/pages.yml`](./.github/workflows/pages.yml) | Builds and publishes the site to `gh-pages` |

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
- Page inventory: http://127.0.0.1:8000/site/pages

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
| `INBOXREADY_HISTORY_MAX_ENTRIES` | `500` | Audit history retained in memory |
| `INBOXREADY_HISTORY_PATH` | _(empty)_ | Optional JSON file for audit history |
| `INBOXREADY_WEBHOOK_URL` | _(empty)_ | Notified when a score falls below the floor |
| `INBOXREADY_WEBHOOK_MIN_SCORE` | `70` | The score floor |
| `INBOXREADY_ENVIRONMENT` | `development` | Only `production` is crawlable |
| `INBOXREADY_SITE_BASE_URL` | _(empty)_ | Absolute origin for canonicals, sitemap, `og:image` |
| `INBOXREADY_ANALYTICS_GA4_ID` | _(empty)_ | GA4 measurement ID; empty serves no analytics |
| `INBOXREADY_ANALYTICS_REQUIRE_CONSENT` | `true` | Withhold analytics until the banner is accepted |
| `INBOXREADY_SUPPORT_RESPONSE_HOURS` | `24` | Drives the published response-time promise |
| `INBOXREADY_LEADS_PATH` | _(empty)_ | Optional JSON file for contact submissions |
| `INBOXREADY_SECURITY_HEADERS_ENABLED` | `true` | CSP and hardening headers on HTML |

## Site routes

| Path | Notes |
| --- | --- |
| `/` | Landing page |
| `/product` | Every check, in detail |
| `/case-studies`, `/case-studies/{slug}` | Three illustrative walkthroughs |
| `/pricing` | Plans and overage behaviour |
| `/faq` | Eight questions, with `FAQPage` schema |
| `/about` | Team and commitments |
| `/contact` | Form, response promise, map and directions |
| `/thank-you` | Conversion destination (`noindex`) |
| `/app` | Live audit workspace |
| `/privacy`, `/terms`, `/security` | Legal |
| `/robots.txt`, `/sitemap.xml` | Crawler surfaces |
| `/site/pages` | JSON page inventory |

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
make check          # ruff + pytest
```

Unit tests mock DNS and do not require live internet. The site suites render
every registered page and assert the SEO, accessibility, and conversion
invariants — including that no invented testimonials have crept in.

```bash
pytest tests/test_growth_checklist.py -v   # the twenty-item checklist
```

## Publish the site

```bash
cd API && make site
```

Renders every page to `../_site` and checks the links. CI does the same on
every push to `main` and publishes to `gh-pages`. The published copy has no
backend, so the audit and contact forms explain themselves rather than failing
— pass `--api-base` to point them at a running instance. Details in
[`docs/publishing.md`](./docs/publishing.md).

## Deploy notes

- **Set `INBOXREADY_ENVIRONMENT=production`.** Any other value serves a blanket
  `robots.txt` disallow and marks every page `noindex` — deliberate, so a staging
  copy cannot compete with the real site in search results.
- **Set `INBOXREADY_SITE_BASE_URL`**, or canonical URLs and the sitemap will
  point at whatever origin the request arrived on.
- Prefer setting `INBOXREADY_API_KEYS` and a sensible `INBOXREADY_RATE_LIMIT_PER_MINUTE` in production.
- Cache and rate limits are **in-process** (per instance). Multi-instance deploys need sticky sessions or an external store for strict global limits.
- Health checks: liveness → `/healthz`, readiness → `/readyz`.
- Render: see [`render.yaml`](./render.yaml).

## License

See [LICENSE](./LICENSE).
