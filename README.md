# InboxReady API

InboxReady is a Python/FastAPI service that audits whether customer domains are ready to send trustworthy email.

**Version:** 0.7.0 · **Site:** <https://sebby1770.github.io/inboxready-api/>

It checks MX, SPF, DMARC, DKIM, MTA-STS, TLS-RPT, and BIMI; detects likely sending providers; returns a weighted readiness score and remediation guidance; and includes caching, optional API keys, rate limiting, domain compare, and markdown reports.

It also reads the DMARC aggregate reports mailbox providers send back, which is the only way to answer the question that actually blocks a rollout: if the policy tightens, whose mail breaks?

It also ships the marketing site around the API — twelve pages, structured data, a sitemap, and a contact form — because an audit product with an unfinished front door is a hard sell.

## Features

### The API

- Single-domain and concurrent batch audits (up to 25 domains)
- DMARC aggregate (RUA) report analysis with a policy-rollout verdict
- Provider fingerprint catalog
- Constant-time API-key checks, hashed in-memory key identities, and per-key/IP rate limiting
- Trusted-proxy-aware client identity and `RateLimit-*` / `Retry-After` response headers
- TTL response cache with `X-Cache: HIT|MISS`
- Bounded request bodies, cache entries, rate-limit buckets, selectors, and provider hints
- Strict MTA-STS discovery/policy validation with bounded, no-redirect fetches
- Signed, retried low-score webhooks delivered outside the API response path
- Markdown / JSON / HTML audit reports
- Side-by-side domain compare
- Audit history with stats and CSV export, optionally persisted
- Free / disposable mailbox domain warnings
- Liveness (`/healthz`) and readiness (`/readyz`) probes
- CLI: `inboxready` with formats, exit codes, compare, and `dmarc-reports`

### Reading DMARC reports (v0.6)

A DNS lookup tells you DMARC is published. It cannot tell you what enforcement
would do. The aggregate reports already arriving in your `rua` mailbox can.

```bash
inboxready dmarc-reports reports/*.xml.gz
```

```text
DMARC aggregate reports for example.com
  window        2026-01-01 to 2026-01-07
  messages      48210
  aligned pass  98.4% (DKIM 97.9%, SPF 91.2%)

Sending sources (14)
  192.0.2.10                     45120 msg  100.0% pass  authenticated
  198.51.100.7                    2348 msg  100.0% pass  forwarded
  203.0.113.9                      742 msg    0.0% pass  unauthenticated

NOT READY to leave p=none
  - 1 source still fails DMARC with volume: 203.0.113.9 (742 msg)
```

Every source is classified from the report's evaluated results, which already
account for alignment:

| Classification | Shape | What it means |
| --- | --- | --- |
| `authenticated` | aligned DKIM and SPF pass | your own infrastructure, set up correctly |
| `forwarded` | aligned DKIM passes, SPF fails | a forwarder or list; already passes DMARC and will keep passing |
| `spf-only` | aligned SPF passes, no aligned DKIM | passes today, breaks the first time it is forwarded |
| `unauthenticated` | neither passes | unauthorised sender, or someone else sending as you |

The readiness gate needs at least 100 reported messages, a 95% aligned pass
rate for `quarantine` (99% for `reject`), and no unauthenticated source above
0.1% of volume. The CLI exits 1 when the next step is not safe, so it can gate
a pipeline. The same analysis is available at `POST /v1/dmarc/reports`.

Report files are treated as untrusted input: compressed size, decompressed
size, zip members, and record count are all bounded, DTD and entity
declarations are refused, and nothing is written to disk.

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
| `INBOXREADY_RATE_LIMIT_MAX_BUCKETS` | `20000` | Maximum client buckets retained per process |
| `INBOXREADY_CACHE_TTL_SECONDS` | `300` | Audit result TTL (`0` disables) |
| `INBOXREADY_CACHE_MAX_ENTRIES` | `2000` | Maximum cached audits retained per process |
| `INBOXREADY_REQUEST_BODY_MAX_BYTES` | `1048576` | Body limit for normal API/form requests |
| `INBOXREADY_REPORT_UPLOAD_BODY_MAX_BYTES` | `37748736` | Multipart body limit for DMARC uploads |
| `INBOXREADY_HTTP_TIMEOUT_SECONDS` | `5.0` | MTA-STS policy fetch timeout |
| `INBOXREADY_USER_AGENT` | `InboxReady/0.7 ...` | Outbound User-Agent |
| `INBOXREADY_BATCH_MAX_WORKERS` | `8` | Thread pool for batch audits |
| `INBOXREADY_HISTORY_MAX_ENTRIES` | `500` | Audit history retained in memory |
| `INBOXREADY_HISTORY_PATH` | _(empty)_ | Optional JSON file for audit history |
| `INBOXREADY_WEBHOOK_URL` | _(empty)_ | Notified when a score falls below the floor |
| `INBOXREADY_WEBHOOK_MIN_SCORE` | `70` | The score floor |
| `INBOXREADY_WEBHOOK_SECRET` | _(empty)_ | HMAC-SHA256 signing secret |
| `INBOXREADY_WEBHOOK_MAX_ATTEMPTS` | `3` | Attempts for transient delivery failures |
| `INBOXREADY_WEBHOOK_TIMEOUT_SECONDS` | `3` | Timeout for each attempt |
| `INBOXREADY_WEBHOOK_ALLOW_PRIVATE_HOSTS` | `false` | Permit intentionally internal receivers |
| `INBOXREADY_TRUSTED_PROXY_CIDRS` | _(empty)_ | Proxies allowed to supply `X-Forwarded-For` |
| `INBOXREADY_ACCESS_LOG_ENABLED` | `true` | Structured request events without bodies or queries |
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

## Production behaviour (v0.7)

All audit inputs are canonicalized before DNS resolution. HTTP(S) domain URLs
remain supported, while credentials, ports, IP literals, malformed DNS labels,
oversized selector/provider lists, and over-limit request bodies return a
bounded JSON error. Client-supplied request IDs are accepted only when they use
a safe 128-character alphabet; otherwise the service creates a UUID.

MTA-STS discovery now requires exactly one valid `v=STSv1` TXT record with an
ID. Policy retrieval pins the connection to a vetted public address while
preserving the original hostname for HTTP and TLS, accepts only a direct `200`,
refuses redirects and non-`text/plain` responses, caps the decoded body at 64
KiB, and validates `version`, `mode`, `max_age`, and MX patterns before an
enforcement policy can pass.

Rate-limited responses include `Retry-After`; successful authenticated routes
include `RateLimit-Limit`, `RateLimit-Remaining`, and `RateLimit-Reset` (plus
the common `X-RateLimit-*` forms). Forwarding headers are ignored unless the
direct peer matches `INBOXREADY_TRUSTED_PROXY_CIDRS`, and multi-hop chains are
walked from the trusted edge inward.

Low-score webhook deliveries carry `X-InboxReady-Event`, a stable
`X-InboxReady-Delivery` ID, and—when `INBOXREADY_WEBHOOK_SECRET` is set—an
`X-InboxReady-Signature-256: sha256=...` signature over the exact request body.
Delivery runs as an in-process background task with bounded exponential retry;
redirects and private/non-global resolved addresses are refused by default.
Set `INBOXREADY_WEBHOOK_ALLOW_PRIVATE_HOSTS=true` only for a deliberately
internal receiver. DNS safety is checked before each attempt, but the standard
HTTP transport resolves again when connecting, so this is not connection-pinned
protection against DNS rebinding. Use fixed egress/DNS policy when webhook URLs
can be configured by untrusted tenants.

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
- Cache, rate limits, history, and webhook retries are **in-process** (per instance). They are bounded, but multi-instance deploys need shared external stores/queues for strict global limits and durable webhook delivery.
- Health checks: liveness → `/healthz`, readiness → `/readyz`.
- Render: see [`render.yaml`](./render.yaml).

## License

See [LICENSE](./LICENSE).
