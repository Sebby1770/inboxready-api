# Changelog

## [0.7.0] — 2026-09-04

A production-boundary release: the audit engine and v0.6 DMARC intelligence
remain API-compatible, while hostile input, client identity, memory growth,
webhook delivery, and failure diagnostics now have explicit policies.

### Added
- Canonical IDNA domain validation before DNS/HTTP work, plus bounded and
  deduplicated DKIM selectors and expected-provider hints.
- Configurable request-envelope limits for normal requests and the larger
  DMARC multipart route. Declared and chunked bodies both receive JSON `413`.
- `RateLimit-Limit`, `RateLimit-Remaining`, and `RateLimit-Reset` headers on
  accepted API calls, with `Retry-After` on `429` responses.
- Explicit trusted-proxy CIDRs with right-to-left `X-Forwarded-For` chain
  evaluation. Forwarding headers remain ignored by default.
- Structured request events containing request ID, method, path, status,
  duration, and a one-way client hash—never headers, query strings, or bodies.
- Signed webhook events (`X-InboxReady-Signature-256`), stable delivery IDs,
  bounded retries for transient failures, and configurable timeouts.

### Changed
- API keys use constant-time comparison, and only SHA-256 key identities are
  retained in rate-limit state. Arbitrary key headers can no longer bypass an
  open deployment's IP bucket.
- Audit cache entries and rate-limit client buckets are LRU-bounded.
- Low-score webhooks run after the response and refuse redirects plus
  private/non-global targets unless explicitly enabled. Target DNS is checked
  before every attempt; the default HTTP transport still resolves on connect,
  so operators accepting tenant-controlled URLs must also enforce egress policy
  against DNS rebinding.
- MTA-STS discovery now requires one valid versioned TXT record. Policy fetches
  pin the connection to a vetted public address (with the original HTTP Host
  and TLS SNI), reject redirects and non-plain-text responses, and cap bodies
  at 64 KiB; required fields, maximum age, and MX patterns are validated before
  `enforce` can pass.
- `/readyz` fails closed when authentication is required without configured
  keys, and no longer returns internal exception text.
- Untrusted request IDs are syntax/length checked before response reflection.

### Compatibility
- Existing endpoints, successful response bodies, API-key header, domain URL
  shorthand, scoring, and CLI commands are preserved. Trailing-dot domains are
  canonicalized to the equivalent non-dot hostname.

## [0.6.0] — 2026-09-02

Reading the reports, not just the records. A DNS audit says DMARC is
published; it cannot say what happens when you enforce it. That answer lives
in the aggregate (RUA) reports mailbox providers already send, as gzipped XML
nobody opens.

### Added
- **DMARC aggregate report analysis** (`services/dmarc_reports.py`) — reads
  RFC 7489 Appendix C reports from raw XML, gzip, or zip; merges reports
  across reporters and windows; classifies every sending IP as
  *authenticated*, *forwarded*, *SPF-only*, or *unauthenticated* from the
  evaluated (alignment-aware) results.
- **Rollout readiness gate** — says whether `p=none → quarantine → reject` is
  safe yet and names the sources standing in the way. Forwarded mail never
  blocks a rollout; SPF-only alignment is flagged as fragile because it does
  not survive forwarding.
- **`POST /v1/dmarc/reports`** — multipart upload of up to 25 report files,
  returning the merged summary, per-source breakdown, and the readiness
  verdict. Unreadable files are reported per file instead of failing the batch.
- **`inboxready dmarc-reports FILE...`** — the same analysis from the command
  line, exiting 1 when the next policy step is not safe, so it can gate a
  pipeline.
- **`/dmarc-reports` page** documenting the four source classifications, the
  thresholds, and exactly what happens to an uploaded report.

### Fixed
- **The published scoring document did not match the scorer.** `/v1/scoring`
  advertised MX at 15 points with a `warn` multiplier of 0.55, while the audit
  actually used 10 and 0.6, so a customer could not reproduce their own score.
  Both now read one table in `services/scoring.py`, and
  `test_scoring_document_matches_the_scorer` recomputes a published score by
  hand to keep them together.

### Security
- Report files are attacker-influenced input (anyone can email you one), so
  uploads are bounded on compressed size, decompressed size, zip member count,
  and record count, and any file declaring a DTD or XML entities is refused
  before it reaches the parser. Reports are parsed in memory and not retained.

## [0.5.0] — 2026-08-24

The public surface, brought up to the same standard the API holds other
people's domains to. Twenty conversion and SEO items, each implemented and each
guarded by a test in `tests/test_growth_checklist.py`.

### Added
- **Page registry** (`site/pages.py`) — one declaration per page drives routing,
  navigation, breadcrumbs, `sitemap.xml`, and the SEO test sweep
- **Seven new pages**: `/product`, `/case-studies` (+ three detail pages),
  `/pricing`, `/faq`, `/about`, `/contact`, `/thank-you`
- **Legal pages**: `/privacy`, `/terms`, `/security`
- **Custom 404** for browsers, JSON 404 for API clients
- **Structured data** (`site/seo.py`): `Organization`, `ProfessionalService`
  with geo and opening hours, `WebSite` + `SearchAction`, `BreadcrumbList`,
  `FAQPage`, `Article`, `SoftwareApplication`, `Person`
- **`robots.txt` and `sitemap.xml`**, both environment-aware
- **Open Graph / Twitter cards** plus a 1200×630 social card asset
- **Contact form** with validation, a honeypot, and a bounded lead store
  (`site/leads.py`), optionally persisted to JSON
- **Consent-gated GA4** (`static/js/analytics.js`) — no measurement ID means no
  script and a tighter CSP; Consent Mode defaults to denied and DNT is honoured
- **Sticky mobile CTA**, dismissible, hidden on the page it points at
- **Mobile navigation menu** — the header previously had no way to open the nav
  on a narrow viewport
- **Security headers middleware**: CSP, `nosniff`, `X-Frame-Options`,
  `Referrer-Policy`, `Permissions-Policy`, and HSTS over HTTPS
- **Accessibility**: skip link, visible focus rings, `aria-current`, labelled
  landmarks, alt text on every image, reduced-motion and print styles
- `GET /site/pages` — machine-readable page inventory for link checkers
- Ruff lint configuration and a CI lint job
- [`docs/growth-checklist.md`](../docs/growth-checklist.md) mapping every item
  to its implementation and its test
- **Static site export** (`scripts/build_static.py`, `make site`) — renders all
  15 pages, the 404, `robots.txt`, `sitemap.xml`, and a Redoc API reference
  built from the live OpenAPI schema. Published to GitHub Pages by
  `.github/workflows/pages.yml`, with a link checker over the output
- `INBOXREADY_STATIC_BUILD` and `INBOXREADY_API_BASE_URL`: the published pages
  swap the audit and contact forms for honest alternatives when no backend is
  attached, and call a real API when one is configured

### Changed
- Version **0.5.0**
- `main.py` now delegates all HTML to `site/router.py`
- Startup moved from the deprecated `@app.on_event` to a lifespan handler
- **Landing page redesigned** around an "airmail dispatch" identity: a dark
  hero with an airmail rule and ghosted DNS records, a live audit console that
  plays a clearly-labelled demo trace until you run a real one, a scrolling
  protocol marquee, an animated authentication-chain diagram, perforated
  postage-stamp trust cards, and index-card case study teasers
  (`static/css/home.css`, `static/js/home.js`, loaded only on `/`)

### Fixed
- Scroll-reveal could leave a page blank when the IntersectionObserver never
  fired. Added a `<noscript>` fallback and a JS failsafe that reveals anything
  still hidden after 1.5s — content must never depend on animation succeeding.

### Notes
- `REVIEWS` and the team profiles ship empty / placeholder on purpose. Inventing
  testimonials, or emitting `AggregateRating` with nothing behind it, is both
  dishonest and a structured-data violation. See `docs/growth-checklist.md`.
- Set `INBOXREADY_ENVIRONMENT=production` on the real deployment: any other
  value serves a blanket `robots.txt` disallow and marks pages `noindex`.

## [0.3.0] — 2026-07-24

### Added
- Audit history store (memory + optional JSON file)
- `GET /v1/history`, `/v1/history/stats`, `/v1/history/export.csv`
- Optional score webhooks (`INBOXREADY_WEBHOOK_URL`)
- HTML report format (`?format=html`)
- Scoring documentation endpoint `GET /v1/scoring`
- `X-Request-Id` middleware
- CLI `history` / `scoring` commands

### Changed
- Version **0.3.0**
