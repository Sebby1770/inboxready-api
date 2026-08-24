# Changelog

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
