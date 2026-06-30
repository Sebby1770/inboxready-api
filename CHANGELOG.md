# Changelog

All notable product-facing changes to InboxReady are tracked here.

## 0.7.0 - 2026-06-30

### Added

- Production operations pack covering Docker staging, Nginx proxying, Kubernetes manifests, CI, and container publishing.
- Runtime observability with request IDs, structured request/error logs, Prometheus-style `/metrics`, and JSON `/v1/metrics/summary`.
- Health streaming and polling surfaces through `/ws/health`, `/v1/health/short-poll`, and `/v1/health/long-poll`.
- Production readiness guide mapping Kubernetes, SQS/S3, CI/CD, encryption, firewalling, WebSockets, queues, caching, load balancing, RPC, polling, and partitioning decisions.

### Improved

- API metadata now advertises metrics, WebSocket health, and polling endpoints.
- Security policy now allows same-origin WebSocket health clients while keeping the defensive browser posture.
- Repository automation now runs Python checks and publishes a GHCR image for deployment branches.

## 0.6.0 - 2026-06-29

### Added

- Dashboard health insights that combine recent audit history, monitor status, and usage headroom.
- Action queue for failed or warning audits, unchecked monitors, and plan-capacity risk.
- Domains-to-watch rows that surface the customer senders worth revisiting first.

### Improved

- Dashboard now explains operational priority instead of only showing raw account data.
- Responsive dashboard styling now supports the new insight panel cleanly on narrow screens.

## 0.5.0 - 2026-06-28

### Added

- Lovable-inspired visual refresh for the landing page and dashboard.
- Landing-page operations strip that highlights monitors, history exports, and batch reviews.
- Dashboard command strip for fast navigation between monitors, history, API keys, billing, and changelog.
- Monthly usage meter inside the dashboard account overview.

### Improved

- Reworked the color palette, typography, card radius, shadows, and buttons for a cleaner B2B SaaS feel.
- Reduced decorative background noise and made the interface more dashboard-oriented.

## 0.4.0 - 2026-06-27

### Added

- Account-level domain monitors for keeping customer senders on a watchlist.
- Monitor REST endpoints:
  - `POST /v1/monitors`
  - `GET /v1/monitors`
  - `POST /v1/monitors/{monitor_id}/run`
  - `DELETE /v1/monitors/{monitor_id}`
- Dashboard monitor controls for adding, refreshing, and removing watched domains.
- Monitor persistence for cadence, DKIM selectors, expected providers, last score, last status, and last checked time.

### Improved

- Monitor runs now consume normal audit usage and save results to audit history.
- API metadata now advertises the monitor surface.

## 0.3.0 - 2026-06-26

### Added

- Public `/changelog` page in the web app.
- Release-note cards on the landing page and inside the dashboard.
- Dashboard batch-audit workflow for reviewing multiple customer domains in one session.
- Saved-audit export paths for CSV downloads and per-audit JSON inspection.

### Improved

- API metadata now exposes changelog and latest-release details.
- Launch documentation now points readers to product release notes.
- Product messaging better explains how the API fits onboarding, support, and deliverability workflows.

## 0.2.0 - 2026-06-22

### Added

- Session-backed signup, login, logout, and dashboard flows.
- Account-level API key lifecycle management with one-time key reveal.
- Usage metering, saved audit history, support intake, and Stripe billing hooks.

### Security

- CSRF protection for session-backed actions.
- Hardened password handling and defensive response headers.

## 0.1.0 - 2026-04-28

### Added

- Core FastAPI service for MX, SPF, DKIM, DMARC, BIMI, MTA-STS, and TLS-RPT audits.
- Provider detection, weighted readiness scoring, and remediation guidance.
- Public demo endpoint, batch audit endpoint, CLI, and initial test coverage.
