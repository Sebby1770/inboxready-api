# Changelog

## [0.4.0] — 2026-08-18

### Added
- SPF include tree (`expand_spf`) with injected TXT resolver, cycle detection, and resolved lookup counts
- DMARC 2024 sender checks: parse `p`/`sp`/`rua`/`ruf`/`pct`/`adkim`/`aspf`, warn on `p=none`, fail without `rua`
- Optional BIMI logo probe (`l=` URL) recording `content_type`, `ok`, and `bytes`
- CAA check with `issue` tags (NXDOMAIN treated as info)
- History score deltas and `changed_checks` on new audits and `GET /v1/history`
- CLI `inboxready delta example.com` for the last two scores
- Remediation playbook: `GET /v1/playbook/{domain}` and `POST /v1/playbook`
- Workspace score sparkline from `/v1/history` plus `score_delta` on the latest result

### Changed
- Version **0.4.0**
- Scoring document version **0.4** (CAA remains advisory / unweighted)

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
