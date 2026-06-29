# InboxReady API

InboxReady is a Python/FastAPI coding project for auditing whether customer domains are ready to send trustworthy email.

It checks MX, SPF, DMARC, DKIM, MTA-STS, TLS-RPT, and BIMI, detects likely sending providers, returns a weighted readiness score, and gives concrete remediation guidance. The project includes:

- A production-shaped FastAPI app in [`API/`](./API)
- A polished landing page and rate-limited public audit workspace
- Lovable-inspired visual system for the public site and operator dashboard
- Dashboard health insights with an action queue and domains-to-watch summary
- API-key protected single-domain and batch audit endpoints
- Canonical domain validation and concurrent batch execution
- SQLite-backed launch accounts, usage metering, rate limits, and audit history
- Audit history CSV exports and full saved-audit JSON detail views
- Account-level domain monitors with run-now checks and last-known status
- API-key listing and revocation for credential hygiene
- Stripe Checkout, Billing Portal, and webhook routes for paid plans
- Product release notes in [`CHANGELOG.md`](./CHANGELOG.md) and at `/changelog`
- A command-line interface via `inboxready`
- Tests for parsing, provider detection, batch summarization, and web routes
- Render deployment configuration in [`render.yaml`](./render.yaml)

## Run Locally

```bash
cd API
python3 -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
uvicorn --app-dir src inboxready_api.main:app --reload
```

Open the workspace at [http://127.0.0.1:8000/app](http://127.0.0.1:8000/app).

Create a launch account at `/app#account` or call `POST /v1/accounts`, then use the returned
API key with `Authorization: Bearer $INBOXREADY_API_KEY`.

Release notes are tracked in [CHANGELOG.md](./CHANGELOG.md) and served inside the app at `/changelog`.

## Test

```bash
cd API
pytest
```
