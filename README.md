# InboxReady API

InboxReady is a Python/FastAPI coding project for auditing whether customer domains are ready to send trustworthy email.

It checks MX, SPF, DMARC, DKIM, MTA-STS, TLS-RPT, and BIMI, detects likely sending providers, returns a weighted readiness score, and gives concrete remediation guidance. The project includes:

- A production-shaped FastAPI app in [`API/`](./API)
- A polished landing page and interactive audit workspace
- Single-domain and batch audit endpoints
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

## Test

```bash
cd API
pytest
```
