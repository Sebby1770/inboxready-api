# Launch Plan

This is the practical launch path for `InboxReady API` as a real product, not just a code sample.

## 1. Narrow the ICP

Start with one buyer:

- B2B SaaS products that let customers send email from their own domain

Examples:

- helpdesk platforms
- outbound sales tools
- CRMs
- notification/messaging tools
- agencies that white-label email setup

Reason: they feel the pain immediately during onboarding and can understand the value in one demo.

## 2. Package the MVP

Ship only these features first:

- API keys
- single-domain audit endpoint
- batch audit endpoint
- basic provider detection
- score + remediation response
- docs + example SDK snippets
- simple usage dashboard

Do not build first:

- full DMARC aggregate report ingestion
- multi-role enterprise admin
- billing edge cases
- fancy UI

## 3. Pricing to Launch With

Use simple pricing from day one:

- Free: 100 audits/month
- Starter: $49/month
- Growth: $149/month
- Pro: $399/month

Add annual option after the first 5-10 paying customers.

## 4. Required Product Work Before Public Launch

1. API key auth is implemented.
2. Per-key usage metering is implemented.
3. Stripe subscription hooks are implemented.
4. App-level and proxy-level rate limiting are implemented.
5. Persistent audit logging is implemented.
6. Request IDs, structured logs, `/metrics`, JSON metrics, WebSocket health, and polling health endpoints are implemented.
7. Add external alerting next: Sentry, Better Stack, Datadog, or provider-native alerts.
8. Add a public status page once the first paying customers depend on the API.

## 5. Deploy the API

### Option A: Render

Fastest path for a solo founder.

Steps:

1. Push the repo to GitHub.
2. Create a new Web Service in Render.
3. Set root directory to `/Users/sebastianforbes/Desktop/CODE/API-as-a-Service/API` after pushing the folder structure into the repo.
4. Build command:

```bash
pip install .
```

5. Start command:

```bash
uvicorn inboxready_api.main:app --host 0.0.0.0 --port $PORT
```

6. Add env vars from `.env.example`.
7. Attach a managed Postgres instance when you add accounts, billing, and audit history.

### Option B: Fly.io

Better if you want tighter control and lower-cost global deployment.

Steps:

1. Install Fly CLI.
2. Run `fly launch` from the `API` directory.
3. Use the included `Dockerfile`.
4. Set secrets with `fly secrets set`.
5. Deploy with `fly deploy`.

## 6. Add Billing

Use Stripe:

1. Create monthly subscription products for each tier.
2. Track usage in your database by API key and billing period.
3. If usage exceeds included volume, either hard-limit or invoice overages.
4. Keep invoices simple for the first version.

Good enough first implementation:

- included usage per plan
- soft warning at 80%
- hard stop or overage billing at 100%

## 7. Add Customer-Facing Docs

Minimum docs set:

- quickstart
- auth
- rate limits
- error codes
- audit response schema
- “how to fix SPF”
- “how to fix DMARC”
- “how to verify DKIM selectors”

This matters because documentation is part of the product in developer APIs.

## 8. Acquire the First 10 Customers

### Direct outbound

Find SaaS products that:

- ask users to “verify domain”
- offer branded sending
- publish email setup docs
- have support pages about SPF, DKIM, or DMARC

Send a short founder email offering:

- faster onboarding
- fewer DNS-related support tickets
- embeddable API instead of internal scripts

### Content

Publish:

- “How to verify a customer email domain with one API call”
- “Google and Yahoo sender requirements: what SaaS teams need to check automatically”
- “Why DMARC dashboards are overkill for onboarding”

### Free tool funnel

Offer a public domain checker with:

- one free audit
- shareable report
- upgrade CTA for API access

## 9. Convert to a Sticky Workflow Product

Add retention features after the first few customers:

- saved domains
- scheduled re-checks
- webhooks when posture changes
- provider-specific remediation templates
- audit history for support teams

That shifts the product from utility to workflow infrastructure.

## 10. 30-Day Build Timeline

### Week 1

- harden current MVP
- add API keys
- add persistent storage
- add billing schema

### Week 2

- add usage metering
- add dashboard
- add hosted docs
- polish response schema and errors

### Week 3

- deploy production environment
- connect Stripe
- add logging, monitoring, and rate limiting
- build public checker landing page

### Week 4

- outbound to 100 prospects
- onboard 3-5 design partners
- ship missing must-have fixes
- collect testimonials and case-study data

## 11. Success Metrics

Track:

- audit-to-signup conversion
- paid conversion from free
- average domains audited per account
- support tickets avoided or resolved faster
- activation time from signup to first API call
- net revenue retention by account cohort

## 12. What to Avoid

- selling to huge enterprises first
- adding dashboards before API reliability
- underpricing so hard that support kills margin
- custom consulting work that blocks productization
- chasing every email-auth edge case before finding demand

## Launch Commands

Local dev:

```bash
cd /Users/sebastianforbes/Desktop/CODE/API-as-a-Service/API
python3 -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
uvicorn --app-dir src inboxready_api.main:app --reload
```

Run tests:

```bash
cd /Users/sebastianforbes/Desktop/CODE/API-as-a-Service/API
source .venv/bin/activate
pytest
```

Stage with Docker and Nginx:

```bash
cd /Users/sebastianforbes/Desktop/CODE/API-as-a-Service
docker compose up --build
```

Production readiness checklist:

```bash
open /Users/sebastianforbes/Desktop/CODE/API-as-a-Service/infra/production-readiness.md
```
