# InboxReady launch guide

Updated November 13, 2026. Release 1.1.0 includes the redesigned website and improved
signup-to-billing journey. Revenue is not enabled merely by deploying the website.

## Run locally

From `API/`, activate the existing virtual environment and run:

```sh
python -m pip install -e '.[dev]'
python -m uvicorn inboxready_api.main:app --reload --app-dir src
```

Open http://127.0.0.1:8000. Run `python -m pytest -q` from the same directory.

## Deploy the current application

1. Import this GitHub repository into Render as a Blueprint using `render.yaml`.
2. Review Render's service and persistent disk charges before creating the service.
3. Set `INBOXREADY_PUBLIC_BASE_URL` to your public HTTPS origin and
   `INBOXREADY_SUPPORT_EMAIL` to an inbox you control. The Blueprint generates the
   session secret, enables secure cookies, and stores SQLite and exports on `/var/data`.
4. Keep one service instance while using SQLite. Configure regular database backups
   with SQLite's backup API and test a restore before inviting paying customers.
5. Verify `/healthz`, `/readyz`, signup, login, an authenticated domain audit, key
   revocation, and persistence after redeployment.

The disk configuration follows the [Render Blueprint reference](https://render.com/docs/blueprint-spec).
The Vercel adapter uses ephemeral `/tmp` storage and remains a disposable preview option.

## Activate subscriptions

1. Create monthly USD prices matching the website: Starter $49, Growth $149, Pro $399.
2. Add these server-only environment variables through your hosting provider:
   `INBOXREADY_STRIPE_SECRET_KEY`, `INBOXREADY_STRIPE_WEBHOOK_SECRET`,
   `INBOXREADY_STRIPE_STARTER_PRICE_ID`, `INBOXREADY_STRIPE_GROWTH_PRICE_ID`,
   `INBOXREADY_STRIPE_PRO_PRICE_ID`. Never put secrets in Git or browser code.
3. Configure Stripe to deliver `checkout.session.completed`,
   `customer.subscription.updated`, and `customer.subscription.deleted` events
   to `https://YOUR_HOST/v1/billing/webhook`.
4. Enable the Stripe billing portal and its cancellation options. Existing
   subscribers manage their subscription there instead of creating a second one.
5. In test mode, verify checkout, webhook delivery, quota changes, cancellation,
   and webhook replay. Then configure the equivalent live prices and secrets.

Both the dashboard and API disable checkout without the Stripe secret key, webhook
signing secret, or selected plan's price ID. Verify actual webhook delivery, not
just the presence of the secret. A checkout
success query string never grants a paid plan; the signed webhook updates it.
Concurrent first-time checkout sessions remain a billing limitation: the existing
subscription guard operates after a subscription has been saved.

## Supabase status

A dedicated `inboxready-api` project was provisioned in Sydney. The application
still uses SQLite. Provisioning this project does not migrate
accounts, enable Supabase Auth, or make the Vercel adapter durable. Before switching,
implement a Postgres storage adapter, migrate data, verify tenant ownership and RLS,
and test backups and rollback. Do not repurpose another application's database.

## First customers

- Start with SaaS teams that support customer sending domains, and agencies managing
  email setup for several clients. Offer a guided review of one domain they control.
- Link outreach to the free checker. Follow a useful result with the API example
  and free account, then suggest a paid plan based on actual recurring audit volume.
- Track signups, first successful account audits, active integrations, and paid
  conversions. Use aggregate counts; do not collect keys or customer DNS payloads
  in marketing analytics.
- Publish practical guides for domain onboarding, missing DKIM selectors, and
  interpreting DMARC warnings. Never promise inbox placement from a DNS score.
- Read and respond to stored support requests until a helpdesk or email integration
  is connected. The current form stores requests; it does not send notifications.

## Remaining external setup

- Production host and custom domain have not been provisioned in this release.
- Live payment credentials and an end-to-end live billing run remain necessary.
- The scoped pre-release review identified five backend issues. The release adds
  fixes and local regression coverage; this is not a production security certification.
- Before accepting payment, confirm your billing support process, test a database
  restore, and complete checkout and cancellation in Stripe test mode.
