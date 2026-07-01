# Vercel Deployment

InboxReady can run on Vercel as a Python Function through `API/index.py`. This is a good preview,
demo, and early-production lane when you want GitHub preview URLs and simple production promotion
without operating containers.

## What Was Added

- `API/index.py` imports the FastAPI app from `API/src`.
- `vercel.json` rewrites every path to the Python function and applies defensive headers.
- `requirements.txt` exposes Python dependencies at the repository root for Vercel builds.
- `.vercelignore` keeps local caches, infra files, and SQLite data out of deployments.
- GitHub Actions create preview deployments on PRs and production deployments on `main` when Vercel secrets are configured.

## Required GitHub Secrets

Set these in GitHub Actions before enabling the Vercel workflows:

```text
VERCEL_TOKEN
VERCEL_ORG_ID
VERCEL_PROJECT_ID
```

## Required Vercel Environment Variables

At minimum:

```text
INBOXREADY_SESSION_SECRET
INBOXREADY_PUBLIC_BASE_URL
INBOXREADY_SESSION_HTTPS_ONLY=true
INBOXREADY_API_AUTH_REQUIRED=true
INBOXREADY_PUBLIC_SIGNUP_ENABLED=true
```

Optional billing:

```text
INBOXREADY_STRIPE_SECRET_KEY
INBOXREADY_STRIPE_WEBHOOK_SECRET
INBOXREADY_STRIPE_STARTER_PRICE_ID
INBOXREADY_STRIPE_GROWTH_PRICE_ID
INBOXREADY_STRIPE_PRO_PRICE_ID
```

## Important Storage Note

Vercel functions have an ephemeral filesystem. The adapter defaults SQLite and export archives to
`/tmp`, which is useful for demos and preview deployments but not durable production storage. Before
paid production usage on Vercel, move these surfaces to managed storage:

- SQLite account/audit/job data -> Postgres, Neon, Supabase, DynamoDB, or another managed database.
- Local export archive -> S3, Vercel Blob, or another durable object store.

## Local Vercel Commands

```bash
npm install -g vercel
vercel link
vercel dev
vercel deploy
vercel deploy --prod
```
