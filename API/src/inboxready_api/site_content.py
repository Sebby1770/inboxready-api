from __future__ import annotations

HERO_METRICS = [
    {
        "value": "7",
        "label": "protocol checks in every audit",
    },
    {
        "value": "<5m",
        "label": "to embed in an onboarding flow",
    },
    {
        "value": "1 call",
        "label": "to explain what DNS teams need to fix",
    },
]

SIGNAL_STRIPS = [
    "SPF",
    "DKIM",
    "DMARC",
    "BIMI",
    "MTA-STS",
    "TLS-RPT",
    "Provider detection",
]

USE_CASES = [
    {
        "eyebrow": "Product onboarding",
        "title": "Turn domain verification into a confident setup flow.",
        "body": (
            "Instead of sending customers to a doc wall, call the API, show the "
            "score, and present exact DNS actions while they are still in your product."
        ),
        "points": [
            "Reduce setup tickets before they hit support",
            "Detect likely providers to tailor remediation copy",
            "Keep activation moving with machine-readable status",
        ],
    },
    {
        "eyebrow": "Support operations",
        "title": "Give support and success teams an audit they can trust.",
        "body": (
            "Frontline teams need one report that explains why mail is failing "
            "without escalating every issue to engineering."
        ),
        "points": [
            "Readable score and recommendations",
            "Clear pass, warn, fail, and info categories",
            "References to current sender guidance",
        ],
    },
    {
        "eyebrow": "Deliverability posture",
        "title": "Keep branded sending safe as customers scale up.",
        "body": (
            "Monitor the DNS layer before weak SPF, DMARC drift, or missing DKIM "
            "turn into sender reputation problems."
        ),
        "points": [
            "Catch weak or overly complex SPF",
            "Spot DMARC policies still stuck in monitoring mode",
            "Validate transport hardening like MTA-STS and TLS-RPT",
        ],
    },
]

FLOW_STEPS = [
    {
        "number": "01",
        "title": "Collect a root domain",
        "body": "Pass a customer domain and optional DKIM selectors from your setup wizard or admin panel.",
    },
    {
        "number": "02",
        "title": "Receive a structured posture report",
        "body": "InboxReady returns provider hints, check status, weighted score, and remediation guidance.",
    },
    {
        "number": "03",
        "title": "Drive product actions",
        "body": "Gate activation, show inline setup help, create support tasks, or re-check later for drift.",
    },
]

OPS_CAPABILITIES = [
    {
        "name": "Container staging",
        "status": "Implemented",
        "detail": (
            "Docker Compose runs the API behind Nginx with health checks, request IDs, "
            "caching, rate limits, and WebSocket upgrades."
        ),
    },
    {
        "name": "CI/CD",
        "status": "Implemented",
        "detail": (
            "GitHub Actions compile the package, run tests, and publish a GHCR container "
            "image from release branches."
        ),
    },
    {
        "name": "Runtime metrics",
        "status": "Implemented",
        "detail": (
            "Prometheus and JSON endpoints report request volume, QPS, throughput, "
            "latency, availability, status codes, and recent errors."
        ),
    },
    {
        "name": "Kubernetes",
        "status": "Ready path",
        "detail": (
            "Manifests cover deployment, service, ingress, probes, secrets, config, "
            "and autoscaling once storage is externalized."
        ),
    },
    {
        "name": "Queues and object storage",
        "status": "Implemented",
        "detail": (
            "Audit jobs now run through a persisted queue abstraction, and audit-history "
            "exports are archived into a local S3-style object store."
        ),
    },
    {
        "name": "RPC and worker hooks",
        "status": "Implemented",
        "detail": (
            "RPC commands, long-poll job waits, manual job execution, and due-monitor runs "
            "create a clean path to Lambda, SQS, RabbitMQ, or Kafka later."
        ),
    },
    {
        "name": "Secure operations",
        "status": "Implemented",
        "detail": (
            "CSRF, secure hashing, defensive headers, Stripe signature checks, TLS-ready "
            "ingress, and no plain FTP by design."
        ),
    },
]

PRICING_TIERS = [
    {
        "name": "Starter",
        "price": "$49",
        "period": "/month",
        "description": "For early-stage SaaS products that want a domain audit in onboarding fast.",
        "features": [
            "2,500 audits each month",
            "Live audit API and provider fingerprints",
            "Email support and shared rate limits",
        ],
        "cta": "Start With Starter",
        "featured": False,
    },
    {
        "name": "Growth",
        "price": "$149",
        "period": "/month",
        "description": "For products with steady domain volume and a support team that needs clean outputs.",
        "features": [
            "15,000 audits each month",
            "Batch jobs and webhook-ready roadmap",
            "Priority support and higher limits",
        ],
        "cta": "Choose Growth",
        "featured": True,
    },
    {
        "name": "Pro",
        "price": "$399",
        "period": "/month",
        "description": "For agencies, platforms, and MSPs auditing many domains across customers.",
        "features": [
            "75,000 audits each month",
            "Team usage visibility and SLA lane",
            "Lower overage pricing for heavy volume",
        ],
        "cta": "Talk To Sales",
        "featured": False,
    },
]

FAQS = [
    {
        "question": "Is this a full DMARC analytics platform?",
        "answer": (
            "No. The current product position is API-first domain readiness and "
            "remediation, which makes it lighter to ship and much easier to embed."
        ),
    },
    {
        "question": "Who is the best first customer?",
        "answer": (
            "B2B SaaS products that let customers send from their own domain. "
            "They feel the pain during activation, support, and deliverability."
        ),
    },
    {
        "question": "What keeps churn low?",
        "answer": (
            "The audit sits inside onboarding and support workflows. Once a product "
            "depends on that response to activate or troubleshoot accounts, it becomes sticky."
        ),
    },
    {
        "question": "What would you build next after this MVP?",
        "answer": (
            "API keys, usage metering, stored audit history, and Stripe billing hooks are now "
            "in the launch layer. Queue-backed audits, due-monitor runs, and remediation "
            "playbooks are now available; webhook alerts are the next retention feature."
        ),
    },
]

CHANGELOG_ENTRIES = [
    {
        "version": "0.9.0",
        "date": "2026-07-01",
        "display_date": "July 1, 2026",
        "status": "Current release",
        "title": "InboxReady now has queue, archive, worker, and RPC surfaces.",
        "summary": (
            "This release turns more of the infrastructure checklist into usable product "
            "capabilities: async audit jobs, archived exports, scheduled monitor hooks, and RPC."
        ),
        "highlights": [
            "Added queue-backed audit jobs with create, list, get, run, and long-poll wait endpoints.",
            "Added S3-style audit-history export objects with JSON/CSV archive creation, listing, and download.",
            "Added due-monitor execution for cron or Lambda-style scheduled checks.",
            "Added /v1/rpc for health, metrics, providers, synchronous audits, and queued audits.",
        ],
        "impact": (
            "Best for customers that want InboxReady to fit worker queues, serverless jobs, "
            "internal RPC clients, and archive workflows without forcing a cloud migration yet."
        ),
    },
    {
        "version": "0.8.0",
        "date": "2026-06-30",
        "display_date": "June 30, 2026",
        "status": "Remediation playbooks",
        "title": "InboxReady now turns saved audits into customer-ready playbooks.",
        "summary": (
            "This release adds launch decisions, protocol coverage, and owner-ready remediation "
            "tasks so teams can move from raw DNS findings to clear customer action plans."
        ),
        "highlights": [
            "Added remediation playbook models and saved-audit playbook endpoints for API and dashboard users.",
            "Added dashboard customer playbooks with launch decisions, protocol coverage, score cards, and task owners.",
            "Added live audit playbook guidance so demos immediately show what to do next.",
            "Added playbook links beside saved audit history rows for faster support handoff.",
        ],
        "impact": (
            "Best for customer support, success, and onboarding teams that need audit output "
            "to become a clear customer-facing checklist."
        ),
    },
    {
        "version": "0.7.0",
        "date": "2026-06-30",
        "display_date": "June 30, 2026",
        "status": "Operations layer",
        "title": "InboxReady now has a real production operations layer.",
        "summary": (
            "This release adds deployable infrastructure assets and live runtime signals so "
            "teams can stage, monitor, and scale the API with less guesswork."
        ),
        "highlights": [
            "Added request IDs, structured access/error logs, QPS, throughput, latency, and availability metrics.",
            "Added Prometheus-style /metrics, JSON /v1/metrics/summary, WebSocket health, and polling endpoints.",
            "Added Docker Compose staging, Nginx proxy/cache/rate-limit config, and Kubernetes manifests.",
            "Added GitHub Actions for CI and GHCR container publishing.",
        ],
        "impact": (
            "Best for turning the MVP into something an early B2B buyer can evaluate as an "
            "operated API product, not just a local demo."
        ),
    },
    {
        "version": "0.6.0",
        "date": "2026-06-29",
        "display_date": "June 29, 2026",
        "status": "Health insights",
        "title": "InboxReady now turns dashboard activity into operator priorities.",
        "summary": (
            "This release adds a health insight layer that summarizes recent audits, monitor "
            "coverage, attention domains, and usage headroom inside the dashboard."
        ),
        "highlights": [
            "Added dashboard health insights that combine usage, audit history, and monitor state.",
            "Added an action queue for failed audits, unchecked monitors, and plan-capacity risk.",
            "Added domains-to-watch rows that help operators spot the accounts worth revisiting.",
            "Added responsive styling for the new insight panel across desktop and mobile layouts.",
        ],
        "impact": (
            "Best for support and customer-success teams that need InboxReady to recommend "
            "the next operational move, not just display raw audit results."
        ),
    },
    {
        "version": "0.5.0",
        "date": "2026-06-28",
        "display_date": "June 28, 2026",
        "status": "Visual refresh",
        "title": "InboxReady got a sharper Lovable-inspired product interface.",
        "summary": (
            "This release refreshes the visual system so the product feels more like a "
            "credible SaaS console for operators, support teams, and API buyers."
        ),
        "highlights": [
            "Reworked the palette, shadows, radii, and typography for a cleaner B2B SaaS feel.",
            "Added a landing-page operations strip for monitors, exports, and batch reviews.",
            "Added a dashboard command strip for faster navigation between core operator workflows.",
            "Added a monthly usage meter that makes plan consumption easier to scan.",
        ],
        "impact": (
            "Best for first impressions, demos, and buyers who need the dashboard to feel "
            "trustworthy before they wire InboxReady into customer onboarding."
        ),
    },
    {
        "version": "0.4.0",
        "date": "2026-06-27",
        "display_date": "June 27, 2026",
        "status": "Domain monitors",
        "title": "InboxReady now tracks domains instead of only auditing them once.",
        "summary": (
            "This release adds account-level domain monitors so teams can keep important "
            "customer senders on a watchlist and refresh their readiness when needed."
        ),
        "highlights": [
            "Added monitor create, list, run, and delete endpoints for API customers.",
            "Added dashboard monitor forms with last score, status, checked time, and run-now controls.",
            "Persisted monitor cadence, selectors, expected providers, and latest audit metadata in SQLite.",
            "Connected monitor runs to the existing usage meter and saved audit history.",
        ],
        "impact": (
            "Best for support and success teams that need repeatable follow-up on customer "
            "domains instead of one-off DNS checks."
        ),
    },
    {
        "version": "0.3.0",
        "date": "2026-06-26",
        "display_date": "June 26, 2026",
        "status": "History exports",
        "title": "InboxReady now feels maintained like a product, not a hidden backend.",
        "summary": (
            "This release turns saved audits and product updates into visible operating surfaces "
            "while extending the account workflow for multi-domain reviews."
        ),
        "highlights": [
            "Added a public changelog page, dashboard release card, and landing-page shipping notes.",
            "Extended the dashboard with authenticated batch audits for customer portfolios and shared usage enforcement.",
            "Added CSV export and saved-audit JSON views so teams can inspect or move audit history downstream.",
            "Expanded launch documentation and API metadata so prospects can understand the product state quickly.",
        ],
        "impact": (
            "Best for design partners, support leads, and buyers who want proof that the product is "
            "shipping and getting safer over time."
        ),
    },
    {
        "version": "0.2.0",
        "date": "2026-06-22",
        "display_date": "June 22, 2026",
        "status": "Launch surface",
        "title": "The API grew a real SaaS shell around the audit engine.",
        "summary": (
            "InboxReady moved beyond a single endpoint and added the customer-facing surfaces "
            "needed for onboarding, support, billing, and trust."
        ),
        "highlights": [
            "Added signup, login, session-backed dashboard access, and one-time API key reveal flows.",
            "Introduced usage metering, saved audit history, Stripe hooks, and support/legal pages.",
            "Hardened session security with CSRF protection, secure password handling, and defensive headers.",
        ],
        "impact": (
            "Best for early paying customers who need more than a raw API response before they can deploy."
        ),
    },
    {
        "version": "0.1.0",
        "date": "2026-04-28",
        "display_date": "April 28, 2026",
        "status": "Initial release",
        "title": "Core domain-readiness auditing shipped.",
        "summary": (
            "The initial release established the DNS audit engine and provider detection model "
            "for sender-domain onboarding."
        ),
        "highlights": [
            "Shipped MX, SPF, DMARC, DKIM, BIMI, MTA-STS, and TLS-RPT checks.",
            "Added provider fingerprinting, weighted scoring, and remediation recommendations.",
            "Exposed a clean FastAPI service with versioned endpoints and interactive docs.",
        ],
        "impact": "Best for proving the API wedge before layering on accounts and commercial workflows.",
    },
]

LATEST_CHANGELOG = CHANGELOG_ENTRIES[0]

ROADMAP_ITEMS = [
    {
        "title": "Automated schedule execution",
        "body": (
            "Run stored weekly and monthly monitors without a manual button press, then surface "
            "fresh warnings before support tickets arrive."
        ),
    },
    {
        "title": "Webhook alerts",
        "body": (
            "Push failed or regressed domain states into product workflows, ticketing systems, "
            "or internal ops channels."
        ),
    },
    {
        "title": "Team reporting",
        "body": (
            "Give customer success and deliverability teams shared visibility into accounts, "
            "portfolio trends, and repeated remediation patterns."
        ),
    },
]

SAMPLE_CURL = """curl -X POST https://api.inboxready.dev/v1/audits/email-domain \\
  -H "Authorization: Bearer $INBOXREADY_API_KEY" \\
  -H "Content-Type: application/json" \\
  -d '{
    "domain": "customer-example.com",
    "selectors": ["google", "selector1"],
    "expected_providers": ["Google Workspace"]
  }'"""

SAMPLE_JS = """const response = await fetch("/v1/audits/email-domain", {
  method: "POST",
  headers: {
    "Authorization": `Bearer ${process.env.INBOXREADY_API_KEY}`,
    "Content-Type": "application/json"
  },
  body: JSON.stringify({
    domain: "customer-example.com",
    selectors: ["google", "selector1"]
  })
});

const audit = await response.json();
console.log(audit.score, audit.recommendations);"""
