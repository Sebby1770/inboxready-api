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
            "in the launch layer. Scheduled re-checks, webhook alerts, and branded remediation "
            "guides are the next retention features."
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
