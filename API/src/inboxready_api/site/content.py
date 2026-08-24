"""Editable business content for the public site.

Everything a non-engineer would want to change lives here as plain data. The
templates never hard-code copy, so updating this module updates the site, the
structured data, the sitemap descriptions, and the tests that guard them.

Three placeholder-aware collections deserve a note:

* :data:`TEAM` ships with ``placeholder=True`` entries. Real photos and names
  belong to real people, so the repository ships slots rather than invented
  colleagues. Placeholder members are rendered with a visible badge and are
  deliberately excluded from ``Person`` structured data.
* :data:`REVIEWS` ships **empty**. Publishing invented testimonials — or
  ``AggregateRating`` markup with no ratings behind it — is both dishonest and
  a Google structured-data violation. Add real, attributable reviews and the
  section plus its schema light up automatically.
* :data:`CASE_STUDIES` are labelled *illustrative scenarios*. They describe the
  workflow honestly without claiming a named customer.
"""

from __future__ import annotations

from dataclasses import dataclass

# ---------------------------------------------------------------------------
# Organisation profile — powers Organization + LocalBusiness structured data,
# the contact page, the map, and the footer.
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class PostalAddress:
    """A postal address. Street level is optional for remote-first companies."""

    locality: str
    region: str
    country: str
    country_code: str
    street: str = ""
    postal_code: str = ""

    @property
    def single_line(self) -> str:
        parts = [self.street, self.locality, self.region, self.postal_code, self.country]
        return ", ".join(part for part in parts if part)

    @property
    def map_query(self) -> str:
        return self.single_line


@dataclass(frozen=True)
class GeoPoint:
    latitude: float
    longitude: float


@dataclass(frozen=True)
class Organisation:
    name: str
    legal_name: str
    tagline: str
    description: str
    email: str
    address: PostalAddress
    geo: GeoPoint
    service_area: str
    founded: str
    opening_hours: tuple[str, ...]
    timezone: str
    social_profiles: tuple[str, ...]
    repository: str
    logo_path: str = "img/favicon.svg"


ORG = Organisation(
    name="InboxReady",
    legal_name="InboxReady",
    tagline="Domain readiness for sender-facing SaaS",
    description=(
        "InboxReady audits whether a customer-owned domain is ready to send trustworthy "
        "email. One API call checks MX, SPF, DKIM, DMARC, MTA-STS, TLS-RPT, and BIMI, "
        "then returns a weighted score with the exact DNS records to fix."
    ),
    email="hello@inboxready.dev",
    address=PostalAddress(
        locality="Melbourne",
        region="Victoria",
        country="Australia",
        country_code="AU",
    ),
    geo=GeoPoint(latitude=-37.8136, longitude=144.9631),
    service_area="Worldwide — remote-first, with an Australian home base.",
    founded="2026",
    opening_hours=("Mo-Fr 09:00-17:00",),
    timezone="Australia/Melbourne",
    social_profiles=("https://github.com/Sebby1770/inboxready-api",),
    repository="https://github.com/Sebby1770/inboxready-api",
)


# ---------------------------------------------------------------------------
# Response-time promise (checklist item 08)
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class ResponsePromise:
    hours: int
    channel: str
    business_days: str
    escalation: str

    @property
    def headline(self) -> str:
        if self.hours <= 1:
            return "We reply within the hour"
        if self.hours % 24 == 0 and self.hours >= 24:
            days = self.hours // 24
            unit = "business day" if days == 1 else "business days"
            return f"We reply within {days} {unit}"
        return f"We reply within {self.hours} hours"


def response_promise(hours: int = 24) -> ResponsePromise:
    return ResponsePromise(
        hours=hours,
        channel=ORG.email,
        business_days="Monday to Friday, 09:00–17:00 " + ORG.timezone.split("/")[-1].replace("_", " ") + " time",
        escalation=(
            "Anything that looks like an outage is triaged first. "
            "Check /healthz and /readyz before writing in — they answer instantly."
        ),
    )


# ---------------------------------------------------------------------------
# Team (checklist item 20)
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class TeamMember:
    name: str
    role: str
    bio: str
    photo: str
    photo_alt: str
    placeholder: bool = False
    profile_url: str = ""


TEAM: tuple[TeamMember, ...] = (
    TeamMember(
        name="Add your name",
        role="Founder / engineering",
        bio=(
            "Replace this slot in site/content.py with a real person and a real "
            "photograph. Buyers trust a face and a name far more than a logo."
        ),
        photo="img/team/placeholder-1.svg",
        photo_alt="Placeholder portrait illustration for an unfilled team profile",
        placeholder=True,
    ),
    TeamMember(
        name="Add a teammate",
        role="Deliverability / support",
        bio=(
            "A named support owner is the cheapest trust signal on a B2B site. "
            "Pair the photo with the response-time promise below it."
        ),
        photo="img/team/placeholder-2.svg",
        photo_alt="Placeholder portrait illustration for an unfilled team profile",
        placeholder=True,
    ),
    TeamMember(
        name="Add an advisor",
        role="Advisor",
        bio=(
            "Advisors and contractors count. List who a customer would actually "
            "meet during onboarding or an incident."
        ),
        photo="img/team/placeholder-3.svg",
        photo_alt="Placeholder portrait illustration for an unfilled team profile",
        placeholder=True,
    ),
)

TEAM_PHOTO = {
    "src": "img/team/team-photo.svg",
    "alt": (
        "Illustrated placeholder for a team group photograph, showing three "
        "abstract figures in front of the InboxReady wordmark"
    ),
    "caption": (
        "Placeholder group photo — swap in a real one. A single candid shot of "
        "the people behind the API outperforms stock photography every time."
    ),
    "placeholder": True,
}


# ---------------------------------------------------------------------------
# Reviews (checklist item 15) — intentionally empty. See the module docstring.
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class Review:
    author: str
    author_title: str
    rating: int
    body: str
    published: str
    source: str = ""
    source_url: str = ""


REVIEWS: tuple[Review, ...] = ()


@dataclass(frozen=True)
class TrustSignal:
    label: str
    detail: str
    href: str = ""


#: Shown wherever reviews would go until real reviews exist. Every entry is
#: independently checkable by the reader, which is the point.
TRUST_SIGNALS: tuple[TrustSignal, ...] = (
    TrustSignal(
        label="Source available",
        detail="Every check, weight, and remediation string is readable in the repository.",
        href=ORG.repository,
    ),
    TrustSignal(
        label="Audited against public specs",
        detail="Scoring follows RFC 7208 (SPF), RFC 7489 (DMARC), and current bulk-sender guidance.",
        href="https://datatracker.ietf.org/doc/html/rfc7489",
    ),
    TrustSignal(
        label="No customer DNS data retained",
        detail="Audits run in-process; history is opt-in and stays on your own instance.",
        href="/privacy",
    ),
    TrustSignal(
        label="Health you can verify yourself",
        detail="Liveness and readiness probes are public — no status-page theatre.",
        href="/healthz",
    ),
)


def has_reviews() -> bool:
    return bool(REVIEWS)


def average_rating() -> float | None:
    if not REVIEWS:
        return None
    return round(sum(review.rating for review in REVIEWS) / len(REVIEWS), 2)


# ---------------------------------------------------------------------------
# Case studies (checklist item 06)
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class CaseStudyMetric:
    value: str
    label: str


@dataclass(frozen=True)
class CaseStudy:
    slug: str
    title: str
    summary: str
    segment: str
    illustrative: bool
    challenge: str
    approach: tuple[str, ...]
    outcome: str
    metrics: tuple[CaseStudyMetric, ...]
    integration: str
    read_minutes: int = 4

    @property
    def path(self) -> str:
        return f"/case-studies/{self.slug}"


CASE_STUDIES: tuple[CaseStudy, ...] = (
    CaseStudy(
        slug="onboarding-activation",
        title="Cutting DNS back-and-forth out of self-serve activation",
        summary=(
            "How a sender-facing SaaS turns a blocking DNS step into a guided, "
            "self-correcting part of its signup flow."
        ),
        segment="B2B SaaS onboarding",
        illustrative=True,
        challenge=(
            "Customers sign up, hit 'send from your own domain', and stall. The product "
            "shows a documentation link; the customer pastes records into the wrong zone; "
            "support inherits a ticket that is really a DNS question. Activation drags on "
            "for days and the account never reaches the aha moment."
        ),
        approach=(
            "Call POST /v1/audits/email-domain the moment the customer types their domain.",
            "Render the returned checks inline instead of linking to docs — each failing "
            "check already carries its own remediation string.",
            "Use detected providers to narrow the instructions to that registrar or ESP.",
            "Re-run the audit on a timer while the customer is still in the wizard, and "
            "unblock the step automatically once the score clears your threshold.",
        ),
        outcome=(
            "The DNS step becomes self-service. The customer sees exactly which record is "
            "missing, fixes it, and the wizard advances without a human touching it."
        ),
        metrics=(
            CaseStudyMetric(value="7 checks", label="run per activation attempt"),
            CaseStudyMetric(value="1 call", label="replaces the documentation hand-off"),
            CaseStudyMetric(value="&lt;5 min", label="typical integration effort"),
        ),
        integration=(
            'const audit = await fetch("/v1/audits/email-domain", {\n'
            '  method: "POST",\n'
            '  headers: { "Content-Type": "application/json" },\n'
            '  body: JSON.stringify({ domain })\n'
            "}).then((r) => r.json());\n"
            "\n"
            "if (audit.score >= 80) unlockSendingStep();\n"
            "else showChecklist(audit.recommendations);"
        ),
    ),
    CaseStudy(
        slug="support-triage",
        title="Giving support an answer before engineering gets paged",
        summary=(
            "How a support team replaces 'it looks like a DNS thing' with a scored, "
            "shareable report attached to the ticket."
        ),
        segment="Support and customer success",
        illustrative=True,
        challenge=(
            "Every deliverability complaint looks the same from the outside: mail is not "
            "arriving. Support has no way to tell a missing DKIM selector from a DMARC "
            "policy that quarantines the customer's own traffic, so everything escalates."
        ),
        approach=(
            "Fetch GET /v1/audit/{domain}/report.md and paste the markdown straight into "
            "the ticket — it renders in every helpdesk.",
            "Use ?format=html when the report goes to the customer instead of the queue.",
            "Compare the failing domain against a known-good one with POST /v1/compare to "
            "isolate the single differing check.",
            "Escalate only when the audit passes and mail still fails — that is a genuine "
            "engineering problem.",
        ),
        outcome=(
            "Tickets arrive at engineering with evidence attached, and most never arrive "
            "at all because the report told the customer what to change."
        ),
        metrics=(
            CaseStudyMetric(value="Markdown", label="reports paste into any helpdesk"),
            CaseStudyMetric(value="Side-by-side", label="compare isolates the broken check"),
            CaseStudyMetric(value="Cached", label="repeat lookups do not re-hit DNS"),
        ),
        integration=(
            "curl -H \"X-API-Key: $INBOXREADY_API_KEY\" \\\n"
            "  https://api.inboxready.dev/v1/audit/customer-example.com/report.md"
        ),
    ),
    CaseStudy(
        slug="portfolio-monitoring",
        title="Watching a portfolio of customer domains for silent drift",
        summary=(
            "How an agency or platform keeps hundreds of managed domains from quietly "
            "losing their authentication posture."
        ),
        segment="Agencies, platforms, and MSPs",
        illustrative=True,
        challenge=(
            "Domains are configured correctly once, at onboarding, and then drift. A "
            "registrar migration drops the DMARC record; someone flattens SPF and breaks "
            "an include; a rebrand replaces the DKIM CNAMEs. Nobody notices until a "
            "campaign lands in spam."
        ),
        approach=(
            "Batch up to 25 domains per call with POST /v1/audits/batch on a schedule.",
            "Persist results by setting INBOXREADY_HISTORY_PATH so scores are comparable "
            "week over week.",
            "Point INBOXREADY_WEBHOOK_URL at your alerting channel with a score floor.",
            "Export GET /v1/history/export.csv into whatever the account team already reads.",
        ),
        outcome=(
            "Regressions surface as an alert with a domain and a score, days before a "
            "customer notices their open rate falling."
        ),
        metrics=(
            CaseStudyMetric(value="25 domains", label="per batch request, run concurrently"),
            CaseStudyMetric(value="Webhook", label="fires below your score floor"),
            CaseStudyMetric(value="CSV", label="history exports into existing reporting"),
        ),
        integration=(
            "curl -X POST https://api.inboxready.dev/v1/audits/batch \\\n"
            '  -H "Content-Type: application/json" \\\n'
            '  -d \'{"domains": ["a.com", "b.com", "c.com"]}\''
        ),
    ),
)


def case_study_by_slug(slug: str) -> CaseStudy | None:
    for study in CASE_STUDIES:
        if study.slug == slug:
            return study
    return None


# ---------------------------------------------------------------------------
# FAQ (checklist item 07 — five minimum)
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class Faq:
    question: str
    answer: str
    category: str = "General"


FAQS: tuple[Faq, ...] = (
    Faq(
        category="Product",
        question="What exactly does an audit check?",
        answer=(
            "MX routing, SPF (including syntax and lookup pressure), DKIM for the selectors "
            "you supply, DMARC policy and alignment, MTA-STS, TLS-RPT, and BIMI. Each check "
            "returns a pass, warn, fail, or info status with its own remediation text, and "
            "the checks roll up into a single weighted score out of 100."
        ),
    ),
    Faq(
        category="Product",
        question="Is this a full DMARC analytics platform?",
        answer=(
            "No, and that is deliberate. Aggregate-report processing is a different, heavier "
            "product. InboxReady answers the question that blocks activation today: is this "
            "domain configured correctly right now, and if not, what record is missing?"
        ),
    ),
    Faq(
        category="Integration",
        question="How long does it take to integrate?",
        answer=(
            "One POST and a score comparison — most teams have the audit rendering in their "
            "onboarding wizard inside an afternoon. The response is deliberately flat and "
            "machine-readable so you can drive UI decisions straight from it."
        ),
    ),
    Faq(
        category="Integration",
        question="Do I need an API key to try it?",
        answer=(
            "Not locally. Leave INBOXREADY_API_KEYS empty and the instance is open for "
            "development. In production, set the key list — the X-API-Key header then becomes "
            "mandatory on every /v1 route and drives per-key rate limiting."
        ),
    ),
    Faq(
        category="Data",
        question="What do you store about the domains I audit?",
        answer=(
            "By default, nothing leaves the process. Audit history is in-memory unless you set "
            "INBOXREADY_HISTORY_PATH, in which case it is written to a file on your own "
            "instance. There is no third-party analytics on API responses. See the privacy "
            "policy for the full picture."
        ),
    ),
    Faq(
        category="Data",
        question="Does an audit send email or touch my customers?",
        answer=(
            "No. Every check is a public DNS lookup plus, for MTA-STS and BIMI, a fetch of a "
            "policy file the domain owner published deliberately. Nothing is delivered to a "
            "mailbox and no mail flow is affected."
        ),
    ),
    Faq(
        category="Support",
        question="How fast will someone answer me?",
        answer=(
            "Within one business day, Monday to Friday, Melbourne time. Suspected outages jump "
            "the queue — and /healthz and /readyz will tell you instantly whether the service "
            "itself is the problem."
        ),
    ),
    Faq(
        category="Pricing",
        question="What happens if I go over my plan's audit volume?",
        answer=(
            "Nothing breaks mid-month. Overage is billed at the plan's rate rather than being "
            "hard-stopped, because an audit usually fires at the exact moment a customer is "
            "trying to activate — a 402 there costs you far more than the overage does."
        ),
    ),
)


def faqs_for_schema(limit: int = 8) -> tuple[Faq, ...]:
    return FAQS[:limit]
