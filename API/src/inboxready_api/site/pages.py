"""The page registry.

One declaration per public page, and everything else is derived from it:

* the FastAPI route,
* the header and footer navigation,
* breadcrumb trails (and their ``BreadcrumbList`` structured data),
* ``sitemap.xml``,
* the SEO test suite, which asserts titles and descriptions are present,
  unique, and correctly sized.

Adding a page means adding a :class:`Page` here. Forgetting a title or reusing
a description fails the test suite rather than silently shipping.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from inboxready_api.site.content import CASE_STUDIES

#: Google truncates page titles beyond roughly this many characters, before the
#: site-name suffix is appended.
TITLE_MAX = 60
#: Practical bounds for a meta description that survives a SERP snippet.
DESCRIPTION_MIN = 70
DESCRIPTION_MAX = 165


@dataclass(frozen=True)
class Page:
    """A single indexable HTML page."""

    path: str
    template: str
    title: str
    description: str
    #: Label used in navigation. ``None`` keeps the page out of the menus.
    nav_label: str | None = None
    #: Which menu the page belongs to: ``"primary"`` or a footer column name.
    nav_group: str | None = None
    #: Parent page path, used to build the breadcrumb trail.
    parent: str | None = None
    #: Short label for the breadcrumb itself (defaults to ``nav_label``/title).
    crumb: str | None = None
    priority: float = 0.5
    changefreq: str = "monthly"
    noindex: bool = False
    og_type: str = "website"
    #: Identifies the record a detail template should render (e.g. a case study).
    context_key: str | None = None
    extra: dict[str, str] = field(default_factory=dict)

    @property
    def breadcrumb_label(self) -> str:
        return self.crumb or self.nav_label or self.title


HOME = Page(
    path="/",
    template="index.html",
    title="Email domain readiness API",
    description=(
        "Audit MX, SPF, DKIM, DMARC, MTA-STS, TLS-RPT, and BIMI in one API call and get "
        "back a weighted score plus the exact DNS records your customer needs to fix."
    ),
    nav_label="Home",
    priority=1.0,
    changefreq="weekly",
    crumb="Home",
)

STATIC_PAGES: tuple[Page, ...] = (
    HOME,
    Page(
        path="/product",
        template="product.html",
        title="What InboxReady checks",
        description=(
            "A check-by-check tour of the InboxReady audit: mail routing, authentication, "
            "transport hardening, provider fingerprinting, and how the score is weighted."
        ),
        nav_label="Product",
        nav_group="primary",
        parent="/",
        priority=0.9,
    ),
    Page(
        path="/case-studies",
        template="case_studies.html",
        title="Case studies",
        description=(
            "Three worked scenarios showing how teams wire domain audits into activation "
            "flows, support triage, and ongoing monitoring of a portfolio of domains."
        ),
        nav_label="Case studies",
        nav_group="primary",
        parent="/",
        priority=0.8,
    ),
    Page(
        path="/dmarc-reports",
        template="dmarc_reports.html",
        title="Read your DMARC reports",
        description=(
            "Upload the aggregate reports mailbox providers send you and find out who is "
            "sending as your domain, what authenticates, and whether p=reject is safe yet."
        ),
        nav_label="DMARC reports",
        nav_group="primary",
        parent="/product",
        crumb="DMARC reports",
        priority=0.8,
    ),
    Page(
        path="/pricing",
        template="pricing.html",
        title="Pricing and plans",
        description=(
            "Starter, Growth, and Pro plans for embedding domain audits in your product, "
            "with monthly audit allowances, overage behaviour, and the support included."
        ),
        nav_label="Pricing",
        nav_group="primary",
        parent="/",
        priority=0.9,
    ),
    Page(
        path="/faq",
        template="faq.html",
        title="Frequently asked questions",
        description=(
            "What the audit actually checks, how long integration takes, what data is "
            "stored, how fast support replies, and what happens when you exceed a plan."
        ),
        nav_label="FAQ",
        nav_group="primary",
        parent="/",
        priority=0.7,
    ),
    Page(
        path="/about",
        template="about.html",
        title="About InboxReady",
        description=(
            "Who builds InboxReady, why the product is deliberately narrow, and how the "
            "team works with the customers who embed the audit in their onboarding."
        ),
        nav_label="About",
        nav_group="Company",
        parent="/",
        priority=0.6,
    ),
    Page(
        path="/contact",
        template="contact.html",
        title="Contact and directions",
        description=(
            "Reach the InboxReady team, read our first-response promise, and find where "
            "we are based, with directions for anyone visiting Melbourne in person."
        ),
        nav_label="Contact",
        nav_group="Company",
        parent="/",
        priority=0.7,
    ),
    Page(
        path="/app",
        template="app.html",
        title="Live audit workspace",
        description=(
            "Run a live email-domain audit in the browser: enter a domain, review every "
            "check and recommendation, and inspect the raw JSON that the API returns."
        ),
        nav_label="Workspace",
        nav_group="Product",
        parent="/",
        priority=0.9,
        changefreq="weekly",
    ),
    Page(
        path="/privacy",
        template="privacy.html",
        title="Privacy policy",
        description=(
            "What InboxReady collects when you audit a domain or contact us, the lawful "
            "basis for holding it, how long it is kept, and how to have it deleted."
        ),
        nav_label="Privacy",
        nav_group="Legal",
        parent="/",
        priority=0.4,
        changefreq="yearly",
    ),
    Page(
        path="/terms",
        template="terms.html",
        title="Terms of service",
        description=(
            "The terms covering acceptable use of the InboxReady API, fair-use limits, "
            "billing and overages, availability expectations, and limits on liability."
        ),
        nav_label="Terms",
        nav_group="Legal",
        parent="/",
        priority=0.3,
        changefreq="yearly",
    ),
    Page(
        path="/security",
        template="security.html",
        title="Security and disclosure",
        description=(
            "How InboxReady is hardened, what an audit does and does not touch on your "
            "network, and how to report a vulnerability to us responsibly."
        ),
        nav_label="Security",
        nav_group="Legal",
        parent="/",
        priority=0.4,
        changefreq="yearly",
    ),
    Page(
        path="/thank-you",
        template="thank_you.html",
        title="Thanks — message received",
        description=(
            "Your message reached the InboxReady team. Here is when to expect a reply, "
            "and what is worth reading or trying in the meantime while you wait."
        ),
        noindex=True,
        parent="/contact",
        crumb="Thank you",
        priority=0.1,
    ),
)


def _case_study_pages() -> tuple[Page, ...]:
    return tuple(
        Page(
            path=study.path,
            template="case_study.html",
            title=study.title,
            description=study.summary,
            parent="/case-studies",
            crumb=study.segment,
            priority=0.6,
            og_type="article",
            context_key=study.slug,
        )
        for study in CASE_STUDIES
    )


CASE_STUDY_PAGES: tuple[Page, ...] = _case_study_pages()

ALL_PAGES: tuple[Page, ...] = STATIC_PAGES + CASE_STUDY_PAGES

PAGES_BY_PATH: dict[str, Page] = {page.path: page for page in ALL_PAGES}


def get_page(path: str) -> Page:
    """Return the registered page for ``path``.

    Raises :class:`KeyError` for unknown paths, so a typo in a route surfaces in
    tests rather than as a blank ``<title>`` in production.
    """
    return PAGES_BY_PATH[path]


def indexable_pages() -> tuple[Page, ...]:
    return tuple(page for page in ALL_PAGES if not page.noindex)


def primary_nav() -> tuple[Page, ...]:
    return tuple(page for page in ALL_PAGES if page.nav_group == "primary")


FOOTER_COLUMNS: tuple[str, ...] = ("Product", "Company", "Legal")


def footer_nav() -> dict[str, list[Page]]:
    """Footer link columns. Primary-nav pages are repeated under *Product*."""
    columns: dict[str, list[Page]] = {name: [] for name in FOOTER_COLUMNS}
    for page in ALL_PAGES:
        if page.nav_group in columns:
            columns[page.nav_group].append(page)
    for page in primary_nav():
        columns["Product"].append(page)
    return columns


def breadcrumbs(page: Page) -> list[Page]:
    """Return the ancestor chain for ``page``, root first, including ``page``."""
    trail: list[Page] = []
    seen: set[str] = set()
    current: Page | None = page
    while current is not None and current.path not in seen:
        trail.append(current)
        seen.add(current.path)
        current = PAGES_BY_PATH.get(current.parent) if current.parent else None
    trail.reverse()
    return trail
