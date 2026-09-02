"""FastAPI routes for the public site.

Every HTML page is served through :func:`render_page`, so the SEO head, the
navigation, the breadcrumb trail, the structured data, and the analytics gate
are impossible to forget on a new page — you get them by registering a
:class:`~inboxready_api.site.pages.Page`.
"""

from __future__ import annotations

from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from fastapi import APIRouter, Form, Request
from fastapi.responses import HTMLResponse, PlainTextResponse, RedirectResponse, Response
from fastapi.templating import Jinja2Templates

from inboxready_api import __version__
from inboxready_api.services.provider_detection import get_provider_catalog
from inboxready_api.settings import get_settings
from inboxready_api.site import content, seo
from inboxready_api.site.leads import LeadValidationError, get_leads, validate
from inboxready_api.site.pages import (
    ALL_PAGES,
    STATIC_PAGES,
    Page,
    breadcrumbs,
    footer_nav,
    get_page,
    primary_nav,
)
from inboxready_api.site_content import (
    FLOW_STEPS,
    HERO_METRICS,
    PRICING_TIERS,
    SAMPLE_CURL,
    SAMPLE_JS,
    SIGNAL_STRIPS,
    USE_CASES,
)

TEMPLATE_DIR = Path(__file__).resolve().parent.parent / "templates"
templates = Jinja2Templates(directory=str(TEMPLATE_DIR))

router = APIRouter(include_in_schema=False)

#: Pages that must never be cached by a shared proxy.
_PRIVATE_PAGES = {"/thank-you"}


def _now_iso_date() -> str:
    return datetime.now(UTC).date().isoformat()


def _trust_signals(static_build: bool) -> tuple[content.TrustSignal, ...]:
    """Only advertise proof the current deployment can actually serve.

    The live health probes are a genuine trust signal on a running instance and
    a dead link on a static mirror, so the static build simply does not make
    the claim.
    """
    if not static_build:
        return content.TRUST_SIGNALS
    return tuple(
        signal
        for signal in content.TRUST_SIGNALS
        if not signal.href.startswith(("/healthz", "/readyz"))
    )


def base_context(request: Request, page: Page) -> dict[str, Any]:
    """Context shared by every page: nav, SEO head, structured data, analytics."""
    settings = get_settings()
    origin = seo.site_origin(settings, str(request.base_url))
    trail = breadcrumbs(page)

    return {
        "request": request,
        "page": page,
        "version": __version__,
        "org": content.ORG,
        "promise": content.response_promise(settings.support_response_hours),
        "page_title": page.title,
        "page_description": page.description,
        "canonical_url": seo.absolute_url(origin, page.path),
        "origin": origin,
        "robots_content": "noindex, nofollow" if page.noindex or not settings.is_production else "index, follow",
        "social_meta": seo.social_meta(origin, page),
        "json_ld": seo.build_json_ld(origin, page, __version__),
        "breadcrumb_trail": trail if len(trail) > 1 else [],
        "primary_nav": primary_nav(),
        "footer_nav": footer_nav(),
        "static_build": settings.static_build,
        "api_base_url": settings.api_base_url,
        "docs_url": "/docs/" if settings.static_build else "/docs",
        "repository_url": content.ORG.repository,
        "analytics_id": settings.analytics_ga4_id.strip(),
        "analytics_require_consent": settings.analytics_require_consent,
        "current_year": datetime.now(UTC).year,
        "directions_url": seo.directions_url(),
        "apple_maps_url": seo.apple_maps_url(),
        "map_view_url": seo.map_view_url(),
        "trust_signals": _trust_signals(settings.static_build),
        "reviews": content.REVIEWS,
        "has_reviews": content.has_reviews(),
        "faqs": content.FAQS,
        "case_studies": content.CASE_STUDIES,
    }


# --- per-page context ------------------------------------------------------


def _home_context(request: Request) -> dict[str, Any]:
    return {
        "hero_metrics": HERO_METRICS,
        "signal_strips": SIGNAL_STRIPS,
        "use_cases": USE_CASES,
        "flow_steps": FLOW_STEPS,
        "pricing_tiers": PRICING_TIERS,
        "sample_curl": SAMPLE_CURL,
        "sample_js": SAMPLE_JS,
        "featured_faqs": content.FAQS[:5],
        "featured_case_studies": content.CASE_STUDIES,
    }


def _product_context(request: Request) -> dict[str, Any]:
    return {
        "signal_strips": SIGNAL_STRIPS,
        "use_cases": USE_CASES,
        "flow_steps": FLOW_STEPS,
        "sample_curl": SAMPLE_CURL,
        "sample_js": SAMPLE_JS,
        "provider_catalog": get_provider_catalog(),
        "checks": CHECK_REFERENCE,
    }


#: The four shapes a sending source can take, mirroring
#: :data:`inboxready_api.services.dmarc_reports.CLASSIFICATIONS`.
SOURCE_CLASSES: tuple[dict[str, str], ...] = (
    {
        "key": "authenticated",
        "name": "Authenticated",
        "shape": "Aligned DKIM and aligned SPF both pass.",
        "detail": "Your own infrastructure, correctly set up. Nothing to do.",
    },
    {
        "key": "forwarded",
        "name": "Forwarded",
        "shape": "Aligned DKIM passes, SPF fails.",
        "detail": (
            "A mailing list or forwarder rewrote the envelope. The signature survived, so this "
            "already passes DMARC and will keep passing after you enforce."
        ),
    },
    {
        "key": "spf-only",
        "name": "SPF-only",
        "shape": "Aligned SPF passes, no aligned DKIM signature.",
        "detail": (
            "Passes today and breaks the first time a message is forwarded. Add DKIM signing "
            "for this sender before tightening policy."
        ),
    },
    {
        "key": "unauthenticated",
        "name": "Unauthenticated",
        "shape": "Neither aligned mechanism passes.",
        "detail": (
            "Either a legitimate sender nobody authorised, or someone else sending as you. "
            "With real volume behind it, this is what blocks a rollout."
        ),
    },
)

SAMPLE_DMARC_CLI = """\
$ inboxready dmarc-reports reports/*.xml.gz
DMARC aggregate reports for example.com
  window        2026-01-01 to 2026-01-07
  messages      48,210
  aligned pass  98.4% (DKIM 97.9%, SPF 91.2%)

NOT READY to leave p=none
  - 1 source still fails DMARC with volume: 203.0.113.9 (742 msg)
$ echo $?
1"""


def _dmarc_reports_context(request: Request) -> dict[str, Any]:
    from inboxready_api.services import dmarc_reports

    return {
        "classifications": SOURCE_CLASSES,
        "sample_cli": SAMPLE_DMARC_CLI,
        "quarantine_threshold": f"{dmarc_reports.QUARANTINE_READY_RATE:.0%}",
        "reject_threshold": f"{dmarc_reports.REJECT_READY_RATE:.0%}",
        "blocker_share": f"{dmarc_reports.BLOCKER_MIN_SHARE:.1%}",
    }


def _pricing_context(request: Request) -> dict[str, Any]:
    return {"pricing_tiers": PRICING_TIERS, "featured_faqs": content.FAQS[-3:]}


def _about_context(request: Request) -> dict[str, Any]:
    return {"team": content.TEAM, "team_photo": content.TEAM_PHOTO}


def _contact_context(request: Request) -> dict[str, Any]:
    return {"topics": CONTACT_TOPICS, "form_error": request.query_params.get("error", "")}


def _app_context(request: Request) -> dict[str, Any]:
    return {"provider_catalog": get_provider_catalog()}


def _legal_context(request: Request) -> dict[str, Any]:
    return {"last_updated": "24 August 2026"}


CONTEXT_BUILDERS: dict[str, Callable[[Request], dict[str, Any]]] = {
    "/": _home_context,
    "/product": _product_context,
    "/dmarc-reports": _dmarc_reports_context,
    "/pricing": _pricing_context,
    "/about": _about_context,
    "/contact": _contact_context,
    "/app": _app_context,
    "/privacy": _legal_context,
    "/terms": _legal_context,
    "/security": _legal_context,
}

CONTACT_TOPICS: tuple[str, ...] = (
    "Product question",
    "Pricing or plans",
    "Integration help",
    "Security or privacy",
    "Something is broken",
)

#: Human-readable reference for the /product page, mirroring the audit engine.
CHECK_REFERENCE: tuple[dict[str, str], ...] = (
    {
        "key": "mx",
        "name": "MX routing",
        "question": "Can anyone deliver mail to this domain at all?",
        "detail": (
            "Resolves the MX record set and reports the hosts in preference order. "
            "A domain with no MX cannot receive replies, bounces, or DMARC reports."
        ),
    },
    {
        "key": "spf",
        "name": "SPF",
        "question": "Which servers are allowed to send as this domain?",
        "detail": (
            "Parses the TXT policy, flags multiple conflicting records, a soft "
            "~all where -all was intended, and include chains pushing the ten-lookup limit."
        ),
    },
    {
        "key": "dkim",
        "name": "DKIM",
        "question": "Is outbound mail cryptographically signed?",
        "detail": (
            "Looks up each selector you supply at selector._domainkey and reports "
            "which ones publish a usable public key."
        ),
    },
    {
        "key": "dmarc",
        "name": "DMARC",
        "question": "What should a receiver do when authentication fails?",
        "detail": (
            "Reads _dmarc, reports the policy, and warns when it is still parked "
            "at p=none — monitoring is not enforcement."
        ),
    },
    {
        "key": "mta_sts",
        "name": "MTA-STS",
        "question": "Is TLS enforced for inbound mail?",
        "detail": (
            "Checks the _mta-sts TXT record and fetches the published policy file "
            "over HTTPS to confirm the mode and the MX list agree."
        ),
    },
    {
        "key": "tls_rpt",
        "name": "TLS-RPT",
        "question": "Will you hear about TLS failures?",
        "detail": "Confirms _smtp._tls publishes a reporting destination so downgrade attempts surface.",
    },
    {
        "key": "bimi",
        "name": "BIMI",
        "question": "Is the brand logo eligible to appear in the inbox?",
        "detail": (
            "Checks the default._bimi record and its logo and certificate "
            "references. Informational — BIMI needs enforcing DMARC first."
        ),
    },
)


def render_page(
    request: Request,
    page: Page,
    *,
    extra: dict[str, Any] | None = None,
    status_code: int = 200,
) -> HTMLResponse:
    context = base_context(request, page)
    builder = CONTEXT_BUILDERS.get(page.path)
    if builder is not None:
        context.update(builder(request))
    if extra:
        context.update(extra)

    response = templates.TemplateResponse(
        request=request,
        name=page.template,
        context=context,
        status_code=status_code,
    )
    if page.path in _PRIVATE_PAGES or page.noindex:
        response.headers["Cache-Control"] = "no-store"
    else:
        response.headers["Cache-Control"] = "public, max-age=300, stale-while-revalidate=86400"
    return response


def _register_static_pages() -> None:
    for page in STATIC_PAGES:
        def handler(request: Request, _page: Page = page) -> HTMLResponse:
            return render_page(request, _page)

        router.add_api_route(
            page.path,
            handler,
            methods=["GET"],
            response_class=HTMLResponse,
            name=f"page:{page.path}",
            include_in_schema=False,
        )


_register_static_pages()


@router.get("/case-studies/{slug}", response_class=HTMLResponse)
def case_study_detail(request: Request, slug: str) -> Response:
    study = content.case_study_by_slug(slug)
    if study is None:
        return render_not_found(request)
    page = get_page(study.path)
    others = [item for item in content.CASE_STUDIES if item.slug != slug]
    return render_page(request, page, extra={"study": study, "other_studies": others})


# --- contact form ----------------------------------------------------------


@router.post("/contact")
async def submit_contact(
    request: Request,
    name: str = Form(default=""),
    email: str = Form(default=""),
    company: str = Form(default=""),
    topic: str = Form(default="General"),
    message: str = Form(default=""),
    website: str = Form(default=""),
) -> Response:
    """Accept the contact form and redirect to the thank-you page.

    ``website`` is a honeypot: it is hidden from humans, so anything in it is a
    bot. Bots are answered with the same redirect a human gets — a visible
    rejection just teaches the crawler to try again.
    """
    if website.strip():
        return RedirectResponse(url="/thank-you?ref=contact", status_code=303)

    try:
        lead = validate(name=name, email=email, company=company, topic=topic, message=message)
    except LeadValidationError as exc:
        page = get_page("/contact")
        return render_page(
            request,
            page,
            extra={
                "form_error": str(exc),
                "form_values": {
                    "name": name,
                    "email": email,
                    "company": company,
                    "topic": topic,
                    "message": message,
                },
            },
            status_code=400,
        )

    get_leads().add(lead)
    return RedirectResponse(url="/thank-you?ref=contact", status_code=303)


# --- crawler surfaces ------------------------------------------------------


@router.get("/robots.txt", response_class=PlainTextResponse)
def robots(request: Request) -> PlainTextResponse:
    settings = get_settings()
    origin = seo.site_origin(settings, str(request.base_url))
    return PlainTextResponse(
        content=seo.robots_txt(origin, indexable=settings.is_production),
        media_type="text/plain; charset=utf-8",
        headers={"Cache-Control": "public, max-age=3600"},
    )


@router.get("/sitemap.xml")
def sitemap(request: Request) -> Response:
    settings = get_settings()
    origin = seo.site_origin(settings, str(request.base_url))
    return Response(
        content=seo.sitemap_xml(origin, _now_iso_date()),
        media_type="application/xml",
        headers={"Cache-Control": "public, max-age=3600"},
    )


@router.get("/site/pages")
def site_pages() -> dict[str, Any]:
    """Machine-readable page inventory — handy for link checkers and audits."""
    return {
        "count": len(ALL_PAGES),
        "pages": [
            {
                "path": page.path,
                "title": page.title,
                "description": page.description,
                "indexable": not page.noindex,
                "parent": page.parent,
            }
            for page in ALL_PAGES
        ],
    }


# --- error pages -----------------------------------------------------------


def render_not_found(request: Request, status_code: int = 404) -> HTMLResponse:
    """The custom 404 (checklist item 01).

    It is a wayfinding page, not an apology: the most-wanted destinations, a
    domain input so a mistyped URL can still become an audit, and a link to
    contact if the page really should exist.
    """
    page = Page(
        path=request.url.path,
        template="error.html",
        title="Page not found",
        description=(
            "That page does not exist. Here are the pages people usually want, plus "
            "a shortcut straight into a live domain audit."
        ),
        parent="/",
        crumb="Not found",
        noindex=True,
    )
    return render_page(
        request,
        page,
        extra={
            "error_code": status_code,
            "error_title": "We could not find that page",
            "error_body": (
                "The link may be out of date, or the address may have a typo. "
                "Everything below still works."
            ),
            "attempted_path": request.url.path,
        },
        status_code=status_code,
    )


def render_server_error(request: Request) -> HTMLResponse:
    page = Page(
        path=request.url.path,
        template="error.html",
        title="Something went wrong",
        description="An unexpected error occurred while rendering this page.",
        parent="/",
        crumb="Error",
        noindex=True,
    )
    return render_page(
        request,
        page,
        extra={
            "error_code": 500,
            "error_title": "Something went wrong on our side",
            "error_body": (
                "This one is ours, not yours. The API health probes below will tell "
                "you instantly whether the service itself is affected."
            ),
            "attempted_path": request.url.path,
        },
        status_code=500,
    )
