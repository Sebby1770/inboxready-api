from __future__ import annotations

from pathlib import Path

import dns.resolver
from fastapi import Depends, FastAPI, Query, Request, Response
from fastapi.responses import HTMLResponse, JSONResponse, PlainTextResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from inboxready_api import __version__
from inboxready_api.cache import audit_cache, make_audit_cache_key
from inboxready_api.models import (
    BatchAuditRequest,
    BatchAuditResponse,
    CacheClearResponse,
    CompareRequest,
    CompareResponse,
    DomainAuditRequest,
    DomainAuditResponse,
    ProviderCatalogResponse,
)
from inboxready_api.security import require_api_access
from inboxready_api.services.batch_audit import audit_domains
from inboxready_api.services.compare import compare_domains
from inboxready_api.services.dns_audit import audit_domain, normalize_domain
from inboxready_api.services.provider_detection import get_provider_catalog
from inboxready_api.services.report import render_markdown_report
from inboxready_api.settings import get_settings
from inboxready_api.site_content import (
    FAQS,
    FLOW_STEPS,
    HERO_METRICS,
    PRICING_TIERS,
    SAMPLE_CURL,
    SAMPLE_JS,
    SIGNAL_STRIPS,
    USE_CASES,
)

BASE_DIR = Path(__file__).resolve().parent
templates = Jinja2Templates(directory=str(BASE_DIR / "templates"))

app = FastAPI(
    title="InboxReady API",
    version=__version__,
    summary="Developer-first email domain readiness checks.",
    description=(
        "Audit email authentication posture for customer-owned domains. "
        "Checks MX, SPF, DMARC, DKIM, MTA-STS, TLS-RPT, and BIMI with optional "
        "API keys, rate limiting, result caching, compare, and markdown reports."
    ),
)
app.mount("/static", StaticFiles(directory=str(BASE_DIR / "static")), name="static")


def build_template_context(request: Request, *, page_title: str, page_description: str) -> dict[str, object]:
    return {
        "request": request,
        "page_title": page_title,
        "page_description": page_description,
        "hero_metrics": HERO_METRICS,
        "signal_strips": SIGNAL_STRIPS,
        "use_cases": USE_CASES,
        "flow_steps": FLOW_STEPS,
        "pricing_tiers": PRICING_TIERS,
        "faqs": FAQS,
        "sample_curl": SAMPLE_CURL,
        "sample_js": SAMPLE_JS,
        "provider_catalog": get_provider_catalog(),
    }


def _run_cached_audit(request: DomainAuditRequest) -> tuple[DomainAuditResponse, str]:
    settings = get_settings()
    domain = normalize_domain(request.domain)
    cache_key = make_audit_cache_key(domain, request.selectors, request.expected_providers)

    if settings.cache_ttl_seconds > 0:
        cached = audit_cache.get(cache_key)
        if cached is not None:
            return cached, "HIT"

    result = audit_domain(request, settings)
    if settings.cache_ttl_seconds > 0:
        audit_cache.set(cache_key, result, float(settings.cache_ttl_seconds))
    return result, "MISS"


@app.get("/", response_class=HTMLResponse)
def root(request: Request) -> HTMLResponse:
    return templates.TemplateResponse(
        request=request,
        name="index.html",
        context=build_template_context(
            request,
            page_title="Email Domain Readiness",
            page_description=(
                "Polished SaaS front door for InboxReady, an API that audits customer "
                "email domain setup and returns actionable remediation guidance."
            ),
        ),
    )


@app.get("/app", response_class=HTMLResponse)
def workspace(request: Request) -> HTMLResponse:
    return templates.TemplateResponse(
        request=request,
        name="app.html",
        context=build_template_context(
            request,
            page_title="Workspace",
            page_description="Interactive InboxReady workspace for running live email-domain audits.",
        ),
    )


@app.get("/api")
def api_root() -> dict[str, object]:
    return {
        "name": "InboxReady API",
        "version": __version__,
        "docs": "/docs",
        "workspace": "/app",
        "health": "/healthz",
        "ready": "/readyz",
    }


@app.get("/healthz")
def healthz() -> dict[str, str]:
    return {"status": "ok", "version": __version__}


@app.get("/readyz")
def readyz() -> JSONResponse:
    try:
        resolver = dns.resolver.Resolver()
        _ = resolver.nameservers
        return JSONResponse(
            status_code=200,
            content={"status": "ready", "version": __version__},
        )
    except Exception as exc:  # pragma: no cover - defensive
        return JSONResponse(
            status_code=503,
            content={
                "status": "not_ready",
                "version": __version__,
                "detail": str(exc),
            },
        )


@app.get("/v1/providers", response_model=ProviderCatalogResponse)
def list_providers(_auth: str = Depends(require_api_access)) -> ProviderCatalogResponse:
    return ProviderCatalogResponse(providers=get_provider_catalog())


@app.post("/v1/audits/email-domain", response_model=None)
def create_email_domain_audit(
    body: DomainAuditRequest,
    response: Response,
    format: str = Query(default="json", pattern="^(json|markdown|md)$"),
    _auth: str = Depends(require_api_access),
):
    result, cache_status = _run_cached_audit(body)
    response.headers["X-Cache"] = cache_status

    if format in {"markdown", "md"}:
        return PlainTextResponse(
            content=render_markdown_report(result),
            media_type="text/markdown; charset=utf-8",
            headers={"X-Cache": cache_status},
        )
    # Explicit JSON so X-Cache is always present on the wire.
    return JSONResponse(
        content=result.model_dump(mode="json"),
        headers={"X-Cache": cache_status},
    )


@app.get("/v1/audit/{domain}/report.md", response_class=PlainTextResponse)
def get_markdown_report(
    domain: str,
    response: Response,
    selectors: str = Query(default=""),
    expected_providers: str = Query(default=""),
    _auth: str = Depends(require_api_access),
) -> PlainTextResponse:
    selector_list = [item.strip() for item in selectors.split(",") if item.strip()]
    provider_list = [item.strip() for item in expected_providers.split(",") if item.strip()]
    result, cache_status = _run_cached_audit(
        DomainAuditRequest(
            domain=domain,
            selectors=selector_list,
            expected_providers=provider_list,
        )
    )
    response.headers["X-Cache"] = cache_status
    return PlainTextResponse(
        content=render_markdown_report(result),
        media_type="text/markdown; charset=utf-8",
        headers={"X-Cache": cache_status},
    )


@app.post("/v1/audits/batch", response_model=BatchAuditResponse)
def create_batch_email_domain_audits(
    body: BatchAuditRequest,
    _auth: str = Depends(require_api_access),
) -> BatchAuditResponse:
    return audit_domains(body, get_settings())


@app.post("/v1/compare", response_model=CompareResponse)
def create_domain_compare(
    body: CompareRequest,
    _auth: str = Depends(require_api_access),
) -> CompareResponse:
    return compare_domains(body, get_settings())


@app.post("/v1/cache/clear", response_model=CacheClearResponse)
def clear_audit_cache(_auth: str = Depends(require_api_access)) -> CacheClearResponse:
    """Clear the in-memory audit cache. Requires X-API-Key when keys are configured."""
    cleared = audit_cache.clear()
    return CacheClearResponse(cleared=cleared, message=f"Cleared {cleared} cached audit(s).")
