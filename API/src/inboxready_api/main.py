from __future__ import annotations

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from pathlib import Path

import dns.resolver
from fastapi import Depends, FastAPI, File, HTTPException, Query, Request, Response, UploadFile
from fastapi.exceptions import RequestValidationError
from fastapi.responses import HTMLResponse, JSONResponse, PlainTextResponse
from fastapi.staticfiles import StaticFiles
from starlette.exceptions import HTTPException as StarletteHTTPException

from inboxready_api import __version__
from inboxready_api.cache import audit_cache, make_audit_cache_key
from inboxready_api.middleware import RequestIdMiddleware, SecurityHeadersMiddleware
from inboxready_api.models import (
    BatchAuditRequest,
    BatchAuditResponse,
    CacheClearResponse,
    CompareRequest,
    CompareResponse,
    DmarcReportResponse,
    DomainAuditRequest,
    DomainAuditResponse,
    ProviderCatalogResponse,
)
from inboxready_api.security import require_api_access
from inboxready_api.services.batch_audit import audit_domains
from inboxready_api.services.compare import compare_domains
from inboxready_api.services.dmarc_reports import (
    MAX_COMPRESSED_BYTES,
    ReportError,
    assess_readiness,
    parse_reports,
    summarize_reports,
)
from inboxready_api.services.dns_audit import audit_domain, normalize_domain
from inboxready_api.services.history import configure_history, get_history
from inboxready_api.services.provider_detection import get_provider_catalog
from inboxready_api.services.report import render_html_report, render_markdown_report
from inboxready_api.services.scoring import scoring_document
from inboxready_api.settings import get_settings
from inboxready_api.site import router as site_router
from inboxready_api.site.leads import configure_leads

BASE_DIR = Path(__file__).resolve().parent

#: Prefixes that must answer with JSON even when something goes wrong. Serving
#: an HTML 404 to a client that asked for JSON is a debugging trap.
API_PREFIXES = ("/v1", "/api", "/healthz", "/readyz", "/openapi.json", "/docs", "/redoc")

@asynccontextmanager
async def lifespan(_app: FastAPI) -> AsyncIterator[None]:
    """Configure the persistence-backed stores once, at process start."""
    settings = get_settings()
    configure_history(
        max_entries=settings.history_max_entries,
        path=settings.history_path or None,
    )
    configure_leads(
        max_entries=settings.leads_max_entries,
        path=settings.leads_path or None,
    )
    yield


app = FastAPI(
    lifespan=lifespan,
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
app.add_middleware(SecurityHeadersMiddleware)
app.add_middleware(RequestIdMiddleware)
app.include_router(site_router.router)




def _wants_json(request: Request) -> bool:
    if request.url.path.startswith(API_PREFIXES):
        return True
    accept = request.headers.get("accept", "")
    return "application/json" in accept and "text/html" not in accept


@app.exception_handler(StarletteHTTPException)
async def http_exception_handler(request: Request, exc: StarletteHTTPException) -> Response:
    """Serve the branded 404 page to browsers, JSON to API clients."""
    if exc.status_code == 404 and not _wants_json(request):
        return site_router.render_not_found(request)
    return JSONResponse(
        status_code=exc.status_code,
        content={"detail": exc.detail},
        headers=getattr(exc, "headers", None),
    )


@app.exception_handler(RequestValidationError)
async def validation_exception_handler(request: Request, exc: RequestValidationError) -> Response:
    return JSONResponse(status_code=422, content={"detail": exc.errors()})


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


@app.get("/api")
def api_root() -> dict[str, object]:
    return {
        "name": "InboxReady API",
        "version": __version__,
        "docs": "/docs",
        "workspace": "/app",
        "health": "/healthz",
        "ready": "/readyz",
        "sitemap": "/sitemap.xml",
        "robots": "/robots.txt",
        "pages": "/site/pages",
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


def _record_audit(result, cache_status: str) -> None:
    get_history().add(
        domain=result.domain,
        score=result.score,
        overall_status=result.overall_status,
        checked_at=result.checked_at,
        cached=cache_status == "HIT",
    )
    _maybe_webhook(result)


def _maybe_webhook(result) -> None:
    settings = get_settings()
    if not settings.webhook_url:
        return
    if result.score >= settings.webhook_min_score:
        return
    try:
        import httpx

        httpx.post(
            settings.webhook_url,
            json={
                "domain": result.domain,
                "score": result.score,
                "overall_status": result.overall_status,
                "checked_at": result.checked_at,
            },
            timeout=2.0,
        )
    except Exception:
        pass


@app.post("/v1/audits/email-domain", response_model=None)
def create_email_domain_audit(
    body: DomainAuditRequest,
    response: Response,
    format: str = Query(default="json", pattern="^(json|markdown|md|html)$"),
    _auth: str = Depends(require_api_access),
):
    result, cache_status = _run_cached_audit(body)
    response.headers["X-Cache"] = cache_status
    _record_audit(result, cache_status)

    if format in {"markdown", "md"}:
        return PlainTextResponse(
            content=render_markdown_report(result),
            media_type="text/markdown; charset=utf-8",
            headers={"X-Cache": cache_status},
        )
    if format == "html":
        return HTMLResponse(
            content=render_html_report(result),
            headers={"X-Cache": cache_status},
        )
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


#: Report uploads are bounded per request as well as per file, so a single
#: multipart body cannot be used to exhaust memory.
MAX_REPORT_FILES = 25
MAX_REPORT_UPLOAD_BYTES = 32 * 1024 * 1024


@app.post("/v1/dmarc/reports", response_model=DmarcReportResponse)
async def analyze_dmarc_reports(
    files: list[UploadFile] = File(
        ...,
        description="DMARC aggregate report files: XML, .xml.gz, or .zip.",
    ),
    policy: str | None = Query(
        default=None,
        pattern="^(none|quarantine|reject)$",
        description="Current DMARC policy. Defaults to the policy inside the reports.",
    ),
    _auth: str = Depends(require_api_access),
) -> DmarcReportResponse:
    """Turn aggregate (RUA) reports into a rollout decision.

    Answers the question a DNS lookup cannot: if the policy tightens, whose
    mail breaks? Every source is classified, and the response says whether the
    next policy step is safe and what stands in the way.
    """
    if len(files) > MAX_REPORT_FILES:
        raise HTTPException(
            status_code=413,
            detail=f"Too many files. Upload at most {MAX_REPORT_FILES} reports per request.",
        )

    payloads: list[tuple[str, bytes]] = []
    total = 0
    for upload in files:
        data = await upload.read(MAX_COMPRESSED_BYTES + 1)
        await upload.close()
        total += len(data)
        if total > MAX_REPORT_UPLOAD_BYTES:
            raise HTTPException(status_code=413, detail="Upload exceeds the total size limit.")
        payloads.append((upload.filename or "report", data))

    reports, errors = parse_reports(payloads)
    if not reports:
        detail = errors[0] if errors else "No readable reports were supplied."
        raise HTTPException(status_code=422, detail=detail)

    try:
        summary = summarize_reports(reports)
    except ReportError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc

    return DmarcReportResponse(
        summary=summary,
        readiness=assess_readiness(summary, current_policy=policy),
        reports=[report.metadata for report in reports],
        errors=errors,
    )


@app.get("/v1/scoring")
def get_scoring_document(_auth: str = Depends(require_api_access)) -> dict:
    return scoring_document()


@app.get("/v1/history")
def list_history(
    domain: str | None = None,
    limit: int = Query(default=20, ge=1, le=500),
    _auth: str = Depends(require_api_access),
) -> dict:
    entries = get_history().list(domain=domain, limit=limit)
    return {"count": len(entries), "entries": [e.to_dict() for e in entries]}


@app.get("/v1/history/stats")
def history_stats(_auth: str = Depends(require_api_access)) -> dict:
    return get_history().stats()


@app.get("/v1/history/export.csv")
def history_export_csv(_auth: str = Depends(require_api_access)) -> PlainTextResponse:
    return PlainTextResponse(
        content=get_history().export_csv(),
        media_type="text/csv; charset=utf-8",
    )


@app.post("/v1/cache/clear", response_model=CacheClearResponse)
def clear_audit_cache(_auth: str = Depends(require_api_access)) -> CacheClearResponse:
    """Clear the in-memory audit cache. Requires X-API-Key when keys are configured."""
    cleared = audit_cache.clear()
    return CacheClearResponse(cleared=cleared, message=f"Cleared {cleared} cached audit(s).")
