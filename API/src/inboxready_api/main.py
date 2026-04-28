from __future__ import annotations

from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from inboxready_api.models import (
    BatchAuditRequest,
    BatchAuditResponse,
    DomainAuditRequest,
    DomainAuditResponse,
    ProviderCatalogResponse,
)
from inboxready_api.site_content import FAQS, FLOW_STEPS, HERO_METRICS, PRICING_TIERS, SAMPLE_CURL, SAMPLE_JS, SIGNAL_STRIPS, USE_CASES
from inboxready_api.services.batch_audit import audit_domains
from inboxready_api.services.dns_audit import audit_domain
from inboxready_api.services.provider_detection import get_provider_catalog
from inboxready_api.settings import get_settings

BASE_DIR = Path(__file__).resolve().parent
templates = Jinja2Templates(directory=str(BASE_DIR / "templates"))

app = FastAPI(
    title="InboxReady API",
    version="0.1.0",
    summary="Developer-first email domain readiness checks.",
    description=(
        "Audit email authentication posture for customer-owned domains. "
        "This MVP checks MX, SPF, DMARC, DKIM, MTA-STS, TLS-RPT, and BIMI."
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
        "version": "0.1.0",
        "docs": "/docs",
        "workspace": "/app",
        "health": "/healthz",
    }


@app.get("/healthz")
def healthz() -> dict[str, str]:
    return {"status": "ok"}


@app.get("/v1/providers", response_model=ProviderCatalogResponse)
def list_providers() -> ProviderCatalogResponse:
    return ProviderCatalogResponse(providers=get_provider_catalog())


@app.post("/v1/audits/email-domain", response_model=DomainAuditResponse)
def create_email_domain_audit(request: DomainAuditRequest) -> DomainAuditResponse:
    return audit_domain(request, get_settings())


@app.post("/v1/audits/batch", response_model=BatchAuditResponse)
def create_batch_email_domain_audits(request: BatchAuditRequest) -> BatchAuditResponse:
    return audit_domains(request, get_settings())
