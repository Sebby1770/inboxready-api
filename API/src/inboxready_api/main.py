from __future__ import annotations

import asyncio
import csv
from io import StringIO
import json
import logging
from pathlib import Path
import secrets
import time
from typing import Annotated, Any
import uuid

from fastapi import (
    Depends,
    FastAPI,
    Header,
    HTTPException,
    Query,
    Request,
    WebSocket,
    WebSocketDisconnect,
)
from fastapi.responses import (
    HTMLResponse,
    JSONResponse,
    PlainTextResponse,
    RedirectResponse,
    Response,
)
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from starlette.middleware.sessions import SessionMiddleware

from inboxready_api import __version__
from inboxready_api.billing import (
    BillingConfigurationError,
    BillingProviderError,
    WebhookSignatureError,
    create_checkout_session,
    create_portal_session,
    handle_stripe_webhook,
)
from inboxready_api.commerce import PLAN_LIMITS, RateLimitError, UsageLimitError, recent_window_start
from inboxready_api.dashboard_insights import build_dashboard_insights
from inboxready_api.models import (
    AccountCreateRequest,
    AccountOverviewResponse,
    AccountProvisionResponse,
    ApiKeyCreateRequest,
    ApiKeyListResponse,
    ApiKeyProvisionResponse,
    ApiKeyResponse,
    AuditHistoryDetailResponse,
    AuditHistoryResponse,
    BatchAuditRequest,
    BatchAuditResponse,
    BillingCheckoutRequest,
    BillingSessionResponse,
    DomainAuditRequest,
    DomainAuditResponse,
    MonitorCreateRequest,
    MonitorListResponse,
    MonitorResponse,
    MonitorRunResponse,
    PlanUsageResponse,
    ProviderCatalogResponse,
    SupportRequestCreateRequest,
    SupportRequestResponse,
)
from inboxready_api.observability import metrics_snapshot, prometheus_metrics, record_request
from inboxready_api.security import hash_password, validate_password
from inboxready_api.site_content import (
    CHANGELOG_ENTRIES,
    FAQS,
    FLOW_STEPS,
    HERO_METRICS,
    LATEST_CHANGELOG,
    OPS_CAPABILITIES,
    PRICING_TIERS,
    ROADMAP_ITEMS,
    SAMPLE_CURL,
    SAMPLE_JS,
    SIGNAL_STRIPS,
    USE_CASES,
)
from inboxready_api.services.batch_audit import audit_domains, unique_normalized_domains
from inboxready_api.services.dns_audit import audit_domain
from inboxready_api.services.provider_detection import get_provider_catalog
from inboxready_api.settings import get_settings
from inboxready_api.storage import (
    AccountRecord,
    AuthContext,
    AuthenticationError,
    DuplicateAccountError,
    DuplicateMonitorError,
    MonitorRecord,
    Storage,
)

BASE_DIR = Path(__file__).resolve().parent
templates = Jinja2Templates(directory=str(BASE_DIR / "templates"))
access_logger = logging.getLogger("inboxready_api.access")

CSV_FIELDNAMES = [
    "id",
    "domain",
    "score",
    "overall_status",
    "units",
    "provider_names",
    "recommendation_count",
    "top_recommendation",
    "checked_at",
    "created_at",
]

app = FastAPI(
    title="InboxReady API",
    version=__version__,
    summary="Developer-first email domain readiness checks.",
    description=(
        "Audit email authentication posture for customer-owned domains. "
        "This MVP checks MX, SPF, DMARC, DKIM, MTA-STS, TLS-RPT, and BIMI."
    ),
)
app.mount("/static", StaticFiles(directory=str(BASE_DIR / "static")), name="static")
app.add_middleware(
    SessionMiddleware,
    secret_key=get_settings().session_secret,
    https_only=get_settings().session_https_only,
    same_site="lax",
)


def request_route_path(request: Request) -> str:
    route = request.scope.get("route")
    path = getattr(route, "path", None)
    return path if isinstance(path, str) else request.url.path


@app.middleware("http")
async def observe_requests(request: Request, call_next):
    request_id = request.headers.get("X-Request-ID") or str(uuid.uuid4())
    started = time.perf_counter()
    try:
        response = await call_next(request)
    except Exception as exc:
        duration_ms = (time.perf_counter() - started) * 1000
        path = request_route_path(request)
        record_request(
            method=request.method,
            path=path,
            status_code=500,
            duration_ms=duration_ms,
            request_id=request_id,
            error=str(exc),
        )
        access_logger.exception(
            json.dumps(
                {
                    "event": "http_request_error",
                    "request_id": request_id,
                    "method": request.method,
                    "path": path,
                    "status_code": 500,
                    "duration_ms": round(duration_ms, 3),
                }
            )
        )
        raise

    duration_ms = (time.perf_counter() - started) * 1000
    path = request_route_path(request)
    record_request(
        method=request.method,
        path=path,
        status_code=response.status_code,
        duration_ms=duration_ms,
        request_id=request_id,
    )
    response.headers["X-Request-ID"] = request_id
    access_logger.info(
        json.dumps(
            {
                "event": "http_request",
                "request_id": request_id,
                "method": request.method,
                "path": path,
                "status_code": response.status_code,
                "duration_ms": round(duration_ms, 3),
            }
        )
    )
    return response


@app.middleware("http")
async def add_security_headers(request: Request, call_next):
    response = await call_next(request)
    response.headers.setdefault("X-Content-Type-Options", "nosniff")
    response.headers.setdefault("X-Frame-Options", "DENY")
    response.headers.setdefault("Referrer-Policy", "strict-origin-when-cross-origin")
    response.headers.setdefault(
        "Permissions-Policy",
        "camera=(), microphone=(), geolocation=(), payment=()",
    )
    response.headers.setdefault("Cross-Origin-Opener-Policy", "same-origin")
    response.headers.setdefault(
        "Content-Security-Policy",
        "default-src 'self'; base-uri 'self'; frame-ancestors 'none'; object-src 'none'; "
        "script-src 'self' https://cdn.jsdelivr.net; "
        "style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; "
        "img-src 'self' data: https://fastapi.tiangolo.com; connect-src 'self' ws: wss:; "
        "form-action 'self'",
    )
    if get_settings().session_https_only:
        response.headers.setdefault(
            "Strict-Transport-Security",
            "max-age=31536000; includeSubDomains",
        )
    return response


def storage() -> Storage:
    return Storage(get_settings())


def extract_api_key(authorization: str | None, x_api_key: str | None) -> str | None:
    if x_api_key:
        return x_api_key.strip()
    if not authorization:
        return None
    scheme, _, token = authorization.partition(" ")
    if scheme.lower() == "bearer" and token:
        return token.strip()
    return authorization.strip()


def require_api_context(
    authorization: Annotated[str | None, Header()] = None,
    x_api_key: Annotated[str | None, Header(alias="X-API-Key")] = None,
) -> AuthContext:
    settings = get_settings()
    if not settings.api_auth_required:
        store = storage()
        account = store.get_account_by_email("dev@inboxready.local")
        if account is None:
            account = store.create_account(email="dev@inboxready.local")[0]
        return AuthContext(account=account, api_key=None)

    raw_key = extract_api_key(authorization, x_api_key)
    if not raw_key:
        raise HTTPException(status_code=401, detail="Missing API key.")
    try:
        return storage().authenticate(raw_key)
    except AuthenticationError as exc:
        raise HTTPException(status_code=401, detail=str(exc)) from exc


def current_account_from_session(request: Request) -> AccountRecord | None:
    account_id = request.session.get("account_id")
    if not isinstance(account_id, str):
        return None
    account = storage().get_account(account_id)
    if account is None:
        request.session.pop("account_id", None)
    return account


def require_session_account(request: Request) -> AccountRecord:
    account = current_account_from_session(request)
    if account is None:
        raise HTTPException(status_code=401, detail="Sign in required.")
    return account


def redirect(path: str, *, status_code: int = 303) -> RedirectResponse:
    return RedirectResponse(url=path, status_code=status_code)


def redirect_to_login(next_path: str = "/dashboard") -> RedirectResponse:
    return redirect(f"/login?next={next_path}")


def safe_next_path(value: str | None) -> str:
    if value and value.startswith("/") and not value.startswith("//"):
        return value
    return "/dashboard"


def get_csrf_token(request: Request) -> str:
    token = request.session.get("_csrf_token")
    if isinstance(token, str) and token:
        return token
    token = secrets.token_urlsafe(32)
    request.session["_csrf_token"] = token
    return token


def require_csrf_token(request: Request, submitted_token: str | None = None) -> None:
    expected = request.session.get("_csrf_token")
    presented = submitted_token or request.headers.get("X-CSRF-Token")
    if not isinstance(expected, str) or not presented:
        raise HTTPException(status_code=403, detail="Invalid CSRF token.")
    if not secrets.compare_digest(expected, presented):
        raise HTTPException(status_code=403, detail="Invalid CSRF token.")


def set_flash(request: Request, kind: str, message: str) -> None:
    request.session["_flash"] = {"kind": kind, "message": message}


def pop_flash(request: Request) -> dict[str, str] | None:
    flash = request.session.pop("_flash", None)
    return flash if isinstance(flash, dict) else None


def stash_one_time_api_key(request: Request, api_key: str) -> None:
    request.session["_one_time_api_key"] = api_key


def pop_one_time_api_key(request: Request) -> str | None:
    value = request.session.pop("_one_time_api_key", None)
    return value if isinstance(value, str) else None


def enforce_api_usage(context: AuthContext, *, units: int) -> None:
    account = context.account
    key = context.api_key
    limits = PLAN_LIMITS[account.plan]
    store = storage()
    used = store.count_monthly_usage(account.id)
    if used + units > limits.monthly_audits:
        raise UsageLimitError(
            plan=account.plan,
            limit=limits.monthly_audits,
            used=used,
            requested=units,
        )

    identifier = f"key:{key.key_hash if key else account.id}"
    since = recent_window_start(60).isoformat()
    recent_units = store.count_recent_rate_units(identifier, since)
    if recent_units + units > limits.rate_limit_per_minute:
        raise RateLimitError(limit=limits.rate_limit_per_minute, requested=units)
    store.record_rate_event(identifier=identifier, units=units)


def enforce_demo_usage(request: Request) -> None:
    settings = get_settings()
    host = request.client.host if request.client else "unknown"
    identifier = f"demo:{host}"
    store = storage()

    minute_units = store.count_recent_rate_units(identifier, recent_window_start(60).isoformat())
    if minute_units + 1 > settings.demo_rate_limit_per_minute:
        raise HTTPException(status_code=429, detail="Demo rate limit exceeded. Try again soon.")

    day_units = store.count_recent_rate_units(identifier, recent_window_start(86_400).isoformat())
    if day_units + 1 > settings.demo_daily_limit:
        raise HTTPException(status_code=429, detail="Daily public demo limit reached.")

    store.record_rate_event(identifier=identifier, units=1)


def usage_http_error(exc: Exception) -> HTTPException:
    if isinstance(exc, UsageLimitError):
        return HTTPException(status_code=402, detail=str(exc))
    if isinstance(exc, RateLimitError):
        return HTTPException(status_code=429, detail=str(exc))
    return HTTPException(status_code=500, detail="Unknown usage error.")


def audit_history_csv_response(account: AccountRecord, *, filename: str) -> Response:
    rows = storage().audit_history_export_rows(account)
    output = StringIO()
    writer = csv.DictWriter(output, fieldnames=CSV_FIELDNAMES)
    writer.writeheader()
    writer.writerows(rows)
    return Response(
        content=output.getvalue(),
        media_type="text/csv; charset=utf-8",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


def split_csvish(value: str) -> list[str]:
    return [item.strip() for item in value.replace("\n", ",").split(",") if item.strip()]


def perform_monitor_audit(
    *,
    account: AccountRecord,
    monitor: MonitorRecord,
    api_key_id: str | None,
) -> MonitorRunResponse:
    request = DomainAuditRequest(
        domain=monitor.domain,
        selectors=monitor.selectors,
        expected_providers=monitor.expected_providers,
    )
    result = audit_domain(request, get_settings())
    store = storage()
    audit_id = store.log_audit(
        account_id=account.id,
        api_key_id=api_key_id,
        audit=result,
    )
    updated_monitor = store.update_monitor_after_audit(
        account_id=account.id,
        monitor_id=monitor.id,
        audit=result,
        audit_log_id=audit_id,
    )
    if updated_monitor is None:
        raise HTTPException(status_code=404, detail="Monitor not found.")
    return MonitorRunResponse(
        monitor=store.monitor_response(updated_monitor),
        audit=result,
    )


def render_page(
    request: Request,
    *,
    name: str,
    page_title: str,
    page_description: str,
    extra_context: dict[str, Any] | None = None,
) -> HTMLResponse:
    settings = get_settings()
    current_account = current_account_from_session(request)
    context: dict[str, Any] = {
        "request": request,
        "csrf_token": get_csrf_token(request),
        "page_title": page_title,
        "page_description": page_description,
        "hero_metrics": HERO_METRICS,
        "signal_strips": SIGNAL_STRIPS,
        "use_cases": USE_CASES,
        "flow_steps": FLOW_STEPS,
        "pricing_tiers": PRICING_TIERS,
        "faqs": FAQS,
        "changelog_entries": CHANGELOG_ENTRIES,
        "changelog_preview": CHANGELOG_ENTRIES[:3],
        "latest_release": LATEST_CHANGELOG,
        "ops_capabilities": OPS_CAPABILITIES,
        "roadmap_items": ROADMAP_ITEMS,
        "sample_curl": SAMPLE_CURL,
        "sample_js": SAMPLE_JS,
        "provider_catalog": get_provider_catalog(),
        "plan_limits": PLAN_LIMITS,
        "current_account": current_account,
        "flash": pop_flash(request),
        "support_email": settings.support_email,
        "company_name": settings.company_name,
        "billing_enabled": bool(settings.stripe_secret_key),
        "public_signup_enabled": settings.public_signup_enabled,
    }
    if extra_context:
        context.update(extra_context)
    return templates.TemplateResponse(request=request, name=name, context=context)


@app.get("/", response_class=HTMLResponse)
def root(request: Request) -> HTMLResponse:
    return render_page(
        request,
        name="index.html",
        page_title="Email Domain Readiness",
        page_description=(
            "Polished SaaS front door for InboxReady, an API that audits customer "
            "email domain setup and returns actionable remediation guidance."
        ),
    )


@app.get("/app", response_class=HTMLResponse)
def workspace(request: Request) -> HTMLResponse:
    return render_page(
        request,
        name="app.html",
        page_title="Workspace",
        page_description="Interactive InboxReady workspace for running live email-domain audits.",
    )


@app.get("/signup", response_class=HTMLResponse, response_model=None)
def signup_page(request: Request, next: str | None = None) -> HTMLResponse | RedirectResponse:
    if current_account_from_session(request):
        return redirect(safe_next_path(next))
    return render_page(
        request,
        name="auth.html",
        page_title="Create Account",
        page_description="Create an InboxReady account and start using your dashboard.",
        extra_context={"auth_mode": "signup", "next_path": safe_next_path(next)},
    )


@app.post("/signup", response_class=HTMLResponse, response_model=None)
async def signup_submit(request: Request) -> HTMLResponse | RedirectResponse:
    if not get_settings().public_signup_enabled:
        raise HTTPException(status_code=403, detail="Public signup is disabled.")

    form = await request.form()
    require_csrf_token(request, str(form.get("csrf_token") or ""))
    email = str(form.get("email") or "").strip().lower()
    password = str(form.get("password") or "")
    key_name = str(form.get("key_name") or "Default key").strip() or "Default key"
    next_path = safe_next_path(str(form.get("next") or "/dashboard"))

    try:
        validate_password(password)
        account, _api_key, raw_key = storage().create_account(
            email=email,
            plan="free",
            key_name=key_name,
            password_hash=hash_password(password),
        )
    except ValueError as exc:
        return render_page(
            request,
            name="auth.html",
            page_title="Create Account",
            page_description="Create an InboxReady account and start using your dashboard.",
            extra_context={
                "auth_mode": "signup",
                "next_path": next_path,
                "form_error": str(exc),
                "form_email": email,
            },
        )
    except DuplicateAccountError as exc:
        return render_page(
            request,
            name="auth.html",
            page_title="Create Account",
            page_description="Create an InboxReady account and start using your dashboard.",
            extra_context={
                "auth_mode": "signup",
                "next_path": next_path,
                "form_error": str(exc),
                "form_email": email,
            },
        )

    request.session.clear()
    request.session["account_id"] = account.id
    get_csrf_token(request)
    stash_one_time_api_key(request, raw_key)
    set_flash(request, "success", "Account created. Your first API key is ready in the dashboard.")
    return redirect(next_path)


@app.get("/login", response_class=HTMLResponse, response_model=None)
def login_page(request: Request, next: str | None = None) -> HTMLResponse | RedirectResponse:
    if current_account_from_session(request):
        return redirect(safe_next_path(next))
    return render_page(
        request,
        name="auth.html",
        page_title="Sign In",
        page_description="Sign in to manage InboxReady usage, API keys, and billing.",
        extra_context={"auth_mode": "login", "next_path": safe_next_path(next)},
    )


@app.post("/login", response_class=HTMLResponse, response_model=None)
async def login_submit(request: Request) -> HTMLResponse | RedirectResponse:
    form = await request.form()
    require_csrf_token(request, str(form.get("csrf_token") or ""))
    email = str(form.get("email") or "").strip().lower()
    password = str(form.get("password") or "")
    next_path = safe_next_path(str(form.get("next") or "/dashboard"))

    try:
        account = storage().verify_account_password(email=email, password=password)
    except AuthenticationError as exc:
        return render_page(
            request,
            name="auth.html",
            page_title="Sign In",
            page_description="Sign in to manage InboxReady usage, API keys, and billing.",
            extra_context={
                "auth_mode": "login",
                "next_path": next_path,
                "form_error": str(exc),
                "form_email": email,
            },
        )

    request.session.clear()
    request.session["account_id"] = account.id
    get_csrf_token(request)
    set_flash(request, "success", "Signed in successfully.")
    return redirect(next_path)


@app.post("/logout")
async def logout(request: Request) -> RedirectResponse:
    form = await request.form()
    require_csrf_token(request, str(form.get("csrf_token") or ""))
    request.session.clear()
    return redirect("/")


@app.get("/dashboard", response_class=HTMLResponse, response_model=None)
def dashboard(request: Request) -> HTMLResponse | RedirectResponse:
    account = current_account_from_session(request)
    if account is None:
        return redirect_to_login("/dashboard")

    store = storage()
    audit_history = store.audit_history(account, limit=50)
    monitors = store.list_monitors(account.id)
    usage = audit_history.usage
    return render_page(
        request,
        name="dashboard.html",
        page_title="Dashboard",
        page_description="Usage, billing, API keys, and audit history for your InboxReady account.",
        extra_context={
            "dashboard_account": account,
            "usage": usage,
            "audit_history": audit_history,
            "monitors": monitors,
            "dashboard_insights": build_dashboard_insights(
                usage=usage,
                audit_history=audit_history,
                monitors=monitors,
            ),
            "api_keys": store.list_api_keys(account.id),
            "one_time_api_key": pop_one_time_api_key(request),
        },
    )


@app.post("/dashboard/audit", response_model=DomainAuditResponse)
def dashboard_audit(request: DomainAuditRequest, http_request: Request) -> DomainAuditResponse:
    account = require_session_account(http_request)
    require_csrf_token(http_request)
    context = AuthContext(account=account, api_key=None)
    try:
        enforce_api_usage(context, units=1)
    except (UsageLimitError, RateLimitError) as exc:
        raise usage_http_error(exc) from exc

    result = audit_domain(request, get_settings())
    storage().log_audit(account_id=account.id, api_key_id=None, audit=result)
    return result


@app.post("/dashboard/audits/batch", response_model=BatchAuditResponse)
def dashboard_batch_audit(request: BatchAuditRequest, http_request: Request) -> BatchAuditResponse:
    account = require_session_account(http_request)
    require_csrf_token(http_request)
    context = AuthContext(account=account, api_key=None)
    units = len(unique_normalized_domains(request.domains))
    try:
        enforce_api_usage(context, units=units)
    except (UsageLimitError, RateLimitError) as exc:
        raise usage_http_error(exc) from exc

    result = audit_domains(request, get_settings())
    for audit in result.audits:
        storage().log_audit(account_id=account.id, api_key_id=None, audit=audit)
    return result


@app.post("/dashboard/monitors")
async def dashboard_create_monitor(request: Request) -> RedirectResponse:
    account = current_account_from_session(request)
    if account is None:
        return redirect_to_login("/dashboard")

    form = await request.form()
    require_csrf_token(request, str(form.get("csrf_token") or ""))

    try:
        payload = MonitorCreateRequest(
            domain=str(form.get("domain") or ""),
            selectors=split_csvish(str(form.get("selectors") or "")),
            expected_providers=split_csvish(str(form.get("expected_providers") or "")),
            cadence=str(form.get("cadence") or "weekly"),
        )
        monitor = storage().create_monitor(
            account_id=account.id,
            domain=payload.domain,
            selectors=payload.selectors,
            expected_providers=payload.expected_providers,
            cadence=payload.cadence,
        )
    except DuplicateMonitorError as exc:
        set_flash(request, "error", str(exc))
        return redirect("/dashboard#monitors")
    except Exception as exc:
        set_flash(request, "error", f"Monitor could not be created: {exc}")
        return redirect("/dashboard#monitors")

    set_flash(request, "success", f"Added {monitor.domain} to the monitor watchlist.")
    return redirect("/dashboard#monitors")


@app.post("/dashboard/monitors/{monitor_id}/run")
async def dashboard_run_monitor(monitor_id: str, request: Request) -> RedirectResponse:
    account = current_account_from_session(request)
    if account is None:
        return redirect_to_login("/dashboard")

    form = await request.form()
    require_csrf_token(request, str(form.get("csrf_token") or ""))
    store = storage()
    monitor = store.get_monitor(account_id=account.id, monitor_id=monitor_id)
    if monitor is None:
        set_flash(request, "error", "Monitor not found.")
        return redirect("/dashboard#monitors")

    context = AuthContext(account=account, api_key=None)
    try:
        enforce_api_usage(context, units=1)
        result = perform_monitor_audit(account=account, monitor=monitor, api_key_id=None)
    except (UsageLimitError, RateLimitError) as exc:
        set_flash(request, "error", str(exc))
        return redirect("/dashboard#monitors")

    set_flash(
        request,
        "success",
        f"Refreshed {monitor.domain}: score {result.audit.score}/100.",
    )
    return redirect("/dashboard#monitors")


@app.post("/dashboard/monitors/{monitor_id}/delete")
async def dashboard_delete_monitor(monitor_id: str, request: Request) -> RedirectResponse:
    account = current_account_from_session(request)
    if account is None:
        return redirect_to_login("/dashboard")

    form = await request.form()
    require_csrf_token(request, str(form.get("csrf_token") or ""))
    removed = storage().delete_monitor(account_id=account.id, monitor_id=monitor_id)
    if removed is None:
        set_flash(request, "error", "Monitor not found.")
    else:
        set_flash(request, "success", f"Removed {removed.domain} from the watchlist.")
    return redirect("/dashboard#monitors")


@app.post("/dashboard/api-keys")
async def dashboard_create_api_key(request: Request) -> RedirectResponse:
    account = current_account_from_session(request)
    if account is None:
        return redirect_to_login("/dashboard")

    form = await request.form()
    require_csrf_token(request, str(form.get("csrf_token") or ""))
    name = str(form.get("name") or "API key").strip() or "API key"
    api_key, raw_key = storage().create_api_key(account_id=account.id, name=name)
    stash_one_time_api_key(request, raw_key)
    set_flash(request, "success", f"Created API key '{api_key.name}'.")
    return redirect("/dashboard#api-keys")


@app.post("/dashboard/api-keys/{key_id}/revoke")
async def dashboard_revoke_api_key(key_id: str, request: Request) -> RedirectResponse:
    account = current_account_from_session(request)
    if account is None:
        return redirect_to_login("/dashboard")

    form = await request.form()
    require_csrf_token(request, str(form.get("csrf_token") or ""))
    revoked = storage().revoke_api_key(account_id=account.id, key_id=key_id)
    if revoked is None:
        set_flash(request, "error", "API key not found.")
    else:
        set_flash(request, "success", f"Revoked API key '{revoked.name}'.")
    return redirect("/dashboard#api-keys")


@app.post("/dashboard/billing/checkout")
async def dashboard_billing_checkout(request: Request) -> RedirectResponse:
    account = current_account_from_session(request)
    if account is None:
        return redirect_to_login("/dashboard")

    form = await request.form()
    require_csrf_token(request, str(form.get("csrf_token") or ""))
    plan = str(form.get("plan") or "").strip().lower()
    if plan not in {"starter", "growth", "pro"}:
        set_flash(request, "error", "Choose a paid plan to continue.")
        return redirect("/dashboard#billing")

    try:
        url = create_checkout_session(get_settings(), account, plan)  # type: ignore[arg-type]
    except BillingConfigurationError as exc:
        set_flash(request, "error", str(exc))
        return redirect("/dashboard#billing")
    except BillingProviderError as exc:
        set_flash(request, "error", "Stripe checkout could not be created right now.")
        return redirect("/dashboard#billing")

    return redirect(url)


@app.post("/dashboard/billing/portal")
async def dashboard_billing_portal(request: Request) -> RedirectResponse:
    account = current_account_from_session(request)
    if account is None:
        return redirect_to_login("/dashboard")

    form = await request.form()
    require_csrf_token(request, str(form.get("csrf_token") or ""))
    try:
        url = create_portal_session(get_settings(), account)
    except BillingConfigurationError as exc:
        set_flash(request, "error", str(exc))
        return redirect("/dashboard#billing")
    except BillingProviderError:
        set_flash(request, "error", "Stripe billing portal could not be opened right now.")
        return redirect("/dashboard#billing")
    return redirect(url)


@app.get("/support", response_class=HTMLResponse)
def support_page(request: Request) -> HTMLResponse:
    return render_page(
        request,
        name="support.html",
        page_title="Support",
        page_description="Contact InboxReady support for onboarding, setup, or billing help.",
    )


@app.post("/support", response_class=HTMLResponse, response_model=None)
async def support_submit(request: Request) -> HTMLResponse | RedirectResponse:
    account = current_account_from_session(request)
    form = await request.form()
    require_csrf_token(request, str(form.get("csrf_token") or ""))
    email = str(form.get("email") or (account.email if account else "")).strip().lower()
    subject = str(form.get("subject") or "").strip()
    message = str(form.get("message") or "").strip()

    try:
        payload = SupportRequestCreateRequest(email=email, subject=subject, message=message)
        storage().create_support_request(
            account_id=account.id if account else None,
            email=payload.email,
            subject=payload.subject,
            message=payload.message,
        )
    except Exception as exc:
        return render_page(
            request,
            name="support.html",
            page_title="Support",
            page_description="Contact InboxReady support for onboarding, setup, or billing help.",
            extra_context={
                "form_error": str(exc),
                "support_form": {"email": email, "subject": subject, "message": message},
            },
        )

    set_flash(request, "success", "Support request received. We will get back to you shortly.")
    return redirect("/support")


@app.get("/changelog", response_class=HTMLResponse)
def changelog_page(request: Request) -> HTMLResponse:
    return render_page(
        request,
        name="changelog.html",
        page_title="Changelog",
        page_description="Track InboxReady product updates, release notes, and near-term roadmap items.",
    )


@app.get("/ops", response_class=HTMLResponse)
def ops_page(request: Request) -> HTMLResponse:
    return render_page(
        request,
        name="ops.html",
        page_title="Operations",
        page_description=(
            "Production readiness, deployment surfaces, metrics, and scaling notes for InboxReady."
        ),
    )


@app.get("/privacy", response_class=HTMLResponse)
def privacy_page(request: Request) -> HTMLResponse:
    return render_page(
        request,
        name="legal.html",
        page_title="Privacy Policy",
        page_description="InboxReady privacy policy placeholder for launch and design-partner use.",
        extra_context={"legal_mode": "privacy"},
    )


@app.get("/terms", response_class=HTMLResponse)
def terms_page(request: Request) -> HTMLResponse:
    return render_page(
        request,
        name="legal.html",
        page_title="Terms of Service",
        page_description="InboxReady terms of service placeholder for launch and design-partner use.",
        extra_context={"legal_mode": "terms"},
    )


@app.get("/dashboard/audit-history.csv", response_class=Response, response_model=None)
def dashboard_audit_history_csv(request: Request) -> Response | RedirectResponse:
    account = current_account_from_session(request)
    if account is None:
        return redirect_to_login("/dashboard")
    return audit_history_csv_response(account, filename="inboxready-audit-history.csv")


@app.get(
    "/dashboard/audit-history/{audit_id}.json",
    response_model=AuditHistoryDetailResponse,
)
def dashboard_audit_history_detail(
    audit_id: str,
    request: Request,
) -> AuditHistoryDetailResponse | RedirectResponse:
    account = current_account_from_session(request)
    if account is None:
        return redirect_to_login("/dashboard")

    detail = storage().audit_detail(account, audit_id=audit_id)
    if detail is None:
        raise HTTPException(status_code=404, detail="Audit log not found.")
    return detail


@app.get("/api")
def api_root() -> dict[str, object]:
    return {
        "name": "InboxReady API",
        "version": __version__,
        "docs": "/docs",
        "workspace": "/app",
        "dashboard": "/dashboard",
        "support": "/support",
        "changelog": "/changelog",
        "operations": "/ops",
        "health": "/healthz",
        "readiness": "/readyz",
        "metrics": "/metrics",
        "metrics_summary": "/v1/metrics/summary",
        "websocket_health": "/ws/health",
        "polling": {
            "short": "/v1/health/short-poll",
            "long": "/v1/health/long-poll",
        },
        "monitors": "/v1/monitors",
        "latest_release": {
            "version": LATEST_CHANGELOG["version"],
            "date": LATEST_CHANGELOG["date"],
            "title": LATEST_CHANGELOG["title"],
        },
    }


@app.get("/healthz")
def healthz() -> dict[str, str]:
    return {"status": "ok"}


@app.get("/readyz")
def readyz() -> dict[str, str]:
    try:
        storage().ping()
    except Exception as exc:
        raise HTTPException(status_code=503, detail="Storage is unavailable.") from exc
    return {"status": "ready", "storage": "ok"}


@app.get("/metrics", response_class=PlainTextResponse)
def metrics() -> PlainTextResponse:
    return PlainTextResponse(
        prometheus_metrics(),
        media_type="text/plain; version=0.0.4; charset=utf-8",
    )


@app.get("/v1/metrics/summary")
def metrics_summary() -> dict[str, Any]:
    return metrics_snapshot()


@app.websocket("/ws/health")
async def websocket_health(websocket: WebSocket) -> None:
    await websocket.accept()
    try:
        while True:
            await websocket.send_json(metrics_snapshot())
            await asyncio.sleep(2)
    except WebSocketDisconnect:
        return


@app.get("/v1/health/short-poll")
def health_short_poll() -> dict[str, Any]:
    return {"status": "ok", "metrics": metrics_snapshot()}


@app.get("/v1/health/long-poll")
async def health_long_poll(
    timeout_seconds: Annotated[int, Query(ge=1, le=30)] = 1,
) -> dict[str, Any]:
    await asyncio.sleep(timeout_seconds)
    return {"status": "ok", "waited_seconds": timeout_seconds, "metrics": metrics_snapshot()}


@app.post("/v1/accounts", response_model=AccountProvisionResponse)
def create_account(request: AccountCreateRequest) -> AccountProvisionResponse:
    if request.plan != "free" and not get_settings().allow_unpaid_plan_provisioning:
        raise HTTPException(
            status_code=400,
            detail="Create a free account first, then upgrade through /v1/billing/checkout.",
        )

    try:
        account, api_key, raw_key = storage().create_account(
            email=request.email,
            plan=request.plan,
            key_name=request.key_name,
        )
    except DuplicateAccountError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc

    store = storage()
    return AccountProvisionResponse(
        account=store.account_response(account),
        api_key=raw_key,
        key=store.api_key_response(api_key),
    )


@app.get("/v1/account", response_model=AccountOverviewResponse)
def get_account_overview(
    context: Annotated[AuthContext, Depends(require_api_context)],
) -> AccountOverviewResponse:
    return storage().account_overview(context.account)


@app.post("/v1/api-keys", response_model=ApiKeyProvisionResponse)
def create_api_key(
    request: ApiKeyCreateRequest,
    context: Annotated[AuthContext, Depends(require_api_context)],
) -> ApiKeyProvisionResponse:
    api_key, raw_key = storage().create_api_key(account_id=context.account.id, name=request.name)
    return ApiKeyProvisionResponse(api_key=raw_key, key=storage().api_key_response(api_key))


@app.get("/v1/api-keys", response_model=ApiKeyListResponse)
def list_api_keys(
    context: Annotated[AuthContext, Depends(require_api_context)],
) -> ApiKeyListResponse:
    return storage().api_key_list(context.account)


@app.delete("/v1/api-keys/{key_id}", response_model=ApiKeyResponse)
def revoke_api_key(
    key_id: str,
    context: Annotated[AuthContext, Depends(require_api_context)],
) -> ApiKeyResponse:
    store = storage()
    api_key = store.revoke_api_key(account_id=context.account.id, key_id=key_id)
    if api_key is None:
        raise HTTPException(status_code=404, detail="API key not found.")
    return store.api_key_response(api_key)


@app.get("/v1/usage", response_model=PlanUsageResponse)
def get_usage(context: Annotated[AuthContext, Depends(require_api_context)]) -> PlanUsageResponse:
    return storage().usage_response(context.account)


@app.get("/v1/audit-history", response_model=AuditHistoryResponse)
def get_audit_history(
    context: Annotated[AuthContext, Depends(require_api_context)],
    limit: Annotated[int, Query(ge=1, le=100)] = 25,
) -> AuditHistoryResponse:
    return storage().audit_history(context.account, limit=limit)


@app.get("/v1/audit-history.csv", response_class=Response)
def get_audit_history_csv(
    context: Annotated[AuthContext, Depends(require_api_context)],
) -> Response:
    return audit_history_csv_response(context.account, filename="inboxready-audit-history.csv")


@app.get("/v1/audit-history/{audit_id}", response_model=AuditHistoryDetailResponse)
def get_audit_history_detail(
    audit_id: str,
    context: Annotated[AuthContext, Depends(require_api_context)],
) -> AuditHistoryDetailResponse:
    detail = storage().audit_detail(context.account, audit_id=audit_id)
    if detail is None:
        raise HTTPException(status_code=404, detail="Audit log not found.")
    return detail


@app.post("/v1/monitors", response_model=MonitorResponse)
def create_monitor(
    request: MonitorCreateRequest,
    context: Annotated[AuthContext, Depends(require_api_context)],
) -> MonitorResponse:
    try:
        monitor = storage().create_monitor(
            account_id=context.account.id,
            domain=request.domain,
            selectors=request.selectors,
            expected_providers=request.expected_providers,
            cadence=request.cadence,
        )
    except DuplicateMonitorError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    return storage().monitor_response(monitor)


@app.get("/v1/monitors", response_model=MonitorListResponse)
def list_monitors(
    context: Annotated[AuthContext, Depends(require_api_context)],
) -> MonitorListResponse:
    return storage().monitor_list(context.account)


@app.post("/v1/monitors/{monitor_id}/run", response_model=MonitorRunResponse)
def run_monitor(
    monitor_id: str,
    context: Annotated[AuthContext, Depends(require_api_context)],
) -> MonitorRunResponse:
    store = storage()
    monitor = store.get_monitor(account_id=context.account.id, monitor_id=monitor_id)
    if monitor is None:
        raise HTTPException(status_code=404, detail="Monitor not found.")

    try:
        enforce_api_usage(context, units=1)
    except (UsageLimitError, RateLimitError) as exc:
        raise usage_http_error(exc) from exc
    return perform_monitor_audit(
        account=context.account,
        monitor=monitor,
        api_key_id=context.api_key.id if context.api_key else None,
    )


@app.delete("/v1/monitors/{monitor_id}", response_model=MonitorResponse)
def delete_monitor(
    monitor_id: str,
    context: Annotated[AuthContext, Depends(require_api_context)],
) -> MonitorResponse:
    monitor = storage().delete_monitor(account_id=context.account.id, monitor_id=monitor_id)
    if monitor is None:
        raise HTTPException(status_code=404, detail="Monitor not found.")
    return storage().monitor_response(monitor)


@app.get("/v1/providers", response_model=ProviderCatalogResponse)
def list_providers() -> ProviderCatalogResponse:
    return ProviderCatalogResponse(providers=get_provider_catalog())


@app.post("/v1/audits/email-domain", response_model=DomainAuditResponse)
def create_email_domain_audit(
    request: DomainAuditRequest,
    context: Annotated[AuthContext, Depends(require_api_context)],
) -> DomainAuditResponse:
    try:
        enforce_api_usage(context, units=1)
    except (UsageLimitError, RateLimitError) as exc:
        raise usage_http_error(exc) from exc

    result = audit_domain(request, get_settings())
    storage().log_audit(
        account_id=context.account.id,
        api_key_id=context.api_key.id if context.api_key else None,
        audit=result,
    )
    return result


@app.post("/v1/audits/batch", response_model=BatchAuditResponse)
def create_batch_email_domain_audits(
    request: BatchAuditRequest,
    context: Annotated[AuthContext, Depends(require_api_context)],
) -> BatchAuditResponse:
    units = len(unique_normalized_domains(request.domains))
    try:
        enforce_api_usage(context, units=units)
    except (UsageLimitError, RateLimitError) as exc:
        raise usage_http_error(exc) from exc

    result = audit_domains(request, get_settings())
    for audit in result.audits:
        storage().log_audit(
            account_id=context.account.id,
            api_key_id=context.api_key.id if context.api_key else None,
            audit=audit,
        )
    return result


@app.post("/demo/audit", response_model=DomainAuditResponse)
def create_demo_audit(request: DomainAuditRequest, http_request: Request) -> DomainAuditResponse:
    enforce_demo_usage(http_request)
    return audit_domain(request, get_settings())


@app.post("/v1/support", response_model=SupportRequestResponse)
def support_api(request: SupportRequestCreateRequest) -> SupportRequestResponse:
    storage().create_support_request(
        email=request.email,
        subject=request.subject,
        message=request.message,
    )
    return SupportRequestResponse(status="received", email=request.email, subject=request.subject)


@app.post("/v1/billing/checkout", response_model=BillingSessionResponse)
def billing_checkout(
    request: BillingCheckoutRequest,
    context: Annotated[AuthContext, Depends(require_api_context)],
) -> BillingSessionResponse:
    try:
        url = create_checkout_session(get_settings(), context.account, request.plan)
    except BillingConfigurationError as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc
    except BillingProviderError as exc:
        raise HTTPException(status_code=502, detail=str(exc)) from exc
    return BillingSessionResponse(url=url)


@app.post("/v1/billing/portal", response_model=BillingSessionResponse)
def billing_portal(
    context: Annotated[AuthContext, Depends(require_api_context)],
) -> BillingSessionResponse:
    try:
        url = create_portal_session(get_settings(), context.account)
    except BillingConfigurationError as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc
    except BillingProviderError as exc:
        raise HTTPException(status_code=502, detail=str(exc)) from exc
    return BillingSessionResponse(url=url)


@app.post("/v1/billing/webhook")
async def stripe_webhook(request: Request) -> dict[str, str]:
    payload = await request.body()
    signature = request.headers.get("stripe-signature")
    try:
        return handle_stripe_webhook(
            settings=get_settings(),
            storage=storage(),
            payload=payload,
            signature_header=signature,
        )
    except BillingConfigurationError as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc
    except WebhookSignatureError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@app.exception_handler(AuthenticationError)
def auth_exception_handler(_request: Request, exc: AuthenticationError) -> JSONResponse:
    return JSONResponse(status_code=401, content={"detail": str(exc)})
