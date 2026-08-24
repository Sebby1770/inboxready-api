"""HTTP middleware helpers for InboxReady."""

from __future__ import annotations

import uuid

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response

from inboxready_api.settings import get_settings


class RequestIdMiddleware(BaseHTTPMiddleware):
    """Attach X-Request-Id to every response."""

    header_name = "X-Request-Id"

    async def dispatch(self, request: Request, call_next) -> Response:  # type: ignore[no-untyped-def]
        request_id = request.headers.get(self.header_name) or str(uuid.uuid4())
        request.state.request_id = request_id
        response = await call_next(request)
        response.headers[self.header_name] = request_id
        return response


#: Sources the site itself needs. Analytics is appended only when configured,
#: so a deployment without a measurement ID ships a strictly tighter policy.
_BASE_CSP = {
    "default-src": ["'self'"],
    "base-uri": ["'self'"],
    "form-action": ["'self'"],
    "frame-ancestors": ["'none'"],
    "object-src": ["'none'"],
    "img-src": ["'self'", "data:"],
    "style-src": ["'self'", "'unsafe-inline'"],
    "script-src": ["'self'"],
    "connect-src": ["'self'"],
    "font-src": ["'self'", "data:"],
}

_ANALYTICS_SOURCES = {
    "script-src": ["https://www.googletagmanager.com"],
    "connect-src": [
        "https://www.google-analytics.com",
        "https://region1.google-analytics.com",
        "https://analytics.google.com",
    ],
    "img-src": ["https://www.google-analytics.com", "https://www.googletagmanager.com"],
}


def build_csp(*, analytics_enabled: bool) -> str:
    directives = {key: list(value) for key, value in _BASE_CSP.items()}
    if analytics_enabled:
        for key, extra in _ANALYTICS_SOURCES.items():
            directives[key].extend(extra)
    return "; ".join(f"{key} {' '.join(values)}" for key, values in directives.items())


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    """Baseline hardening headers.

    A Content-Security-Policy is only applied to HTML responses: sending one on
    a JSON API response is noise, and on ``/docs`` it would break Swagger UI,
    which loads its assets from a CDN.
    """

    async def dispatch(self, request: Request, call_next) -> Response:  # type: ignore[no-untyped-def]
        response = await call_next(request)
        settings = get_settings()
        if not settings.security_headers_enabled:
            return response

        response.headers.setdefault("X-Content-Type-Options", "nosniff")
        response.headers.setdefault("Referrer-Policy", "strict-origin-when-cross-origin")
        response.headers.setdefault("X-Frame-Options", "DENY")
        response.headers.setdefault(
            "Permissions-Policy",
            "geolocation=(), microphone=(), camera=(), payment=(), interest-cohort=()",
        )
        if request.url.scheme == "https":
            response.headers.setdefault(
                "Strict-Transport-Security", "max-age=31536000; includeSubDomains"
            )

        content_type = response.headers.get("content-type", "")
        is_docs = request.url.path in {"/docs", "/redoc"}
        if content_type.startswith("text/html") and not is_docs:
            response.headers.setdefault(
                "Content-Security-Policy",
                build_csp(analytics_enabled=settings.analytics_enabled),
            )
        return response
