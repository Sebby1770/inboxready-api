"""HTTP middleware helpers for InboxReady."""

from __future__ import annotations

import hashlib
import json
import logging
import re
import time
import uuid

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse, Response
from starlette.types import ASGIApp, Message, Receive, Scope, Send

from inboxready_api.security import resolve_client_ip
from inboxready_api.settings import get_settings

logger = logging.getLogger("inboxready_api.requests")

_REQUEST_ID_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")


def _request_id(value: str | None) -> str:
    candidate = (value or "").strip()
    if _REQUEST_ID_PATTERN.fullmatch(candidate):
        return candidate
    return str(uuid.uuid4())


class RequestIdMiddleware(BaseHTTPMiddleware):
    """Attach X-Request-Id to every response."""

    header_name = "X-Request-Id"

    async def dispatch(self, request: Request, call_next) -> Response:  # type: ignore[no-untyped-def]
        request_id = _request_id(request.headers.get(self.header_name))
        request.state.request_id = request_id
        response = await call_next(request)
        response.headers[self.header_name] = request_id
        return response


class RateLimitHeadersMiddleware(BaseHTTPMiddleware):
    """Copy rate-limit metadata produced by the auth dependency to responses."""

    async def dispatch(self, request: Request, call_next) -> Response:  # type: ignore[no-untyped-def]
        response = await call_next(request)
        for name, value in getattr(request.state, "rate_limit_headers", {}).items():
            response.headers.setdefault(name, value)
        return response


class RequestBodyLimitMiddleware:
    """Enforce body limits for declared and chunked requests before parsing."""

    def __init__(self, app: ASGIApp) -> None:
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http" or scope.get("method") not in {"POST", "PUT", "PATCH"}:
            await self.app(scope, receive, send)
            return

        settings = get_settings()
        path = scope.get("path", "")
        limit = (
            settings.report_upload_body_max_bytes
            if path == "/v1/dmarc/reports"
            else settings.request_body_max_bytes
        )
        headers = {name.lower(): value for name, value in scope.get("headers", [])}
        raw_length = headers.get(b"content-length")
        if raw_length is not None:
            try:
                content_length = int(raw_length)
            except ValueError:
                await self._reject(scope, receive, send, 400, "Invalid Content-Length header.")
                return
            if content_length < 0:
                await self._reject(scope, receive, send, 400, "Invalid Content-Length header.")
                return
            if content_length > limit:
                await self._reject(scope, receive, send, 413, self._detail(limit))
                return

        # Buffer only after the cheap Content-Length check. Reading before the
        # framework parser is the only reliable way to reject chunked bodies:
        # FastAPI intentionally translates exceptions from ``receive`` into a
        # generic 400. Coalescing chunks also prevents an unbounded number of
        # empty ASGI messages from growing the replay queue.
        body = bytearray()
        terminal_message: Message | None = None
        saw_request = False
        while True:
            message = await receive()
            if message["type"] != "http.request":
                terminal_message = message
                break
            saw_request = True
            chunk = message.get("body", b"")
            if len(body) + len(chunk) > limit:
                await self._reject(scope, receive, send, 413, self._detail(limit))
                return
            body.extend(chunk)
            if not message.get("more_body", False):
                break

        messages: list[Message] = []
        if saw_request:
            messages.append({"type": "http.request", "body": bytes(body), "more_body": False})
        if terminal_message is not None:
            messages.append(terminal_message)
        index = 0

        async def replay_receive() -> Message:
            nonlocal index
            if index < len(messages):
                message = messages[index]
                index += 1
                return message
            return await receive()

        await self.app(scope, replay_receive, send)

    @staticmethod
    def _detail(limit: int) -> str:
        return f"Request body exceeds the configured {limit}-byte limit."

    @staticmethod
    async def _reject(
        scope: Scope,
        receive: Receive,
        send: Send,
        status_code: int,
        detail: str,
    ) -> None:
        await JSONResponse(status_code=status_code, content={"detail": detail})(scope, receive, send)


class ObservabilityMiddleware(BaseHTTPMiddleware):
    """Emit bounded structured access events without headers, queries, or bodies."""

    async def dispatch(self, request: Request, call_next) -> Response:  # type: ignore[no-untyped-def]
        started = time.perf_counter()
        status_code = 500
        try:
            response = await call_next(request)
            status_code = response.status_code
        except Exception:
            self._log(request, status_code, started, exception=True)
            raise

        elapsed_ms = max(0.0, (time.perf_counter() - started) * 1_000)
        response.headers.setdefault("Server-Timing", f"app;dur={elapsed_ms:.2f}")
        self._log(request, status_code, started)
        return response

    @staticmethod
    def _log(request: Request, status_code: int, started: float, *, exception: bool = False) -> None:
        if not get_settings().access_log_enabled:
            return
        client = resolve_client_ip(request)
        event = {
            "event": "http_request",
            "request_id": getattr(request.state, "request_id", ""),
            "method": request.method,
            "path": request.url.path,
            "status": status_code,
            "duration_ms": round(max(0.0, (time.perf_counter() - started) * 1_000), 2),
            "client_hash": hashlib.sha256(client.encode("utf-8")).hexdigest()[:16],
        }
        message = json.dumps(event, separators=(",", ":"), sort_keys=True)
        if exception:
            logger.exception(message)
        else:
            logger.info(message)


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
