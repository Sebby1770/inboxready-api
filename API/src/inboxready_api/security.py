from __future__ import annotations

import threading
import time
from collections import defaultdict, deque

from fastapi import Header, HTTPException, Request

from inboxready_api.settings import Settings, get_settings


class SlidingWindowRateLimiter:
    """Thread-safe per-key sliding window rate limiter."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._hits: dict[str, deque[float]] = defaultdict(deque)

    def allow(self, key: str, limit: int, window_seconds: float = 60.0) -> bool:
        if limit <= 0:
            return True

        now = time.monotonic()
        cutoff = now - window_seconds

        with self._lock:
            bucket = self._hits[key]
            while bucket and bucket[0] <= cutoff:
                bucket.popleft()
            if len(bucket) >= limit:
                return False
            bucket.append(now)
            return True

    def clear(self) -> None:
        with self._lock:
            self._hits.clear()


rate_limiter = SlidingWindowRateLimiter()


def auth_required(settings: Settings | None = None) -> bool:
    settings = settings or get_settings()
    return settings.require_api_key or bool(settings.parsed_api_keys)


def resolve_client_key(
    request: Request,
    x_api_key: str | None,
    settings: Settings | None = None,
) -> str:
    """Validate API key when required and return a rate-limit bucket key."""
    settings = settings or get_settings()
    configured = settings.parsed_api_keys
    required = settings.require_api_key or bool(configured)

    if required:
        if not x_api_key:
            raise HTTPException(status_code=401, detail="Missing X-API-Key header.")
        if configured and x_api_key not in configured:
            raise HTTPException(status_code=401, detail="Invalid API key.")
        return f"key:{x_api_key}"

    if x_api_key:
        return f"key:{x_api_key}"

    client_host = request.client.host if request.client else "unknown"
    return f"ip:{client_host}"


def enforce_rate_limit(bucket_key: str, settings: Settings | None = None) -> None:
    settings = settings or get_settings()
    if not rate_limiter.allow(bucket_key, settings.rate_limit_per_minute):
        raise HTTPException(
            status_code=429,
            detail="Rate limit exceeded. Try again later.",
        )


async def require_api_access(
    request: Request,
    x_api_key: str | None = Header(default=None, alias="X-API-Key"),
) -> str:
    """FastAPI dependency: API key gate + rate limit. Returns bucket key."""
    settings = get_settings()
    bucket_key = resolve_client_key(request, x_api_key, settings)
    enforce_rate_limit(bucket_key, settings)
    return bucket_key
