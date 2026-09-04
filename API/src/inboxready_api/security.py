from __future__ import annotations

import hashlib
import hmac
import ipaddress
import math
import threading
import time
from collections import OrderedDict, deque
from dataclasses import dataclass

from fastapi import Header, HTTPException, Request

from inboxready_api.settings import Settings, get_settings


class SlidingWindowRateLimiter:
    """Thread-safe per-key sliding window rate limiter."""

    def __init__(self, *, max_buckets: int = 20_000) -> None:
        self._lock = threading.Lock()
        self._max_buckets = max(1, max_buckets)
        self._hits: OrderedDict[str, deque[float]] = OrderedDict()

    def configure(self, *, max_buckets: int) -> None:
        with self._lock:
            self._max_buckets = max(1, max_buckets)
            while len(self._hits) > self._max_buckets:
                self._hits.popitem(last=False)

    def check(self, key: str, limit: int, window_seconds: float = 60.0) -> RateLimitDecision:
        if limit <= 0:
            return RateLimitDecision(allowed=True, limit=0, remaining=0, reset_after=0)

        now = time.monotonic()
        cutoff = now - window_seconds

        with self._lock:
            bucket = self._hits.get(key)
            if bucket is None:
                while len(self._hits) >= self._max_buckets:
                    self._hits.popitem(last=False)
                bucket = deque()
                self._hits[key] = bucket
            else:
                self._hits.move_to_end(key)
            while bucket and bucket[0] <= cutoff:
                bucket.popleft()
            if len(bucket) >= limit:
                reset_after = max(1, math.ceil(bucket[0] + window_seconds - now))
                return RateLimitDecision(
                    allowed=False,
                    limit=limit,
                    remaining=0,
                    reset_after=reset_after,
                )
            bucket.append(now)
            reset_after = max(1, math.ceil(bucket[0] + window_seconds - now))
            return RateLimitDecision(
                allowed=True,
                limit=limit,
                remaining=max(0, limit - len(bucket)),
                reset_after=reset_after,
            )

    def allow(self, key: str, limit: int, window_seconds: float = 60.0) -> bool:
        """Compatibility wrapper for callers that only need a decision."""
        return self.check(key, limit, window_seconds).allowed

    def clear(self) -> None:
        with self._lock:
            self._hits.clear()

    def __len__(self) -> int:
        with self._lock:
            return len(self._hits)


rate_limiter = SlidingWindowRateLimiter()


@dataclass(frozen=True)
class RateLimitDecision:
    allowed: bool
    limit: int
    remaining: int
    reset_after: int

    def headers(self) -> dict[str, str]:
        if self.limit <= 0:
            return {}
        values = {
            "RateLimit-Limit": str(self.limit),
            "RateLimit-Remaining": str(self.remaining),
            "RateLimit-Reset": str(self.reset_after),
            "X-RateLimit-Limit": str(self.limit),
            "X-RateLimit-Remaining": str(self.remaining),
        }
        if not self.allowed:
            values["Retry-After"] = str(self.reset_after)
        return values


def auth_required(settings: Settings | None = None) -> bool:
    settings = settings or get_settings()
    return settings.require_api_key or bool(settings.parsed_api_keys)


def _key_matches(candidate: str, configured: set[str]) -> bool:
    """Compare against every configured key without early-exit timing leaks."""
    matched = False
    for expected in configured:
        matched = hmac.compare_digest(candidate, expected) or matched
    return matched


def _api_key_bucket(api_key: str) -> str:
    """Avoid retaining plaintext credentials in process memory."""
    digest = hashlib.sha256(api_key.encode("utf-8")).hexdigest()
    return f"key-sha256:{digest}"


def resolve_client_ip(request: Request, settings: Settings | None = None) -> str:
    """Resolve the client without trusting spoofable forwarding headers.

    ``X-Forwarded-For`` is considered only when the direct peer belongs to an
    explicitly configured trusted proxy network. The chain is walked from the
    nearest hop outwards, stopping at the first untrusted address.
    """
    settings = settings or get_settings()
    peer = request.client.host if request.client else "unknown"
    networks = settings.parsed_trusted_proxy_networks
    if not networks:
        return peer

    try:
        peer_address = ipaddress.ip_address(peer)
    except ValueError:
        return peer
    if not any(peer_address in network for network in networks):
        return peer

    forwarded = request.headers.get("x-forwarded-for", "")
    if not forwarded:
        return peer
    parts = forwarded.split(",")
    if len(parts) > 32:
        return peer
    try:
        chain = [ipaddress.ip_address(item.strip()) for item in parts]
    except ValueError:
        return peer

    current = peer_address
    for previous in reversed(chain):
        if not any(current in network for network in networks):
            break
        current = previous
    return str(current)


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
        if not configured:
            raise HTTPException(
                status_code=503,
                detail="API authentication is required but no API keys are configured.",
            )
        if not x_api_key:
            raise HTTPException(status_code=401, detail="Missing X-API-Key header.")
        if not _key_matches(x_api_key, configured):
            raise HTTPException(status_code=401, detail="Invalid API key.")
        return _api_key_bucket(x_api_key)

    # On an open deployment, arbitrary X-API-Key values are not identities:
    # accepting them would let callers bypass the IP bucket with random keys.
    client_host = resolve_client_ip(request, settings)
    return f"ip:{client_host}"


def enforce_rate_limit(
    bucket_key: str,
    settings: Settings | None = None,
) -> RateLimitDecision:
    settings = settings or get_settings()
    decision = rate_limiter.check(bucket_key, settings.rate_limit_per_minute)
    if not decision.allowed:
        raise HTTPException(
            status_code=429,
            detail="Rate limit exceeded. Try again later.",
            headers=decision.headers(),
        )
    return decision


async def require_api_access(
    request: Request,
    x_api_key: str | None = Header(default=None, alias="X-API-Key"),
) -> str:
    """FastAPI dependency: API key gate + rate limit. Returns bucket key."""
    settings = get_settings()
    bucket_key = resolve_client_key(request, x_api_key, settings)
    decision = enforce_rate_limit(bucket_key, settings)
    request.state.rate_limit_headers = decision.headers()
    return bucket_key
