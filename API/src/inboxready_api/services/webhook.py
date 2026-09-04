"""Safe, signed, observable delivery for audit webhooks."""

from __future__ import annotations

import hashlib
import hmac
import json
import logging
import socket
import time
from collections.abc import Callable

import httpx

from inboxready_api import __version__
from inboxready_api.models import DomainAuditResponse
from inboxready_api.services.outbound import (
    OutboundResolutionError,
    UnsafeOutboundTarget,
    validate_public_http_target,
)
from inboxready_api.settings import Settings

logger = logging.getLogger("inboxready_api.webhook")


class UnsafeWebhookTarget(ValueError):
    """Raised when an outbound target violates the webhook network policy."""


class WebhookResolutionError(UnsafeWebhookTarget):
    """A potentially transient DNS-resolution failure."""


def validate_webhook_target(
    url: str,
    *,
    allow_private_hosts: bool,
    resolver: Callable[..., list[tuple]] = socket.getaddrinfo,
) -> str:
    """Validate a webhook URL and every currently resolved address.

    Redirects are separately disabled during delivery, and this validation is
    repeated before every attempt. Private targets can be explicitly enabled
    for self-hosted deployments that intentionally use an internal receiver.
    """
    try:
        return validate_public_http_target(
            url,
            allow_private_hosts=allow_private_hosts,
            resolver=resolver,
        )
    except OutboundResolutionError as exc:
        raise WebhookResolutionError(str(exc)) from exc
    except UnsafeOutboundTarget as exc:
        raise UnsafeWebhookTarget(str(exc)) from exc


def webhook_payload(result: DomainAuditResponse) -> tuple[str, bytes]:
    identity = f"audit.completed\0{result.domain}\0{result.checked_at}".encode()
    delivery_id = hashlib.sha256(identity).hexdigest()[:32]
    payload = {
        "event": "audit.completed",
        "delivery_id": delivery_id,
        "api_version": __version__,
        "domain": result.domain,
        "score": result.score,
        "overall_status": result.overall_status,
        "checked_at": result.checked_at,
    }
    return delivery_id, json.dumps(payload, separators=(",", ":"), sort_keys=True).encode("utf-8")


def signature_for(body: bytes, secret: str) -> str:
    digest = hmac.new(secret.encode("utf-8"), body, hashlib.sha256).hexdigest()
    return f"sha256={digest}"


def deliver_webhook(
    result: DomainAuditResponse,
    settings: Settings,
    *,
    client_factory: Callable[..., httpx.Client] = httpx.Client,
    sleep: Callable[[float], None] = time.sleep,
) -> bool:
    """Deliver one audit event with bounded retry and no redirect following."""
    if not settings.webhook_url:
        return False

    delivery_id, body = webhook_payload(result)
    headers = {
        "Content-Type": "application/json",
        "User-Agent": settings.user_agent,
        "X-InboxReady-Event": "audit.completed",
        "X-InboxReady-Delivery": delivery_id,
    }
    if settings.webhook_secret:
        headers["X-InboxReady-Signature-256"] = signature_for(body, settings.webhook_secret)

    for attempt in range(1, settings.webhook_max_attempts + 1):
        try:
            target = validate_webhook_target(
                settings.webhook_url,
                allow_private_hosts=settings.webhook_allow_private_hosts,
            )
            with client_factory(
                timeout=settings.webhook_timeout_seconds,
                follow_redirects=False,
            ) as client:
                response = client.post(target, content=body, headers=headers)
            if 200 <= response.status_code < 300:
                _log("webhook_delivered", result.domain, delivery_id, attempt, response.status_code)
                return True
            retryable = response.status_code in {408, 409, 425, 429} or response.status_code >= 500
            _log("webhook_rejected", result.domain, delivery_id, attempt, response.status_code)
            if not retryable:
                return False
        except WebhookResolutionError as exc:
            _log("webhook_failed", result.domain, delivery_id, attempt, detail=str(exc))
        except UnsafeWebhookTarget as exc:
            _log("webhook_blocked", result.domain, delivery_id, attempt, detail=str(exc))
            return False
        except httpx.HTTPError as exc:
            _log("webhook_failed", result.domain, delivery_id, attempt, detail=type(exc).__name__)

        if attempt < settings.webhook_max_attempts:
            sleep(min(2.0, 0.25 * (2 ** (attempt - 1))))
    return False


def _log(
    event: str,
    domain: str,
    delivery_id: str,
    attempt: int,
    status: int | None = None,
    detail: str | None = None,
) -> None:
    fields: dict[str, object] = {
        "event": event,
        "domain": domain,
        "delivery_id": delivery_id,
        "attempt": attempt,
    }
    if status is not None:
        fields["status"] = status
    if detail:
        fields["detail"] = detail
    level = logging.INFO if event == "webhook_delivered" else logging.WARNING
    logger.log(level, json.dumps(fields, separators=(",", ":"), sort_keys=True))
