from __future__ import annotations

import hashlib
import hmac
import json
import time
from typing import TYPE_CHECKING, Any

from inboxready_api.commerce import normalize_plan
from inboxready_api.models import PlanName
from inboxready_api.settings import Settings

if TYPE_CHECKING:
    from inboxready_api.storage import AccountRecord, Storage


STRIPE_API = "https://api.stripe.com/v1"


class BillingConfigurationError(Exception):
    pass


class BillingProviderError(Exception):
    pass


class WebhookSignatureError(Exception):
    pass


def price_id_for_plan(settings: Settings, plan: PlanName) -> str | None:
    return {
        "starter": settings.stripe_starter_price_id,
        "growth": settings.stripe_growth_price_id,
        "pro": settings.stripe_pro_price_id,
    }.get(plan)


def plan_for_price_id(settings: Settings, price_id: str | None) -> PlanName:
    if price_id and price_id == settings.stripe_starter_price_id:
        return "starter"
    if price_id and price_id == settings.stripe_growth_price_id:
        return "growth"
    if price_id and price_id == settings.stripe_pro_price_id:
        return "pro"
    return "free"


def create_checkout_session(settings: Settings, account: "AccountRecord", plan: PlanName) -> str:
    if not settings.stripe_secret_key:
        raise BillingConfigurationError("Stripe secret key is not configured.")

    price_id = price_id_for_plan(settings, plan)
    if not price_id:
        raise BillingConfigurationError(f"Stripe price ID is not configured for plan '{plan}'.")

    data: dict[str, str] = {
        "mode": "subscription",
        "line_items[0][price]": price_id,
        "line_items[0][quantity]": "1",
        "success_url": f"{settings.public_base_url}/app?checkout=success",
        "cancel_url": f"{settings.public_base_url}/app?checkout=cancelled",
        "metadata[account_id]": account.id,
        "metadata[plan]": plan,
        "subscription_data[metadata][account_id]": account.id,
        "subscription_data[metadata][plan]": plan,
    }

    if account.stripe_customer_id:
        data["customer"] = account.stripe_customer_id
    else:
        data["customer_email"] = account.email

    payload = stripe_post(settings, "/checkout/sessions", data)
    url = payload.get("url")
    if not isinstance(url, str):
        raise BillingProviderError("Stripe did not return a Checkout URL.")
    return url


def create_portal_session(settings: Settings, account: "AccountRecord") -> str:
    if not settings.stripe_secret_key:
        raise BillingConfigurationError("Stripe secret key is not configured.")
    if not account.stripe_customer_id:
        raise BillingConfigurationError("This account does not have a Stripe customer yet.")

    payload = stripe_post(
        settings,
        "/billing_portal/sessions",
        {
            "customer": account.stripe_customer_id,
            "return_url": f"{settings.public_base_url}/app",
        },
    )
    url = payload.get("url")
    if not isinstance(url, str):
        raise BillingProviderError("Stripe did not return a Billing Portal URL.")
    return url


def stripe_post(settings: Settings, path: str, data: dict[str, str]) -> dict[str, Any]:
    import httpx

    with httpx.Client(timeout=10.0) as client:
        response = client.post(
            f"{STRIPE_API}{path}",
            data=data,
            headers={"Authorization": f"Bearer {settings.stripe_secret_key}"},
        )

    if response.status_code >= 400:
        raise BillingProviderError(response.text)
    return response.json()


def verify_stripe_signature(
    *,
    payload: bytes,
    signature_header: str | None,
    secret: str | None,
    tolerance_seconds: int = 300,
) -> None:
    if not secret:
        raise BillingConfigurationError("Stripe webhook secret is not configured.")
    if not signature_header:
        raise WebhookSignatureError("Missing Stripe signature.")

    parts: dict[str, list[str]] = {}
    for item in signature_header.split(","):
        if "=" not in item:
            continue
        key, value = item.split("=", maxsplit=1)
        parts.setdefault(key, []).append(value)

    timestamp_values = parts.get("t") or []
    signatures = parts.get("v1") or []
    if not timestamp_values or not signatures:
        raise WebhookSignatureError("Malformed Stripe signature.")

    timestamp = int(timestamp_values[0])
    if abs(time.time() - timestamp) > tolerance_seconds:
        raise WebhookSignatureError("Expired Stripe signature.")

    signed_payload = f"{timestamp}.{payload.decode('utf-8')}".encode("utf-8")
    expected = hmac.new(secret.encode("utf-8"), signed_payload, hashlib.sha256).hexdigest()
    if not any(hmac.compare_digest(expected, candidate) for candidate in signatures):
        raise WebhookSignatureError("Stripe signature did not match.")


def handle_stripe_webhook(
    *,
    settings: Settings,
    storage: "Storage",
    payload: bytes,
    signature_header: str | None,
) -> dict[str, str]:
    verify_stripe_signature(
        payload=payload,
        signature_header=signature_header,
        secret=settings.stripe_webhook_secret,
    )
    event = json.loads(payload)
    event_type = event.get("type")
    obj = event.get("data", {}).get("object", {})

    if event_type == "checkout.session.completed":
        handle_checkout_completed(settings, storage, obj)
    elif event_type in {"customer.subscription.updated", "customer.subscription.deleted"}:
        handle_subscription_change(settings, storage, obj, deleted=event_type.endswith("deleted"))

    return {"received": "true"}


def handle_checkout_completed(settings: Settings, storage: "Storage", obj: dict[str, Any]) -> None:
    account_id = obj.get("metadata", {}).get("account_id")
    if not account_id:
        return

    plan = normalize_plan(obj.get("metadata", {}).get("plan", "free"))
    customer_id = obj.get("customer")
    subscription_id = obj.get("subscription")
    storage.update_billing(
        account_id=account_id,
        plan=plan,
        stripe_customer_id=customer_id if isinstance(customer_id, str) else None,
        stripe_subscription_id=subscription_id if isinstance(subscription_id, str) else None,
        stripe_subscription_status="active",
    )


def handle_subscription_change(
    settings: Settings,
    storage: "Storage",
    obj: dict[str, Any],
    *,
    deleted: bool,
) -> None:
    account_id = obj.get("metadata", {}).get("account_id")
    account = storage.get_account(account_id) if isinstance(account_id, str) else None
    customer_id = obj.get("customer")
    if account is None and isinstance(customer_id, str):
        account = storage.get_account_by_customer_id(customer_id)
    if account is None:
        return

    status = obj.get("status")
    active = status in {"active", "trialing", "past_due"} and not deleted
    price_id = None
    items = obj.get("items", {}).get("data", [])
    if items:
        price_id = items[0].get("price", {}).get("id")

    storage.update_billing(
        account_id=account.id,
        plan=plan_for_price_id(settings, price_id) if active else "free",
        stripe_customer_id=customer_id if isinstance(customer_id, str) else None,
        stripe_subscription_id=obj.get("id") if isinstance(obj.get("id"), str) else None,
        stripe_subscription_status=status if isinstance(status, str) else None,
    )
