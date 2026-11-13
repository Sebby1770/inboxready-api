"""Regression coverage for the acquisition-to-billing journey; no network calls."""
import html
import json
import re
from urllib.parse import parse_qs, urlsplit

import pytest
from fastapi.testclient import TestClient

from inboxready_api import billing, main
from inboxready_api.commerce import PLAN_LIMITS
from inboxready_api.settings import Settings
from inboxready_api.site_content import PRICING_TIERS
from inboxready_api.storage import Storage


@pytest.fixture
def launch(tmp_path, monkeypatch):
    settings = Settings(database_path=str(tmp_path / "launch.sqlite3"),
                        object_store_path=str(tmp_path / "exports"),
                        public_base_url="https://api.example.test", stripe_secret_key=None)
    store = Storage(settings)
    store.init_schema()
    monkeypatch.setattr(main, "storage", lambda: store)
    monkeypatch.setattr(main, "get_settings", lambda: settings)
    return TestClient(main.app), store, settings


def csrf(response):
    return re.search(r'name="csrf_token" value="([^"]+)"', response.text).group(1)


def test_pricing_selection_survives_signup_and_key_is_one_time(launch):
    browser, _, _ = launch
    tier = next(t for t in PRICING_TIERS if t["name"] == "Growth")
    signup = browser.get(tier["signup_url"])
    next_path = html.unescape(re.search(r'name="next" value="([^"]+)"', signup.text).group(1))
    assert next_path == "/dashboard?plan=growth#billing"
    login_link = html.unescape(re.search(r'href="(/login\?next=[^"]+)"', signup.text).group(1))
    assert parse_qs(urlsplit(login_link).query)["next"] == [next_path]
    result = browser.post("/signup", data={"csrf_token": csrf(signup), "email": "new@example.com",
                          "password": "Example-Test-Password123", "next": next_path}, follow_redirects=False)
    assert result.headers["location"] == next_path
    dashboard = browser.get(next_path)
    assert "You selected <strong>Growth</strong>" in dashboard.text
    assert 'id="new-api-key"' in dashboard.text
    assert 'id="new-api-key"' not in browser.get("/dashboard").text


def test_volume_calculator_uses_enforced_limits_and_real_origin(launch):
    browser, _, _ = launch
    response = browser.get("/")
    catalog = json.loads(re.search(r'id="plan-catalog">(.*?)</script>', response.text, re.S).group(1))
    assert {name: p["limit"] for name, p in catalog.items()} == {name: p.monthly_audits for name, p in PLAN_LIMITS.items()}
    assert "https://api.example.test/v1/audits/email-domain" in response.text
    assert "https://api.inboxready.dev" not in response.text


def test_signed_out_dashboard_keeps_valid_plan_and_discards_invalid_plan(launch):
    browser, _, _ = launch
    response = browser.get("/dashboard?plan=pro", follow_redirects=False)
    assert parse_qs(urlsplit(response.headers["location"]).query)["next"] == ["/dashboard?plan=pro"]
    response = browser.get("/dashboard?plan=https://evil.example", follow_redirects=False)
    assert parse_qs(urlsplit(response.headers["location"]).query)["next"] == ["/dashboard"]


def test_checkout_returns_to_dashboard_and_blocks_duplicate_subscriptions(launch, monkeypatch):
    _, store, settings = launch
    settings.stripe_secret_key = "sk_test_placeholder"
    settings.stripe_webhook_secret = "test-only-webhook"
    settings.stripe_growth_price_id = "price_growth"
    account, _, _ = store.create_account(email="billing@example.com", plan="free")
    calls = []
    def fake_post(settings, path, data):
        calls.append(data)
        return {"url": "https://checkout.stripe.com/test"}
    monkeypatch.setattr(billing, "stripe_post", fake_post)
    billing.create_checkout_session(settings, account, "growth")
    assert calls[0]["success_url"].endswith("/dashboard?checkout=success#billing")
    assert calls[0]["cancel_url"].endswith("/dashboard?checkout=cancelled#billing")
    store.update_billing(account_id=account.id, plan="growth", stripe_customer_id="cus_test",
                         stripe_subscription_id="sub_test", stripe_subscription_status="active")
    with pytest.raises(billing.BillingConfigurationError, match="existing subscription"):
        billing.create_checkout_session(settings, store.get_account(account.id), "pro")
    assert len(calls) == 1


def test_checkout_requires_webhook_before_contacting_stripe(launch, monkeypatch):
    _, store, settings = launch
    settings.stripe_secret_key = "sk_test_placeholder"
    settings.stripe_growth_price_id = "price_test"
    settings.stripe_webhook_secret = None
    account, _, _ = store.create_account(email="pending@example.com", plan="free")
    monkeypatch.setattr(billing, "stripe_post", lambda *args: pytest.fail("checkout must stay closed"))
    with pytest.raises(billing.BillingConfigurationError, match="webhook"):
        billing.create_checkout_session(settings, account, "growth")


def test_checkout_query_parameter_cannot_upgrade_account(launch):
    browser, store, _ = launch
    page = browser.get("/signup")
    browser.post("/signup", data={"csrf_token": csrf(page), "email": "return@example.com",
                                "password": "Example-Test-Password123"})
    page = browser.get("/dashboard?checkout=success")
    assert "after payment confirmation arrives" in page.text
    assert "FREE" in page.text
