"""Tests for the security hardening added for paid launch:

* SSRF guard in the MTA-STS policy fetch (services/safe_http.py)
* Fail-closed production config validation (settings.py)
* Stripe webhook idempotency (storage.py + billing.py)

None of these tests touch the network.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import socket
import time

import pytest

from inboxready_api import billing
from inboxready_api.services import safe_http
from inboxready_api.services.safe_http import UnsafeRequestError, _validate_url
from inboxready_api.settings import (
    DEFAULT_SESSION_SECRET,
    ProductionConfigError,
    Settings,
)
from inboxready_api.storage import Storage


# --------------------------------------------------------------------------- #
# SSRF guard
# --------------------------------------------------------------------------- #

@pytest.mark.parametrize(
    "url",
    [
        "https://127.0.0.1/.well-known/mta-sts.txt",
        "https://169.254.169.254/latest/meta-data/",  # cloud metadata
        "https://10.0.0.5/",
        "https://192.168.1.1/",
        "https://[::1]/",
        "https://0.0.0.0/",
    ],
)
def test_validate_url_blocks_private_literals(url: str) -> None:
    with pytest.raises(UnsafeRequestError):
        _validate_url(url)


@pytest.mark.parametrize(
    "url",
    [
        "http://example.com/",  # non-https scheme
        "ftp://example.com/",
        "https:///nohost",
    ],
)
def test_validate_url_rejects_bad_scheme_or_host(url: str) -> None:
    with pytest.raises(UnsafeRequestError):
        _validate_url(url)


def test_validate_url_blocks_hostname_resolving_to_private_ip(monkeypatch) -> None:
    def fake_getaddrinfo(host, *args, **kwargs):
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("169.254.169.254", 443))]

    monkeypatch.setattr(safe_http.socket, "getaddrinfo", fake_getaddrinfo)
    with pytest.raises(UnsafeRequestError):
        _validate_url("https://mta-sts.attacker.example/.well-known/mta-sts.txt")


def test_validate_url_rejects_when_any_resolved_ip_is_private(monkeypatch) -> None:
    # DNS returns one public and one internal address; we must refuse rather
    # than race the connection to the internal one.
    def fake_getaddrinfo(host, *args, **kwargs):
        return [
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", 443)),
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("127.0.0.1", 443)),
        ]

    monkeypatch.setattr(safe_http.socket, "getaddrinfo", fake_getaddrinfo)
    with pytest.raises(UnsafeRequestError):
        _validate_url("https://mta-sts.attacker.example/.well-known/mta-sts.txt")


def test_validate_url_allows_public_hostname(monkeypatch) -> None:
    def fake_getaddrinfo(host, *args, **kwargs):
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", 443))]

    monkeypatch.setattr(safe_http.socket, "getaddrinfo", fake_getaddrinfo)
    # Should not raise.
    _validate_url("https://mta-sts.example.com/.well-known/mta-sts.txt")


# --------------------------------------------------------------------------- #
# Production config fails closed
# --------------------------------------------------------------------------- #

def _prod_settings(**overrides) -> Settings:
    base = dict(
        environment="production",
        session_secret="x" * 40,
        session_https_only=True,
        public_base_url="https://inboxready.example",
        allow_private_network_fetches=False,
    )
    base.update(overrides)
    return Settings(**base)


def test_production_rejects_default_session_secret() -> None:
    with pytest.raises(ProductionConfigError):
        _prod_settings(session_secret=DEFAULT_SESSION_SECRET).validate_production_safety()


def test_production_requires_secure_cookies() -> None:
    with pytest.raises(ProductionConfigError):
        _prod_settings(session_https_only=False).validate_production_safety()


def test_production_requires_https_base_url() -> None:
    with pytest.raises(ProductionConfigError):
        _prod_settings(public_base_url="http://inboxready.example").validate_production_safety()


def test_production_rejects_private_network_fetches() -> None:
    with pytest.raises(ProductionConfigError):
        _prod_settings(allow_private_network_fetches=True).validate_production_safety()


def test_valid_production_config_passes() -> None:
    _prod_settings().validate_production_safety()  # no raise


def test_development_config_is_lenient() -> None:
    Settings(environment="development").validate_production_safety()  # no raise


# --------------------------------------------------------------------------- #
# Stripe webhook idempotency
# --------------------------------------------------------------------------- #

def _storage(tmp_path) -> Storage:
    settings = Settings(
        database_path=str(tmp_path / "test.sqlite3"),
        object_store_path=str(tmp_path / "objects"),
        stripe_webhook_secret="whsec_test_secret",
    )
    store = Storage(settings)
    store.init_schema()
    return store, settings


def test_mark_stripe_event_processed_is_idempotent(tmp_path) -> None:
    store, _ = _storage(tmp_path)
    assert store.mark_stripe_event_processed(event_id="evt_1", event_type="x") is True
    assert store.mark_stripe_event_processed(event_id="evt_1", event_type="x") is False
    assert store.mark_stripe_event_processed(event_id="evt_2", event_type="x") is True


def _signed(secret: str, payload: bytes) -> str:
    ts = int(time.time())
    signed = f"{ts}.{payload.decode()}".encode()
    sig = hmac.new(secret.encode(), signed, hashlib.sha256).hexdigest()
    return f"t={ts},v1={sig}"


def test_delete_stripe_event_allows_reprocessing(tmp_path) -> None:
    store, _ = _storage(tmp_path)
    assert store.mark_stripe_event_processed(event_id="evt_x", event_type="t") is True
    store.delete_stripe_event(event_id="evt_x")
    # After deletion the id is treated as unseen again.
    assert store.mark_stripe_event_processed(event_id="evt_x", event_type="t") is True


def test_webhook_rolls_back_event_on_handler_failure(tmp_path, monkeypatch) -> None:
    store, settings = _storage(tmp_path)
    account, _key, _raw = store.create_account(email="rollback@example.com", plan="free")

    event = {
        "id": "evt_fail_1",
        "type": "checkout.session.completed",
        "data": {"object": {"metadata": {"account_id": account.id, "plan": "pro"}}},
    }
    payload = json.dumps(event).encode()
    header = _signed(settings.stripe_webhook_secret, payload)

    # First delivery: the handler blows up transiently.
    def boom(*_args, **_kwargs):
        raise RuntimeError("transient failure")

    monkeypatch.setattr(billing, "handle_checkout_completed", boom)
    with pytest.raises(RuntimeError):
        billing.handle_stripe_webhook(
            settings=settings, storage=store, payload=payload, signature_header=header
        )

    # The event was rolled back, so Stripe's retry (handler now healthy) is
    # reprocessed rather than skipped as a duplicate.
    monkeypatch.undo()
    result = billing.handle_stripe_webhook(
        settings=settings, storage=store, payload=payload, signature_header=header
    )
    assert result == {"received": "true"}
    assert store.get_account(account.id).plan == "pro"


def test_webhook_applies_once_and_skips_replay(tmp_path) -> None:
    store, settings = _storage(tmp_path)
    account, _key, _raw = store.create_account(email="dupe@example.com", plan="free")

    event = {
        "id": "evt_checkout_1",
        "type": "checkout.session.completed",
        "data": {
            "object": {
                "metadata": {"account_id": account.id, "plan": "pro"},
                "customer": "cus_123",
                "subscription": "sub_123",
            }
        },
    }
    payload = json.dumps(event).encode()
    header = _signed(settings.stripe_webhook_secret, payload)

    first = billing.handle_stripe_webhook(
        settings=settings, storage=store, payload=payload, signature_header=header
    )
    assert first == {"received": "true"}
    assert store.get_account(account.id).plan == "pro"

    # Manually downgrade, then replay the SAME event id — a replay must not
    # re-apply the upgrade.
    store.update_billing(account_id=account.id, plan="free")
    second = billing.handle_stripe_webhook(
        settings=settings, storage=store, payload=payload, signature_header=header
    )
    assert second.get("duplicate") == "true"
    assert store.get_account(account.id).plan == "free"
