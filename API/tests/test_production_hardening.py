from __future__ import annotations

import asyncio
import json

import httpx
import pytest
from fastapi.testclient import TestClient
from starlette.requests import Request

from inboxready_api.cache import TTLCache, audit_cache
from inboxready_api.main import app
from inboxready_api.middleware import RequestBodyLimitMiddleware
from inboxready_api.models import AuditCheck, DomainAuditRequest, DomainAuditResponse
from inboxready_api.security import rate_limiter, resolve_client_ip, resolve_client_key
from inboxready_api.services import dns_audit
from inboxready_api.services.dns_audit import (
    MAX_MTA_STS_POLICY_BYTES,
    build_mta_sts_check,
    parse_mta_sts_policy,
    validate_mta_sts_policy,
    validate_mta_sts_txt_record,
)
from inboxready_api.services.outbound import ResolvedHttpTarget, UnsafeOutboundTarget
from inboxready_api.services.webhook import (
    UnsafeWebhookTarget,
    deliver_webhook,
    signature_for,
    validate_webhook_target,
)
from inboxready_api.settings import Settings, get_settings

client = TestClient(app)
_HTTPX_CLIENT = httpx.Client


@pytest.fixture(autouse=True)
def _runtime_state(monkeypatch):
    monkeypatch.setenv("INBOXREADY_API_KEYS", "")
    monkeypatch.setenv("INBOXREADY_REQUIRE_API_KEY", "false")
    monkeypatch.setenv("INBOXREADY_RATE_LIMIT_PER_MINUTE", "60")
    monkeypatch.setenv("INBOXREADY_REQUEST_BODY_MAX_BYTES", "1048576")
    monkeypatch.setenv("INBOXREADY_REPORT_UPLOAD_BODY_MAX_BYTES", "37748736")
    monkeypatch.setenv("INBOXREADY_ACCESS_LOG_ENABLED", "false")
    monkeypatch.setenv("INBOXREADY_WEBHOOK_URL", "")
    get_settings.cache_clear()
    rate_limiter.clear()
    rate_limiter.configure(max_buckets=20_000)
    audit_cache.clear()
    yield
    get_settings.cache_clear()
    rate_limiter.clear()
    rate_limiter.configure(max_buckets=20_000)
    audit_cache.clear()


def _request(*, client_ip: str = "203.0.113.10", forwarded: str = "") -> Request:
    headers = []
    if forwarded:
        headers.append((b"x-forwarded-for", forwarded.encode()))
    return Request(
        {
            "type": "http",
            "method": "GET",
            "path": "/v1/providers",
            "headers": headers,
            "client": (client_ip, 12345),
            "scheme": "https",
            "server": ("api.example", 443),
            "query_string": b"",
        }
    )


def _audit_result() -> DomainAuditResponse:
    return DomainAuditResponse(
        domain="example.com",
        score=25,
        overall_status="fail",
        checked_at="2026-09-03T00:00:00Z",
        checks={"dmarc": AuditCheck(status="fail", summary="missing")},
    )


@pytest.mark.parametrize(
    "domain",
    [
        "http://user:password@example.com/path",
        "https://example.com:8443/path",
        "127.0.0.1",
        "bad label.example",
        "ftp://example.com",
    ],
)
def test_invalid_domains_are_rejected_before_audit(domain: str) -> None:
    response = client.post("/v1/audits/email-domain", json={"domain": domain})
    assert response.status_code == 422


def test_domain_and_selector_inputs_are_canonicalized_and_bounded() -> None:
    request = DomainAuditRequest(
        domain="HTTPS://BÜCHER.Example./path",
        selectors=["Selector1", "selector1", "s2"],
        expected_providers=["Google Workspace", "google workspace"],
    )
    assert request.domain == "xn--bcher-kva.example"
    assert request.selectors == ["selector1", "s2"]
    assert request.expected_providers == ["Google Workspace"]

    response = client.post(
        "/v1/audits/email-domain",
        json={"domain": "example.com", "selectors": [f"s{i}" for i in range(21)]},
    )
    assert response.status_code == 422


def test_request_body_limit_rejects_before_validation(monkeypatch) -> None:
    monkeypatch.setenv("INBOXREADY_REQUEST_BODY_MAX_BYTES", "1024")
    get_settings.cache_clear()
    response = client.post(
        "/v1/audits/email-domain",
        content=b"{" + (b"x" * 2048) + b"}",
        headers={"Content-Type": "application/json"},
    )
    assert response.status_code == 413
    assert "1024-byte" in response.json()["detail"]
    assert response.headers["X-Request-Id"]


def test_request_body_limit_also_rejects_chunked_requests(monkeypatch) -> None:
    monkeypatch.setenv("INBOXREADY_REQUEST_BODY_MAX_BYTES", "1024")
    get_settings.cache_clear()
    chunks = (part for part in [b'{"domain":"', b"x" * 2048, b'"}'])
    response = client.post(
        "/v1/audits/email-domain",
        content=chunks,
        headers={"Content-Type": "application/json"},
    )
    assert response.status_code == 413


def test_body_limit_coalesces_empty_asgi_chunks_before_replay() -> None:
    downstream_messages = []

    async def run() -> None:
        incoming = [
            {"type": "http.request", "body": b"", "more_body": True}
            for _ in range(1_000)
        ]
        incoming.append({"type": "http.request", "body": b"{}", "more_body": False})
        sent = []

        async def receive():
            return incoming.pop(0)

        async def send(message):
            sent.append(message)

        async def downstream(scope, receive, send):
            downstream_messages.append(await receive())
            await send({"type": "http.response.start", "status": 204, "headers": []})
            await send({"type": "http.response.body", "body": b""})

        scope = {
            "type": "http",
            "method": "POST",
            "path": "/v1/audits/email-domain",
            "headers": [],
        }
        await RequestBodyLimitMiddleware(downstream)(scope, receive, send)
        assert sent[0]["status"] == 204

    asyncio.run(run())
    assert downstream_messages == [
        {"type": "http.request", "body": b"{}", "more_body": False}
    ]


def test_api_keys_are_compared_securely_and_not_retained_in_bucket() -> None:
    settings = Settings(api_keys="top-secret,second-secret")
    bucket = resolve_client_key(_request(), "top-secret", settings)
    assert bucket.startswith("key-sha256:")
    assert "top-secret" not in bucket

    with pytest.raises(Exception) as caught:
        resolve_client_key(_request(), "not-a-key", settings)
    assert getattr(caught.value, "status_code", None) == 401


def test_required_auth_without_keys_fails_closed() -> None:
    settings = Settings(require_api_key=True, api_keys="")
    for candidate in (None, "made-up-key"):
        with pytest.raises(Exception) as caught:
            resolve_client_key(_request(), candidate, settings)
        assert getattr(caught.value, "status_code", None) == 503


def test_webhook_setting_preserves_trailing_slash() -> None:
    settings = Settings(webhook_url="  https://hooks.example/events/  ")
    assert settings.webhook_url == "https://hooks.example/events/"


def test_open_api_key_header_cannot_bypass_ip_rate_limit(monkeypatch) -> None:
    monkeypatch.setenv("INBOXREADY_RATE_LIMIT_PER_MINUTE", "1")
    get_settings.cache_clear()
    first = client.get("/v1/providers", headers={"X-API-Key": "random-one"})
    second = client.get("/v1/providers", headers={"X-API-Key": "random-two"})
    assert first.status_code == 200
    assert second.status_code == 429
    assert second.headers["Retry-After"] == second.headers["RateLimit-Reset"]


def test_rate_limit_headers_are_returned_on_success(monkeypatch) -> None:
    monkeypatch.setenv("INBOXREADY_RATE_LIMIT_PER_MINUTE", "3")
    get_settings.cache_clear()
    response = client.get("/v1/providers")
    assert response.headers["RateLimit-Limit"] == "3"
    assert response.headers["RateLimit-Remaining"] == "2"
    assert int(response.headers["RateLimit-Reset"]) >= 1


def test_rate_limiter_bounds_client_bucket_memory() -> None:
    rate_limiter.configure(max_buckets=2)
    rate_limiter.check("client-a", 10)
    rate_limiter.check("client-b", 10)
    rate_limiter.check("client-c", 10)
    assert len(rate_limiter) == 2


def test_forwarded_chain_is_used_only_for_a_trusted_direct_peer() -> None:
    settings = Settings(trusted_proxy_cidrs="10.0.0.0/8,192.0.2.0/24")
    trusted = _request(
        client_ip="10.0.0.8",
        forwarded="198.51.100.30, 192.0.2.5",
    )
    assert resolve_client_ip(trusted, settings) == "198.51.100.30"

    untrusted = _request(client_ip="203.0.113.20", forwarded="198.51.100.30")
    assert resolve_client_ip(untrusted, settings) == "203.0.113.20"


def test_request_id_is_bounded_and_server_timing_is_present() -> None:
    response = client.get("/healthz", headers={"X-Request-Id": "bad\nheader"})
    assert response.status_code == 200
    assert response.headers["X-Request-Id"] != "bad\nheader"
    assert len(response.headers["X-Request-Id"]) == 36
    assert response.headers["Server-Timing"].startswith("app;dur=")


def test_cache_evicts_least_recently_used_entry() -> None:
    cache: TTLCache[str] = TTLCache(max_entries=2)
    cache.set("a", "A", 60)
    cache.set("b", "B", 60)
    assert cache.get("a") == "A"
    cache.set("c", "C", 60)
    assert cache.get("b") is None
    assert cache.get("a") == "A"
    assert cache.get("c") == "C"


def test_webhook_target_rejects_private_and_accepts_global_resolution() -> None:
    def private_resolver(*args, **kwargs):
        return [(2, 1, 6, "", ("127.0.0.1", 443))]

    def global_resolver(*args, **kwargs):
        return [(2, 1, 6, "", ("8.8.8.8", 443))]

    with pytest.raises(UnsafeWebhookTarget):
        validate_webhook_target(
            "https://hooks.example/events",
            allow_private_hosts=False,
            resolver=private_resolver,
        )
    assert (
        validate_webhook_target(
            "https://hooks.example/events",
            allow_private_hosts=False,
            resolver=global_resolver,
        )
        == "https://hooks.example/events"
    )


def test_webhook_is_signed_and_retries_transient_response() -> None:
    requests: list[tuple[bytes, dict[str, str], bool]] = []
    statuses = iter([503, 202])

    class FakeClient:
        def __init__(self, *, timeout: float, follow_redirects: bool) -> None:
            self.follow_redirects = follow_redirects

        def __enter__(self):
            return self

        def __exit__(self, *args):
            return None

        def post(self, target: str, *, content: bytes, headers: dict[str, str]):
            requests.append((content, headers, self.follow_redirects))
            return httpx.Response(next(statuses))

    settings = Settings(
        webhook_url="https://hooks.example/events",
        webhook_secret="signing-secret",
        webhook_allow_private_hosts=True,
        webhook_max_attempts=3,
    )
    assert deliver_webhook(_audit_result(), settings, client_factory=FakeClient, sleep=lambda _: None)
    assert len(requests) == 2
    body, headers, follows = requests[-1]
    assert follows is False
    assert headers["X-InboxReady-Signature-256"] == signature_for(body, "signing-secret")
    assert json.loads(body)["event"] == "audit.completed"


def _mta_sts_check(monkeypatch, handler) -> tuple[AuditCheck, list[bool]]:
    redirect_settings: list[bool] = []

    def client_factory(**kwargs):
        redirect_settings.append(kwargs["follow_redirects"])
        return _HTTPX_CLIENT(transport=httpx.MockTransport(handler), **kwargs)

    monkeypatch.setattr(
        dns_audit,
        "resolve_public_http_target",
        lambda url: ResolvedHttpTarget(
            url=url,
            hostname="mta-sts.example.com",
            port=443,
            addresses=("8.8.8.8",),
        ),
    )
    monkeypatch.setattr(dns_audit.httpx, "Client", client_factory)
    check = build_mta_sts_check(
        "example.com",
        ["v=STSv1; id=20260904;"],
        Settings(),
    )
    return check, redirect_settings


def test_mta_sts_fetch_is_bounded_no_redirect_and_policy_validated(monkeypatch) -> None:
    requests: list[httpx.Request] = []
    policy = b"version: STSv1\nmode: enforce\nmx: mx.example.com\nmax_age: 86400\n"

    def valid_policy(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        return httpx.Response(200, headers={"Content-Type": "text/plain; charset=utf-8"}, content=policy)

    check, redirect_settings = _mta_sts_check(monkeypatch, valid_policy)
    assert check.status == "pass"
    assert check.details["policy"]["mode"] == "enforce"
    assert redirect_settings == [False]
    assert len(requests) == 1
    assert requests[0].url.path == "/.well-known/mta-sts.txt"
    assert requests[0].url.host == "8.8.8.8"
    assert requests[0].headers["Host"] == "mta-sts.example.com"
    assert requests[0].extensions["sni_hostname"] == "mta-sts.example.com"


def test_mta_sts_redirect_is_not_followed(monkeypatch) -> None:
    requests = 0

    def redirect(request: httpx.Request) -> httpx.Response:
        nonlocal requests
        requests += 1
        return httpx.Response(302, headers={"Location": "https://elsewhere.example/policy"})

    check, redirect_settings = _mta_sts_check(monkeypatch, redirect)
    assert check.status == "warn"
    assert check.details["policy_fetch_status"] == 302
    assert redirect_settings == [False]
    assert requests == 1


def test_mta_sts_rejects_oversized_or_non_plaintext_policy(monkeypatch) -> None:
    def oversized(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            headers={"Content-Type": "text/plain"},
            content=b"x" * (MAX_MTA_STS_POLICY_BYTES + 1),
        )

    check, _ = _mta_sts_check(monkeypatch, oversized)
    assert check.status == "warn"
    assert "64 KiB" in check.details["policy_fetch_error"]

    def html(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, headers={"Content-Type": "text/html"}, content=b"<html></html>")

    check, _ = _mta_sts_check(monkeypatch, html)
    assert check.status == "warn"
    assert check.details["policy_content_type"] == "text/html"


def test_mta_sts_rejects_private_policy_host_before_http(monkeypatch) -> None:
    def blocked(*args, **kwargs):
        raise UnsafeOutboundTarget("Target resolves to a private or non-global address.")

    monkeypatch.setattr(dns_audit, "resolve_public_http_target", blocked)
    check = build_mta_sts_check(
        "example.com",
        ["v=STSv1; id=20260904;"],
        Settings(),
    )
    assert check.status == "warn"
    assert "private or non-global" in check.details["policy_fetch_error"]


def test_mta_sts_validators_reject_malformed_discovery_and_policy_fields() -> None:
    assert validate_mta_sts_txt_record("v=STSv1; id=release20260904;") == []
    assert validate_mta_sts_txt_record("v=stsv1; id=bad-id;")
    assert validate_mta_sts_txt_record("v=STSv1; id=valid;;")
    assert validate_mta_sts_txt_record("v=STSv1; id=valid; note=not valid;")

    policy = parse_mta_sts_policy(
        "version: wrong\nmode: enforce\nmx: *.*.example.com\nmax_age: 9999999999"
    )
    errors = validate_mta_sts_policy(policy)
    assert any("version" in error for error in errors)
    assert any("mx pattern" in error for error in errors)
    assert any("max_age" in error for error in errors)


def test_mta_sts_invalid_policy_never_passes(monkeypatch) -> None:
    def invalid_policy(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            headers={"Content-Type": "text/plain"},
            content=b"version: STSv1\nmode: enforce\nmax_age: 86400\n",
        )

    check, _ = _mta_sts_check(monkeypatch, invalid_policy)
    assert check.status == "warn"
    assert any("mx pattern" in error for error in check.details["policy_errors"])
