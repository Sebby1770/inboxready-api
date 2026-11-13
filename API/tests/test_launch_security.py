"""Launch regression tests use temporary storage and mocked network transports."""

from concurrent.futures import ThreadPoolExecutor
import socket
import threading

import httpx
import pytest
from fastapi.testclient import TestClient
from pydantic import ValidationError

from inboxready_api import main, observability
from inboxready_api.models import (
    AuditJobCreateRequest, BatchAuditRequest, DomainAuditRequest,
    DomainAuditResponse, MonitorCreateRequest,
)
from inboxready_api.services import dns_audit, safe_http
from inboxready_api.settings import Settings
from inboxready_api.storage import Storage


@pytest.fixture
def isolated_app(tmp_path, monkeypatch):
    settings = Settings(_env_file=None, database_path=str(tmp_path / "security.sqlite3"))
    store = Storage(settings)
    store.init_schema()
    monkeypatch.setattr(main, "storage", lambda: store)
    monkeypatch.setattr(main, "get_settings", lambda: settings)
    with TestClient(main.app) as client:
        yield client, store, settings


def test_job_execution_has_one_owner_and_one_audit(isolated_app, monkeypatch):
    _, store, _ = isolated_app
    account, key, _ = store.create_account(email="jobs@example.com", plan="free")
    job = store.create_audit_job(account_id=account.id, api_key_id=key.id,
                                 payload={"domain": "example.com"})
    entered = threading.Event()
    release = threading.Event()
    calls = []

    def fake_audit(request, settings):
        calls.append(request.domain)
        entered.set()
        assert release.wait(5)
        return DomainAuditResponse(domain=request.domain, score=70, overall_status="warn",
                                   checked_at="2026-11-06T00:00:00Z", checks={})

    monkeypatch.setattr(main, "audit_domain", fake_audit)
    with ThreadPoolExecutor(max_workers=2) as pool:
        winner = pool.submit(main.execute_audit_job, account.id, job.id)
        try:
            assert entered.wait(5)
            assert main.execute_audit_job(account.id, job.id).status == "running"
            assert store.mark_audit_job_running(account_id=account.id, job_id=job.id) is None
            assert main.execute_audit_job("another-account", job.id) is None
        finally:
            release.set()
        assert winner.result(timeout=5).status == "succeeded"
    assert main.execute_audit_job(account.id, job.id).status == "succeeded"
    assert calls == ["example.com"]
    assert len(store.audit_history(account).audits) == 1


@pytest.mark.parametrize("model", [DomainAuditRequest, BatchAuditRequest, MonitorCreateRequest, AuditJobCreateRequest])
@pytest.mark.parametrize("bad_selectors", [[f"s{i}" for i in range(11)], ["x" * 64], ["../../host"], ["bad..label"], [""]])
def test_all_audit_inputs_bound_selectors(model, bad_selectors):
    payload = {"domains": ["example.com"]} if model is BatchAuditRequest else {"domain": "example.com"}
    with pytest.raises(ValidationError):
        model(**payload, selectors=bad_selectors)


def test_selector_normalization_and_provider_bounds():
    valid = DomainAuditRequest(domain="example.com", selectors=[" selector1 ", "key.v2"])
    assert valid.selectors == ["selector1", "key.v2"]
    for providers in [["provider"] * 11, ["x" * 81]]:
        with pytest.raises(ValidationError):
            DomainAuditRequest(domain="example.com", expected_providers=providers)


def test_demo_rejects_selector_fanout_before_network(isolated_app, monkeypatch):
    client, _, _ = isolated_app
    def unexpected(*args):
        pytest.fail("invalid input must not reach DNS work")
    monkeypatch.setattr(main, "audit_domain", unexpected)
    response = client.post("/demo/audit", json={"domain": "example.com", "selectors": ["key"] * 11})
    assert response.status_code == 422


def test_dns_query_budget_and_deadline(monkeypatch):
    now = [100.0]
    monkeypatch.setattr(dns_audit.time, "monotonic", lambda: now[0])
    resolver = dns_audit.AuditResolver(timeout_seconds=5, max_queries=2)
    calls = []
    def resolve(name, record_type, **kwargs):
        calls.append(kwargs)
        return []
    monkeypatch.setattr(resolver.resolver, "resolve", resolve)
    resolver.resolve("example.com", "TXT")
    now[0] = 104.0
    resolver.resolve("example.com", "MX")
    assert calls == [{"lifetime": 3.0, "search": False}, {"lifetime": 1.0, "search": False}]
    with pytest.raises(dns_audit.AuditBudgetExceeded):
        resolver.resolve("example.com", "TXT")
    deadline = dns_audit.AuditResolver(timeout_seconds=1)
    now[0] = 106.0
    with pytest.raises(dns_audit.AuditBudgetExceeded):
        deadline.resolve("example.com", "TXT")


def test_dns_budget_returns_retryable_error_not_false_report(isolated_app, monkeypatch):
    client, _, _ = isolated_app
    def timeout(*args):
        raise dns_audit.AuditBudgetExceeded("DNS audit timed out. Retry later.")
    monkeypatch.setattr(main, "audit_domain", timeout)
    response = client.post("/demo/audit", json={"domain": "example.com"})
    assert response.status_code == 503
    assert response.headers["retry-after"] == "30"
    assert "score" not in response.json()


def test_signup_disabled_blocks_browser_and_api(isolated_app):
    client, store, settings = isolated_app
    settings.public_signup_enabled = False
    assert client.post("/signup", data={"email": "blocked@example.com"}).status_code == 403
    assert client.post("/v1/accounts", json={"email": "blocked@example.com"}).status_code == 403
    assert store.get_account_by_email("blocked@example.com") is None


def test_unknown_routes_and_methods_do_not_expand_metrics(isolated_app, monkeypatch):
    client, _, _ = isolated_app
    monkeypatch.setattr(observability, "_route_counts", {})
    for index in range(30):
        assert client.request(f"UNKNOWN{index}", f"/missing-{index}").status_code == 404
    assert observability.metrics_snapshot()["route_counts"] == {"OTHER __unmatched__": 30}
    for index in range(1000):
        observability.record_request(method="GET", path=f"/route-{index}", status_code=200,
                                     duration_ms=1, request_id="test")
    counts = observability.metrics_snapshot()["route_counts"]
    assert len(counts) == observability._MAX_ROUTE_KEYS
    assert counts["OTHER __overflow__"] > 0
    assert sum(counts.values()) == 1030


def mock_http(monkeypatch, handler):
    client_class = httpx.Client
    options = []
    def client(**kwargs):
        options.append(kwargs)
        return client_class(transport=httpx.MockTransport(handler), **kwargs)
    monkeypatch.setattr(safe_http.httpx, "Client", client)
    return options


def public_dns(monkeypatch, addresses):
    calls = []
    def getaddrinfo(host, *args, **kwargs):
        calls.append(host)
        address = addresses[min(len(calls) - 1, len(addresses) - 1)]
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", (address, 443))]
    monkeypatch.setattr(safe_http.socket, "getaddrinfo", getaddrinfo)
    return calls


def test_policy_fetch_pins_ip_and_preserves_host_and_tls_name(monkeypatch):
    dns_calls = public_dns(monkeypatch, ["93.184.216.34", "127.0.0.1"])
    requests = []
    def respond(request):
        requests.append(request)
        return httpx.Response(200, stream=httpx.ByteStream(b"version: STSv1"))
    options = mock_http(monkeypatch, respond)
    result = safe_http.safe_get("https://mta-sts.example.com/policy", timeout=3, user_agent="test")
    assert result.text == "version: STSv1"
    assert dns_calls == ["mta-sts.example.com"]
    assert requests[0].url.host == "93.184.216.34"
    assert requests[0].url.path == "/policy"
    assert requests[0].headers["host"] == "mta-sts.example.com"
    assert requests[0].extensions["sni_hostname"] == "mta-sts.example.com"
    assert options[0]["trust_env"] is False
    assert options[0]["limits"].max_keepalive_connections == 0
    assert options[0].get("verify", True) is True


def test_redirect_revalidates_before_connecting(monkeypatch):
    dns_calls = public_dns(monkeypatch, ["93.184.216.34", "127.0.0.1"])
    requests = []
    def redirect(request):
        requests.append(request)
        return httpx.Response(302, headers={"Location": "/next"}, stream=httpx.ByteStream(b""))
    mock_http(monkeypatch, redirect)
    with pytest.raises(safe_http.UnsafeRequestError, match="non-public"):
        safe_http.safe_get("https://mta-sts.example.com/policy", timeout=3, user_agent="test")
    assert dns_calls == ["mta-sts.example.com"] * 2
    assert len(requests) == 1


@pytest.mark.parametrize("headers,body", [({}, b"x" * (safe_http._MAX_BYTES + 1)), ({"Content-Encoding": "gzip"}, b"compressed")])
def test_policy_fetch_rejects_oversized_or_compressed_body(monkeypatch, headers, body):
    public_dns(monkeypatch, ["93.184.216.34"])
    mock_http(monkeypatch, lambda request: httpx.Response(200, headers=headers, stream=httpx.ByteStream(body)))
    with pytest.raises(safe_http.UnsafeRequestError):
        safe_http.safe_get("https://mta-sts.example.com/policy", timeout=3, user_agent="test")
