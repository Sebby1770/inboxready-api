from inboxready_api.services.dns_audit import (
    build_bimi_check,
    parse_mta_sts_policy,
    parse_semicolon_tags,
    parse_spf_record,
)
import re
from threading import Lock
from time import sleep
from uuid import uuid4

import pytest
from inboxready_api.main import app
from inboxready_api.models import (
    AuditCheck,
    BatchAuditResponse,
    BatchAuditRequest,
    DomainAuditRequest,
    DomainAuditResponse,
    Recommendation,
)
from inboxready_api.services.batch_audit import (
    audit_domains,
    summarize_batch,
    unique_normalized_domains,
)
from inboxready_api.services.provider_detection import detect_providers
from inboxready_api.security import verify_password
from inboxready_api.settings import Settings
from fastapi.testclient import TestClient
from pydantic import ValidationError


client = TestClient(app)
CSRF_PATTERN = re.compile(r'name="csrf_token" value="([^"]+)"')


def csrf_token(browser: TestClient, path: str) -> str:
    response = browser.get(path)
    assert response.status_code == 200
    match = CSRF_PATTERN.search(response.text)
    assert match is not None
    return match.group(1)


def provision_api_key(plan: str = "free") -> str:
    response = client.post(
        "/v1/accounts",
        json={
            "email": f"test-{uuid4()}@example.com",
            "plan": plan,
            "key_name": "pytest",
        },
    )
    assert response.status_code == 200
    return response.json()["api_key"]


def test_parse_spf_record_counts_direct_lookups() -> None:
    record = "v=spf1 include:_spf.google.com include:mailgun.org a mx ~all"
    parsed = parse_spf_record(record)

    assert parsed["estimated_dns_lookups"] == 4
    assert parsed["include_count"] == 2
    assert parsed["all_mechanism"] == "~all"


def test_parse_semicolon_tags_handles_dmarc_style_records() -> None:
    tags = parse_semicolon_tags("v=DMARC1; p=quarantine; rua=mailto:dmarc@example.com; pct=100")

    assert tags["v"] == "DMARC1"
    assert tags["p"] == "quarantine"
    assert tags["rua"] == "mailto:dmarc@example.com"
    assert tags["pct"] == "100"


def test_parse_mta_sts_policy_supports_multiple_mx_lines() -> None:
    policy = parse_mta_sts_policy(
        "version: STSv1\nmode: enforce\nmx: mx1.example.com\nmx: mx2.example.com\nmax_age: 86400"
    )

    assert policy["version"] == "STSv1"
    assert policy["mode"] == "enforce"
    assert policy["mx"] == ["mx1.example.com", "mx2.example.com"]
    assert policy["max_age"] == "86400"


def test_detect_providers_uses_dns_evidence() -> None:
    providers = detect_providers(
        [
            "v=spf1 include:_spf.google.com include:sendgrid.net ~all",
            "1 aspmx.l.google.com.",
        ]
    )

    names = [provider.name for provider in providers]
    assert "Google Workspace" in names
    assert "SendGrid" in names


def test_bimi_warns_when_dmarc_not_enforced() -> None:
    dmarc_check = AuditCheck(
        status="warn",
        summary="DMARC in monitoring mode.",
        details={"policy": "none"},
    )

    bimi_check = build_bimi_check(
        ["v=BIMI1; l=https://example.com/logo.svg; a=https://example.com/vmc.pem"],
        dmarc_check,
    )

    assert bimi_check.status == "warn"


def test_root_returns_html() -> None:
    response = client.get("/")

    assert response.status_code == 200
    assert "text/html" in response.headers["content-type"]
    assert "InboxReady" in response.text


def test_workspace_page_renders() -> None:
    response = client.get("/app")

    assert response.status_code == 200
    assert "Run Domain Audit" in response.text


def test_changelog_page_renders() -> None:
    response = client.get("/changelog")

    assert response.status_code == 200
    assert "Track what changed" in response.text
    assert "v0.3.0" in response.text
    assert "Roadmap" in response.text


def test_unique_normalized_domains_keeps_first_seen_order() -> None:
    domains = unique_normalized_domains(["https://Example.com/app", "example.com", "api.example.com"])

    assert domains == ["example.com", "api.example.com"]


def test_domain_input_is_canonicalized() -> None:
    request = DomainAuditRequest(domain="https://Bücher.example/path?q=1")

    assert request.domain == "xn--bcher-kva.example"


@pytest.mark.parametrize(
    "domain",
    ["localhost", "127.0.0.1", "bad_domain.example", "example.com:443"],
)
def test_domain_input_rejects_unsafe_or_invalid_hosts(domain: str) -> None:
    with pytest.raises(ValidationError):
        DomainAuditRequest(domain=domain)


def test_batch_summary_prioritizes_repeated_high_severity_recommendations() -> None:
    audits = [
        DomainAuditResponse(
            domain="alpha.example",
            score=20,
            overall_status="fail",
            checked_at="2026-04-28T00:00:00+00:00",
            providers=[],
            checks={},
            recommendations=[
                Recommendation(
                    severity="high",
                    code="dmarc-missing",
                    message="Publish a DMARC record, even if you start with p=none.",
                )
            ],
            references=[],
        ),
        DomainAuditResponse(
            domain="bravo.example",
            score=80,
            overall_status="warn",
            checked_at="2026-04-28T00:00:00+00:00",
            providers=[],
            checks={},
            recommendations=[
                Recommendation(
                    severity="high",
                    code="dmarc-missing",
                    message="Publish a DMARC record, even if you start with p=none.",
                )
            ],
            references=[],
        ),
    ]

    summary = summarize_batch(audits)

    assert summary.domain_count == 2
    assert summary.average_score == 50.0
    assert summary.status_counts["fail"] == 1
    assert summary.status_counts["warn"] == 1
    assert summary.priority_recommendations[0].code == "dmarc-missing"
    assert summary.priority_recommendations[0].affected_domains == ["alpha.example", "bravo.example"]


def test_batch_endpoint_accepts_multiple_domains(monkeypatch) -> None:
    def fake_audit_domain(request, settings):
        return DomainAuditResponse(
            domain=request.domain,
            score=90,
            overall_status="pass",
            checked_at="2026-04-28T00:00:00+00:00",
            providers=[],
            checks={},
            recommendations=[],
            references=[],
        )

    monkeypatch.setattr("inboxready_api.services.batch_audit.audit_domain", fake_audit_domain)

    response = client.post(
        "/v1/audits/batch",
        headers={"Authorization": f"Bearer {provision_api_key()}"},
        json=BatchAuditRequest(domains=["example.com", "https://openai.com/docs"]).model_dump(),
    )

    assert response.status_code == 200
    payload = response.json()
    assert payload["summary"]["domain_count"] == 2
    assert payload["summary"]["average_score"] == 90.0
    assert [audit["domain"] for audit in payload["audits"]] == ["example.com", "openai.com"]


def test_batch_audits_run_concurrently_and_preserve_order(monkeypatch) -> None:
    lock = Lock()
    active = 0
    max_active = 0

    def fake_audit_domain(request, settings):
        nonlocal active, max_active
        with lock:
            active += 1
            max_active = max(max_active, active)
        sleep(0.03)
        with lock:
            active -= 1
        return DomainAuditResponse(
            domain=request.domain,
            score=90,
            overall_status="pass",
            checked_at="2026-04-28T00:00:00+00:00",
            providers=[],
            checks={},
            recommendations=[],
            references=[],
        )

    monkeypatch.setattr("inboxready_api.services.batch_audit.audit_domain", fake_audit_domain)
    request = BatchAuditRequest(
        domains=["alpha.example", "bravo.example", "charlie.example"]
    )

    result = audit_domains(request, Settings(batch_max_workers=3))

    assert max_active >= 2
    assert [audit.domain for audit in result.audits] == [
        "alpha.example",
        "bravo.example",
        "charlie.example",
    ]


def test_audit_endpoint_requires_api_key() -> None:
    response = client.post("/v1/audits/email-domain", json={"domain": "example.com"})

    assert response.status_code == 401


def test_public_account_creation_rejects_unpaid_paid_plan() -> None:
    response = client.post(
        "/v1/accounts",
        json={"email": f"paid-{uuid4()}@example.com", "plan": "growth"},
    )

    assert response.status_code == 400


def test_account_creation_validates_email() -> None:
    response = client.post(
        "/v1/accounts",
        json={"email": "not-an-email", "plan": "free"},
    )

    assert response.status_code == 422


def test_api_keys_can_be_listed_and_revoked() -> None:
    primary_key = provision_api_key()
    headers = {"Authorization": f"Bearer {primary_key}"}
    created = client.post(
        "/v1/api-keys",
        headers=headers,
        json={"name": "Temporary integration"},
    )
    assert created.status_code == 200
    temporary_key = created.json()["api_key"]
    temporary_key_id = created.json()["key"]["id"]

    listed = client.get("/v1/api-keys", headers=headers)
    assert listed.status_code == 200
    assert temporary_key_id in {key["id"] for key in listed.json()["keys"]}

    revoked = client.delete(f"/v1/api-keys/{temporary_key_id}", headers=headers)
    assert revoked.status_code == 200
    assert revoked.json()["revoked_at"] is not None

    rejected = client.get(
        "/v1/usage",
        headers={"Authorization": f"Bearer {temporary_key}"},
    )
    assert rejected.status_code == 401


def test_audit_history_limit_is_bounded() -> None:
    api_key = provision_api_key()
    response = client.get(
        "/v1/audit-history?limit=101",
        headers={"Authorization": f"Bearer {api_key}"},
    )

    assert response.status_code == 422


def test_readiness_checks_storage() -> None:
    response = client.get("/readyz")

    assert response.status_code == 200
    assert response.json() == {"status": "ready", "storage": "ok"}


def test_api_root_exposes_changelog_metadata() -> None:
    response = client.get("/api")

    assert response.status_code == 200
    payload = response.json()
    assert payload["changelog"] == "/changelog"
    assert payload["latest_release"]["version"] == "0.3.0"


def test_account_usage_and_history_are_metered(monkeypatch) -> None:
    def fake_audit_domain(request, settings):
        return DomainAuditResponse(
            domain=request.domain,
            score=88,
            overall_status="pass",
            checked_at="2026-04-28T00:00:00+00:00",
            providers=[],
            checks={},
            recommendations=[],
            references=[],
        )

    monkeypatch.setattr("inboxready_api.main.audit_domain", fake_audit_domain)
    api_key = provision_api_key()
    headers = {"Authorization": f"Bearer {api_key}"}

    response = client.post("/v1/audits/email-domain", headers=headers, json={"domain": "example.com"})

    assert response.status_code == 200
    usage = client.get("/v1/usage", headers=headers)
    assert usage.status_code == 200
    assert usage.json()["audits_used"] >= 1

    history = client.get("/v1/audit-history", headers=headers)
    assert history.status_code == 200
    assert history.json()["audits"][0]["domain"] == "example.com"
    audit_id = history.json()["audits"][0]["id"]

    detail = client.get(f"/v1/audit-history/{audit_id}", headers=headers)
    assert detail.status_code == 200
    assert detail.json()["audit"]["domain"] == "example.com"
    assert detail.json()["units"] == 1

    csv_export = client.get("/v1/audit-history.csv", headers=headers)
    assert csv_export.status_code == 200
    assert "text/csv" in csv_export.headers["content-type"]
    assert "domain,score,overall_status" in csv_export.text
    assert "example.com" in csv_export.text


def test_demo_endpoint_does_not_require_api_key(monkeypatch) -> None:
    def fake_audit_domain(request, settings):
        return DomainAuditResponse(
            domain=request.domain,
            score=72,
            overall_status="warn",
            checked_at="2026-04-28T00:00:00+00:00",
            providers=[],
            checks={},
            recommendations=[],
            references=[],
        )

    monkeypatch.setattr("inboxready_api.main.audit_domain", fake_audit_domain)

    response = client.post("/demo/audit", json={"domain": "example.com"})

    assert response.status_code == 200
    assert response.json()["score"] == 72


def test_signup_creates_session_and_dashboard_access() -> None:
    browser = TestClient(app)
    email = f"signup-{uuid4()}@example.com"
    token = csrf_token(browser, "/signup")
    response = browser.post(
        "/signup",
        data={
            "csrf_token": token,
            "email": email,
            "password": "LaunchPass123",
            "key_name": "Dashboard key",
            "next": "/dashboard",
        },
        follow_redirects=False,
    )

    assert response.status_code == 303
    assert response.headers["location"] == "/dashboard"

    dashboard = browser.get("/dashboard")
    assert dashboard.status_code == 200
    assert email in dashboard.text
    assert "Store this API key now" in dashboard.text
    assert "/dashboard/audit-history.csv" in dashboard.text


def test_dashboard_redirects_when_not_logged_in() -> None:
    anonymous = TestClient(app)
    response = anonymous.get("/dashboard", follow_redirects=False)

    assert response.status_code == 303
    assert response.headers["location"].startswith("/login")


def test_support_form_accepts_submission() -> None:
    browser = TestClient(app)
    token = csrf_token(browser, "/support")
    response = browser.post(
        "/support",
        data={
            "csrf_token": token,
            "email": f"support-{uuid4()}@example.com",
            "subject": "Need help with onboarding",
            "message": "We are configuring a customer domain and need help understanding the audit output.",
        },
        follow_redirects=False,
    )

    assert response.status_code == 303
    assert response.headers["location"] == "/support"


def test_session_forms_reject_missing_csrf_token() -> None:
    browser = TestClient(app)
    response = browser.post(
        "/signup",
        data={
            "email": f"csrf-{uuid4()}@example.com",
            "password": "LaunchPass123",
            "key_name": "Blocked key",
        },
    )

    assert response.status_code == 403
    assert response.json()["detail"] == "Invalid CSRF token."


def test_pages_include_defensive_security_headers() -> None:
    response = TestClient(app).get("/")

    assert response.headers["x-content-type-options"] == "nosniff"
    assert response.headers["x-frame-options"] == "DENY"
    assert "frame-ancestors 'none'" in response.headers["content-security-policy"]


@pytest.mark.parametrize(
    "encoded",
    [
        "not-a-password-hash",
        "pbkdf2_sha256$nope$00$00",
        "pbkdf2_sha256$999999999$00$00",
    ],
)
def test_malformed_password_hashes_fail_closed(encoded: str) -> None:
    assert verify_password("LaunchPass123", encoded) is False


def test_dashboard_batch_audit_uses_session(monkeypatch) -> None:
    authenticated = TestClient(app)
    email = f"batch-session-{uuid4()}@example.com"
    signup_token = csrf_token(authenticated, "/signup")
    signup = authenticated.post(
        "/signup",
        data={
            "csrf_token": signup_token,
            "email": email,
            "password": "LaunchPass123",
            "key_name": "Dashboard key",
            "next": "/dashboard",
        },
        follow_redirects=False,
    )
    assert signup.status_code == 303

    def fake_audit_domains(request, settings):
        return BatchAuditResponse(
            audits=[
                DomainAuditResponse(
                    domain="example.com",
                    score=91,
                    overall_status="pass",
                    checked_at="2026-04-28T00:00:00+00:00",
                    providers=[],
                    checks={},
                    recommendations=[],
                    references=[],
                )
            ],
            summary={
                "domain_count": 1,
                "average_score": 91.0,
                "status_counts": {"pass": 1},
                "priority_recommendations": [],
            },
        )

    monkeypatch.setattr("inboxready_api.main.audit_domains", fake_audit_domains)

    dashboard_token = csrf_token(authenticated, "/dashboard")
    response = authenticated.post(
        "/dashboard/audits/batch",
        headers={"X-CSRF-Token": dashboard_token},
        json={"domains": ["example.com"], "selectors": [], "expected_providers": []},
    )

    assert response.status_code == 200
    assert response.json()["summary"]["average_score"] == 91.0
