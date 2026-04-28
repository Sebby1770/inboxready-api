from inboxready_api.services.dns_audit import (
    build_bimi_check,
    parse_mta_sts_policy,
    parse_semicolon_tags,
    parse_spf_record,
)
from inboxready_api.models import AuditCheck, BatchAuditRequest, DomainAuditResponse, Recommendation
from inboxready_api.main import app
from inboxready_api.services.batch_audit import summarize_batch, unique_normalized_domains
from inboxready_api.services.provider_detection import detect_providers
from fastapi.testclient import TestClient


client = TestClient(app)


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


def test_unique_normalized_domains_keeps_first_seen_order() -> None:
    domains = unique_normalized_domains(["https://Example.com/app", "example.com", "api.example.com"])

    assert domains == ["example.com", "api.example.com"]


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
        json=BatchAuditRequest(domains=["example.com", "https://openai.com/docs"]).model_dump(),
    )

    assert response.status_code == 200
    payload = response.json()
    assert payload["summary"]["domain_count"] == 2
    assert payload["summary"]["average_score"] == 90.0
    assert [audit["domain"] for audit in payload["audits"]] == ["example.com", "openai.com"]
