from __future__ import annotations

from unittest.mock import MagicMock

import pytest
from fastapi.testclient import TestClient

from inboxready_api.cache import audit_cache, make_audit_cache_key
from inboxready_api.cli import EXIT_FAIL, EXIT_PASS, main as cli_main, run_command
from inboxready_api.main import app
from inboxready_api.models import (
    AuditCheck,
    DomainAuditRequest,
    DomainAuditResponse,
    Recommendation,
)
from inboxready_api.security import rate_limiter
from inboxready_api.services.dns_audit import audit_domain
from inboxready_api.services.free_email import is_free_email_domain
from inboxready_api.services.report import render_markdown_report
from inboxready_api.settings import Settings, get_settings


client = TestClient(app)


@pytest.fixture(autouse=True)
def _reset_runtime_state(monkeypatch):
    """Isolate settings cache, rate limiter, and audit cache between tests."""
    get_settings.cache_clear()
    rate_limiter.clear()
    audit_cache.clear()
    monkeypatch.setenv("INBOXREADY_API_KEYS", "")
    monkeypatch.setenv("INBOXREADY_REQUIRE_API_KEY", "false")
    monkeypatch.setenv("INBOXREADY_RATE_LIMIT_PER_MINUTE", "60")
    monkeypatch.setenv("INBOXREADY_CACHE_TTL_SECONDS", "300")
    get_settings.cache_clear()
    yield
    get_settings.cache_clear()
    rate_limiter.clear()
    audit_cache.clear()


def _fake_query_records(resolver, name: str, record_type: str) -> list[str]:
    name = name.lower()
    if record_type == "MX" and name == "good.example":
        return ["10 mail.good.example."]
    if record_type == "TXT" and name == "good.example":
        return ["v=spf1 include:_spf.google.com ~all"]
    if record_type == "TXT" and name == "_dmarc.good.example":
        return ["v=DMARC1; p=quarantine; rua=mailto:dmarc@good.example"]
    if record_type == "TXT" and name.endswith("._domainkey.good.example"):
        if name.startswith("google."):
            return ["v=DKIM1; k=rsa; p=abc"]
        return []
    if record_type == "CNAME" and name.endswith("._domainkey.good.example"):
        return []
    if record_type == "TXT" and name.startswith("_mta-sts."):
        return []
    if record_type == "TXT" and name.startswith("_smtp._tls."):
        return []
    if record_type == "TXT" and name.startswith("default._bimi."):
        return []
    return []


def test_is_free_email_domain_detects_common_providers() -> None:
    assert is_free_email_domain("gmail.com") is True
    assert is_free_email_domain("mailinator.com") is True
    assert is_free_email_domain("GMail.COM") is True
    assert is_free_email_domain("custombrand.io") is False
    assert is_free_email_domain("acme-corp.example") is False


def test_free_email_warning_in_audit(monkeypatch) -> None:
    monkeypatch.setattr(
        "inboxready_api.services.dns_audit.query_records",
        lambda *args, **kwargs: [],
    )
    result = audit_domain(DomainAuditRequest(domain="gmail.com"), Settings())
    assert "sending_domain" in result.checks
    assert result.checks["sending_domain"].status == "warn"
    assert any(item.code == "free-email-domain" for item in result.recommendations)


def test_full_audit_scoring_with_mocked_dns(monkeypatch) -> None:
    monkeypatch.setattr(
        "inboxready_api.services.dns_audit.query_records",
        _fake_query_records,
    )
    result = audit_domain(
        DomainAuditRequest(domain="good.example", selectors=["google"]),
        Settings(),
    )
    assert result.domain == "good.example"
    assert result.checks["mx"].status == "pass"
    assert result.checks["spf"].status == "pass"
    assert result.checks["dmarc"].status == "pass"
    assert result.checks["dkim"].status == "pass"
    assert result.score >= 70
    assert result.overall_status in {"pass", "warn"}


def test_markdown_report_contains_score_and_checks() -> None:
    result = DomainAuditResponse(
        domain="example.com",
        score=74,
        overall_status="warn",
        checked_at="2026-04-28T00:00:00+00:00",
        providers=[],
        checks={
            "mx": AuditCheck(status="pass", summary="Found MX."),
            "spf": AuditCheck(status="pass", summary="SPF ok."),
            "dmarc": AuditCheck(status="warn", summary="Monitoring only."),
        },
        recommendations=[
            Recommendation(
                severity="medium",
                code="dmarc-monitoring-only",
                message="Move toward quarantine.",
            )
        ],
        references=[],
    )
    md = render_markdown_report(result)
    assert "# InboxReady Audit: example.com" in md
    assert "**Score:** 74/100" in md
    assert "| dmarc | warn |" in md
    assert "dmarc-monitoring-only" in md


def test_audit_cache_hit_header(monkeypatch) -> None:
    call_count = {"n": 0}

    def fake_audit(request, settings):
        call_count["n"] += 1
        return DomainAuditResponse(
            domain=request.domain,
            score=88,
            overall_status="pass",
            checked_at="2026-04-28T00:00:00+00:00",
            providers=[],
            checks={"mx": AuditCheck(status="pass", summary="ok")},
            recommendations=[],
            references=[],
        )

    monkeypatch.setattr("inboxready_api.main.audit_domain", fake_audit)

    first = client.post("/v1/audits/email-domain", json={"domain": "cache-test.example"})
    second = client.post("/v1/audits/email-domain", json={"domain": "cache-test.example"})

    assert first.status_code == 200
    assert first.headers.get("X-Cache") == "MISS"
    assert second.status_code == 200
    assert second.headers.get("X-Cache") == "HIT"
    assert call_count["n"] == 1
    assert first.json()["score"] == 88


def test_cache_clear_endpoint(monkeypatch) -> None:
    monkeypatch.setattr(
        "inboxready_api.main.audit_domain",
        lambda request, settings: DomainAuditResponse(
            domain=request.domain,
            score=10,
            overall_status="fail",
            checked_at="2026-04-28T00:00:00+00:00",
            providers=[],
            checks={},
            recommendations=[],
            references=[],
        ),
    )
    client.post("/v1/audits/email-domain", json={"domain": "clear-me.example"})
    assert len(audit_cache) >= 1

    cleared = client.post("/v1/cache/clear")
    assert cleared.status_code == 200
    assert cleared.json()["cleared"] >= 1
    assert len(audit_cache) == 0


def test_api_key_rejection(monkeypatch) -> None:
    monkeypatch.setenv("INBOXREADY_API_KEYS", "secret-key-one,secret-key-two")
    get_settings.cache_clear()

    missing = client.get("/v1/providers")
    assert missing.status_code == 401

    bad = client.get("/v1/providers", headers={"X-API-Key": "wrong"})
    assert bad.status_code == 401

    good = client.get("/v1/providers", headers={"X-API-Key": "secret-key-one"})
    assert good.status_code == 200
    assert "providers" in good.json()


def test_require_api_key_without_configured_keys(monkeypatch) -> None:
    monkeypatch.setenv("INBOXREADY_API_KEYS", "")
    monkeypatch.setenv("INBOXREADY_REQUIRE_API_KEY", "true")
    get_settings.cache_clear()

    response = client.get("/v1/providers")
    assert response.status_code == 401


def test_rate_limit_returns_429(monkeypatch) -> None:
    monkeypatch.setenv("INBOXREADY_RATE_LIMIT_PER_MINUTE", "2")
    get_settings.cache_clear()
    rate_limiter.clear()

    assert client.get("/v1/providers").status_code == 200
    assert client.get("/v1/providers").status_code == 200
    limited = client.get("/v1/providers")
    assert limited.status_code == 429


def test_compare_endpoint(monkeypatch) -> None:
    def fake_audit(request, settings):
        score = 90 if request.domain == "a.example" else 40
        status = "pass" if score >= 70 else "fail"
        return DomainAuditResponse(
            domain=request.domain,
            score=score,
            overall_status=status,
            checked_at="2026-04-28T00:00:00+00:00",
            providers=[],
            checks={
                "mx": AuditCheck(
                    status="pass" if request.domain == "a.example" else "fail",
                    summary="mx",
                ),
                "spf": AuditCheck(status="pass", summary="spf"),
            },
            recommendations=[],
            references=[],
        )

    monkeypatch.setattr("inboxready_api.services.compare.audit_domain", fake_audit)

    response = client.post(
        "/v1/compare",
        json={"domains": ["a.example", "b.example"]},
    )
    assert response.status_code == 200
    payload = response.json()
    assert len(payload["domains"]) == 2
    assert any(diff["differs"] for diff in payload["check_diffs"])


def test_markdown_format_query(monkeypatch) -> None:
    monkeypatch.setattr(
        "inboxready_api.main.audit_domain",
        lambda request, settings: DomainAuditResponse(
            domain=request.domain,
            score=55,
            overall_status="warn",
            checked_at="2026-04-28T00:00:00+00:00",
            providers=[],
            checks={"mx": AuditCheck(status="pass", summary="Found MX.")},
            recommendations=[],
            references=[],
        ),
    )
    response = client.post(
        "/v1/audits/email-domain?format=markdown",
        json={"domain": "md.example"},
    )
    assert response.status_code == 200
    assert "text/markdown" in response.headers["content-type"]
    assert "# InboxReady Audit: md.example" in response.text
    assert response.headers.get("X-Cache") == "MISS"


def test_report_md_route(monkeypatch) -> None:
    monkeypatch.setattr(
        "inboxready_api.main.audit_domain",
        lambda request, settings: DomainAuditResponse(
            domain=request.domain,
            score=60,
            overall_status="warn",
            checked_at="2026-04-28T00:00:00+00:00",
            providers=[],
            checks={"spf": AuditCheck(status="fail", summary="No SPF.")},
            recommendations=[],
            references=[],
        ),
    )
    response = client.get("/v1/audit/report-me.example/report.md")
    assert response.status_code == 200
    assert "report-me.example" in response.text


def test_healthz_and_readyz_include_version() -> None:
    health = client.get("/healthz")
    assert health.status_code == 200
    assert health.json()["status"] == "ok"
    assert "version" in health.json()

    ready = client.get("/readyz")
    assert ready.status_code == 200
    assert ready.json()["status"] == "ready"
    assert "version" in ready.json()


def test_make_audit_cache_key_sorts_selectors() -> None:
    a = make_audit_cache_key("Example.COM", ["b", "a"], ["Z", "y"])
    b = make_audit_cache_key("example.com", ["a", "b"], ["y", "Z"])
    assert a == b


def test_cli_version(capsys) -> None:
    with pytest.raises(SystemExit) as exc:
        cli_main(["version"])
    assert exc.value.code == EXIT_PASS
    assert capsys.readouterr().out.strip()


def test_cli_audit_exit_codes(monkeypatch) -> None:
    monkeypatch.setattr(
        "inboxready_api.cli.audit_domain",
        lambda request, settings: DomainAuditResponse(
            domain=request.domain,
            score=10,
            overall_status="fail",
            checked_at="2026-04-28T00:00:00+00:00",
            providers=[],
            checks={},
            recommendations=[],
            references=[],
        ),
    )
    from argparse import Namespace

    args = Namespace(
        command="audit",
        domains=["fail.example"],
        selectors="",
        expected_providers="",
        json=False,
        format="json",
        out=None,
        timeout=None,
    )
    assert run_command(args) == EXIT_FAIL

    monkeypatch.setattr(
        "inboxready_api.cli.audit_domain",
        lambda request, settings: DomainAuditResponse(
            domain=request.domain,
            score=95,
            overall_status="pass",
            checked_at="2026-04-28T00:00:00+00:00",
            providers=[],
            checks={},
            recommendations=[],
            references=[],
        ),
    )
    assert run_command(args) == EXIT_PASS


def test_cli_compare_and_markdown_out(tmp_path, monkeypatch) -> None:
    def fake_compare(request, settings):
        from inboxready_api.models import CompareCheckDiff, CompareResponse, DomainScoreSummary

        return CompareResponse(
            domains=[
                DomainScoreSummary(domain="a.com", score=80, overall_status="pass"),
                DomainScoreSummary(domain="b.com", score=20, overall_status="fail"),
            ],
            check_diffs=[
                CompareCheckDiff(
                    check="mx",
                    statuses={"a.com": "pass", "b.com": "fail"},
                    summaries={"a.com": "ok", "b.com": "missing"},
                    differs=True,
                )
            ],
            audits=[],
        )

    monkeypatch.setattr("inboxready_api.cli.compare_domains", fake_compare)
    out = tmp_path / "compare.json"
    from argparse import Namespace

    code = run_command(
        Namespace(
            command="compare",
            domains=["a.com", "b.com"],
            selectors="",
            expected_providers="",
            json=True,
            format=None,
            out=str(out),
            timeout=None,
        )
    )
    assert code == EXIT_FAIL
    assert out.exists()
    assert "a.com" in out.read_text()
