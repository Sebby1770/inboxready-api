from __future__ import annotations

from argparse import Namespace
from unittest.mock import MagicMock

import pytest
from fastapi.testclient import TestClient

from inboxready_api import __version__
from inboxready_api.cache import audit_cache
from inboxready_api.cli import EXIT_PASS, run_command
from inboxready_api.main import app
from inboxready_api.models import AuditCheck, DomainAuditResponse, Recommendation
from inboxready_api.security import rate_limiter
from inboxready_api.services.dns_audit import (
    build_bimi_check,
    build_caa_check,
    build_dmarc_check,
    build_spf_check,
    expand_spf,
    extract_mailto_targets,
)
from inboxready_api.services.history import (
    HistoryStore,
    compute_history_delta,
    configure_history,
    get_history,
)
from inboxready_api.services.playbook import build_playbook
from inboxready_api.services.scoring import scoring_document
from inboxready_api.settings import get_settings


client = TestClient(app)

SPF_ZONE = {
    "include.example": ["v=spf1 include:nested.example ~all"],
    "nested.example": ["v=spf1 include:leaf.example ~all"],
    "leaf.example": ["v=spf1 ip4:1.2.3.4 ~all"],
    "loop-a.example": ["v=spf1 include:loop-b.example ~all"],
    "loop-b.example": ["v=spf1 include:loop-a.example ~all"],
    "redir.example": ["v=spf1 ip4:9.9.9.9 -all"],
    "deep-a.example": ["v=spf1 include:deep-b.example ~all"],
    "deep-b.example": ["v=spf1 include:deep-c.example ~all"],
    "deep-c.example": ["v=spf1 include:deep-d.example ~all"],
    "deep-d.example": ["v=spf1 ip4:8.8.8.8 ~all"],
}


@pytest.fixture(autouse=True)
def _reset_runtime_state(monkeypatch):
    get_settings.cache_clear()
    rate_limiter.clear()
    audit_cache.clear()
    monkeypatch.setenv("INBOXREADY_API_KEYS", "")
    monkeypatch.setenv("INBOXREADY_REQUIRE_API_KEY", "false")
    monkeypatch.setenv("INBOXREADY_RATE_LIMIT_PER_MINUTE", "60")
    monkeypatch.setenv("INBOXREADY_CACHE_TTL_SECONDS", "0")
    get_settings.cache_clear()
    configure_history(max_entries=50, path=None)
    get_history().clear()
    yield
    get_settings.cache_clear()
    rate_limiter.clear()
    audit_cache.clear()


def test_version_is_040() -> None:
    assert __version__ == "0.4.0"
    assert scoring_document()["version"] == "0.4"


def test_expand_spf_counts_resolved_lookups_with_dict_resolver() -> None:
    tree = expand_spf("v=spf1 include:include.example ~all", SPF_ZONE)

    assert tree["resolved_lookups"] == 3
    assert tree["cycle"] is False
    assert tree["truncated"] is False
    assert tree["includes"][0]["domain"] == "include.example"
    assert tree["includes"][0]["children"]["includes"][0]["domain"] == "nested.example"


def test_expand_spf_detects_cycles() -> None:
    tree = expand_spf("v=spf1 include:loop-a.example ~all", SPF_ZONE)

    assert tree["cycle"] is True
    assert tree["resolved_lookups"] == 2
    loop_b = tree["includes"][0]["children"]["includes"][0]
    assert loop_b["children"]["includes"][0]["cycle"] is True


def test_expand_spf_stops_at_depth_three() -> None:
    tree = expand_spf("v=spf1 include:deep-a.example ~all", SPF_ZONE)

    assert tree["resolved_lookups"] == 3
    assert tree["truncated"] is True
    deep_c = tree["includes"][0]["children"]["includes"][0]["children"]["includes"][0]
    assert deep_c["domain"] == "deep-c.example"
    assert deep_c["children"]["includes"][0]["truncated"] is True
    assert deep_c["children"]["includes"][0]["domain"] == "deep-d.example"


def test_expand_spf_follows_redirect() -> None:
    tree = expand_spf("v=spf1 redirect=redir.example", SPF_ZONE)

    assert tree["resolved_lookups"] == 1
    assert tree["redirect"]["domain"] == "redir.example"
    assert tree["redirect"]["record"] == "v=spf1 ip4:9.9.9.9 -all"


def test_build_spf_check_attaches_include_tree() -> None:
    check = build_spf_check(
        ["v=spf1 include:include.example ~all"],
        resolve_txt=SPF_ZONE,
    )

    assert check.status == "pass"
    assert check.details["estimated_dns_lookups"] == 1
    assert "include_tree" in check.details
    assert check.details["resolved_dns_lookups"] == 3


def test_build_spf_check_skips_tree_without_resolver() -> None:
    check = build_spf_check(["v=spf1 include:include.example ~all"])
    assert "include_tree" not in check.details


def test_dmarc_2024_parses_alignment_and_mailto_targets() -> None:
    check = build_dmarc_check(
        [
            "v=DMARC1; p=reject; sp=quarantine; pct=100; adkim=s; aspf=r; "
            "rua=mailto:agg@example.com,mailto:ops@example.com; ruf=mailto:for@example.com!10m"
        ]
    )

    assert check.status == "pass"
    assert check.details["p"] == "reject"
    assert check.details["sp"] == "quarantine"
    assert check.details["pct"] == "100"
    assert check.details["adkim"] == "s"
    assert check.details["aspf"] == "r"
    assert check.details["rua"] == ["agg@example.com", "ops@example.com"]
    assert check.details["ruf"] == ["for@example.com"]
    assert check.details["mailto_targets"]["rua"] == ["agg@example.com", "ops@example.com"]


def test_dmarc_2024_p_none_warns() -> None:
    check = build_dmarc_check(["v=DMARC1; p=none; rua=mailto:dmarc@example.com"])
    assert check.status == "warn"
    assert "gmail" in check.summary.lower() or "yahoo" in check.summary.lower()
    assert check.details["p"] == "none"
    assert check.details["rua"] == ["dmarc@example.com"]


def test_dmarc_2024_missing_rua_fails() -> None:
    check = build_dmarc_check(["v=DMARC1; p=quarantine; adkim=r"])
    assert check.status == "fail"
    assert check.details["rua"] == []
    assert check.details["adkim"] == "r"


def test_extract_mailto_targets_strips_scheme_and_size() -> None:
    assert extract_mailto_targets("mailto:reports@example.com!50m") == ["reports@example.com"]


def test_bimi_probe_svg_pass_with_mocked_httpx() -> None:
    client_mock = MagicMock()
    head = MagicMock()
    head.status_code = 200
    head.headers = {"content-type": "image/svg+xml", "content-length": "42"}
    head.content = b"<svg></svg>"
    client_mock.head.return_value = head

    dmarc = AuditCheck(status="pass", summary="ok", details={"policy": "reject"})
    check = build_bimi_check(
        ["v=BIMI1; l=https://cdn.example.com/logo.svg"],
        dmarc,
        http_client=client_mock,
    )

    assert check.status == "pass"
    assert check.details["asset"]["ok"] is True
    assert "svg" in check.details["asset"]["content_type"]
    assert check.details["asset"]["bytes"] == len(b"<svg></svg>")
    client_mock.get.assert_not_called()


def test_bimi_probe_missing_asset_warns() -> None:
    client_mock = MagicMock()
    missing = MagicMock()
    missing.status_code = 404
    missing.headers = {}
    missing.content = b""
    client_mock.head.return_value = missing
    client_mock.get.return_value = missing

    dmarc = AuditCheck(status="pass", summary="ok", details={"policy": "reject"})
    check = build_bimi_check(
        ["v=BIMI1; l=https://cdn.example.com/missing.svg"],
        dmarc,
        http_client=client_mock,
    )

    assert check.status == "warn"
    assert check.details["asset"]["ok"] is False
    client_mock.get.assert_called_once()


def test_bimi_probe_not_used_without_client() -> None:
    dmarc = AuditCheck(status="warn", summary="monitor", details={"policy": "none"})
    check = build_bimi_check(
        ["v=BIMI1; l=https://example.com/logo.svg"],
        dmarc,
    )
    assert check.status == "warn"
    assert "asset" not in check.details


def test_caa_issue_tags_from_injected_records() -> None:
    check = build_caa_check(
        ['0 issue "letsencrypt.org"', '0 issuewild "letsencrypt.org"', '0 iodef "mailto:sec@example.com"']
    )
    assert check.status == "pass"
    assert check.details["issue"] == ["letsencrypt.org"]
    assert "letsencrypt.org" in check.details["issue"]


def test_caa_nxdomain_is_info() -> None:
    check = build_caa_check([], nxdomain=True)
    assert check.status == "info"
    assert check.details["nxdomain"] is True
    assert check.details["issue"] == []


def test_history_delta_between_same_domain_audits() -> None:
    store = HistoryStore()
    first = store.add(
        domain="ex.com",
        score=50,
        overall_status="fail",
        checks={"spf": "fail", "dmarc": "fail"},
    )
    assert first.score_delta is None
    second = store.add(
        domain="ex.com",
        score=80,
        overall_status="warn",
        checks={"spf": "pass", "dmarc": "fail"},
    )
    assert second.score_delta == 30
    assert second.changed_checks == ["spf"]

    listed = store.list(domain="ex.com", limit=10)
    assert listed[0].score_delta == 30
    assert listed[0].changed_checks == ["spf"]
    assert listed[1].score_delta is None


def test_compute_history_delta_without_previous() -> None:
    delta, changed = compute_history_delta(90, {"mx": "pass"}, None)
    assert delta is None
    assert changed == []


def test_audit_endpoint_attaches_score_delta(monkeypatch) -> None:
    scores = iter([40, 70])

    def fake_audit(request, settings):
        score = next(scores)
        return DomainAuditResponse(
            domain=request.domain,
            score=score,
            overall_status="fail" if score < 50 else "warn",
            checked_at="2026-08-18T00:00:00+00:00",
            providers=[],
            checks={
                "spf": AuditCheck(status="fail" if score < 50 else "pass", summary="spf"),
                "dmarc": AuditCheck(status="fail", summary="dmarc"),
            },
            recommendations=[],
            references=[],
        )

    monkeypatch.setattr("inboxready_api.main.audit_domain", fake_audit)

    first = client.post("/v1/audits/email-domain", json={"domain": "delta.example"})
    assert first.status_code == 200
    assert first.json()["score_delta"] is None

    second = client.post("/v1/audits/email-domain", json={"domain": "delta.example"})
    assert second.status_code == 200
    body = second.json()
    assert body["score"] == 70
    assert body["score_delta"] == 30
    assert "spf" in body["changed_checks"]

    history = client.get("/v1/history", params={"domain": "delta.example"})
    entries = history.json()["entries"]
    assert entries[0]["score_delta"] == 30
    assert "spf" in entries[0]["changed_checks"]


def test_playbook_groups_by_effort() -> None:
    checks = {
        "spf": AuditCheck(status="fail", summary="No SPF record found."),
        "dmarc": AuditCheck(status="warn", summary="p=none", details={"p": "none"}),
        "tls_rpt": AuditCheck(status="info", summary="No TLS-RPT record found."),
        "mta_sts": AuditCheck(status="info", summary="No MTA-STS TXT record found."),
        "mx": AuditCheck(status="pass", summary="Found MX."),
    }
    recs = [
        Recommendation(severity="high", code="spf-missing", message="Add a single SPF record."),
        Recommendation(
            severity="medium",
            code="dmarc-monitoring-only",
            message="Move DMARC toward quarantine.",
        ),
        Recommendation(severity="low", code="tls-rpt-missing", message="Add TLS-RPT."),
    ]

    book = build_playbook(checks, recs)
    assert any(item["check"] == "spf" for item in book["quick"])
    assert any(item["check"] == "tls_rpt" for item in book["quick"])
    assert any(item["check"] == "dmarc" for item in book["half-day"])
    assert any(item["check"] == "mta_sts" for item in book["project"])
    assert all(item["check"] != "mx" for group in book.values() for item in group)


def test_playbook_endpoint_from_post_body() -> None:
    response = client.post(
        "/v1/playbook",
        json={
            "domain": "play.example",
            "checks": {
                "spf": {"status": "fail", "summary": "No SPF record found."},
                "bimi": {"status": "info", "summary": "No BIMI record found."},
            },
            "recommendations": [
                {
                    "severity": "high",
                    "code": "spf-missing",
                    "message": "Add a single SPF record for the domain.",
                }
            ],
        },
    )
    assert response.status_code == 200
    body = response.json()
    assert body["domain"] == "play.example"
    assert any(item["check"] == "spf" for item in body["quick"])
    assert any(item["check"] == "bimi" for item in body["project"])


def test_playbook_get_uses_audit(monkeypatch) -> None:
    monkeypatch.setattr(
        "inboxready_api.main.audit_domain",
        lambda request, settings: DomainAuditResponse(
            domain=request.domain,
            score=20,
            overall_status="fail",
            checked_at="2026-08-18T00:00:00+00:00",
            providers=[],
            checks={"dmarc": AuditCheck(status="fail", summary="No DMARC record found.")},
            recommendations=[
                Recommendation(
                    severity="high",
                    code="dmarc-missing",
                    message="Publish a DMARC record, even if you start with p=none.",
                )
            ],
            references=[],
        ),
    )
    response = client.get("/v1/playbook/need-dmarc.example")
    assert response.status_code == 200
    assert any(item["check"] == "dmarc" for item in response.json()["quick"])


def test_cli_delta_prints_last_two_scores(tmp_path, monkeypatch, capsys) -> None:
    path = tmp_path / "hist.json"
    store = HistoryStore(max_entries=10, path=path)
    store.add(domain="example.com", score=40, overall_status="fail", checks={"spf": "fail"})
    store.add(domain="example.com", score=70, overall_status="warn", checks={"spf": "pass"})

    monkeypatch.setenv("INBOXREADY_HISTORY_PATH", str(path))
    get_settings.cache_clear()

    code = run_command(
        Namespace(command="delta", domain="example.com", json=False, out=None, timeout=None)
    )
    assert code == EXIT_PASS
    output = capsys.readouterr().out
    assert "40" in output
    assert "70" in output


def test_workspace_script_includes_sparkline_and_delta() -> None:
    from pathlib import Path

    script = (
        Path(__file__).resolve().parents[1]
        / "src"
        / "inboxready_api"
        / "static"
        / "js"
        / "app.js"
    ).read_text(encoding="utf-8")
    assert "score_delta" in script
    assert "score-sparkline" in script
    assert "/v1/history" in script
