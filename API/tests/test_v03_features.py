from __future__ import annotations

from fastapi.testclient import TestClient

from inboxready_api.main import app
from inboxready_api.middleware import RequestIdMiddleware
from inboxready_api.services.history import HistoryStore, configure_history, get_history
from inboxready_api.services.report import render_html_report
from inboxready_api.services.scoring import scoring_document
from inboxready_api.models import AuditCheck, DomainAuditResponse


client = TestClient(app)


def test_request_id_header() -> None:
    response = client.get("/healthz")
    assert response.status_code == 200
    assert "X-Request-Id" in response.headers
    assert len(response.headers["X-Request-Id"]) >= 8


def test_scoring_document() -> None:
    doc = scoring_document()
    assert doc["max_score"] == 100
    assert sum(doc["weights"].values()) == 100  # type: ignore[arg-type]
    response = client.get("/v1/scoring")
    assert response.status_code == 200
    assert response.json()["weights"]["dmarc"] == 25


def test_history_store_roundtrip(tmp_path) -> None:
    path = tmp_path / "hist.json"
    store = HistoryStore(max_entries=10, path=path)
    store.add(domain="a.com", score=80, overall_status="pass")
    store.add(domain="b.com", score=40, overall_status="fail")
    assert len(store.list(limit=10)) == 2
    stats = store.stats()
    assert stats["count"] == 2
    assert stats["unique_domains"] == 2
    csv = store.export_csv()
    assert "a.com" in csv and "score" in csv
    # reload
    store2 = HistoryStore(max_entries=10, path=path)
    assert len(store2.list(limit=10)) == 2


def test_html_report_contains_score() -> None:
    result = DomainAuditResponse(
        domain="example.com",
        score=88,
        overall_status="pass",
        checked_at="2026-01-01T00:00:00Z",
        providers=[],
        checks={"mx": AuditCheck(status="pass", summary="ok")},
        recommendations=[],
        references=[],
    )
    html = render_html_report(result)
    assert "88/100" in html
    assert "example.com" in html
    assert "<table>" in html


def test_history_endpoints() -> None:
    configure_history(max_entries=50, path=None)
    get_history().clear()
    get_history().add(domain="z.com", score=55, overall_status="warn")
    r = client.get("/v1/history")
    assert r.status_code == 200
    body = r.json()
    assert body["count"] >= 1
    s = client.get("/v1/history/stats")
    assert s.status_code == 200
    assert "average_score" in s.json()
    csv = client.get("/v1/history/export.csv")
    assert csv.status_code == 200
    assert "text/csv" in csv.headers.get("content-type", "")
