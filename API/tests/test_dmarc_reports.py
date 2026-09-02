"""DMARC aggregate report parsing, analysis, and the rollout decision.

The fixtures are built from the RFC 7489 Appendix C schema rather than copied
from one provider, so a reporter that omits optional elements is covered too.
"""

from __future__ import annotations

import gzip
import io
import zipfile

import pytest

from inboxready_api.services import dmarc_reports as dr
from inboxready_api.services.dmarc_reports import (
    ReportError,
    assess_readiness,
    classify_row,
    decode_report_bytes,
    parse_report,
    parse_reports,
    summarize_reports,
)


def record_xml(
    ip: str,
    count: int,
    *,
    dkim: str = "pass",
    spf: str = "pass",
    disposition: str = "none",
    header_from: str = "example.com",
    selector: str | None = "s1",
) -> str:
    dkim_block = (
        f"<dkim><domain>example.com</domain><result>{dkim}</result>"
        f"<selector>{selector}</selector></dkim>"
        if selector
        else ""
    )
    return f"""
  <record>
    <row>
      <source_ip>{ip}</source_ip>
      <count>{count}</count>
      <policy_evaluated>
        <disposition>{disposition}</disposition>
        <dkim>{dkim}</dkim>
        <spf>{spf}</spf>
      </policy_evaluated>
    </row>
    <identifiers><header_from>{header_from}</header_from></identifiers>
    <auth_results>
      {dkim_block}
      <spf><domain>example.com</domain><result>{spf}</result></spf>
    </auth_results>
  </record>"""


def report_xml(
    records: str,
    *,
    org: str = "google.com",
    policy: str = "none",
    begin: int = 1_767_225_600,
    end: int = 1_767_311_999,
    domain: str = "example.com",
) -> bytes:
    return f"""<?xml version="1.0" encoding="UTF-8"?>
<feedback>
  <report_metadata>
    <org_name>{org}</org_name>
    <email>noreply-dmarc-support@{org}</email>
    <report_id>report-{begin}</report_id>
    <date_range><begin>{begin}</begin><end>{end}</end></date_range>
  </report_metadata>
  <policy_published>
    <domain>{domain}</domain>
    <adkim>r</adkim><aspf>r</aspf>
    <p>{policy}</p><sp>{policy}</sp><pct>100</pct>
  </policy_published>{records}
</feedback>
""".encode()


HEALTHY = report_xml(
    record_xml("192.0.2.10", 900)
    + record_xml("198.51.100.7", 80, spf="fail")  # forwarded: aligned DKIM survives
    + record_xml("203.0.113.9", 20, dkim="fail", spf="fail", selector=None)
)


# --- decoding ---------------------------------------------------------------


class TestDecoding:
    def test_reads_plain_xml(self):
        assert decode_report_bytes(HEALTHY).startswith(b"<?xml")

    def test_reads_gzip(self):
        assert decode_report_bytes(gzip.compress(HEALTHY)) == HEALTHY

    def test_reads_zip(self):
        buffer = io.BytesIO()
        with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as archive:
            archive.writestr("example.com!123!456.xml", HEALTHY)
        assert decode_report_bytes(buffer.getvalue()) == HEALTHY

    def test_rejects_empty_and_oversized_files(self):
        with pytest.raises(ReportError, match="empty"):
            decode_report_bytes(b"")
        with pytest.raises(ReportError, match="larger than"):
            decode_report_bytes(b"x" * (dr.MAX_COMPRESSED_BYTES + 1))

    def test_rejects_a_compression_bomb(self, monkeypatch):
        monkeypatch.setattr(dr, "MAX_DECOMPRESSED_BYTES", 4096)
        bomb = gzip.compress(b"\0" * 200_000)
        assert len(bomb) < 4096, "the bomb must be small enough to pass the input cap"
        with pytest.raises(ReportError, match="size limit"):
            decode_report_bytes(bomb)

    def test_rejects_a_zip_bomb(self, monkeypatch):
        monkeypatch.setattr(dr, "MAX_DECOMPRESSED_BYTES", 4096)
        buffer = io.BytesIO()
        with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as archive:
            archive.writestr("big.xml", b"\0" * 200_000)
        with pytest.raises(ReportError, match="size limit"):
            decode_report_bytes(buffer.getvalue())

    def test_rejects_a_zip_with_too_many_members(self, monkeypatch):
        monkeypatch.setattr(dr, "MAX_ZIP_MEMBERS", 2)
        buffer = io.BytesIO()
        with zipfile.ZipFile(buffer, "w") as archive:
            for index in range(3):
                archive.writestr(f"{index}.xml", b"<feedback/>")
        with pytest.raises(ReportError, match="too many members"):
            decode_report_bytes(buffer.getvalue())

    def test_rejects_corrupt_containers(self):
        with pytest.raises(ReportError, match="gzip"):
            decode_report_bytes(b"\x1f\x8b" + b"not really gzip")
        with pytest.raises(ReportError, match="zip"):
            decode_report_bytes(b"PK\x03\x04" + b"not really a zip")


# --- XML hardening ----------------------------------------------------------


class TestXmlHardening:
    def test_rejects_a_doctype(self):
        payload = b'<?xml version="1.0"?><!DOCTYPE feedback [ ]><feedback/>'
        with pytest.raises(ReportError, match="DTD or entities"):
            parse_report(payload)

    def test_rejects_an_entity_expansion_attack(self):
        payload = (
            b'<?xml version="1.0"?>'
            b'<!DOCTYPE feedback [<!ENTITY a "aaaaaaaaaa">'
            b'<!ENTITY b "&a;&a;&a;&a;&a;&a;&a;&a;&a;&a;">]>'
            b"<feedback><record>&b;</record></feedback>"
        )
        with pytest.raises(ReportError, match="DTD or entities"):
            parse_report(payload)

    def test_rejects_malformed_xml(self):
        with pytest.raises(ReportError, match="well-formed"):
            parse_report(b"<feedback><record>")

    def test_rejects_a_foreign_root_element(self):
        with pytest.raises(ReportError, match="<feedback>"):
            parse_report(b"<html><body/></html>")

    def test_rejects_a_report_with_no_rows(self):
        with pytest.raises(ReportError, match="no <record> rows"):
            parse_report(report_xml(""))


# --- parsing ----------------------------------------------------------------


class TestParsing:
    def test_reads_metadata_policy_and_rows(self):
        report = parse_report(HEALTHY, filename="google.xml")
        assert report.metadata.org_name == "google.com"
        assert report.metadata.source_file == "google.xml"
        assert report.metadata.begin.startswith("2026-01-01")
        assert report.policy_published.domain == "example.com"
        assert report.policy_published.policy == "none"
        assert report.policy_published.percentage == 100
        assert [row.count for row in report.rows] == [900, 80, 20]
        assert report.rows[0].dkim_selectors == ["s1"]

    def test_defaults_survive_a_minimal_reporter(self):
        minimal = b"""<feedback>
          <record><row><source_ip>192.0.2.1</source_ip><count>5</count></row></record>
        </feedback>"""
        report = parse_report(minimal)
        assert report.metadata.org_name == "unknown"
        assert report.policy_published.policy == "none"
        assert report.policy_published.dkim_alignment == "r"
        row = report.rows[0]
        assert row.count == 5
        assert row.dkim == "fail" and row.spf == "fail"

    def test_non_pass_auth_results_collapse_to_fail(self):
        for value in ("softfail", "temperror", "permerror", "none", "neutral", ""):
            report = parse_report(report_xml(record_xml("192.0.2.1", 1, spf=value)))
            assert report.rows[0].spf == "fail", value

    def test_record_count_is_capped(self, monkeypatch):
        monkeypatch.setattr(dr, "MAX_RECORDS", 3)
        report = parse_report(report_xml("".join(record_xml(f"192.0.2.{i}", 1) for i in range(10))))
        assert len(report.rows) == 3

    def test_parse_reports_collects_errors_without_failing_the_batch(self):
        reports, errors = parse_reports([("good.xml", HEALTHY), ("bad.xml", b"nope")])
        assert len(reports) == 1
        assert errors == ["bad.xml: Report is not well-formed XML: syntax error: line 1, column 0"]


# --- classification ---------------------------------------------------------


class TestClassification:
    @pytest.mark.parametrize(
        ("dkim", "spf", "expected"),
        [
            ("pass", "pass", "authenticated"),
            ("pass", "fail", "forwarded"),
            ("fail", "pass", "spf-only"),
            ("fail", "fail", "unauthenticated"),
        ],
    )
    def test_every_combination_has_a_name(self, dkim, spf, expected):
        report = parse_report(report_xml(record_xml("192.0.2.1", 1, dkim=dkim, spf=spf)))
        assert classify_row(report.rows[0]) == expected
        assert expected in dr.CLASSIFICATIONS

    def test_dmarc_passes_when_either_aligned_mechanism_passes(self):
        report = parse_report(
            report_xml(
                record_xml("192.0.2.1", 1, dkim="pass", spf="fail")
                + record_xml("192.0.2.2", 1, dkim="fail", spf="pass")
                + record_xml("192.0.2.3", 1, dkim="fail", spf="fail")
            )
        )
        assert [dr.row_passes(row) for row in report.rows] == [True, True, False]


# --- summary ----------------------------------------------------------------


class TestSummary:
    def test_totals_and_rates(self):
        summary = summarize_reports([parse_report(HEALTHY)])
        assert summary.total_messages == 1000
        assert summary.passing_messages == 980
        assert summary.failing_messages == 20
        assert summary.pass_rate == 0.98
        assert summary.dkim_aligned_rate == 0.98
        assert summary.spf_aligned_rate == 0.9
        assert summary.domains == ["example.com"]
        assert summary.source_count == 3

    def test_sources_are_ranked_by_volume_and_classified(self):
        summary = summarize_reports([parse_report(HEALTHY)])
        assert [source.source_ip for source in summary.sources] == [
            "192.0.2.10",
            "198.51.100.7",
            "203.0.113.9",
        ]
        top, forwarder, rogue = summary.sources
        assert top.classification == "authenticated"
        assert top.volume_share == 0.9
        assert forwarder.classification == "forwarded"
        assert rogue.classification == "unauthenticated"
        assert rogue.failing == 20
        assert rogue.pass_rate == 0.0

    def test_reports_merge_across_reporters_and_windows(self):
        first = parse_report(report_xml(record_xml("192.0.2.10", 100), org="google.com"))
        second = parse_report(
            report_xml(
                record_xml("192.0.2.10", 50) + record_xml("192.0.2.11", 25),
                org="yahoo.com",
                begin=1_767_312_000,
                end=1_767_398_399,
            )
        )
        summary = summarize_reports([first, second])
        assert summary.report_count == 2
        assert summary.reporters == ["google.com", "yahoo.com"]
        assert summary.total_messages == 175
        merged = next(s for s in summary.sources if s.source_ip == "192.0.2.10")
        assert merged.messages == 150
        assert merged.reporters == ["google.com", "yahoo.com"]
        assert summary.window_start.startswith("2026-01-01")
        assert summary.window_end.startswith("2026-01-02")

    def test_dispositions_are_totalled(self):
        summary = summarize_reports(
            [
                parse_report(
                    report_xml(
                        record_xml("192.0.2.1", 10, disposition="none")
                        + record_xml("192.0.2.2", 4, dkim="fail", spf="fail", disposition="quarantine")
                    )
                )
            ]
        )
        assert summary.dispositions == {"none": 10, "quarantine": 4}

    def test_empty_input_is_an_error(self):
        with pytest.raises(ReportError, match="No readable reports"):
            summarize_reports([])


# --- readiness --------------------------------------------------------------


class TestReadiness:
    def test_clean_traffic_is_ready_to_quarantine(self):
        summary = summarize_reports([parse_report(report_xml(record_xml("192.0.2.10", 5000)))])
        readiness = assess_readiness(summary)
        assert readiness.ready is True
        assert readiness.current_policy == "none"
        assert readiness.recommended_policy == "quarantine"
        assert readiness.reasons == []
        assert readiness.recommendations[0].code == "dmarc-advance-policy"

    def test_a_failing_source_with_volume_blocks_the_step(self):
        summary = summarize_reports([parse_report(HEALTHY)])
        readiness = assess_readiness(summary)
        assert readiness.ready is False
        assert readiness.recommended_policy == "none"
        assert [s.source_ip for s in readiness.blocking_sources] == ["203.0.113.9"]
        assert any("203.0.113.9" in reason for reason in readiness.reasons)
        assert any(r.code == "dmarc-unauthenticated-source" for r in readiness.recommendations)

    def test_a_trickle_of_failures_does_not_block(self):
        summary = summarize_reports(
            [
                parse_report(
                    report_xml(
                        record_xml("192.0.2.10", 100_000)
                        + record_xml("203.0.113.9", 9, dkim="fail", spf="fail")
                    )
                )
            ]
        )
        readiness = assess_readiness(summary)
        assert readiness.blocking_sources == []
        assert readiness.ready is True

    def test_forwarding_never_blocks_a_rollout(self):
        summary = summarize_reports(
            [
                parse_report(
                    report_xml(
                        record_xml("192.0.2.10", 4000)
                        + record_xml("198.51.100.7", 1000, spf="fail")
                    )
                )
            ]
        )
        readiness = assess_readiness(summary)
        assert readiness.ready is True
        assert readiness.blocking_sources == []

    def test_spf_only_alignment_is_flagged_as_fragile(self):
        summary = summarize_reports(
            [parse_report(report_xml(record_xml("192.0.2.10", 500, dkim="fail", spf="pass")))]
        )
        readiness = assess_readiness(summary)
        assert [s.source_ip for s in readiness.fragile_sources] == ["192.0.2.10"]
        assert any(r.code == "dmarc-spf-only-alignment" for r in readiness.recommendations)

    def test_too_little_data_is_not_a_green_light(self):
        summary = summarize_reports([parse_report(report_xml(record_xml("192.0.2.10", 12)))])
        readiness = assess_readiness(summary)
        assert readiness.ready is False
        assert any("Only 12 messages" in reason for reason in readiness.reasons)

    def test_reject_needs_a_higher_bar_than_quarantine(self):
        records = record_xml("192.0.2.10", 970) + record_xml(
            "198.51.100.7", 30, dkim="fail", spf="fail"
        )
        summary = summarize_reports([parse_report(report_xml(records, policy="quarantine"))])
        assert summary.pass_rate == 0.97
        readiness = assess_readiness(summary, current_policy="quarantine")
        assert readiness.threshold == dr.REJECT_READY_RATE
        assert readiness.ready is False
        assert any("below the 99%" in reason for reason in readiness.reasons)
        # The same traffic clears the lower quarantine bar.
        assert assess_readiness(summary, current_policy="none").threshold == dr.QUARANTINE_READY_RATE

    def test_reject_is_the_end_of_the_ladder(self):
        summary = summarize_reports([parse_report(report_xml(record_xml("192.0.2.10", 5000)))])
        readiness = assess_readiness(summary, current_policy="reject")
        assert readiness.ready is False
        assert readiness.recommended_policy == "reject"
        assert any("no stricter policy" in reason for reason in readiness.reasons)


# --- API + CLI --------------------------------------------------------------


class TestEndpoint:
    def test_upload_returns_summary_and_readiness(self, client):
        response = client.post(
            "/v1/dmarc/reports",
            files=[("files", ("google.xml.gz", gzip.compress(HEALTHY), "application/gzip"))],
        )
        assert response.status_code == 200
        body = response.json()
        assert body["summary"]["total_messages"] == 1000
        assert body["summary"]["pass_rate"] == 0.98
        assert body["readiness"]["ready"] is False
        assert body["reports"][0]["org_name"] == "google.com"
        assert body["reports"][0]["source_file"] == "google.xml.gz"
        assert body["errors"] == []

    def test_multiple_files_merge_and_bad_ones_are_reported(self, client):
        response = client.post(
            "/v1/dmarc/reports",
            files=[
                ("files", ("a.xml", report_xml(record_xml("192.0.2.10", 600)), "text/xml")),
                ("files", ("b.xml", report_xml(record_xml("192.0.2.10", 400)), "text/xml")),
                ("files", ("junk.txt", b"not xml", "text/plain")),
            ],
        )
        assert response.status_code == 200
        body = response.json()
        assert body["summary"]["total_messages"] == 1000
        assert body["summary"]["source_count"] == 1
        assert len(body["errors"]) == 1 and "junk.txt" in body["errors"][0]

    def test_policy_override_raises_the_bar(self, client):
        files = [("files", ("a.xml", report_xml(record_xml("192.0.2.10", 5000)), "text/xml"))]
        assert client.post("/v1/dmarc/reports", files=files).json()["readiness"][
            "recommended_policy"
        ] == "quarantine"
        response = client.post("/v1/dmarc/reports?policy=quarantine", files=files)
        assert response.json()["readiness"]["recommended_policy"] == "reject"

    def test_an_invalid_policy_is_rejected(self, client):
        response = client.post(
            "/v1/dmarc/reports?policy=banana",
            files=[("files", ("a.xml", HEALTHY, "text/xml"))],
        )
        assert response.status_code == 422

    def test_unreadable_uploads_are_a_422_not_a_500(self, client):
        response = client.post(
            "/v1/dmarc/reports",
            files=[("files", ("junk.txt", b"not a report", "text/plain"))],
        )
        assert response.status_code == 422
        assert "junk.txt" in response.json()["detail"]

    def test_too_many_files_is_refused(self, client):
        files = [("files", (f"{i}.xml", HEALTHY, "text/xml")) for i in range(26)]
        response = client.post("/v1/dmarc/reports", files=files)
        assert response.status_code == 413

    def test_endpoint_is_documented(self, client):
        schema = client.get("/openapi.json").json()
        assert "/v1/dmarc/reports" in schema["paths"]


class TestCli:
    def _write(self, tmp_path):
        (tmp_path / "google.xml.gz").write_bytes(gzip.compress(HEALTHY))
        (tmp_path / "yahoo.xml").write_bytes(
            report_xml(record_xml("192.0.2.10", 500), org="yahoo.com")
        )
        return [str(tmp_path / "google.xml.gz"), str(tmp_path / "yahoo.xml")]

    def test_text_output_and_failing_exit_code(self, tmp_path, capsys):
        from inboxready_api.cli import main

        with pytest.raises(SystemExit) as exit_info:
            main(["dmarc-reports", *self._write(tmp_path)])
        assert exit_info.value.code == 1  # not ready: a rogue source still fails
        output = capsys.readouterr().out
        assert "DMARC aggregate reports for example.com" in output
        assert "203.0.113.9" in output
        assert "NOT READY to leave p=none" in output

    def test_json_output(self, tmp_path, capsys):
        import json as json_module

        from inboxready_api.cli import main

        with pytest.raises(SystemExit):
            main(["dmarc-reports", "--json", *self._write(tmp_path)])
        payload = json_module.loads(capsys.readouterr().out)
        assert payload["summary"]["total_messages"] == 1500
        assert payload["readiness"]["current_policy"] == "none"

    def test_clean_traffic_exits_zero(self, tmp_path, capsys):
        from inboxready_api.cli import main

        path = tmp_path / "clean.xml"
        path.write_bytes(report_xml(record_xml("192.0.2.10", 9000)))
        with pytest.raises(SystemExit) as exit_info:
            main(["dmarc-reports", str(path)])
        assert exit_info.value.code == 0
        assert "READY to move to p=quarantine" in capsys.readouterr().out

    def test_a_missing_file_is_an_error(self, tmp_path, capsys):
        from inboxready_api.cli import main

        with pytest.raises(SystemExit) as exit_info:
            main(["dmarc-reports", str(tmp_path / "nope.xml")])
        assert exit_info.value.code == 2
        assert "no such report file" in capsys.readouterr().err


class TestScoringIsOneTable:
    """The published scoring document and the scorer used to disagree."""

    def test_scoring_document_matches_the_scorer(self):
        from inboxready_api.models import AuditCheck
        from inboxready_api.services.dns_audit import score_checks
        from inboxready_api.services.scoring import CHECK_WEIGHTS, STATUS_SCORE, scoring_document

        document = scoring_document()
        assert document["weights"] == CHECK_WEIGHTS
        assert document["status_multipliers"] == STATUS_SCORE
        assert document["total_weight"] == sum(CHECK_WEIGHTS.values()) == 100

        # Reproduce a published score by hand, exactly as a customer would.
        statuses = {
            "mx": "pass",
            "spf": "warn",
            "dmarc": "fail",
            "dkim": "pass",
            "mta_sts": "info",
            "tls_rpt": "pass",
            "bimi": "warn",
        }
        checks = {
            key: AuditCheck(status=value, summary="", details={}) for key, value in statuses.items()
        }
        weights = document["weights"]
        multipliers = document["status_multipliers"]
        expected = round(
            sum(weights[key] * multipliers[value] for key, value in statuses.items())
            / document["total_weight"]
            * 100
        )
        assert score_checks(checks) == expected

    def test_absent_checks_are_excluded_rather_than_failed(self):
        from inboxready_api.models import AuditCheck
        from inboxready_api.services.dns_audit import score_checks

        passing = AuditCheck(status="pass", summary="", details={})
        assert score_checks({"mx": passing, "spf": passing}) == 100

    def test_advisory_checks_do_not_move_the_score(self):
        from inboxready_api.models import AuditCheck
        from inboxready_api.services.dns_audit import score_checks

        passing = AuditCheck(status="pass", summary="", details={})
        advisory = AuditCheck(status="warn", summary="free mailbox", details={})
        assert score_checks({"mx": passing, "sending_domain": advisory}) == score_checks(
            {"mx": passing}
        )

    def test_endpoint_serves_the_same_table(self, client):
        from inboxready_api.services.scoring import CHECK_WEIGHTS

        payload = client.get("/v1/scoring").json()
        assert payload["weights"] == CHECK_WEIGHTS
