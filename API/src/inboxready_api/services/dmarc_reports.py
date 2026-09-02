"""Parse and interpret DMARC aggregate (RUA) reports.

A DNS audit answers *"is DMARC published?"*. It cannot answer the question that
actually blocks a rollout: *"if I move from ``p=none`` to ``p=quarantine``,
whose mail breaks?"* Only the aggregate reports mailbox providers send back
carry that, and they arrive as gzipped XML that nobody reads.

This module turns a pile of those files into the rollout decision:

* :func:`parse_report` reads one report (raw XML, gzip, or zip) into
  :class:`~inboxready_api.models.DmarcAggregateReport`.
* :func:`summarize_reports` merges reports over a window and classifies every
  sending source.
* :func:`assess_readiness` says whether the next policy step is safe, and names
  the sources that would break if it is not.

Report files are attacker-influenced input — anyone can email you one — so the
readers are bounded on every axis: compressed size, decompressed size, member
count, record count, and XML shape. Entity and DOCTYPE declarations are
rejected outright rather than handed to the XML parser.

References: RFC 7489 (DMARC) §7.2 and Appendix C for the aggregate report
schema; RFC 7489 §6.6.3 for what ``policy_evaluated`` actually means.
"""

from __future__ import annotations

import gzip
import io
import ipaddress
import zipfile
from collections import defaultdict
from collections.abc import Iterable, Sequence
from datetime import UTC, datetime
from xml.etree import ElementTree

from inboxready_api.models import (
    DmarcAggregateReport,
    DmarcPolicyPublished,
    DmarcReadiness,
    DmarcReportMetadata,
    DmarcReportRow,
    DmarcSource,
    DmarcSummary,
    Recommendation,
)

#: Largest report file accepted, before decompression.
MAX_COMPRESSED_BYTES = 8 * 1024 * 1024
#: Largest XML accepted after decompression. Guards against a compression bomb.
MAX_DECOMPRESSED_BYTES = 64 * 1024 * 1024
#: Largest number of ``<record>`` elements read from one report.
MAX_RECORDS = 50_000
#: Largest number of members read from a zip container.
MAX_ZIP_MEMBERS = 32

#: A source must send at least this many messages before its failures are
#: treated as a rollout blocker rather than background noise.
BLOCKER_MIN_VOLUME = 10
#: Share of total volume a failing source must exceed to block a rollout.
BLOCKER_MIN_SHARE = 0.001
#: Aligned pass rate required before recommending the next policy step.
QUARANTINE_READY_RATE = 0.95
REJECT_READY_RATE = 0.99

_GZIP_MAGIC = b"\x1f\x8b"
_ZIP_MAGIC = b"PK\x03\x04"

PASS = "pass"
FAIL = "fail"

#: How a sending source relates to the domain's authentication.
CLASSIFICATIONS = ("authenticated", "forwarded", "spf-only", "unauthenticated")


class ReportError(ValueError):
    """A report file could not be read. The message is safe to show a user."""


# --- decoding ---------------------------------------------------------------


def _decompress_gzip(data: bytes) -> bytes:
    """Decompress with a hard output cap, so a small file cannot fill memory."""
    out = bytearray()
    try:
        with gzip.GzipFile(fileobj=io.BytesIO(data)) as handle:
            while True:
                chunk = handle.read(1024 * 256)
                if not chunk:
                    break
                out.extend(chunk)
                if len(out) > MAX_DECOMPRESSED_BYTES:
                    raise ReportError("Report expands beyond the size limit.")
    except ReportError:
        raise
    except (OSError, EOFError) as exc:
        raise ReportError(f"Not a readable gzip report: {exc}") from exc
    return bytes(out)


def _decompress_zip(data: bytes) -> bytes:
    try:
        with zipfile.ZipFile(io.BytesIO(data)) as archive:
            members = [info for info in archive.infolist() if not info.is_dir()]
            if not members:
                raise ReportError("Zip archive contains no report.")
            if len(members) > MAX_ZIP_MEMBERS:
                raise ReportError("Zip archive contains too many members.")
            # Trust the central directory only as a first filter; the read below
            # is still capped, because a crafted header can understate the size.
            total = sum(info.file_size for info in members)
            if total > MAX_DECOMPRESSED_BYTES:
                raise ReportError("Report expands beyond the size limit.")
            member = max(members, key=lambda info: info.file_size)
            with archive.open(member) as handle:
                payload = handle.read(MAX_DECOMPRESSED_BYTES + 1)
    except ReportError:
        raise
    except (zipfile.BadZipFile, OSError) as exc:
        raise ReportError(f"Not a readable zip report: {exc}") from exc
    if len(payload) > MAX_DECOMPRESSED_BYTES:
        raise ReportError("Report expands beyond the size limit.")
    return payload


def decode_report_bytes(data: bytes) -> bytes:
    """Return the XML inside ``data``, decompressing gzip or zip if needed."""
    if not data:
        raise ReportError("Report file is empty.")
    if len(data) > MAX_COMPRESSED_BYTES:
        raise ReportError("Report file is larger than the accepted limit.")
    if data[:2] == _GZIP_MAGIC:
        return _decompress_gzip(data)
    if data[:4] == _ZIP_MAGIC:
        return _decompress_zip(data)
    return data


# --- XML ---------------------------------------------------------------------


def _parse_xml(payload: bytes) -> ElementTree.Element:
    head = payload[:4096].lstrip()
    # ElementTree does not resolve external entities, but a DOCTYPE is never
    # present in a legitimate aggregate report, so refuse it rather than reason
    # about the parser's behaviour.
    if b"<!DOCTYPE" in head or b"<!ENTITY" in payload[:65536]:
        raise ReportError("Report declares a DTD or entities and was rejected.")
    try:
        root = ElementTree.fromstring(payload)
    except ElementTree.ParseError as exc:
        raise ReportError(f"Report is not well-formed XML: {exc}") from exc
    if root.tag.rsplit("}", 1)[-1] != "feedback":
        raise ReportError("Report root element is not <feedback>.")
    return root


def _text(node: ElementTree.Element | None, path: str, default: str = "") -> str:
    if node is None:
        return default
    found = node.find(path)
    if found is None or found.text is None:
        return default
    return found.text.strip()


def _int(node: ElementTree.Element | None, path: str, default: int = 0) -> int:
    raw = _text(node, path)
    if not raw:
        return default
    try:
        return int(float(raw))
    except ValueError:
        return default


def _epoch_to_iso(value: int) -> str:
    if value <= 0:
        return ""
    try:
        return datetime.fromtimestamp(value, tz=UTC).isoformat()
    except (OverflowError, OSError, ValueError):
        return ""


def _normalize_result(value: str) -> str:
    """Collapse reporter spellings onto pass/fail.

    ``policy_evaluated`` is defined as pass or fail; ``auth_results`` can carry
    the fuller set from RFC 7601 (``none``, ``temperror``, ``permerror``,
    ``softfail``, ``neutral``). Anything that is not an explicit pass is treated
    as a non-pass, which is how a receiver treats it too.
    """
    return PASS if value.strip().lower() == PASS else FAIL


def _valid_ip(value: str) -> str:
    candidate = value.strip()
    if not candidate:
        return ""
    try:
        return str(ipaddress.ip_address(candidate))
    except ValueError:
        return candidate[:64]


def parse_report(data: bytes, *, filename: str | None = None) -> DmarcAggregateReport:
    """Read one aggregate report file into a structured report.

    Accepts raw XML, gzip, or zip. Raises :class:`ReportError` with a message
    that is safe to show the uploader.
    """
    root = _parse_xml(decode_report_bytes(data))

    meta_node = root.find("report_metadata")
    date_range = meta_node.find("date_range") if meta_node is not None else None
    begin = _int(date_range, "begin")
    end = _int(date_range, "end")
    metadata = DmarcReportMetadata(
        org_name=_text(meta_node, "org_name", "unknown"),
        email=_text(meta_node, "email"),
        report_id=_text(meta_node, "report_id"),
        begin=_epoch_to_iso(begin),
        end=_epoch_to_iso(end),
        source_file=filename or "",
    )

    policy_node = root.find("policy_published")
    policy = DmarcPolicyPublished(
        domain=_text(policy_node, "domain").lower(),
        policy=(_text(policy_node, "p") or "none").lower(),
        subdomain_policy=(_text(policy_node, "sp") or None),
        percentage=_int(policy_node, "pct", 100),
        dkim_alignment=(_text(policy_node, "adkim") or "r").lower(),
        spf_alignment=(_text(policy_node, "aspf") or "r").lower(),
    )

    rows: list[DmarcReportRow] = []
    for index, record in enumerate(root.findall("record")):
        if index >= MAX_RECORDS:
            break
        row_node = record.find("row")
        evaluated = row_node.find("policy_evaluated") if row_node is not None else None
        identifiers = record.find("identifiers")
        auth = record.find("auth_results")

        dkim_domains: list[str] = []
        dkim_selectors: list[str] = []
        if auth is not None:
            for dkim in auth.findall("dkim"):
                domain = _text(dkim, "domain").lower()
                selector = _text(dkim, "selector")
                if domain:
                    dkim_domains.append(domain)
                if selector:
                    dkim_selectors.append(selector)

        count = max(0, _int(row_node, "count", 0))
        rows.append(
            DmarcReportRow(
                source_ip=_valid_ip(_text(row_node, "source_ip")),
                count=count,
                disposition=(_text(evaluated, "disposition") or "none").lower(),
                dkim=_normalize_result(_text(evaluated, "dkim")),
                spf=_normalize_result(_text(evaluated, "spf")),
                header_from=_text(identifiers, "header_from").lower(),
                envelope_from=_text(identifiers, "envelope_from").lower(),
                dkim_domains=dkim_domains,
                dkim_selectors=dkim_selectors,
                spf_domain=_text(auth.find("spf") if auth is not None else None, "domain").lower(),
            )
        )

    if not rows:
        raise ReportError("Report contains no <record> rows.")

    return DmarcAggregateReport(metadata=metadata, policy_published=policy, rows=rows)


def parse_reports(files: Iterable[tuple[str, bytes]]) -> tuple[list[DmarcAggregateReport], list[str]]:
    """Parse many files, collecting per-file errors instead of failing the batch."""
    reports: list[DmarcAggregateReport] = []
    errors: list[str] = []
    for name, data in files:
        try:
            reports.append(parse_report(data, filename=name))
        except ReportError as exc:
            errors.append(f"{name or 'report'}: {exc}")
    return reports, errors


# --- analysis ----------------------------------------------------------------


def classify_row(row: DmarcReportRow) -> str:
    """Describe how a source authenticated, using the evaluated (aligned) results.

    ``policy_evaluated`` already accounts for alignment, so a DKIM pass here
    means *aligned* DKIM — which is what survives forwarding, and what a
    rollout decision has to be based on.
    """
    if row.dkim == PASS and row.spf == PASS:
        return "authenticated"
    if row.dkim == PASS:
        # Aligned DKIM survived but SPF did not: the classic forwarding shape.
        return "forwarded"
    if row.spf == PASS:
        # Passes DMARC today, but breaks the moment a message is forwarded.
        return "spf-only"
    return "unauthenticated"


def row_passes(row: DmarcReportRow) -> bool:
    """DMARC passes when either aligned mechanism passes (RFC 7489 §6.6.3)."""
    return row.dkim == PASS or row.spf == PASS


def summarize_reports(reports: Sequence[DmarcAggregateReport]) -> DmarcSummary:
    """Merge reports into one view of who is sending and whether it authenticates."""
    if not reports:
        raise ReportError("No readable reports were supplied.")

    totals = {
        "messages": 0,
        "passing": 0,
        "dkim_aligned": 0,
        "spf_aligned": 0,
    }
    dispositions: dict[str, int] = defaultdict(int)
    by_ip: dict[str, dict[str, object]] = {}
    domains: set[str] = set()
    org_names: set[str] = set()
    begins: list[str] = []
    ends: list[str] = []

    for report in reports:
        if report.policy_published.domain:
            domains.add(report.policy_published.domain)
        org_names.add(report.metadata.org_name)
        if report.metadata.begin:
            begins.append(report.metadata.begin)
        if report.metadata.end:
            ends.append(report.metadata.end)

        for row in report.rows:
            count = row.count
            totals["messages"] += count
            dispositions[row.disposition] += count
            if row_passes(row):
                totals["passing"] += count
            if row.dkim == PASS:
                totals["dkim_aligned"] += count
            if row.spf == PASS:
                totals["spf_aligned"] += count

            entry = by_ip.setdefault(
                row.source_ip,
                {
                    "messages": 0,
                    "passing": 0,
                    "dkim_aligned": 0,
                    "spf_aligned": 0,
                    "classifications": defaultdict(int),
                    "dispositions": defaultdict(int),
                    "header_domains": set(),
                    "dkim_domains": set(),
                    "selectors": set(),
                    "reporters": set(),
                },
            )
            entry["messages"] = int(entry["messages"]) + count
            if row_passes(row):
                entry["passing"] = int(entry["passing"]) + count
            if row.dkim == PASS:
                entry["dkim_aligned"] = int(entry["dkim_aligned"]) + count
            if row.spf == PASS:
                entry["spf_aligned"] = int(entry["spf_aligned"]) + count
            entry["classifications"][classify_row(row)] += count  # type: ignore[index]
            entry["dispositions"][row.disposition] += count  # type: ignore[index]
            if row.header_from:
                entry["header_domains"].add(row.header_from)  # type: ignore[union-attr]
            for domain in row.dkim_domains:
                entry["dkim_domains"].add(domain)  # type: ignore[union-attr]
            for selector in row.dkim_selectors:
                entry["selectors"].add(selector)  # type: ignore[union-attr]
            entry["reporters"].add(report.metadata.org_name)  # type: ignore[union-attr]

    total_messages = totals["messages"]
    sources: list[DmarcSource] = []
    for ip, entry in by_ip.items():
        messages = int(entry["messages"])
        passing = int(entry["passing"])
        classifications: dict[str, int] = dict(entry["classifications"])  # type: ignore[arg-type]
        dominant = max(classifications.items(), key=lambda item: (item[1], item[0]))[0]
        sources.append(
            DmarcSource(
                source_ip=ip,
                messages=messages,
                passing=passing,
                failing=messages - passing,
                pass_rate=_ratio(passing, messages),
                volume_share=_ratio(messages, total_messages),
                dkim_aligned=int(entry["dkim_aligned"]),
                spf_aligned=int(entry["spf_aligned"]),
                classification=dominant,
                classifications=classifications,
                dispositions=dict(entry["dispositions"]),  # type: ignore[arg-type]
                header_domains=sorted(entry["header_domains"]),  # type: ignore[arg-type]
                dkim_domains=sorted(entry["dkim_domains"]),  # type: ignore[arg-type]
                selectors=sorted(entry["selectors"]),  # type: ignore[arg-type]
                reporters=sorted(entry["reporters"]),  # type: ignore[arg-type]
            )
        )

    sources.sort(key=lambda source: (-source.messages, source.source_ip))
    policies = {report.policy_published.policy for report in reports}

    return DmarcSummary(
        domains=sorted(domains),
        policies=sorted(policies),
        reporters=sorted(org_names),
        report_count=len(reports),
        window_start=min(begins) if begins else "",
        window_end=max(ends) if ends else "",
        total_messages=total_messages,
        passing_messages=totals["passing"],
        failing_messages=total_messages - totals["passing"],
        pass_rate=_ratio(totals["passing"], total_messages),
        dkim_aligned_rate=_ratio(totals["dkim_aligned"], total_messages),
        spf_aligned_rate=_ratio(totals["spf_aligned"], total_messages),
        dispositions=dict(dispositions),
        source_count=len(sources),
        sources=sources,
    )


def _ratio(part: int, whole: int) -> float:
    if whole <= 0:
        return 0.0
    return round(part / whole, 4)


def _next_policy(current: str) -> str | None:
    return {"none": "quarantine", "quarantine": "reject"}.get(current)


def assess_readiness(summary: DmarcSummary, *, current_policy: str | None = None) -> DmarcReadiness:
    """Decide whether the next DMARC policy step is safe, and say what blocks it.

    The gate is deliberately conservative: enough volume to judge, a high
    aligned pass rate, and no meaningful source still failing. Forwarding
    (aligned DKIM, failed SPF) does not block anything, because it already
    passes DMARC.
    """
    policy = (current_policy or (summary.policies[0] if summary.policies else "none")).lower()
    target = _next_policy(policy)

    blockers = [
        source
        for source in summary.sources
        if source.failing >= BLOCKER_MIN_VOLUME
        and source.volume_share >= BLOCKER_MIN_SHARE
        and source.classification == "unauthenticated"
    ]
    fragile = [source for source in summary.sources if source.classification == "spf-only"]
    threshold = REJECT_READY_RATE if target == "reject" else QUARANTINE_READY_RATE

    reasons: list[str] = []
    if target is None:
        ready = False
        reasons.append("Already at p=reject; there is no stricter policy to move to.")
    else:
        if summary.total_messages < 100:
            reasons.append(
                f"Only {summary.total_messages} messages in this window. "
                "Collect at least a week of reports before changing policy."
            )
        if summary.pass_rate < threshold:
            reasons.append(
                f"Aligned pass rate is {summary.pass_rate:.1%}, below the "
                f"{threshold:.0%} needed for p={target}."
            )
        if blockers:
            reasons.append(
                f"{len(blockers)} source(s) still fail DMARC with real volume: "
                + ", ".join(f"{s.source_ip} ({s.failing} messages)" for s in blockers[:5])
            )
        ready = not reasons

    recommendations: list[Recommendation] = []
    if target and ready:
        recommendations.append(
            Recommendation(
                severity="medium",
                code="dmarc-advance-policy",
                message=f"Move DMARC from p={policy} to p={target}.",
                details=(
                    f"{summary.pass_rate:.1%} of {summary.total_messages} reported messages "
                    f"already pass aligned DMARC across {summary.source_count} sending source(s). "
                    "Ramp with pct= if you want a slower rollout."
                ),
            )
        )
    for source in blockers[:5]:
        recommendations.append(
            Recommendation(
                severity="high",
                code="dmarc-unauthenticated-source",
                message=f"{source.source_ip} sends as your domain without passing DMARC.",
                details=(
                    f"{source.failing} of {source.messages} messages failed both aligned SPF and "
                    f"DKIM ({source.volume_share:.1%} of all reported volume). Either authorise it "
                    "(add it to SPF and sign with DKIM) or find out who is sending."
                ),
            )
        )
    if fragile:
        volume = sum(source.messages for source in fragile)
        recommendations.append(
            Recommendation(
                severity="medium",
                code="dmarc-spf-only-alignment",
                message="Some mail passes on aligned SPF alone and will break when forwarded.",
                details=(
                    f"{volume} message(s) from {len(fragile)} source(s) had no aligned DKIM "
                    "signature. SPF does not survive forwarding, so add DKIM signing before "
                    "tightening policy."
                ),
            )
        )

    return DmarcReadiness(
        current_policy=policy,
        recommended_policy=target if ready else policy,
        ready=ready,
        threshold=threshold,
        reasons=reasons,
        blocking_sources=blockers[:10],
        fragile_sources=fragile[:10],
        recommendations=recommendations,
    )
