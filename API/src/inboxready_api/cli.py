from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from inboxready_api import __version__
from inboxready_api.models import BatchAuditRequest, CompareRequest, DomainAuditRequest
from inboxready_api.services.batch_audit import audit_domains
from inboxready_api.services.compare import compare_domains
from inboxready_api.services.dns_audit import audit_domain
from inboxready_api.services.provider_detection import get_provider_catalog
from inboxready_api.services.report import render_html_report, render_markdown_report
from inboxready_api.services.history import configure_history, get_history
from inboxready_api.services.scoring import scoring_document
from inboxready_api.settings import Settings, get_settings


EXIT_PASS = 0
EXIT_FAIL = 1
EXIT_ERROR = 2


def main(argv: list[str] | None = None) -> None:
    parser = build_parser()
    args = parser.parse_args(argv)

    try:
        exit_code = run_command(args)
    except Exception as exc:  # noqa: BLE001 - CLI surface
        print(f"error: {exc}", file=sys.stderr)
        raise SystemExit(EXIT_ERROR) from exc

    raise SystemExit(exit_code)


def run_command(args: argparse.Namespace) -> int:
    if args.command == "version":
        print(__version__)
        return EXIT_PASS

    if args.command == "history":
        settings = resolve_settings(args)
        configure_history(
            max_entries=settings.history_max_entries,
            path=settings.history_path or None,
        )
        store = get_history()
        if getattr(args, "history_cmd", None) == "stats":
            payload = store.stats()
            output = json.dumps(payload, indent=2) if args.json else (
                f"count={payload['count']} avg={payload['average_score']} "
                f"domains={payload['unique_domains']} by_status={payload['by_status']}"
            )
        else:
            entries = store.list(
                domain=getattr(args, "domain", None),
                limit=getattr(args, "limit", 20) or 20,
            )
            if args.json:
                output = json.dumps([e.to_dict() for e in entries], indent=2)
            else:
                lines = [f"{e.checked_at}  {e.score:3d}  {e.overall_status:5}  {e.domain}" for e in entries]
                output = "\n".join(lines) if lines else "(no history)"
        write_output(output, getattr(args, "out", None))
        return EXIT_PASS

    if args.command == "scoring":
        payload = scoring_document()
        write_output(json.dumps(payload, indent=2), getattr(args, "out", None))
        return EXIT_PASS

    if args.command == "providers":
        providers = get_provider_catalog()
        payload = [provider.model_dump(mode="json") for provider in providers]
        if args.json or getattr(args, "format", "text") == "json":
            output = json.dumps(payload, indent=2)
        else:
            lines = ["InboxReady provider fingerprints"]
            for provider in providers:
                evidence = ", ".join(provider.evidence)
                lines.append(f"- {provider.name} ({provider.confidence:.0%}) -> {evidence}")
            output = "\n".join(lines)
        write_output(output, getattr(args, "out", None))
        return EXIT_PASS

    if args.command == "compare":
        settings = resolve_settings(args)
        result = compare_domains(
            CompareRequest(
                domains=args.domains,
                selectors=split_csv_values(getattr(args, "selectors", "") or ""),
                expected_providers=split_csv_values(getattr(args, "expected_providers", "") or ""),
            ),
            settings,
        )
        fmt = resolve_format(args)
        if fmt == "json":
            output = result.model_dump_json(indent=2)
        else:
            output = format_compare_text(result)
        write_output(output, getattr(args, "out", None))
        if any(item.overall_status == "fail" for item in result.domains):
            return EXIT_FAIL
        return EXIT_PASS

    if args.command == "audit":
        settings = resolve_settings(args)
        selectors = split_csv_values(args.selectors)
        expected_providers = split_csv_values(args.expected_providers)

        if len(args.domains) == 1:
            result = audit_domain(
                DomainAuditRequest(
                    domain=args.domains[0],
                    selectors=selectors,
                    expected_providers=expected_providers,
                ),
                settings,
            )
            fmt = resolve_format(args)
            if fmt == "json":
                output = result.model_dump_json(indent=2)
            elif fmt in {"md", "markdown"}:
                output = render_markdown_report(result)
            elif fmt == "html":
                output = render_html_report(result)
            else:
                output = format_domain_text(result)
            write_output(output, getattr(args, "out", None))
            return EXIT_PASS if result.overall_status != "fail" else EXIT_FAIL

        batch = audit_domains(
            BatchAuditRequest(
                domains=args.domains,
                selectors=selectors,
                expected_providers=expected_providers,
            ),
            settings,
        )
        fmt = resolve_format(args)
        if fmt == "json":
            output = batch.model_dump_json(indent=2)
        elif fmt in {"md", "markdown"}:
            parts = [render_markdown_report(audit) for audit in batch.audits]
            output = "\n---\n\n".join(parts)
        else:
            output = format_batch_text(batch)
        write_output(output, getattr(args, "out", None))
        if any(audit.overall_status == "fail" for audit in batch.audits):
            return EXIT_FAIL
        return EXIT_PASS

    build_parser().print_help()
    return EXIT_ERROR


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="inboxready",
        description="Audit email domain readiness from the command line.",
    )
    subparsers = parser.add_subparsers(dest="command")

    audit_parser = subparsers.add_parser("audit", help="Audit one or more domains.")
    audit_parser.add_argument("domains", nargs="+", help="Root domains or URLs to audit.")
    audit_parser.add_argument(
        "--selectors",
        default="",
        help="Comma-separated DKIM selectors to check.",
    )
    audit_parser.add_argument(
        "--expected-providers",
        default="",
        help="Comma-separated provider names expected in DNS evidence.",
    )
    audit_parser.add_argument("--json", action="store_true", help="Print raw JSON output.")
    audit_parser.add_argument(
        "--format",
        choices=["json", "md", "markdown", "text"],
        default=None,
        help="Output format (default: text). --json is an alias for json.",
    )
    audit_parser.add_argument("--out", metavar="FILE", help="Write output to a file.")
    audit_parser.add_argument(
        "--timeout",
        type=float,
        default=None,
        help="HTTP timeout seconds for policy fetches (overrides settings).",
    )

    compare_parser = subparsers.add_parser("compare", help="Compare readiness across domains.")
    compare_parser.add_argument("domains", nargs="+", help="Domains to compare (2+).")
    compare_parser.add_argument("--selectors", default="")
    compare_parser.add_argument("--expected-providers", default="")
    compare_parser.add_argument("--json", action="store_true", help="Print raw JSON output.")
    compare_parser.add_argument(
        "--format",
        choices=["json", "text"],
        default=None,
    )
    compare_parser.add_argument("--out", metavar="FILE", help="Write output to a file.")
    compare_parser.add_argument("--timeout", type=float, default=None)

    providers_parser = subparsers.add_parser("providers", help="List known provider fingerprints.")
    providers_parser.add_argument("--json", action="store_true", help="Print raw JSON output.")
    providers_parser.add_argument(
        "--format",
        choices=["json", "text"],
        default=None,
    )
    providers_parser.add_argument("--out", metavar="FILE", help="Write output to a file.")

    subparsers.add_parser("version", help="Print package version.")


    hist = subparsers.add_parser("history", help="Show recent audit history (file-backed if configured).")
    hist.add_argument("history_cmd", nargs="?", default="list", choices=["list", "stats"])
    hist.add_argument("--domain", default=None)
    hist.add_argument("--limit", type=int, default=20)
    hist.add_argument("--json", action="store_true")
    hist.add_argument("--out", default=None)
    hist.add_argument("--timeout", type=float, default=None)

    scoring_p = subparsers.add_parser("scoring", help="Print scoring weights documentation.")
    scoring_p.add_argument("--out", default=None)
    scoring_p.add_argument("--json", action="store_true")

    return parser


def resolve_settings(args: argparse.Namespace) -> Settings:
    base = get_settings()
    timeout = getattr(args, "timeout", None)
    if timeout is None:
        return base
    return base.model_copy(update={"http_timeout_seconds": timeout})


def resolve_format(args: argparse.Namespace) -> str:
    if getattr(args, "json", False):
        return "json"
    fmt = getattr(args, "format", None)
    if fmt:
        return fmt
    return "text"


def write_output(content: str, out_path: str | None) -> None:
    if out_path:
        Path(out_path).write_text(content if content.endswith("\n") else content + "\n", encoding="utf-8")
        return
    print(content)


def split_csv_values(value: str) -> list[str]:
    return [item.strip() for item in value.split(",") if item.strip()]


def format_domain_text(result: object) -> str:
    lines = [
        f"InboxReady audit: {result.domain}",
        f"Score: {result.score}/100 ({result.overall_status})",
    ]

    if result.providers:
        providers = ", ".join(provider.name for provider in result.providers)
        lines.append(f"Detected providers: {providers}")
    else:
        lines.append("Detected providers: none")

    lines.append("\nChecks")
    for name, check in result.checks.items():
        lines.append(f"- {name}: {check.status} - {check.summary}")

    lines.append("\nNext actions")
    if result.recommendations:
        for item in result.recommendations[:5]:
            lines.append(f"- [{item.severity}] {item.message}")
    else:
        lines.append("- No urgent remediation items.")

    return "\n".join(lines)


def format_batch_text(result: object) -> str:
    lines = [
        "InboxReady batch audit",
        f"Domains: {result.summary.domain_count}",
        f"Average score: {result.summary.average_score}/100",
        "Statuses: "
        + ", ".join(f"{status}={count}" for status, count in result.summary.status_counts.items()),
        "\nDomains",
    ]
    for audit in result.audits:
        lines.append(f"- {audit.domain}: {audit.score}/100 ({audit.overall_status})")

    lines.append("\nPriority patterns")
    if result.summary.priority_recommendations:
        for item in result.summary.priority_recommendations:
            domains = ", ".join(item.affected_domains)
            lines.append(f"- [{item.severity}] {item.code}: {domains}")
    else:
        lines.append("- No repeated remediation patterns found.")

    return "\n".join(lines)


def format_compare_text(result: object) -> str:
    lines = ["InboxReady compare", "\nScores"]
    for item in result.domains:
        lines.append(f"- {item.domain}: {item.score}/100 ({item.overall_status})")

    lines.append("\nCheck diffs")
    for diff in result.check_diffs:
        marker = "DIFF" if diff.differs else "same"
        status_bits = ", ".join(f"{domain}={status}" for domain, status in diff.statuses.items())
        lines.append(f"- {diff.check} [{marker}]: {status_bits}")

    return "\n".join(lines)


# Back-compat aliases used by older tests / scripts
print_domain_report = lambda result: print(format_domain_text(result))  # noqa: E731
print_batch_report = lambda result: print(format_batch_text(result))  # noqa: E731
