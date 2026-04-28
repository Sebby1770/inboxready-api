from __future__ import annotations

import argparse
import json

from inboxready_api.models import BatchAuditRequest, DomainAuditRequest
from inboxready_api.services.batch_audit import audit_domains
from inboxready_api.services.dns_audit import audit_domain
from inboxready_api.services.provider_detection import get_provider_catalog
from inboxready_api.settings import get_settings


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()

    if args.command == "providers":
        providers = get_provider_catalog()
        if args.json:
            print(json.dumps([provider.model_dump(mode="json") for provider in providers], indent=2))
            return

        print("InboxReady provider fingerprints")
        for provider in providers:
            evidence = ", ".join(provider.evidence)
            print(f"- {provider.name} ({provider.confidence:.0%}) -> {evidence}")
        return

    if args.command == "audit":
        selectors = split_csv_values(args.selectors)
        expected_providers = split_csv_values(args.expected_providers)
        settings = get_settings()

        if len(args.domains) == 1:
            result = audit_domain(
                DomainAuditRequest(
                    domain=args.domains[0],
                    selectors=selectors,
                    expected_providers=expected_providers,
                ),
                settings,
            )
        else:
            result = audit_domains(
                BatchAuditRequest(
                    domains=args.domains,
                    selectors=selectors,
                    expected_providers=expected_providers,
                ),
                settings,
            )

        if args.json:
            print(result.model_dump_json(indent=2))
            return

        if hasattr(result, "audits"):
            print_batch_report(result)
        else:
            print_domain_report(result)
        return

    parser.print_help()


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

    providers_parser = subparsers.add_parser("providers", help="List known provider fingerprints.")
    providers_parser.add_argument("--json", action="store_true", help="Print raw JSON output.")

    return parser


def split_csv_values(value: str) -> list[str]:
    return [item.strip() for item in value.split(",") if item.strip()]


def print_domain_report(result: object) -> None:
    print(f"InboxReady audit: {result.domain}")
    print(f"Score: {result.score}/100 ({result.overall_status})")

    if result.providers:
        providers = ", ".join(provider.name for provider in result.providers)
        print(f"Detected providers: {providers}")
    else:
        print("Detected providers: none")

    print("\nChecks")
    for name, check in result.checks.items():
        print(f"- {name}: {check.status} - {check.summary}")

    print("\nNext actions")
    if result.recommendations:
        for item in result.recommendations[:5]:
            print(f"- [{item.severity}] {item.message}")
    else:
        print("- No urgent remediation items.")


def print_batch_report(result: object) -> None:
    print("InboxReady batch audit")
    print(f"Domains: {result.summary.domain_count}")
    print(f"Average score: {result.summary.average_score}/100")
    print(
        "Statuses: "
        + ", ".join(f"{status}={count}" for status, count in result.summary.status_counts.items())
    )

    print("\nDomains")
    for audit in result.audits:
        print(f"- {audit.domain}: {audit.score}/100 ({audit.overall_status})")

    print("\nPriority patterns")
    if result.summary.priority_recommendations:
        for item in result.summary.priority_recommendations:
            domains = ", ".join(item.affected_domains)
            print(f"- [{item.severity}] {item.code}: {domains}")
    else:
        print("- No repeated remediation patterns found.")
