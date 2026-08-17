"""Remediation playbooks grouped by implementation effort."""

from __future__ import annotations

from typing import Any

from inboxready_api.models import AuditCheck, Recommendation


# Recommendation code -> (effort, check name)
CODE_EFFORT: dict[str, tuple[str, str]] = {
    "mx-missing": ("half-day", "mx"),
    "spf-missing": ("quick", "spf"),
    "spf-lookup-limit": ("half-day", "spf"),
    "spf-weak-policy": ("half-day", "spf"),
    "dmarc-missing": ("quick", "dmarc"),
    "dmarc-rua-missing": ("quick", "dmarc"),
    "dmarc-monitoring-only": ("half-day", "dmarc"),
    "dkim-unverified": ("half-day", "dkim"),
    "dkim-unconfirmed": ("half-day", "dkim"),
    "mta-sts-incomplete": ("project", "mta_sts"),
    "tls-rpt-missing": ("quick", "tls_rpt"),
    "bimi-dmarc-prereq": ("project", "bimi"),
    "bimi-asset-missing": ("half-day", "bimi"),
    "caa-missing": ("quick", "caa"),
    "free-email-domain": ("project", "sending_domain"),
    "provider-not-detected": ("half-day", "provider"),
}

CHECK_FALLBACK: dict[str, tuple[str, str]] = {
    "mx": ("half-day", "Publish MX records so mail can be received."),
    "spf": ("quick", "Publish or simplify the SPF record."),
    "dmarc": ("quick", "Publish DMARC with an rua reporting mailbox."),
    "dkim": ("half-day", "Publish DKIM selectors for your sending providers."),
    "mta_sts": ("project", "Stand up MTA-STS policy hosting and enforce mode."),
    "tls_rpt": ("quick", "Publish a TLS-RPT record for TLS failure reports."),
    "bimi": ("project", "Add BIMI after DMARC enforcement and host an SVG logo."),
    "caa": ("quick", "Publish CAA issue tags for your certificate authority."),
    "sending_domain": ("project", "Send from a domain you control."),
}

INFO_PLAYBOOK_CHECKS = {"mta_sts", "tls_rpt", "bimi", "caa"}
EFFORTS = ("quick", "half-day", "project")


def build_playbook(
    checks: dict[str, AuditCheck] | None = None,
    recommendations: list[Recommendation] | None = None,
) -> dict[str, list[dict[str, Any]]]:
    """Group remediation work by effort: quick, half-day, or project."""

    checks = checks or {}
    recommendations = recommendations or []
    groups: dict[str, list[dict[str, Any]]] = {effort: [] for effort in EFFORTS}
    seen_codes: set[str] = set()
    covered_checks: set[str] = set()

    for rec in recommendations:
        effort, check_name = CODE_EFFORT.get(rec.code, ("half-day", _check_from_code(rec.code)))
        if rec.code in seen_codes:
            continue
        seen_codes.add(rec.code)
        covered_checks.add(check_name)
        groups[effort].append(
            {
                "check": check_name,
                "code": rec.code,
                "message": rec.message,
                "severity": rec.severity,
            }
        )

    for name, check in checks.items():
        if name in covered_checks or check.status == "pass":
            continue
        if check.status == "info" and name not in INFO_PLAYBOOK_CHECKS:
            continue
        if name not in CHECK_FALLBACK:
            continue
        effort, default_message = _effort_for_check(name, check)
        groups[effort].append(
            {
                "check": name,
                "code": None,
                "message": check.summary or default_message,
                "severity": _severity_for_status(check.status),
            }
        )

    return groups


def _effort_for_check(name: str, check: AuditCheck) -> tuple[str, str]:
    if name == "dmarc" and check.status == "warn":
        return "half-day", CHECK_FALLBACK["dmarc"][1]
    if name == "spf" and check.status == "warn":
        return "half-day", CHECK_FALLBACK["spf"][1]
    return CHECK_FALLBACK[name]


def _severity_for_status(status: str) -> str:
    if status == "fail":
        return "high"
    if status == "warn":
        return "medium"
    return "low"


def _check_from_code(code: str) -> str:
    return code.split("-", 1)[0].replace("-", "_")
