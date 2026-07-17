from __future__ import annotations

from inboxready_api.models import (
    AuditCheck,
    CompareCheckDiff,
    CompareRequest,
    CompareResponse,
    DomainAuditRequest,
    DomainAuditResponse,
    DomainScoreSummary,
)
from inboxready_api.services.dns_audit import audit_domain, normalize_domain
from inboxready_api.settings import Settings


def compare_domains(request: CompareRequest, settings: Settings) -> CompareResponse:
    domains: list[str] = []
    seen: set[str] = set()
    for raw in request.domains:
        domain = normalize_domain(raw)
        if not domain or domain in seen:
            continue
        seen.add(domain)
        domains.append(domain)

    audits: list[DomainAuditResponse] = []
    for domain in domains:
        audits.append(
            audit_domain(
                DomainAuditRequest(
                    domain=domain,
                    selectors=request.selectors,
                    expected_providers=request.expected_providers,
                ),
                settings,
            )
        )

    scores = [
        DomainScoreSummary(
            domain=audit.domain,
            score=audit.score,
            overall_status=audit.overall_status,
        )
        for audit in audits
    ]

    check_names: set[str] = set()
    for audit in audits:
        check_names.update(audit.checks.keys())

    diffs: list[CompareCheckDiff] = []
    for name in sorted(check_names):
        statuses: dict[str, str] = {}
        summaries: dict[str, str] = {}
        for audit in audits:
            check: AuditCheck | None = audit.checks.get(name)
            if check is None:
                statuses[audit.domain] = "missing"
                summaries[audit.domain] = "Check not present."
            else:
                statuses[audit.domain] = check.status
                summaries[audit.domain] = check.summary
        unique_statuses = set(statuses.values())
        diffs.append(
            CompareCheckDiff(
                check=name,
                statuses=statuses,
                summaries=summaries,
                differs=len(unique_statuses) > 1,
            )
        )

    return CompareResponse(domains=scores, check_diffs=diffs, audits=audits)
