from __future__ import annotations

from collections import defaultdict

from inboxready_api.models import (
    BatchAuditRequest,
    BatchAuditResponse,
    BatchAuditSummary,
    DomainAuditRequest,
    DomainAuditResponse,
    RecommendationTrend,
)
from inboxready_api.services.dns_audit import audit_domain, normalize_domain
from inboxready_api.settings import Settings


SEVERITY_RANK = {
    "high": 0,
    "medium": 1,
    "low": 2,
}


def audit_domains(request: BatchAuditRequest, settings: Settings) -> BatchAuditResponse:
    domains = unique_normalized_domains(request.domains)
    audits = [
        audit_domain(
            DomainAuditRequest(
                domain=domain,
                selectors=request.selectors,
                expected_providers=request.expected_providers,
            ),
            settings,
        )
        for domain in domains
    ]

    return BatchAuditResponse(
        audits=audits,
        summary=summarize_batch(audits),
    )


def unique_normalized_domains(domains: list[str]) -> list[str]:
    seen: set[str] = set()
    normalized_domains: list[str] = []

    for raw_domain in domains:
        domain = normalize_domain(raw_domain)
        if not domain or domain in seen:
            continue
        seen.add(domain)
        normalized_domains.append(domain)

    return normalized_domains


def summarize_batch(audits: list[DomainAuditResponse]) -> BatchAuditSummary:
    status_counts = {"pass": 0, "warn": 0, "fail": 0, "info": 0}
    recommendation_domains: dict[str, set[str]] = defaultdict(set)
    recommendation_templates: dict[str, RecommendationTrend] = {}

    for audit in audits:
        status_counts[audit.overall_status] += 1
        for recommendation in audit.recommendations:
            recommendation_domains[recommendation.code].add(audit.domain)
            recommendation_templates[recommendation.code] = RecommendationTrend(
                severity=recommendation.severity,
                code=recommendation.code,
                message=recommendation.message,
                affected_domains=[],
            )

    trends = []
    for code, template in recommendation_templates.items():
        trends.append(
            template.model_copy(
                update={"affected_domains": sorted(recommendation_domains[code])}
            )
        )

    trends.sort(
        key=lambda item: (
            SEVERITY_RANK[item.severity],
            -len(item.affected_domains),
            item.code,
        )
    )

    average_score = round(sum(audit.score for audit in audits) / len(audits), 1) if audits else 0.0

    return BatchAuditSummary(
        domain_count=len(audits),
        average_score=average_score,
        status_counts=status_counts,
        priority_recommendations=trends[:5],
    )
