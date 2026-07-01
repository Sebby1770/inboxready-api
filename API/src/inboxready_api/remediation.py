from __future__ import annotations

from datetime import UTC, datetime

from inboxready_api.models import (
    DomainAuditResponse,
    ProtocolReadiness,
    Recommendation,
    RemediationPlanResponse,
    RemediationTask,
    Severity,
)


PROTOCOL_LABELS = {
    "mx": "MX routing",
    "spf": "SPF authorization",
    "dmarc": "DMARC policy",
    "dkim": "DKIM signatures",
    "bimi": "BIMI branding",
    "mta_sts": "MTA-STS transport",
    "tls_rpt": "TLS-RPT reporting",
}

OWNER_BY_CODE = {
    "mx-missing": "DNS administrator",
    "spf-missing": "DNS administrator",
    "spf-too-many-lookups": "DNS administrator",
    "dmarc-missing": "DNS administrator",
    "dmarc-monitoring-only": "Deliverability owner",
    "dkim-missing": "Product onboarding",
    "provider-mismatch": "Product onboarding",
    "bimi-missing": "Brand or marketing",
    "mta-sts-missing": "Security engineering",
    "tls-rpt-missing": "Security engineering",
}

EFFORT_BY_SEVERITY: dict[Severity, str] = {
    "high": "Same day",
    "medium": "30-60 min",
    "low": "15-30 min",
}

TASK_TITLE_BY_CODE = {
    "mx-missing": "Publish working MX records",
    "spf-missing": "Publish an SPF record",
    "spf-too-many-lookups": "Reduce SPF DNS lookups",
    "dmarc-missing": "Publish a DMARC record",
    "dmarc-monitoring-only": "Move DMARC toward enforcement",
    "dkim-missing": "Enable DKIM signing",
    "provider-mismatch": "Confirm the sending provider",
    "bimi-missing": "Add BIMI branding after DMARC enforcement",
    "mta-sts-missing": "Add MTA-STS policy publishing",
    "tls-rpt-missing": "Add TLS-RPT reporting",
}


def build_protocol_coverage(audit: DomainAuditResponse) -> list[ProtocolReadiness]:
    coverage = []
    for key, check in audit.checks.items():
        coverage.append(
            ProtocolReadiness(
                key=key,
                name=PROTOCOL_LABELS.get(key, key.replace("_", " ").upper()),
                status=check.status,
                summary=check.summary,
            )
        )
    return coverage


def readiness_stage(audit: DomainAuditResponse) -> str:
    if audit.overall_status == "fail" or any(
        recommendation.severity == "high" for recommendation in audit.recommendations
    ):
        return "blocked"
    if audit.overall_status == "warn" or audit.score < 85:
        return "review"
    return "ready"


def launch_decision_for_stage(stage: str) -> str:
    if stage == "blocked":
        return "Do not launch customer sending from this domain until the high-priority DNS items are fixed."
    if stage == "review":
        return "Launch cautiously only after reviewing the warning items and confirming the expected sender setup."
    return "This domain is ready for customer sending based on the current authentication posture."


def executive_summary(audit: DomainAuditResponse, stage: str) -> str:
    providers = ", ".join(provider.name for provider in audit.providers[:2]) or "no confident provider"
    urgent_count = sum(1 for item in audit.recommendations if item.severity == "high")
    if stage == "ready":
        return (
            f"{audit.domain} scored {audit.score}/100 with {providers} detected. "
            "No launch-blocking remediation is currently visible."
        )
    if stage == "blocked":
        return (
            f"{audit.domain} scored {audit.score}/100 and has {urgent_count} launch-blocking "
            f"item{'s' if urgent_count != 1 else ''}. Prioritize DNS fixes before activation."
        )
    return (
        f"{audit.domain} scored {audit.score}/100 with {providers} detected. "
        "Resolve the warnings before scaling sending volume."
    )


def task_title(recommendation: Recommendation) -> str:
    return TASK_TITLE_BY_CODE.get(recommendation.code, recommendation.message.rstrip("."))


def customer_message(audit: DomainAuditResponse, recommendation: Recommendation) -> str:
    if recommendation.severity == "high":
        return (
            f"{audit.domain} is not ready for production sending yet. "
            f"{recommendation.message}"
        )
    if recommendation.severity == "medium":
        return (
            f"{audit.domain} can move forward after this warning is reviewed: "
            f"{recommendation.message}"
        )
    return f"Optional improvement for {audit.domain}: {recommendation.message}"


def remediation_tasks(audit: DomainAuditResponse) -> list[RemediationTask]:
    return [
        RemediationTask(
            severity=recommendation.severity,
            code=recommendation.code,
            title=task_title(recommendation),
            description=recommendation.message,
            owner=OWNER_BY_CODE.get(recommendation.code, "DNS or deliverability owner"),
            effort=EFFORT_BY_SEVERITY[recommendation.severity],
            customer_message=customer_message(audit, recommendation),
            details=recommendation.details,
        )
        for recommendation in audit.recommendations
    ]


def build_remediation_plan(audit: DomainAuditResponse) -> RemediationPlanResponse:
    stage = readiness_stage(audit)
    return RemediationPlanResponse(
        domain=audit.domain,
        score=audit.score,
        overall_status=audit.overall_status,
        readiness_stage=stage,
        launch_decision=launch_decision_for_stage(stage),
        executive_summary=executive_summary(audit, stage),
        generated_at=datetime.now(UTC).isoformat(),
        protocol_coverage=build_protocol_coverage(audit),
        tasks=remediation_tasks(audit),
        references=audit.references,
    )
