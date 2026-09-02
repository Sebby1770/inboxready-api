from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, Field, HttpUrl

Status = Literal["pass", "warn", "fail", "info"]
Severity = Literal["low", "medium", "high"]
ReportFormat = Literal["json", "markdown", "text"]


class ProviderMatch(BaseModel):
    name: str
    confidence: float = Field(ge=0.0, le=1.0)
    evidence: list[str] = Field(default_factory=list)
    suggested_selectors: list[str] = Field(default_factory=list)


class Recommendation(BaseModel):
    severity: Severity
    code: str
    message: str
    details: str | None = None


class RecommendationTrend(BaseModel):
    severity: Severity
    code: str
    message: str
    affected_domains: list[str] = Field(default_factory=list)


class AuditCheck(BaseModel):
    status: Status
    summary: str
    details: dict[str, Any] = Field(default_factory=dict)


class DomainAuditRequest(BaseModel):
    domain: str = Field(description="The root domain to inspect.")
    selectors: list[str] = Field(
        default_factory=list,
        description="Optional DKIM selectors to test explicitly.",
    )
    expected_providers: list[str] = Field(
        default_factory=list,
        description="Optional provider names expected for this domain.",
    )


class DomainAuditResponse(BaseModel):
    domain: str
    score: int = Field(ge=0, le=100)
    overall_status: Status
    checked_at: str
    providers: list[ProviderMatch] = Field(default_factory=list)
    checks: dict[str, AuditCheck]
    recommendations: list[Recommendation] = Field(default_factory=list)
    references: list[HttpUrl] = Field(default_factory=list)


class BatchAuditRequest(BaseModel):
    domains: list[str] = Field(
        min_length=1,
        max_length=25,
        description="Root domains to inspect. Duplicate normalized domains are audited once.",
    )
    selectors: list[str] = Field(
        default_factory=list,
        description="Optional DKIM selectors to test across every domain.",
    )
    expected_providers: list[str] = Field(
        default_factory=list,
        description="Optional provider names expected across every domain.",
    )


class BatchAuditSummary(BaseModel):
    domain_count: int
    average_score: float = Field(ge=0, le=100)
    status_counts: dict[str, int]
    priority_recommendations: list[RecommendationTrend] = Field(default_factory=list)


class BatchAuditResponse(BaseModel):
    audits: list[DomainAuditResponse]
    summary: BatchAuditSummary


class ProviderCatalogResponse(BaseModel):
    providers: list[ProviderMatch]


class CompareRequest(BaseModel):
    domains: list[str] = Field(
        min_length=2,
        max_length=10,
        description="Domains to compare side-by-side (2–10 unique after normalization).",
    )
    selectors: list[str] = Field(default_factory=list)
    expected_providers: list[str] = Field(default_factory=list)


class DomainScoreSummary(BaseModel):
    domain: str
    score: int = Field(ge=0, le=100)
    overall_status: Status


class CompareCheckDiff(BaseModel):
    check: str
    statuses: dict[str, str]
    summaries: dict[str, str]
    differs: bool


class CompareResponse(BaseModel):
    domains: list[DomainScoreSummary]
    check_diffs: list[CompareCheckDiff]
    audits: list[DomainAuditResponse] = Field(default_factory=list)


class CacheClearResponse(BaseModel):
    cleared: int
    message: str

# --- DMARC aggregate (RUA) reports ------------------------------------------


class DmarcReportMetadata(BaseModel):
    org_name: str
    email: str = ""
    report_id: str = ""
    begin: str = ""
    end: str = ""
    source_file: str = ""


class DmarcPolicyPublished(BaseModel):
    domain: str
    policy: str = "none"
    subdomain_policy: str | None = None
    percentage: int = 100
    dkim_alignment: str = "r"
    spf_alignment: str = "r"


class DmarcReportRow(BaseModel):
    source_ip: str
    count: int = Field(ge=0)
    disposition: str = "none"
    dkim: str = "fail"
    spf: str = "fail"
    header_from: str = ""
    envelope_from: str = ""
    dkim_domains: list[str] = Field(default_factory=list)
    dkim_selectors: list[str] = Field(default_factory=list)
    spf_domain: str = ""


class DmarcAggregateReport(BaseModel):
    metadata: DmarcReportMetadata
    policy_published: DmarcPolicyPublished
    rows: list[DmarcReportRow]


class DmarcSource(BaseModel):
    """One sending IP, merged across every report in the window."""

    source_ip: str
    messages: int
    passing: int
    failing: int
    pass_rate: float = Field(ge=0.0, le=1.0)
    volume_share: float = Field(ge=0.0, le=1.0)
    dkim_aligned: int
    spf_aligned: int
    classification: str
    classifications: dict[str, int] = Field(default_factory=dict)
    dispositions: dict[str, int] = Field(default_factory=dict)
    header_domains: list[str] = Field(default_factory=list)
    dkim_domains: list[str] = Field(default_factory=list)
    selectors: list[str] = Field(default_factory=list)
    reporters: list[str] = Field(default_factory=list)


class DmarcSummary(BaseModel):
    domains: list[str] = Field(default_factory=list)
    policies: list[str] = Field(default_factory=list)
    reporters: list[str] = Field(default_factory=list)
    report_count: int = 0
    window_start: str = ""
    window_end: str = ""
    total_messages: int = 0
    passing_messages: int = 0
    failing_messages: int = 0
    pass_rate: float = Field(default=0.0, ge=0.0, le=1.0)
    dkim_aligned_rate: float = Field(default=0.0, ge=0.0, le=1.0)
    spf_aligned_rate: float = Field(default=0.0, ge=0.0, le=1.0)
    dispositions: dict[str, int] = Field(default_factory=dict)
    source_count: int = 0
    sources: list[DmarcSource] = Field(default_factory=list)


class DmarcReadiness(BaseModel):
    """Whether the next policy step is safe, and what stands in the way."""

    current_policy: str
    recommended_policy: str
    ready: bool
    threshold: float
    reasons: list[str] = Field(default_factory=list)
    blocking_sources: list[DmarcSource] = Field(default_factory=list)
    fragile_sources: list[DmarcSource] = Field(default_factory=list)
    recommendations: list[Recommendation] = Field(default_factory=list)


class DmarcReportResponse(BaseModel):
    summary: DmarcSummary
    readiness: DmarcReadiness
    reports: list[DmarcReportMetadata] = Field(default_factory=list)
    errors: list[str] = Field(default_factory=list)
