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
