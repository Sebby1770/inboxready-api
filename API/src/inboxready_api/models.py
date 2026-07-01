from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, EmailStr, Field, HttpUrl, field_validator

from inboxready_api.domain_validation import normalize_domain


Status = Literal["pass", "warn", "fail", "info"]
Severity = Literal["low", "medium", "high"]
PlanName = Literal["free", "starter", "growth", "pro"]
AuditJobStatus = Literal["queued", "running", "succeeded", "failed"]
ExportFormat = Literal["json", "csv"]


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
    domain: str = Field(
        min_length=1,
        max_length=2048,
        description="The root domain or URL to inspect.",
    )
    selectors: list[str] = Field(
        default_factory=list,
        description="Optional DKIM selectors to test explicitly.",
    )
    expected_providers: list[str] = Field(
        default_factory=list,
        description="Optional provider names expected for this domain.",
    )

    @field_validator("domain")
    @classmethod
    def validate_domain(cls, value: str) -> str:
        return normalize_domain(value)


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
        max_length=10,
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

    @field_validator("domains")
    @classmethod
    def validate_domains(cls, values: list[str]) -> list[str]:
        return [normalize_domain(value) for value in values]


class BatchAuditSummary(BaseModel):
    domain_count: int
    average_score: float = Field(ge=0, le=100)
    status_counts: dict[str, int]
    priority_recommendations: list[RecommendationTrend] = Field(default_factory=list)


class BatchAuditResponse(BaseModel):
    audits: list[DomainAuditResponse]
    summary: BatchAuditSummary


MonitorCadence = Literal["manual", "weekly", "monthly"]


class MonitorCreateRequest(BaseModel):
    domain: str = Field(
        min_length=1,
        max_length=2048,
        description="The customer domain or URL to keep on the account watchlist.",
    )
    selectors: list[str] = Field(
        default_factory=list,
        description="Optional DKIM selectors to re-use whenever this monitor runs.",
    )
    expected_providers: list[str] = Field(
        default_factory=list,
        description="Optional provider names expected whenever this monitor runs.",
    )
    cadence: MonitorCadence = Field(
        default="weekly",
        description="Requested check cadence. The launch build stores this for scheduling.",
    )

    @field_validator("domain")
    @classmethod
    def validate_domain(cls, value: str) -> str:
        return normalize_domain(value)


class MonitorResponse(BaseModel):
    id: str
    domain: str
    selectors: list[str] = Field(default_factory=list)
    expected_providers: list[str] = Field(default_factory=list)
    cadence: MonitorCadence
    last_audit_id: str | None = None
    last_score: int | None = Field(default=None, ge=0, le=100)
    last_status: Status | None = None
    last_checked_at: str | None = None
    created_at: str
    updated_at: str


class MonitorListResponse(BaseModel):
    monitors: list[MonitorResponse] = Field(default_factory=list)


class MonitorRunResponse(BaseModel):
    monitor: MonitorResponse
    audit: DomainAuditResponse


class DueMonitorRunResponse(BaseModel):
    monitors_checked: int
    audits: list[MonitorRunResponse] = Field(default_factory=list)


class AuditJobCreateRequest(DomainAuditRequest):
    pass


class AuditJobResponse(BaseModel):
    id: str
    status: AuditJobStatus
    kind: Literal["email_domain"]
    audit_log_id: str | None = None
    audit: DomainAuditResponse | None = None
    error: str | None = None
    created_at: str
    started_at: str | None = None
    finished_at: str | None = None


class AuditJobListResponse(BaseModel):
    jobs: list[AuditJobResponse] = Field(default_factory=list)


class AuditHistoryExportRequest(BaseModel):
    format: ExportFormat = Field(default="json")
    limit: int = Field(default=500, ge=1, le=1000)


class ExportObjectResponse(BaseModel):
    id: str
    key: str
    kind: Literal["audit_history"]
    format: ExportFormat
    media_type: str
    size_bytes: int
    download_url: str
    created_at: str


class ExportObjectListResponse(BaseModel):
    exports: list[ExportObjectResponse] = Field(default_factory=list)


class RpcRequest(BaseModel):
    method: Literal[
        "inboxready.health",
        "inboxready.metrics",
        "inboxready.providers",
        "inboxready.audit.create",
        "inboxready.audit.enqueue",
    ]
    params: dict[str, Any] = Field(default_factory=dict)
    id: str | int | None = None


class RpcResponse(BaseModel):
    ok: bool
    id: str | int | None = None
    result: dict[str, Any] | list[Any] | None = None
    error: dict[str, Any] | None = None


class ProviderCatalogResponse(BaseModel):
    providers: list[ProviderMatch]


class AccountCreateRequest(BaseModel):
    email: EmailStr = Field(description="Customer email that owns the first API key.")
    plan: PlanName = Field(default="free", description="Initial plan for local launch/testing.")
    key_name: str = Field(default="Default key", max_length=80)


class AccountResponse(BaseModel):
    id: str
    email: str
    plan: PlanName
    stripe_customer_id: str | None = None
    stripe_subscription_status: str | None = None
    created_at: str


class ApiKeyCreateRequest(BaseModel):
    name: str = Field(default="API key", max_length=80)


class ApiKeyResponse(BaseModel):
    id: str
    name: str
    prefix: str
    created_at: str
    last_used_at: str | None = None
    revoked_at: str | None = None


class AccountProvisionResponse(BaseModel):
    account: AccountResponse
    api_key: str = Field(description="Plaintext key. It is only returned once.")
    key: ApiKeyResponse


class ApiKeyProvisionResponse(BaseModel):
    api_key: str = Field(description="Plaintext key. It is only returned once.")
    key: ApiKeyResponse


class ApiKeyListResponse(BaseModel):
    keys: list[ApiKeyResponse] = Field(default_factory=list)


class AccountOverviewResponse(BaseModel):
    account: AccountResponse
    usage: "PlanUsageResponse"
    api_keys: list[ApiKeyResponse] = Field(default_factory=list)


class PlanUsageResponse(BaseModel):
    plan: PlanName
    monthly_audit_limit: int
    rate_limit_per_minute: int
    current_period_start: str
    audits_used: int
    audits_remaining: int


class AuditHistoryItem(BaseModel):
    id: str
    domain: str
    score: int
    overall_status: Status
    units: int
    created_at: str


class AuditHistoryResponse(BaseModel):
    usage: PlanUsageResponse
    audits: list[AuditHistoryItem]


class AuditHistoryDetailResponse(BaseModel):
    id: str
    units: int
    created_at: str
    audit: DomainAuditResponse


class ProtocolReadiness(BaseModel):
    key: str
    name: str
    status: Status
    summary: str


class RemediationTask(BaseModel):
    severity: Severity
    code: str
    title: str
    description: str
    owner: str
    effort: str
    customer_message: str
    details: str | None = None


class RemediationPlanResponse(BaseModel):
    domain: str
    score: int = Field(ge=0, le=100)
    overall_status: Status
    readiness_stage: Literal["ready", "review", "blocked"]
    launch_decision: str
    executive_summary: str
    generated_at: str
    protocol_coverage: list[ProtocolReadiness] = Field(default_factory=list)
    tasks: list[RemediationTask] = Field(default_factory=list)
    references: list[HttpUrl] = Field(default_factory=list)


class BillingCheckoutRequest(BaseModel):
    plan: Literal["starter", "growth", "pro"]


class BillingSessionResponse(BaseModel):
    url: str


class SupportRequestCreateRequest(BaseModel):
    email: EmailStr
    subject: str = Field(min_length=3, max_length=120)
    message: str = Field(min_length=20, max_length=5000)


class SupportRequestResponse(BaseModel):
    status: Literal["received"]
    email: EmailStr
    subject: str
