from __future__ import annotations

from functools import lru_cache
from ipaddress import IPv4Network, IPv6Network, ip_network

from pydantic import Field, field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    http_timeout_seconds: float = 5.0
    user_agent: str = "InboxReady/0.7 (+https://github.com/Sebby1770/inboxready-api)"
    api_keys: str = Field(
        default="",
        description="Comma-separated API keys. When set, X-API-Key is required.",
    )
    require_api_key: bool = Field(
        default=False,
        description="Require API-key auth; fails closed when no keys are configured.",
    )
    rate_limit_per_minute: int = Field(
        default=60,
        ge=0,
        description="Max requests per minute per API key or client IP (0 disables).",
    )
    rate_limit_max_buckets: int = Field(
        default=20_000,
        ge=100,
        le=1_000_000,
        description="Maximum in-memory client buckets retained by each process.",
    )
    cache_ttl_seconds: int = Field(
        default=300,
        ge=0,
        description="TTL for domain audit result cache in seconds (0 disables).",
    )
    cache_max_entries: int = Field(
        default=2_000,
        ge=1,
        le=100_000,
        description="Maximum in-memory audit cache entries per process.",
    )
    request_body_max_bytes: int = Field(
        default=1_048_576,
        ge=1_024,
        le=100 * 1024 * 1024,
        description="Maximum request body size outside the DMARC report upload endpoint.",
    )
    report_upload_body_max_bytes: int = Field(
        default=36 * 1024 * 1024,
        ge=1_024,
        le=100 * 1024 * 1024,
        description="Maximum multipart body size for DMARC report uploads.",
    )
    batch_max_workers: int = Field(
        default=8,
        ge=1,
        le=32,
        description="Thread pool size for concurrent batch domain audits.",
    )
    history_max_entries: int = Field(
        default=500,
        ge=1,
        le=10_000,
        description="Max audit history entries retained in memory.",
    )
    history_path: str = Field(
        default="",
        description="Optional JSON file path for persisting audit history.",
    )
    webhook_url: str = Field(
        default="",
        description="Optional webhook URL notified when score is below threshold.",
    )
    webhook_secret: str = Field(
        default="",
        description="Optional secret used to HMAC-sign webhook request bodies.",
    )
    webhook_max_attempts: int = Field(
        default=3,
        ge=1,
        le=5,
        description="Bounded webhook delivery attempts for transient failures.",
    )
    webhook_timeout_seconds: float = Field(
        default=3.0,
        ge=0.1,
        le=30.0,
        description="Timeout for each webhook delivery attempt.",
    )
    webhook_allow_private_hosts: bool = Field(
        default=False,
        description="Allow webhook targets that resolve to private or local addresses.",
    )
    webhook_min_score: int = Field(
        default=70,
        ge=0,
        le=100,
        description="Fire webhook when audit score is strictly below this value.",
    )

    # --- Site / growth surface (v0.5) -------------------------------------
    environment: str = Field(
        default="development",
        description="Deployment environment. Only 'production' is indexable by crawlers.",
    )
    site_base_url: str = Field(
        default="",
        description=(
            "Absolute public origin (e.g. https://inboxready.dev). Used for canonical "
            "URLs, sitemap entries, and social card metadata. Falls back to the request origin."
        ),
    )
    analytics_ga4_id: str = Field(
        default="",
        description="Google Analytics 4 measurement ID (G-XXXXXXXXXX). Empty disables analytics.",
    )
    analytics_require_consent: bool = Field(
        default=True,
        description="Withhold analytics cookies until the visitor accepts the consent banner.",
    )
    support_response_hours: int = Field(
        default=24,
        ge=1,
        le=168,
        description="Published first-response promise for support and sales enquiries, in hours.",
    )
    leads_path: str = Field(
        default="",
        description="Optional JSON file path for persisting contact form submissions.",
    )
    leads_max_entries: int = Field(
        default=500,
        ge=1,
        le=10_000,
        description="Max contact form submissions retained.",
    )
    security_headers_enabled: bool = Field(
        default=True,
        description="Emit CSP, Referrer-Policy, and related hardening headers on HTML responses.",
    )
    trusted_proxy_cidrs: str = Field(
        default="",
        description=(
            "Comma-separated proxy IPs/CIDRs allowed to supply X-Forwarded-For. "
            "Forwarded headers are ignored when empty."
        ),
    )
    access_log_enabled: bool = Field(
        default=True,
        description="Emit one structured application log event per HTTP request.",
    )

    static_build: bool = Field(
        default=False,
        description=(
            "Render pages for a static host (GitHub Pages). Swaps API-dependent "
            "surfaces for ones that work without a running backend."
        ),
    )
    api_base_url: str = Field(
        default="",
        description=(
            "Absolute origin of a running InboxReady API. Only needed for a static "
            "build that should still run live audits against a deployed backend."
        ),
    )

    model_config = SettingsConfigDict(
        env_prefix="INBOXREADY_",
        env_file=".env",
        extra="ignore",
    )

    @field_validator("api_keys", mode="before")
    @classmethod
    def coerce_api_keys(cls, value: object) -> str:
        if value is None:
            return ""
        return str(value)

    @field_validator("site_base_url", "api_base_url", mode="before")
    @classmethod
    def strip_trailing_slash(cls, value: object) -> str:
        return str(value or "").rstrip("/")

    @field_validator("webhook_url", mode="before")
    @classmethod
    def strip_webhook_whitespace(cls, value: object) -> str:
        return str(value or "").strip()

    @field_validator("trusted_proxy_cidrs")
    @classmethod
    def validate_trusted_proxy_cidrs(cls, value: str) -> str:
        for raw in value.split(","):
            item = raw.strip()
            if not item:
                continue
            try:
                ip_network(item, strict=False)
            except ValueError as exc:
                raise ValueError(f"Invalid trusted proxy IP or CIDR: {item}") from exc
        return value

    @model_validator(mode="after")
    def validate_body_limits(self) -> Settings:
        if self.report_upload_body_max_bytes < self.request_body_max_bytes:
            raise ValueError(
                "report_upload_body_max_bytes must be greater than or equal to request_body_max_bytes"
            )
        return self

    @property
    def parsed_api_keys(self) -> set[str]:
        return {key.strip() for key in self.api_keys.split(",") if key.strip()}

    @property
    def parsed_trusted_proxy_networks(self) -> tuple[IPv4Network | IPv6Network, ...]:
        return tuple(
            ip_network(item.strip(), strict=False)
            for item in self.trusted_proxy_cidrs.split(",")
            if item.strip()
        )

    @property
    def is_production(self) -> bool:
        return self.environment.strip().lower() in {"production", "prod"}

    @property
    def analytics_enabled(self) -> bool:
        return bool(self.analytics_ga4_id.strip())


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    return Settings()
