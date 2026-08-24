from __future__ import annotations

from functools import lru_cache

from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    http_timeout_seconds: float = 5.0
    user_agent: str = "InboxReady/0.5 (+https://github.com/Sebby1770/inboxready-api)"
    api_keys: str = Field(
        default="",
        description="Comma-separated API keys. When set, X-API-Key is required.",
    )
    require_api_key: bool = Field(
        default=False,
        description="Force API key auth even when no keys are configured (demo open by default).",
    )
    rate_limit_per_minute: int = Field(
        default=60,
        ge=0,
        description="Max requests per minute per API key or client IP (0 disables).",
    )
    cache_ttl_seconds: int = Field(
        default=300,
        ge=0,
        description="TTL for domain audit result cache in seconds (0 disables).",
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

    @property
    def parsed_api_keys(self) -> set[str]:
        return {key.strip() for key in self.api_keys.split(",") if key.strip()}

    @property
    def is_production(self) -> bool:
        return self.environment.strip().lower() in {"production", "prod"}

    @property
    def analytics_enabled(self) -> bool:
        return bool(self.analytics_ga4_id.strip())


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    return Settings()
