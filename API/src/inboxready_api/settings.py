from __future__ import annotations

from functools import lru_cache

from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    http_timeout_seconds: float = 5.0
    user_agent: str = "InboxReady/0.2 (+https://example.com)"
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

    @property
    def parsed_api_keys(self) -> set[str]:
        return {key.strip() for key in self.api_keys.split(",") if key.strip()}


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    return Settings()
