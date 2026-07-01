from __future__ import annotations

from functools import lru_cache

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    http_timeout_seconds: float = 5.0
    user_agent: str = "InboxReady/0.9 (+https://example.com)"
    database_path: str = "var/inboxready.sqlite3"
    object_store_path: str = "var/object-store"
    public_base_url: str = "http://127.0.0.1:8000"
    session_secret: str = Field(
        default="dev-only-inboxready-session-secret-change-me",
        min_length=32,
    )
    session_https_only: bool = False
    company_name: str = "InboxReady"
    support_email: str = "support@inboxready.dev"
    public_signup_enabled: bool = True
    api_auth_required: bool = True
    allow_unpaid_plan_provisioning: bool = False
    demo_daily_limit: int = 20
    demo_rate_limit_per_minute: int = 5
    batch_max_workers: int = Field(default=5, ge=1, le=10)
    stripe_secret_key: str | None = None
    stripe_webhook_secret: str | None = None
    stripe_starter_price_id: str | None = None
    stripe_growth_price_id: str | None = None
    stripe_pro_price_id: str | None = None

    model_config = SettingsConfigDict(
        env_prefix="INBOXREADY_",
        env_file=".env",
        extra="ignore",
    )


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    return Settings()
