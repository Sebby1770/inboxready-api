from __future__ import annotations

from functools import lru_cache
from typing import Literal

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict

DEFAULT_SESSION_SECRET = "dev-only-inboxready-session-secret-change-me"


class ProductionConfigError(Exception):
    """Raised when the app is started in production with insecure config."""


class Settings(BaseSettings):
    environment: Literal["development", "staging", "production"] = "development"
    http_timeout_seconds: float = 5.0
    user_agent: str = "InboxReady/1.0 (+https://example.com)"
    database_path: str = "var/inboxready.sqlite3"
    object_store_path: str = "var/object-store"
    public_base_url: str = "http://127.0.0.1:8000"
    session_secret: str = Field(default=DEFAULT_SESSION_SECRET, min_length=32)
    session_https_only: bool = False
    # SSRF guard. Audits fetch policy files from customer-controlled hosts, so
    # by default we refuse to connect to private/loopback/link-local addresses.
    # Only enable for trusted local development against internal test servers.
    allow_private_network_fetches: bool = False
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

    @property
    def is_production(self) -> bool:
        return self.environment == "production"

    def validate_production_safety(self) -> None:
        """Fail closed if production is misconfigured in a dangerous way.

        Called once at startup. Refusing to boot is deliberately louder than
        silently running with forgeable sessions or plaintext cookies.
        """

        if not self.is_production:
            return

        problems: list[str] = []
        if self.session_secret == DEFAULT_SESSION_SECRET:
            problems.append(
                "INBOXREADY_SESSION_SECRET is still the built-in dev default; "
                "set a unique random 32+ char secret."
            )
        if not self.session_https_only:
            problems.append(
                "INBOXREADY_SESSION_HTTPS_ONLY must be true in production so "
                "session cookies are marked Secure."
            )
        if not self.public_base_url.startswith("https://"):
            problems.append(
                "INBOXREADY_PUBLIC_BASE_URL must be an https:// URL in production."
            )
        if self.allow_private_network_fetches:
            problems.append(
                "INBOXREADY_ALLOW_PRIVATE_NETWORK_FETCHES must be false in "
                "production (SSRF guard)."
            )
        if problems:
            raise ProductionConfigError(
                "Refusing to start in production:\n  - " + "\n  - ".join(problems)
            )


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    return Settings()
