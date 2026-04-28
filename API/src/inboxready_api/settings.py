from __future__ import annotations

from functools import lru_cache

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    http_timeout_seconds: float = 5.0
    user_agent: str = "InboxReady/0.1 (+https://example.com)"

    model_config = SettingsConfigDict(
        env_prefix="INBOXREADY_",
        env_file=".env",
        extra="ignore",
    )


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    return Settings()
