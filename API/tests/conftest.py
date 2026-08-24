"""Shared fixtures for the site test suites."""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from inboxready_api.main import app
from inboxready_api.settings import get_settings


@pytest.fixture(scope="session")
def client() -> TestClient:
    return TestClient(app)


@pytest.fixture
def configured(monkeypatch):
    """Rebuild the cached Settings with the given INBOXREADY_* overrides."""

    def _apply(**env: str) -> None:
        get_settings.cache_clear()
        for key, value in env.items():
            monkeypatch.setenv(f"INBOXREADY_{key.upper()}", value)
        get_settings.cache_clear()

    yield _apply
    get_settings.cache_clear()
