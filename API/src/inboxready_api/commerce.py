from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

from inboxready_api.models import PlanName


@dataclass(frozen=True)
class PlanLimit:
    name: PlanName
    monthly_audits: int
    rate_limit_per_minute: int
    price_label: str


PLAN_LIMITS: dict[PlanName, PlanLimit] = {
    "free": PlanLimit("free", 100, 15, "$0"),
    "starter": PlanLimit("starter", 2_500, 60, "$49"),
    "growth": PlanLimit("growth", 15_000, 180, "$149"),
    "pro": PlanLimit("pro", 75_000, 600, "$399"),
}


class UsageLimitError(Exception):
    def __init__(self, *, plan: PlanName, limit: int, used: int, requested: int) -> None:
        super().__init__(
            f"Plan {plan} includes {limit} audits/month. "
            f"This account has used {used} and requested {requested} more."
        )
        self.plan = plan
        self.limit = limit
        self.used = used
        self.requested = requested


class RateLimitError(Exception):
    def __init__(self, *, limit: int, requested: int) -> None:
        super().__init__(
            f"Rate limit exceeded. This key allows {limit} audit units per minute; "
            f"requested {requested} more."
        )
        self.limit = limit
        self.requested = requested


def current_period_start(now: datetime | None = None) -> datetime:
    value = now or datetime.now(UTC)
    return value.replace(day=1, hour=0, minute=0, second=0, microsecond=0)


def recent_window_start(seconds: int, now: datetime | None = None) -> datetime:
    return (now or datetime.now(UTC)) - timedelta(seconds=seconds)


def normalize_plan(value: str) -> PlanName:
    plan = value.strip().lower()
    if plan not in PLAN_LIMITS:
        return "free"
    return plan  # type: ignore[return-value]
