from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime
import hashlib
import json
from pathlib import Path
import secrets
import sqlite3
import uuid

from inboxready_api.commerce import PLAN_LIMITS, current_period_start, normalize_plan
from inboxready_api.models import (
    AccountOverviewResponse,
    AccountResponse,
    AuditJobResponse,
    AuditJobStatus,
    ApiKeyListResponse,
    ApiKeyResponse,
    AuditHistoryDetailResponse,
    AuditHistoryItem,
    AuditHistoryResponse,
    DomainAuditResponse,
    ExportFormat,
    ExportObjectResponse,
    MonitorCadence,
    MonitorListResponse,
    MonitorResponse,
    PlanName,
    PlanUsageResponse,
    Status,
)
from inboxready_api.security import verify_password
from inboxready_api.settings import Settings


def utc_now() -> str:
    return datetime.now(UTC).isoformat()


def key_hash(raw_key: str) -> str:
    return hashlib.sha256(raw_key.encode("utf-8")).hexdigest()


def generate_api_key() -> tuple[str, str, str]:
    raw_key = "ir_live_" + secrets.token_urlsafe(32)
    return raw_key, key_hash(raw_key), raw_key[:18]


@dataclass(frozen=True)
class AccountRecord:
    id: str
    email: str
    plan: PlanName
    stripe_customer_id: str | None
    stripe_subscription_id: str | None
    stripe_subscription_status: str | None
    password_hash: str | None
    created_at: str


@dataclass(frozen=True)
class ApiKeyRecord:
    id: str
    account_id: str
    key_hash: str
    name: str
    prefix: str
    created_at: str
    last_used_at: str | None
    revoked_at: str | None


@dataclass(frozen=True)
class MonitorRecord:
    id: str
    account_id: str
    domain: str
    selectors: list[str]
    expected_providers: list[str]
    cadence: MonitorCadence
    last_audit_id: str | None
    last_score: int | None
    last_status: Status | None
    last_checked_at: str | None
    created_at: str
    updated_at: str


@dataclass(frozen=True)
class AuditJobRecord:
    id: str
    account_id: str
    api_key_id: str | None
    kind: str
    status: AuditJobStatus
    payload: dict[str, object]
    result_audit_log_id: str | None
    result: DomainAuditResponse | None
    error: str | None
    created_at: str
    started_at: str | None
    finished_at: str | None


@dataclass(frozen=True)
class ExportObjectRecord:
    id: str
    account_id: str
    key: str
    kind: str
    format: ExportFormat
    media_type: str
    size_bytes: int
    created_at: str


@dataclass(frozen=True)
class AuthContext:
    account: AccountRecord
    api_key: ApiKeyRecord | None


class DuplicateAccountError(Exception):
    pass


class AuthenticationError(Exception):
    pass


class DuplicateMonitorError(Exception):
    pass


class Storage:
    def __init__(self, settings: Settings) -> None:
        self.settings = settings
        self.path = Path(settings.database_path)

    def connect(self) -> sqlite3.Connection:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        conn = sqlite3.connect(self.path)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys = ON")
        return conn

    def init_schema(self) -> None:
        with self.connect() as conn:
            conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS accounts (
                  id TEXT PRIMARY KEY,
                  email TEXT NOT NULL UNIQUE,
                  plan TEXT NOT NULL DEFAULT 'free',
                  stripe_customer_id TEXT UNIQUE,
                  stripe_subscription_id TEXT UNIQUE,
                  stripe_subscription_status TEXT,
                  password_hash TEXT,
                  created_at TEXT NOT NULL,
                  updated_at TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS api_keys (
                  id TEXT PRIMARY KEY,
                  account_id TEXT NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
                  key_hash TEXT NOT NULL UNIQUE,
                  name TEXT NOT NULL,
                  prefix TEXT NOT NULL,
                  created_at TEXT NOT NULL,
                  last_used_at TEXT,
                  revoked_at TEXT
                );

                CREATE TABLE IF NOT EXISTS audit_logs (
                  id TEXT PRIMARY KEY,
                  account_id TEXT NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
                  api_key_id TEXT REFERENCES api_keys(id) ON DELETE SET NULL,
                  domain TEXT NOT NULL,
                  score INTEGER NOT NULL,
                  overall_status TEXT NOT NULL,
                  units INTEGER NOT NULL DEFAULT 1,
                  response_json TEXT NOT NULL,
                  created_at TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS rate_events (
                  id TEXT PRIMARY KEY,
                  identifier TEXT NOT NULL,
                  units INTEGER NOT NULL,
                  created_at TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS support_requests (
                  id TEXT PRIMARY KEY,
                  account_id TEXT REFERENCES accounts(id) ON DELETE SET NULL,
                  email TEXT NOT NULL,
                  subject TEXT NOT NULL,
                  message TEXT NOT NULL,
                  status TEXT NOT NULL DEFAULT 'open',
                  created_at TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS domain_monitors (
                  id TEXT PRIMARY KEY,
                  account_id TEXT NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
                  domain TEXT NOT NULL,
                  selectors_json TEXT NOT NULL DEFAULT '[]',
                  expected_providers_json TEXT NOT NULL DEFAULT '[]',
                  cadence TEXT NOT NULL DEFAULT 'weekly',
                  last_audit_log_id TEXT REFERENCES audit_logs(id) ON DELETE SET NULL,
                  last_score INTEGER,
                  last_status TEXT,
                  last_checked_at TEXT,
                  created_at TEXT NOT NULL,
                  updated_at TEXT NOT NULL,
                  UNIQUE(account_id, domain)
                );

                CREATE TABLE IF NOT EXISTS audit_jobs (
                  id TEXT PRIMARY KEY,
                  account_id TEXT NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
                  api_key_id TEXT REFERENCES api_keys(id) ON DELETE SET NULL,
                  kind TEXT NOT NULL,
                  status TEXT NOT NULL DEFAULT 'queued',
                  payload_json TEXT NOT NULL,
                  result_audit_log_id TEXT REFERENCES audit_logs(id) ON DELETE SET NULL,
                  result_json TEXT,
                  error TEXT,
                  created_at TEXT NOT NULL,
                  started_at TEXT,
                  finished_at TEXT
                );

                CREATE TABLE IF NOT EXISTS export_objects (
                  id TEXT PRIMARY KEY,
                  account_id TEXT NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
                  object_key TEXT NOT NULL UNIQUE,
                  kind TEXT NOT NULL,
                  format TEXT NOT NULL,
                  media_type TEXT NOT NULL,
                  size_bytes INTEGER NOT NULL,
                  created_at TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS stripe_events (
                  id TEXT PRIMARY KEY,
                  event_type TEXT NOT NULL,
                  processed_at TEXT NOT NULL
                );

                CREATE INDEX IF NOT EXISTS audit_logs_account_created_idx
                  ON audit_logs(account_id, created_at);
                CREATE INDEX IF NOT EXISTS rate_events_identifier_created_idx
                  ON rate_events(identifier, created_at);
                CREATE INDEX IF NOT EXISTS domain_monitors_account_updated_idx
                  ON domain_monitors(account_id, updated_at);
                CREATE INDEX IF NOT EXISTS audit_jobs_account_created_idx
                  ON audit_jobs(account_id, created_at);
                CREATE INDEX IF NOT EXISTS audit_jobs_account_status_idx
                  ON audit_jobs(account_id, status, created_at);
                CREATE INDEX IF NOT EXISTS export_objects_account_created_idx
                  ON export_objects(account_id, created_at);
                """
            )
            self._ensure_column(conn, "accounts", "password_hash", "TEXT")

    def ping(self) -> None:
        self.init_schema()
        with self.connect() as conn:
            conn.execute("SELECT 1").fetchone()

    def create_account(
        self,
        *,
        email: str,
        plan: PlanName = "free",
        key_name: str = "Default key",
        password_hash: str | None = None,
    ) -> tuple[AccountRecord, ApiKeyRecord, str]:
        self.init_schema()
        account_id = str(uuid.uuid4())
        now = utc_now()
        normalized_email = email.strip().lower()
        raw_key, hashed_key, prefix = generate_api_key()
        key_id = str(uuid.uuid4())

        with self.connect() as conn:
            try:
                conn.execute(
                    """
                    INSERT INTO accounts (
                      id, email, plan, password_hash, created_at, updated_at
                    )
                    VALUES (?, ?, ?, ?, ?, ?)
                    """,
                    (account_id, normalized_email, plan, password_hash, now, now),
                )
            except sqlite3.IntegrityError as exc:
                raise DuplicateAccountError("An account already exists for that email.") from exc

            conn.execute(
                """
                INSERT INTO api_keys (id, account_id, key_hash, name, prefix, created_at)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (key_id, account_id, hashed_key, key_name.strip() or "Default key", prefix, now),
            )

        account = self.get_account(account_id)
        api_key = self.get_api_key_by_hash(hashed_key)
        if account is None or api_key is None:
            raise RuntimeError("Account provisioning failed.")
        return account, api_key, raw_key

    def create_api_key(self, *, account_id: str, name: str) -> tuple[ApiKeyRecord, str]:
        self.init_schema()
        raw_key, hashed_key, prefix = generate_api_key()
        key_id = str(uuid.uuid4())
        now = utc_now()

        with self.connect() as conn:
            conn.execute(
                """
                INSERT INTO api_keys (id, account_id, key_hash, name, prefix, created_at)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (key_id, account_id, hashed_key, name.strip() or "API key", prefix, now),
            )

        api_key = self.get_api_key_by_hash(hashed_key)
        if api_key is None:
            raise RuntimeError("API key creation failed.")
        return api_key, raw_key

    def verify_account_password(self, *, email: str, password: str) -> AccountRecord:
        account = self.get_account_by_email(email)
        if account is None or not verify_password(password, account.password_hash):
            raise AuthenticationError("Invalid email or password.")
        return account

    def authenticate(self, raw_key: str) -> AuthContext:
        self.init_schema()
        hashed = key_hash(raw_key.strip())
        api_key = self.get_api_key_by_hash(hashed)
        if api_key is None or api_key.revoked_at is not None:
            raise AuthenticationError("Invalid or revoked API key.")

        account = self.get_account(api_key.account_id)
        if account is None:
            raise AuthenticationError("API key is not attached to an account.")

        now = utc_now()
        with self.connect() as conn:
            conn.execute(
                "UPDATE api_keys SET last_used_at = ? WHERE id = ?",
                (now, api_key.id),
            )

        return AuthContext(account=account, api_key=api_key)

    def get_account(self, account_id: str) -> AccountRecord | None:
        self.init_schema()
        with self.connect() as conn:
            row = conn.execute("SELECT * FROM accounts WHERE id = ?", (account_id,)).fetchone()
        return self._account_from_row(row) if row else None

    def get_account_by_customer_id(self, customer_id: str) -> AccountRecord | None:
        self.init_schema()
        with self.connect() as conn:
            row = conn.execute(
                "SELECT * FROM accounts WHERE stripe_customer_id = ?",
                (customer_id,),
            ).fetchone()
        return self._account_from_row(row) if row else None

    def get_account_by_email(self, email: str) -> AccountRecord | None:
        self.init_schema()
        with self.connect() as conn:
            row = conn.execute(
                "SELECT * FROM accounts WHERE email = ?",
                (email.strip().lower(),),
            ).fetchone()
        return self._account_from_row(row) if row else None

    def get_api_key_by_hash(self, hashed_key: str) -> ApiKeyRecord | None:
        self.init_schema()
        with self.connect() as conn:
            row = conn.execute("SELECT * FROM api_keys WHERE key_hash = ?", (hashed_key,)).fetchone()
        return self._api_key_from_row(row) if row else None

    def list_api_keys(self, account_id: str) -> list[ApiKeyRecord]:
        self.init_schema()
        with self.connect() as conn:
            rows = conn.execute(
                """
                SELECT * FROM api_keys
                WHERE account_id = ?
                ORDER BY created_at DESC
                """,
                (account_id,),
            ).fetchall()
        return [self._api_key_from_row(row) for row in rows]

    def revoke_api_key(self, *, account_id: str, key_id: str) -> ApiKeyRecord | None:
        self.init_schema()
        with self.connect() as conn:
            conn.execute(
                """
                UPDATE api_keys
                SET revoked_at = COALESCE(revoked_at, ?)
                WHERE id = ? AND account_id = ?
                """,
                (utc_now(), key_id, account_id),
            )
            row = conn.execute(
                "SELECT * FROM api_keys WHERE id = ? AND account_id = ?",
                (key_id, account_id),
            ).fetchone()
        return self._api_key_from_row(row) if row else None

    def count_monthly_usage(self, account_id: str) -> int:
        self.init_schema()
        period_start = current_period_start().isoformat()
        with self.connect() as conn:
            row = conn.execute(
                """
                SELECT COALESCE(SUM(units), 0) AS used
                FROM audit_logs
                WHERE account_id = ? AND created_at >= ?
                """,
                (account_id, period_start),
            ).fetchone()
        return int(row["used"] or 0)

    def count_recent_rate_units(self, identifier: str, since_iso: str) -> int:
        self.init_schema()
        with self.connect() as conn:
            row = conn.execute(
                """
                SELECT COALESCE(SUM(units), 0) AS used
                FROM rate_events
                WHERE identifier = ? AND created_at >= ?
                """,
                (identifier, since_iso),
            ).fetchone()
        return int(row["used"] or 0)

    def record_rate_event(self, *, identifier: str, units: int) -> None:
        self.init_schema()
        with self.connect() as conn:
            conn.execute(
                "INSERT INTO rate_events (id, identifier, units, created_at) VALUES (?, ?, ?, ?)",
                (str(uuid.uuid4()), identifier, units, utc_now()),
            )
            conn.execute("DELETE FROM rate_events WHERE created_at < datetime('now', '-2 days')")

    def mark_stripe_event_processed(self, *, event_id: str, event_type: str) -> bool:
        """Record a Stripe event id; return True only the first time it is seen.

        Stripe guarantees at-least-once webhook delivery and retries on any
        non-2xx, so the same event id can arrive several times. Callers use the
        return value to make webhook handling idempotent: apply side effects only
        when this returns True.
        """

        self.init_schema()
        with self.connect() as conn:
            cursor = conn.execute(
                "INSERT OR IGNORE INTO stripe_events (id, event_type, processed_at) "
                "VALUES (?, ?, ?)",
                (event_id, event_type, utc_now()),
            )
            return cursor.rowcount > 0

    def delete_stripe_event(self, *, event_id: str) -> None:
        """Undo mark_stripe_event_processed so a failed handler can be retried.

        If handling an event raises, we remove its idempotency record; Stripe
        then redelivers and the event is reprocessed instead of skipped as a
        duplicate.
        """

        self.init_schema()
        with self.connect() as conn:
            conn.execute("DELETE FROM stripe_events WHERE id = ?", (event_id,))

    def log_audit(
        self,
        *,
        account_id: str,
        api_key_id: str | None,
        audit: DomainAuditResponse,
        units: int = 1,
    ) -> str:
        self.init_schema()
        audit_id = str(uuid.uuid4())
        with self.connect() as conn:
            conn.execute(
                """
                INSERT INTO audit_logs (
                  id, account_id, api_key_id, domain, score, overall_status,
                  units, response_json, created_at
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    audit_id,
                    account_id,
                    api_key_id,
                    audit.domain,
                    audit.score,
                    audit.overall_status,
                    units,
                    audit.model_dump_json(),
                    utc_now(),
                ),
            )
        return audit_id

    def update_billing(
        self,
        *,
        account_id: str,
        plan: PlanName,
        stripe_customer_id: str | None = None,
        stripe_subscription_id: str | None = None,
        stripe_subscription_status: str | None = None,
    ) -> None:
        self.init_schema()
        now = utc_now()
        with self.connect() as conn:
            conn.execute(
                """
                UPDATE accounts
                SET plan = ?,
                    stripe_customer_id = COALESCE(?, stripe_customer_id),
                    stripe_subscription_id = COALESCE(?, stripe_subscription_id),
                    stripe_subscription_status = COALESCE(?, stripe_subscription_status),
                    updated_at = ?
                WHERE id = ?
                """,
                (
                    plan,
                    stripe_customer_id,
                    stripe_subscription_id,
                    stripe_subscription_status,
                    now,
                    account_id,
                ),
            )

    def usage_response(self, account: AccountRecord) -> PlanUsageResponse:
        limit = PLAN_LIMITS[account.plan]
        used = self.count_monthly_usage(account.id)
        return PlanUsageResponse(
            plan=account.plan,
            monthly_audit_limit=limit.monthly_audits,
            rate_limit_per_minute=limit.rate_limit_per_minute,
            current_period_start=current_period_start().isoformat(),
            audits_used=used,
            audits_remaining=max(0, limit.monthly_audits - used),
        )

    def audit_history(self, account: AccountRecord, *, limit: int = 25) -> AuditHistoryResponse:
        self.init_schema()
        capped_limit = max(1, min(limit, 100))
        with self.connect() as conn:
            rows = conn.execute(
                """
                SELECT id, domain, score, overall_status, units, created_at
                FROM audit_logs
                WHERE account_id = ?
                ORDER BY created_at DESC
                LIMIT ?
                """,
                (account.id, capped_limit),
            ).fetchall()

        return AuditHistoryResponse(
            usage=self.usage_response(account),
            audits=[
                AuditHistoryItem(
                    id=row["id"],
                    domain=row["domain"],
                    score=row["score"],
                    overall_status=row["overall_status"],
                    units=row["units"],
                    created_at=row["created_at"],
                )
                for row in rows
            ],
        )

    def audit_detail(
        self,
        account: AccountRecord,
        *,
        audit_id: str,
    ) -> AuditHistoryDetailResponse | None:
        self.init_schema()
        with self.connect() as conn:
            row = conn.execute(
                """
                SELECT id, units, response_json, created_at
                FROM audit_logs
                WHERE account_id = ? AND id = ?
                """,
                (account.id, audit_id),
            ).fetchone()

        if row is None:
            return None
        return AuditHistoryDetailResponse(
            id=row["id"],
            units=row["units"],
            created_at=row["created_at"],
            audit=decode_audit_response(row["response_json"]),
        )

    def create_audit_job(
        self,
        *,
        account_id: str,
        api_key_id: str | None,
        payload: dict[str, object],
        kind: str = "email_domain",
    ) -> AuditJobRecord:
        self.init_schema()
        job_id = str(uuid.uuid4())
        with self.connect() as conn:
            conn.execute(
                """
                INSERT INTO audit_jobs (
                  id, account_id, api_key_id, kind, status, payload_json, created_at
                )
                VALUES (?, ?, ?, ?, 'queued', ?, ?)
                """,
                (job_id, account_id, api_key_id, kind, json.dumps(payload), utc_now()),
            )
        job = self.get_audit_job(account_id=account_id, job_id=job_id)
        if job is None:
            raise RuntimeError("Audit job creation failed.")
        return job

    def list_audit_jobs(self, *, account_id: str, limit: int = 25) -> list[AuditJobRecord]:
        self.init_schema()
        capped_limit = max(1, min(limit, 100))
        with self.connect() as conn:
            rows = conn.execute(
                """
                SELECT * FROM audit_jobs
                WHERE account_id = ?
                ORDER BY created_at DESC
                LIMIT ?
                """,
                (account_id, capped_limit),
            ).fetchall()
        return [self._audit_job_from_row(row) for row in rows]

    def get_audit_job(self, *, account_id: str, job_id: str) -> AuditJobRecord | None:
        self.init_schema()
        with self.connect() as conn:
            row = conn.execute(
                """
                SELECT * FROM audit_jobs
                WHERE account_id = ? AND id = ?
                """,
                (account_id, job_id),
            ).fetchone()
        return self._audit_job_from_row(row) if row else None

    def mark_audit_job_running(self, *, account_id: str, job_id: str) -> AuditJobRecord | None:
        self.init_schema()
        now = utc_now()
        with self.connect() as conn:
            conn.execute(
                """
                UPDATE audit_jobs
                SET status = 'running', started_at = COALESCE(started_at, ?)
                WHERE account_id = ? AND id = ? AND status = 'queued'
                """,
                (now, account_id, job_id),
            )
        return self.get_audit_job(account_id=account_id, job_id=job_id)

    def complete_audit_job(
        self,
        *,
        account_id: str,
        job_id: str,
        audit: DomainAuditResponse,
        audit_log_id: str,
    ) -> AuditJobRecord | None:
        self.init_schema()
        with self.connect() as conn:
            conn.execute(
                """
                UPDATE audit_jobs
                SET status = 'succeeded',
                    result_audit_log_id = ?,
                    result_json = ?,
                    error = NULL,
                    finished_at = ?
                WHERE account_id = ? AND id = ?
                """,
                (audit_log_id, audit.model_dump_json(), utc_now(), account_id, job_id),
            )
        return self.get_audit_job(account_id=account_id, job_id=job_id)

    def fail_audit_job(
        self,
        *,
        account_id: str,
        job_id: str,
        error: str,
    ) -> AuditJobRecord | None:
        self.init_schema()
        with self.connect() as conn:
            conn.execute(
                """
                UPDATE audit_jobs
                SET status = 'failed', error = ?, finished_at = ?
                WHERE account_id = ? AND id = ?
                """,
                (error, utc_now(), account_id, job_id),
            )
        return self.get_audit_job(account_id=account_id, job_id=job_id)

    def create_export_object(
        self,
        *,
        account_id: str,
        key: str,
        kind: str,
        format: ExportFormat,
        media_type: str,
        size_bytes: int,
    ) -> ExportObjectRecord:
        self.init_schema()
        export_id = str(uuid.uuid4())
        with self.connect() as conn:
            conn.execute(
                """
                INSERT INTO export_objects (
                  id, account_id, object_key, kind, format, media_type, size_bytes, created_at
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (export_id, account_id, key, kind, format, media_type, size_bytes, utc_now()),
            )
        export = self.get_export_object(account_id=account_id, export_id=export_id)
        if export is None:
            raise RuntimeError("Export object creation failed.")
        return export

    def list_export_objects(
        self,
        *,
        account_id: str,
        limit: int = 25,
    ) -> list[ExportObjectRecord]:
        self.init_schema()
        capped_limit = max(1, min(limit, 100))
        with self.connect() as conn:
            rows = conn.execute(
                """
                SELECT * FROM export_objects
                WHERE account_id = ?
                ORDER BY created_at DESC
                LIMIT ?
                """,
                (account_id, capped_limit),
            ).fetchall()
        return [self._export_object_from_row(row) for row in rows]

    def get_export_object(
        self,
        *,
        account_id: str,
        export_id: str,
    ) -> ExportObjectRecord | None:
        self.init_schema()
        with self.connect() as conn:
            row = conn.execute(
                """
                SELECT * FROM export_objects
                WHERE account_id = ? AND id = ?
                """,
                (account_id, export_id),
            ).fetchone()
        return self._export_object_from_row(row) if row else None

    def audit_history_export_rows(
        self,
        account: AccountRecord,
        *,
        limit: int = 500,
    ) -> list[dict[str, object]]:
        self.init_schema()
        capped_limit = max(1, min(limit, 1000))
        with self.connect() as conn:
            rows = conn.execute(
                """
                SELECT id, domain, score, overall_status, units, response_json, created_at
                FROM audit_logs
                WHERE account_id = ?
                ORDER BY created_at DESC
                LIMIT ?
                """,
                (account.id, capped_limit),
            ).fetchall()

        export_rows: list[dict[str, object]] = []
        for row in rows:
            audit = decode_audit_response(row["response_json"])
            export_rows.append(
                {
                    "id": row["id"],
                    "domain": row["domain"],
                    "score": row["score"],
                    "overall_status": row["overall_status"],
                    "units": row["units"],
                    "provider_names": ", ".join(provider.name for provider in audit.providers),
                    "recommendation_count": len(audit.recommendations),
                    "top_recommendation": (
                        audit.recommendations[0].message if audit.recommendations else ""
                    ),
                    "checked_at": audit.checked_at,
                    "created_at": row["created_at"],
                }
            )
        return export_rows

    def create_monitor(
        self,
        *,
        account_id: str,
        domain: str,
        selectors: list[str] | None = None,
        expected_providers: list[str] | None = None,
        cadence: MonitorCadence = "weekly",
    ) -> MonitorRecord:
        self.init_schema()
        monitor_id = str(uuid.uuid4())
        now = utc_now()
        with self.connect() as conn:
            try:
                conn.execute(
                    """
                    INSERT INTO domain_monitors (
                      id, account_id, domain, selectors_json, expected_providers_json,
                      cadence, created_at, updated_at
                    )
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        monitor_id,
                        account_id,
                        domain,
                        json.dumps(selectors or []),
                        json.dumps(expected_providers or []),
                        cadence,
                        now,
                        now,
                    ),
                )
            except sqlite3.IntegrityError as exc:
                raise DuplicateMonitorError("That domain is already on this account watchlist.") from exc

        monitor = self.get_monitor(account_id=account_id, monitor_id=monitor_id)
        if monitor is None:
            raise RuntimeError("Monitor creation failed.")
        return monitor

    def list_monitors(self, account_id: str) -> list[MonitorRecord]:
        self.init_schema()
        with self.connect() as conn:
            rows = conn.execute(
                """
                SELECT * FROM domain_monitors
                WHERE account_id = ?
                ORDER BY updated_at DESC
                """,
                (account_id,),
            ).fetchall()
        return [self._monitor_from_row(row) for row in rows]

    def list_due_monitors(self, *, account_id: str, limit: int = 10) -> list[MonitorRecord]:
        self.init_schema()
        capped_limit = max(1, min(limit, 50))
        with self.connect() as conn:
            rows = conn.execute(
                """
                SELECT * FROM domain_monitors
                WHERE account_id = ?
                  AND cadence != 'manual'
                  AND (
                    last_checked_at IS NULL
                    OR (cadence = 'weekly' AND last_checked_at <= datetime('now', '-7 days'))
                    OR (cadence = 'monthly' AND last_checked_at <= datetime('now', '-30 days'))
                  )
                ORDER BY COALESCE(last_checked_at, created_at) ASC
                LIMIT ?
                """,
                (account_id, capped_limit),
            ).fetchall()
        return [self._monitor_from_row(row) for row in rows]

    def get_monitor(self, *, account_id: str, monitor_id: str) -> MonitorRecord | None:
        self.init_schema()
        with self.connect() as conn:
            row = conn.execute(
                """
                SELECT * FROM domain_monitors
                WHERE account_id = ? AND id = ?
                """,
                (account_id, monitor_id),
            ).fetchone()
        return self._monitor_from_row(row) if row else None

    def delete_monitor(self, *, account_id: str, monitor_id: str) -> MonitorRecord | None:
        self.init_schema()
        monitor = self.get_monitor(account_id=account_id, monitor_id=monitor_id)
        if monitor is None:
            return None
        with self.connect() as conn:
            conn.execute(
                "DELETE FROM domain_monitors WHERE account_id = ? AND id = ?",
                (account_id, monitor_id),
            )
        return monitor

    def update_monitor_after_audit(
        self,
        *,
        account_id: str,
        monitor_id: str,
        audit: DomainAuditResponse,
        audit_log_id: str,
    ) -> MonitorRecord | None:
        self.init_schema()
        now = utc_now()
        with self.connect() as conn:
            conn.execute(
                """
                UPDATE domain_monitors
                SET last_audit_log_id = ?,
                    last_score = ?,
                    last_status = ?,
                    last_checked_at = ?,
                    updated_at = ?
                WHERE account_id = ? AND id = ?
                """,
                (
                    audit_log_id,
                    audit.score,
                    audit.overall_status,
                    audit.checked_at,
                    now,
                    account_id,
                    monitor_id,
                ),
            )
        return self.get_monitor(account_id=account_id, monitor_id=monitor_id)

    def account_overview(self, account: AccountRecord) -> AccountOverviewResponse:
        return AccountOverviewResponse(
            account=self.account_response(account),
            usage=self.usage_response(account),
            api_keys=[self.api_key_response(item) for item in self.list_api_keys(account.id)],
        )

    def api_key_list(self, account: AccountRecord) -> ApiKeyListResponse:
        return ApiKeyListResponse(
            keys=[self.api_key_response(item) for item in self.list_api_keys(account.id)],
        )

    def monitor_list(self, account: AccountRecord) -> MonitorListResponse:
        return MonitorListResponse(
            monitors=[self.monitor_response(item) for item in self.list_monitors(account.id)],
        )

    def create_support_request(
        self,
        *,
        email: str,
        subject: str,
        message: str,
        account_id: str | None = None,
    ) -> None:
        self.init_schema()
        with self.connect() as conn:
            conn.execute(
                """
                INSERT INTO support_requests (id, account_id, email, subject, message, created_at)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (
                    str(uuid.uuid4()),
                    account_id,
                    email.strip().lower(),
                    subject.strip(),
                    message.strip(),
                    utc_now(),
                ),
            )

    def account_response(self, account: AccountRecord) -> AccountResponse:
        return AccountResponse(
            id=account.id,
            email=account.email,
            plan=account.plan,
            stripe_customer_id=account.stripe_customer_id,
            stripe_subscription_status=account.stripe_subscription_status,
            created_at=account.created_at,
        )

    def api_key_response(self, api_key: ApiKeyRecord) -> ApiKeyResponse:
        return ApiKeyResponse(
            id=api_key.id,
            name=api_key.name,
            prefix=api_key.prefix,
            created_at=api_key.created_at,
            last_used_at=api_key.last_used_at,
            revoked_at=api_key.revoked_at,
        )

    def monitor_response(self, monitor: MonitorRecord) -> MonitorResponse:
        return MonitorResponse(
            id=monitor.id,
            domain=monitor.domain,
            selectors=monitor.selectors,
            expected_providers=monitor.expected_providers,
            cadence=monitor.cadence,
            last_audit_id=monitor.last_audit_id,
            last_score=monitor.last_score,
            last_status=monitor.last_status,
            last_checked_at=monitor.last_checked_at,
            created_at=monitor.created_at,
            updated_at=monitor.updated_at,
        )

    def audit_job_response(self, job: AuditJobRecord) -> AuditJobResponse:
        return AuditJobResponse(
            id=job.id,
            status=job.status,
            kind="email_domain",
            audit_log_id=job.result_audit_log_id,
            audit=job.result,
            error=job.error,
            created_at=job.created_at,
            started_at=job.started_at,
            finished_at=job.finished_at,
        )

    def export_object_response(self, export: ExportObjectRecord) -> ExportObjectResponse:
        return ExportObjectResponse(
            id=export.id,
            key=export.key,
            kind="audit_history",
            format=export.format,
            media_type=export.media_type,
            size_bytes=export.size_bytes,
            download_url=f"/v1/exports/{export.id}/download",
            created_at=export.created_at,
        )

    def _account_from_row(self, row: sqlite3.Row) -> AccountRecord:
        return AccountRecord(
            id=row["id"],
            email=row["email"],
            plan=normalize_plan(row["plan"]),
            stripe_customer_id=row["stripe_customer_id"],
            stripe_subscription_id=row["stripe_subscription_id"],
            stripe_subscription_status=row["stripe_subscription_status"],
            password_hash=row["password_hash"],
            created_at=row["created_at"],
        )

    def _api_key_from_row(self, row: sqlite3.Row) -> ApiKeyRecord:
        return ApiKeyRecord(
            id=row["id"],
            account_id=row["account_id"],
            key_hash=row["key_hash"],
            name=row["name"],
            prefix=row["prefix"],
            created_at=row["created_at"],
            last_used_at=row["last_used_at"],
            revoked_at=row["revoked_at"],
        )

    def _monitor_from_row(self, row: sqlite3.Row) -> MonitorRecord:
        return MonitorRecord(
            id=row["id"],
            account_id=row["account_id"],
            domain=row["domain"],
            selectors=_decode_string_list(row["selectors_json"]),
            expected_providers=_decode_string_list(row["expected_providers_json"]),
            cadence=_normalize_monitor_cadence(row["cadence"]),
            last_audit_id=row["last_audit_log_id"],
            last_score=row["last_score"],
            last_status=_normalize_status(row["last_status"]) if row["last_status"] else None,
            last_checked_at=row["last_checked_at"],
            created_at=row["created_at"],
            updated_at=row["updated_at"],
        )

    def _audit_job_from_row(self, row: sqlite3.Row) -> AuditJobRecord:
        result_json = row["result_json"]
        return AuditJobRecord(
            id=row["id"],
            account_id=row["account_id"],
            api_key_id=row["api_key_id"],
            kind=row["kind"],
            status=_normalize_audit_job_status(row["status"]),
            payload=json.loads(row["payload_json"]),
            result_audit_log_id=row["result_audit_log_id"],
            result=decode_audit_response(result_json) if result_json else None,
            error=row["error"],
            created_at=row["created_at"],
            started_at=row["started_at"],
            finished_at=row["finished_at"],
        )

    def _export_object_from_row(self, row: sqlite3.Row) -> ExportObjectRecord:
        return ExportObjectRecord(
            id=row["id"],
            account_id=row["account_id"],
            key=row["object_key"],
            kind=row["kind"],
            format=_normalize_export_format(row["format"]),
            media_type=row["media_type"],
            size_bytes=row["size_bytes"],
            created_at=row["created_at"],
        )

    def _ensure_column(
        self,
        conn: sqlite3.Connection,
        table: str,
        column_name: str,
        definition: str,
    ) -> None:
        columns = conn.execute(f"PRAGMA table_info({table})").fetchall()
        names = {row["name"] for row in columns}
        if column_name not in names:
            conn.execute(f"ALTER TABLE {table} ADD COLUMN {column_name} {definition}")


def decode_audit_response(raw_json: str) -> DomainAuditResponse:
    return DomainAuditResponse(**json.loads(raw_json))


def _decode_string_list(raw_json: str) -> list[str]:
    try:
        value = json.loads(raw_json)
    except json.JSONDecodeError:
        return []
    if not isinstance(value, list):
        return []
    return [str(item) for item in value if str(item).strip()]


def _normalize_monitor_cadence(value: str) -> MonitorCadence:
    if value in {"manual", "weekly", "monthly"}:
        return value
    return "weekly"


def _normalize_status(value: str) -> Status:
    if value in {"pass", "warn", "fail", "info"}:
        return value
    return "info"


def _normalize_audit_job_status(value: str) -> AuditJobStatus:
    if value in {"queued", "running", "succeeded", "failed"}:
        return value
    return "failed"


def _normalize_export_format(value: str) -> ExportFormat:
    if value in {"json", "csv"}:
        return value
    return "json"
