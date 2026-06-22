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
    ApiKeyListResponse,
    ApiKeyResponse,
    AuditHistoryItem,
    AuditHistoryResponse,
    DomainAuditResponse,
    PlanName,
    PlanUsageResponse,
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
class AuthContext:
    account: AccountRecord
    api_key: ApiKeyRecord | None


class DuplicateAccountError(Exception):
    pass


class AuthenticationError(Exception):
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

                CREATE INDEX IF NOT EXISTS audit_logs_account_created_idx
                  ON audit_logs(account_id, created_at);
                CREATE INDEX IF NOT EXISTS rate_events_identifier_created_idx
                  ON rate_events(identifier, created_at);
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

    def log_audit(
        self,
        *,
        account_id: str,
        api_key_id: str | None,
        audit: DomainAuditResponse,
        units: int = 1,
    ) -> None:
        self.init_schema()
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
                    str(uuid.uuid4()),
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
