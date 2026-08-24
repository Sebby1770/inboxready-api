"""Contact form capture.

Deliberately small: submissions are held in a bounded in-memory deque and, when
``INBOXREADY_LEADS_PATH`` is set, mirrored to a JSON file on the same instance.
Nothing is forwarded to a third party, which is exactly what the privacy policy
promises.
"""

from __future__ import annotations

import json
import threading
from collections import deque
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from pathlib import Path

MESSAGE_MAX = 4000
NAME_MAX = 120
EMAIL_MAX = 254


@dataclass(frozen=True)
class Lead:
    name: str
    email: str
    company: str
    topic: str
    message: str
    received_at: str

    def to_dict(self) -> dict[str, str]:
        return asdict(self)


class LeadValidationError(ValueError):
    """Raised with a human-readable reason the submission was rejected."""


def _clean(value: str, limit: int) -> str:
    return " ".join(str(value or "").split())[:limit]


def validate(
    *,
    name: str,
    email: str,
    company: str,
    topic: str,
    message: str,
) -> Lead:
    name = _clean(name, NAME_MAX)
    email = _clean(email, EMAIL_MAX)
    company = _clean(company, NAME_MAX)
    topic = _clean(topic, 60) or "General"
    message = "\n".join(line.rstrip() for line in str(message or "").splitlines()).strip()[:MESSAGE_MAX]

    if not name:
        raise LeadValidationError("Please tell us your name.")
    if "@" not in email or "." not in email.split("@")[-1] or email.startswith("@"):
        raise LeadValidationError("That email address does not look right.")
    if len(message) < 10:
        raise LeadValidationError("Please add a little more detail — at least a sentence.")

    return Lead(
        name=name,
        email=email,
        company=company,
        topic=topic,
        message=message,
        received_at=datetime.now(UTC).isoformat(timespec="seconds").replace("+00:00", "Z"),
    )


class LeadStore:
    """Bounded, thread-safe lead store with optional JSON persistence."""

    def __init__(self, max_entries: int = 500, path: Path | str | None = None) -> None:
        self._lock = threading.Lock()
        self._entries: deque[Lead] = deque(maxlen=max_entries)
        self._path = Path(path) if path else None
        self._load()

    def _load(self) -> None:
        if not self._path or not self._path.exists():
            return
        try:
            raw = json.loads(self._path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return
        for item in raw if isinstance(raw, list) else []:
            if isinstance(item, dict):
                try:
                    self._entries.append(Lead(**item))
                except TypeError:
                    continue

    def _persist(self) -> None:
        if not self._path:
            return
        try:
            self._path.parent.mkdir(parents=True, exist_ok=True)
            self._path.write_text(
                json.dumps([entry.to_dict() for entry in self._entries], indent=2),
                encoding="utf-8",
            )
        except OSError:
            # A failed write must never cost the visitor their submission.
            pass

    def add(self, lead: Lead) -> Lead:
        with self._lock:
            self._entries.append(lead)
            self._persist()
        return lead

    def list(self, limit: int = 50) -> list[Lead]:
        with self._lock:
            return list(self._entries)[-limit:][::-1]

    def clear(self) -> int:
        with self._lock:
            count = len(self._entries)
            self._entries.clear()
            self._persist()
        return count

    def __len__(self) -> int:
        return len(self._entries)


_store = LeadStore()


def configure_leads(max_entries: int = 500, path: Path | str | None = None) -> LeadStore:
    global _store
    _store = LeadStore(max_entries=max_entries, path=path)
    return _store


def get_leads() -> LeadStore:
    return _store
