"""In-memory (optionally file-backed) audit history store."""

from __future__ import annotations

import csv
import io
import json
import threading
from collections import Counter
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any


@dataclass
class HistoryEntry:
    domain: str
    score: int
    overall_status: str
    checked_at: str
    cached: bool = False

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


class HistoryStore:
    """Thread-safe ring buffer of recent audit results."""

    def __init__(self, *, max_entries: int = 500, path: Path | None = None) -> None:
        self.max_entries = max(1, max_entries)
        self.path = path
        self._lock = threading.Lock()
        self._entries: list[HistoryEntry] = []
        if path is not None and path.is_file():
            self._load(path)

    def _load(self, path: Path) -> None:
        try:
            raw = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return
        if not isinstance(raw, list):
            return
        entries: list[HistoryEntry] = []
        for item in raw[-self.max_entries :]:
            if not isinstance(item, dict):
                continue
            try:
                entries.append(
                    HistoryEntry(
                        domain=str(item["domain"]),
                        score=int(item["score"]),
                        overall_status=str(item.get("overall_status", "info")),
                        checked_at=str(item.get("checked_at", "")),
                        cached=bool(item.get("cached", False)),
                    )
                )
            except (KeyError, TypeError, ValueError):
                continue
        self._entries = entries

    def _persist_unlocked(self) -> None:
        if self.path is None:
            return
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            payload = [e.to_dict() for e in self._entries]
            self.path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
        except OSError:
            pass

    def add(
        self,
        *,
        domain: str,
        score: int,
        overall_status: str,
        checked_at: str | None = None,
        cached: bool = False,
    ) -> HistoryEntry:
        entry = HistoryEntry(
            domain=domain,
            score=score,
            overall_status=overall_status,
            checked_at=checked_at or datetime.now(UTC).isoformat(),
            cached=cached,
        )
        with self._lock:
            self._entries.append(entry)
            if len(self._entries) > self.max_entries:
                self._entries = self._entries[-self.max_entries :]
            self._persist_unlocked()
        return entry

    def list(
        self, *, domain: str | None = None, limit: int = 20
    ) -> list[HistoryEntry]:
        limit = max(1, min(limit, 500))
        with self._lock:
            items = list(self._entries)
        if domain:
            domain_l = domain.lower()
            items = [e for e in items if e.domain.lower() == domain_l]
        return list(reversed(items[-limit:]))

    def stats(self) -> dict[str, Any]:
        with self._lock:
            items = list(self._entries)
        if not items:
            return {
                "count": 0,
                "average_score": 0.0,
                "by_status": {},
                "unique_domains": 0,
            }
        scores = [e.score for e in items]
        by_status = dict(Counter(e.overall_status for e in items))
        return {
            "count": len(items),
            "average_score": round(sum(scores) / len(scores), 2),
            "by_status": by_status,
            "unique_domains": len({e.domain.lower() for e in items}),
        }

    def export_csv(self) -> str:
        with self._lock:
            items = list(self._entries)
        buf = io.StringIO()
        writer = csv.DictWriter(
            buf,
            fieldnames=["domain", "score", "overall_status", "checked_at", "cached"],
        )
        writer.writeheader()
        for entry in items:
            writer.writerow(entry.to_dict())
        return buf.getvalue()

    def clear(self) -> int:
        with self._lock:
            n = len(self._entries)
            self._entries.clear()
            self._persist_unlocked()
        return n


# Process-wide store (path configured at first access via configure_history).
_history: HistoryStore | None = None
_history_lock = threading.Lock()


def configure_history(*, max_entries: int = 500, path: str | None = None) -> HistoryStore:
    global _history
    with _history_lock:
        _history = HistoryStore(
            max_entries=max_entries,
            path=Path(path) if path else None,
        )
        return _history


def get_history() -> HistoryStore:
    global _history
    with _history_lock:
        if _history is None:
            _history = HistoryStore()
        return _history
