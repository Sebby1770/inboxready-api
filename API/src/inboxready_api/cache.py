from __future__ import annotations

import threading
import time
from collections import OrderedDict
from typing import Any, Generic, TypeVar

T = TypeVar("T")


class TTLCache(Generic[T]):
    """Simple thread-safe TTL cache."""

    def __init__(self, *, max_entries: int = 2_000) -> None:
        self._lock = threading.Lock()
        self._max_entries = max(1, max_entries)
        self._store: OrderedDict[str, tuple[float, T]] = OrderedDict()

    def configure(self, *, max_entries: int) -> None:
        with self._lock:
            self._max_entries = max(1, max_entries)
            while len(self._store) > self._max_entries:
                self._store.popitem(last=False)

    def get(self, key: str) -> T | None:
        now = time.monotonic()
        with self._lock:
            entry = self._store.get(key)
            if entry is None:
                return None
            expires_at, value = entry
            if expires_at <= now:
                del self._store[key]
                return None
            self._store.move_to_end(key)
            return value

    def set(self, key: str, value: T, ttl_seconds: float) -> None:
        if ttl_seconds <= 0:
            return
        expires_at = time.monotonic() + ttl_seconds
        with self._lock:
            self._store.pop(key, None)
            self._store[key] = (expires_at, value)
            while len(self._store) > self._max_entries:
                self._store.popitem(last=False)

    def clear(self) -> int:
        with self._lock:
            count = len(self._store)
            self._store.clear()
            return count

    def __len__(self) -> int:
        with self._lock:
            return len(self._store)


audit_cache: TTLCache[Any] = TTLCache()


def make_audit_cache_key(
    domain: str,
    selectors: list[str] | None = None,
    expected_providers: list[str] | None = None,
) -> str:
    selectors = sorted(s.strip().lower() for s in (selectors or []) if s.strip())
    expected = sorted(p.strip().lower() for p in (expected_providers or []) if p.strip())
    return f"{domain.lower()}|sel={','.join(selectors)}|prov={','.join(expected)}"
