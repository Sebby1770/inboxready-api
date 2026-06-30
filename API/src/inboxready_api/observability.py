from __future__ import annotations

from collections import deque
from datetime import UTC, datetime
import threading
import time
from typing import Any


STARTED_AT = datetime.now(UTC)
STARTED_MONOTONIC = time.monotonic()

_lock = threading.Lock()
_requests_total = 0
_errors_total = 0
_duration_total_ms = 0.0
_status_counts: dict[str, int] = {}
_route_counts: dict[str, int] = {}
_recent_errors: deque[dict[str, Any]] = deque(maxlen=25)


def record_request(
    *,
    method: str,
    path: str,
    status_code: int,
    duration_ms: float,
    request_id: str,
    error: str | None = None,
) -> None:
    route_key = f"{method.upper()} {path}"
    status_key = str(status_code)
    with _lock:
        global _requests_total, _errors_total, _duration_total_ms
        _requests_total += 1
        _duration_total_ms += duration_ms
        _status_counts[status_key] = _status_counts.get(status_key, 0) + 1
        _route_counts[route_key] = _route_counts.get(route_key, 0) + 1
        if status_code >= 500 or error:
            _errors_total += 1
            _recent_errors.appendleft(
                {
                    "request_id": request_id,
                    "method": method.upper(),
                    "path": path,
                    "status_code": status_code,
                    "duration_ms": round(duration_ms, 3),
                    "error": error or "HTTP 5xx response",
                    "occurred_at": datetime.now(UTC).isoformat(),
                }
            )


def metrics_snapshot() -> dict[str, Any]:
    uptime_seconds = max(time.monotonic() - STARTED_MONOTONIC, 0.001)
    with _lock:
        requests_total = _requests_total
        errors_total = _errors_total
        average_latency_ms = _duration_total_ms / requests_total if requests_total else 0.0
        status_counts = dict(sorted(_status_counts.items()))
        route_counts = dict(sorted(_route_counts.items()))
        recent_errors = list(_recent_errors)

    success_total = max(requests_total - errors_total, 0)
    success_rate = (success_total / requests_total) if requests_total else 1.0
    qps = requests_total / uptime_seconds
    return {
        "service": "inboxready-api",
        "started_at": STARTED_AT.isoformat(),
        "uptime_seconds": round(uptime_seconds, 3),
        "requests_total": requests_total,
        "errors_total": errors_total,
        "qps": round(qps, 3),
        "throughput_per_minute": round(qps * 60, 3),
        "average_latency_ms": round(average_latency_ms, 3),
        "availability": {
            "success_rate": round(success_rate, 5),
            "success_percentage": round(success_rate * 100, 3),
        },
        "status_counts": status_counts,
        "route_counts": route_counts,
        "recent_errors": recent_errors,
    }


def prometheus_metrics() -> str:
    snapshot = metrics_snapshot()
    lines = [
        "# HELP inboxready_uptime_seconds Service uptime in seconds.",
        "# TYPE inboxready_uptime_seconds gauge",
        f"inboxready_uptime_seconds {snapshot['uptime_seconds']}",
        "# HELP inboxready_requests_total Total HTTP requests observed by the app.",
        "# TYPE inboxready_requests_total counter",
        f"inboxready_requests_total {snapshot['requests_total']}",
        "# HELP inboxready_errors_total Total HTTP 5xx or uncaught-error requests.",
        "# TYPE inboxready_errors_total counter",
        f"inboxready_errors_total {snapshot['errors_total']}",
        "# HELP inboxready_qps Average requests per second since process start.",
        "# TYPE inboxready_qps gauge",
        f"inboxready_qps {snapshot['qps']}",
        "# HELP inboxready_throughput_per_minute Average requests per minute since process start.",
        "# TYPE inboxready_throughput_per_minute gauge",
        f"inboxready_throughput_per_minute {snapshot['throughput_per_minute']}",
        "# HELP inboxready_average_latency_ms Average application request latency in milliseconds.",
        "# TYPE inboxready_average_latency_ms gauge",
        f"inboxready_average_latency_ms {snapshot['average_latency_ms']}",
        "# HELP inboxready_availability_ratio Successful request ratio since process start.",
        "# TYPE inboxready_availability_ratio gauge",
        f"inboxready_availability_ratio {snapshot['availability']['success_rate']}",
        "# HELP inboxready_status_responses_total HTTP responses by status code.",
        "# TYPE inboxready_status_responses_total counter",
    ]
    for status_code, count in snapshot["status_counts"].items():
        lines.append(f'inboxready_status_responses_total{{status_code="{status_code}"}} {count}')
    lines.append("# HELP inboxready_route_requests_total HTTP requests by normalized route.")
    lines.append("# TYPE inboxready_route_requests_total counter")
    for route, count in snapshot["route_counts"].items():
        safe_route = str(route).replace("\\", "\\\\").replace('"', '\\"')
        lines.append(f'inboxready_route_requests_total{{route="{safe_route}"}} {count}')
    return "\n".join(lines) + "\n"
