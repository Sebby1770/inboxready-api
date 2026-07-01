from __future__ import annotations

from typing import Any

from inboxready_api.models import AuditHistoryResponse, PlanUsageResponse
from inboxready_api.storage import MonitorRecord


def dashboard_tone_for_status(status: str) -> str:
    if status in {"pass", "warn", "fail"}:
        return status
    return "info"


def build_dashboard_insights(
    *,
    usage: PlanUsageResponse,
    audit_history: AuditHistoryResponse,
    monitors: list[MonitorRecord],
) -> dict[str, Any]:
    audits = list(audit_history.audits)
    status_counts = {"pass": 0, "warn": 0, "fail": 0, "info": 0}
    for audit in audits:
        status_counts[audit.overall_status] = status_counts.get(audit.overall_status, 0) + 1

    usage_percent = (
        round((usage.audits_used / usage.monthly_audit_limit) * 100)
        if usage.monthly_audit_limit
        else 0
    )
    average_score = round(sum(audit.score for audit in audits) / len(audits)) if audits else None
    audit_attention = [
        audit for audit in audits if audit.overall_status in {"warn", "fail"}
    ]
    monitor_attention = [
        monitor for monitor in monitors if monitor.last_status in {"warn", "fail"}
    ]
    unchecked_monitors = [monitor for monitor in monitors if monitor.last_score is None]

    attention_domains: list[str] = []
    seen_attention: set[str] = set()
    for domain in [
        *(audit.domain for audit in audit_attention),
        *(monitor.domain for monitor in monitor_attention),
    ]:
        if domain not in seen_attention:
            seen_attention.add(domain)
            attention_domains.append(domain)

    if average_score is None:
        average_value = "No audits"
        average_tone = "info"
        average_detail = "Run an audit to establish the account baseline."
    else:
        average_value = f"{average_score}/100"
        if status_counts["fail"]:
            average_tone = "fail"
        elif status_counts["warn"] or average_score < 85:
            average_tone = "warn"
        else:
            average_tone = "pass"
        average_detail = f"{len(audits)} recent audit rows in this account."

    usage_tone = "fail" if usage_percent >= 90 else "warn" if usage_percent >= 75 else "pass"
    attention_tone = (
        "fail"
        if status_counts["fail"] or any(monitor.last_status == "fail" for monitor in monitors)
        else "warn"
        if attention_domains
        else "pass"
    )
    monitor_tone = "info" if not monitors else "warn" if unchecked_monitors else "pass"

    summary = [
        {
            "label": "Recent average",
            "value": average_value,
            "detail": average_detail,
            "tone": average_tone,
        },
        {
            "label": "Needs attention",
            "value": str(len(attention_domains)),
            "detail": (
                "Domains with warning or failing signals."
                if attention_domains
                else "No warning or failing signals in recent history."
            ),
            "tone": attention_tone,
        },
        {
            "label": "Monitor coverage",
            "value": str(len(monitors)),
            "detail": (
                f"{len(unchecked_monitors)} waiting for a first run."
                if unchecked_monitors
                else "Watchlist results are up to date."
                if monitors
                else "Add recurring customer domains to the watchlist."
            ),
            "tone": monitor_tone,
        },
        {
            "label": "Usage headroom",
            "value": str(usage.audits_remaining),
            "detail": (
                f"{usage_percent}% of {usage.monthly_audit_limit} monthly units used."
            ),
            "tone": usage_tone,
        },
    ]

    action_queue: list[dict[str, str]] = []
    for audit in audit_attention[:3]:
        action_queue.append(
            {
                "title": f"Review {audit.domain}",
                "body": (
                    f"Latest saved audit is {audit.overall_status} with a "
                    f"{audit.score}/100 readiness score."
                ),
                "href": f"/dashboard/audit-history/{audit.id}.json",
                "cta": "Open JSON",
                "tone": dashboard_tone_for_status(audit.overall_status),
            }
        )

    for monitor in unchecked_monitors[: max(0, 3 - len(action_queue))]:
        action_queue.append(
            {
                "title": f"Run {monitor.domain}",
                "body": "This monitor is on the watchlist but has not created a baseline yet.",
                "href": "#monitors",
                "cta": "Run monitor",
                "tone": "info",
            }
        )

    if usage_percent >= 75 and len(action_queue) < 4:
        action_queue.append(
            {
                "title": "Check plan capacity",
                "body": (
                    f"This account has used {usage_percent}% of the monthly "
                    "audit allowance."
                ),
                "href": "#billing",
                "cta": "Open billing",
                "tone": usage_tone,
            }
        )

    if not audits and len(action_queue) < 4:
        action_queue.append(
            {
                "title": "Create the first audit baseline",
                "body": "Run a customer domain check so the dashboard can track health over time.",
                "href": "#run-audit",
                "cta": "Run audit",
                "tone": "info",
            }
        )

    if not monitors and len(action_queue) < 4:
        action_queue.append(
            {
                "title": "Add a domain monitor",
                "body": "Save a key customer sender so support can re-check it quickly.",
                "href": "#monitors",
                "cta": "Add monitor",
                "tone": "info",
            }
        )

    if not action_queue:
        action_queue.append(
            {
                "title": "Health signals look steady",
                "body": "Recent audits and watched domains are not showing urgent issues.",
                "href": "#history",
                "cta": "Review history",
                "tone": "pass",
            }
        )

    focus_domains: list[dict[str, str]] = []
    seen_focus: set[str] = set()
    for audit in [*audit_attention, *audits]:
        if audit.domain in seen_focus:
            continue
        seen_focus.add(audit.domain)
        focus_domains.append(
            {
                "domain": audit.domain,
                "score": f"{audit.score}/100",
                "status": audit.overall_status,
                "source": "Recent audit",
                "tone": dashboard_tone_for_status(audit.overall_status),
            }
        )
        if len(focus_domains) >= 4:
            break

    for monitor in monitors:
        if len(focus_domains) >= 4:
            break
        if monitor.domain in seen_focus:
            continue
        seen_focus.add(monitor.domain)
        focus_domains.append(
            {
                "domain": monitor.domain,
                "score": f"{monitor.last_score}/100" if monitor.last_score is not None else "Pending",
                "status": monitor.last_status or "unchecked",
                "source": "Monitor",
                "tone": dashboard_tone_for_status(monitor.last_status or "info"),
            }
        )

    return {
        "summary": summary,
        "action_queue": action_queue[:4],
        "focus_domains": focus_domains,
        "status_counts": status_counts,
        "usage_percent": usage_percent,
    }
