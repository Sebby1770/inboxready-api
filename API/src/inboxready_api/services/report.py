from __future__ import annotations

from inboxready_api.models import DomainAuditResponse


def render_markdown_report(result: DomainAuditResponse) -> str:
    lines: list[str] = [
        f"# InboxReady Audit: {result.domain}",
        "",
        f"**Score:** {result.score}/100  ",
        f"**Status:** {result.overall_status}  ",
        f"**Checked at:** {result.checked_at}",
        "",
    ]

    if result.providers:
        provider_names = ", ".join(provider.name for provider in result.providers)
        lines.append(f"**Detected providers:** {provider_names}")
    else:
        lines.append("**Detected providers:** none")
    lines.append("")

    lines.extend(
        [
            "## Checks",
            "",
            "| Check | Status | Summary |",
            "| --- | --- | --- |",
        ]
    )
    for name, check in result.checks.items():
        summary = check.summary.replace("|", "\\|")
        lines.append(f"| {name} | {check.status} | {summary} |")
    lines.append("")

    lines.extend(["## Recommendations", ""])
    if result.recommendations:
        for item in result.recommendations:
            detail = f" — {item.details}" if item.details else ""
            lines.append(f"- **[{item.severity}]** `{item.code}`: {item.message}{detail}")
    else:
        lines.append("- No urgent remediation items.")
    lines.append("")

    if result.references:
        lines.extend(["## References", ""])
        for ref in result.references:
            lines.append(f"- {ref}")
        lines.append("")

    return "\n".join(lines)
