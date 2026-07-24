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


def render_html_report(result: DomainAuditResponse) -> str:
    """Standalone HTML report with inline CSS."""

    rows = "".join(
        f"<tr><td>{name}</td><td class='st-{check.status}'>{check.status}</td>"
        f"<td>{_html_escape(check.summary)}</td></tr>"
        for name, check in result.checks.items()
    )
    recs = "".join(
        f"<li><strong>[{item.severity}]</strong> {_html_escape(item.message)}</li>"
        for item in result.recommendations
    ) or "<li>No urgent remediation items.</li>"
    providers = ", ".join(p.name for p in result.providers) or "none"
    return f"""<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8"/>
<title>InboxReady · { _html_escape(result.domain) }</title>
<style>
body{{font-family:system-ui,sans-serif;max-width:800px;margin:2rem auto;padding:0 1rem;color:#1a1a1a}}
h1{{font-size:1.5rem}} table{{border-collapse:collapse;width:100%}}
th,td{{border:1px solid #ddd;padding:.5rem;text-align:left}}
th{{background:#f4f4f5}} .st-pass{{color:#15803d}} .st-warn{{color:#a16207}}
.st-fail{{color:#b91c1c}} .score{{font-size:2rem;font-weight:700}}
</style></head><body>
<h1>InboxReady audit</h1>
<p class="score">{result.score}/100 · {result.overall_status}</p>
<p><strong>Domain:</strong> {_html_escape(result.domain)}<br/>
<strong>Checked:</strong> {_html_escape(result.checked_at)}<br/>
<strong>Providers:</strong> {_html_escape(providers)}</p>
<h2>Checks</h2>
<table><thead><tr><th>Check</th><th>Status</th><th>Summary</th></tr></thead>
<tbody>{rows}</tbody></table>
<h2>Recommendations</h2><ul>{recs}</ul>
</body></html>"""


def _html_escape(value: str) -> str:
    return (
        value.replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
    )
