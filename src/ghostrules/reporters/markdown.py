"""Markdown report, compact enough for a PR comment or ``$GITHUB_STEP_SUMMARY``."""

from __future__ import annotations

from typing import Any

from ghostrules.models import Finding, ScanResult, Severity
from ghostrules.reporters.common import config_notes, safe, summary_line

MAX_ROWS = 100
_ICON = {
    Severity.CRITICAL: "🔴",
    Severity.HIGH: "🟠",
    Severity.MEDIUM: "🟡",
    Severity.LOW: "🔵",
    Severity.INFO: "⚪",
}


def _cell(text: str) -> str:
    """Make text safe inside a table cell and inert as Markdown/HTML."""
    text = safe(text).replace("\\", "\\\\").replace("|", "\\|").replace("`", "'")
    text = text.replace("<", "&lt;").replace(">", "&gt;")
    return " ".join(text.split())


def _row(f: Finding) -> str:
    where = f"`{_cell(f.path)}:{f.line}:{f.column}`"
    detail = _cell(f.message)
    if f.decoded:
        detail += f"<br>**Decoded hidden text:** `{_cell(f.decoded)}`"
    return (
        f"| {_ICON[f.severity]} {f.severity.label} | `{f.rule_id}` | {where} | "
        f"**{_cell(f.title)}**<br>{detail} |"
    )


def render(result: ScanResult, **_options: Any) -> str:
    """Render the Markdown report."""
    lines = ["## ghostrules", ""]
    if not result.findings:
        lines.append(f"✅ **{summary_line(result)}**")
    else:
        lines += [f"**{summary_line(result)}**", ""]
        lines += ["| Severity | Rule | Location | Finding |", "| --- | --- | --- | --- |"]
        lines += [_row(f) for f in result.findings[:MAX_ROWS]]
        extra = len(result.findings) - MAX_ROWS
        if extra > 0:
            lines += ["", f"_…and {extra} more findings (see the JSON or SARIF report)._"]
    notes = config_notes(result)
    if notes:
        lines += [""] + [f"> **Note:** {_cell(n)}" for n in notes]
    lines += [f"> **Warning:** {_cell(w)}" for w in result.warnings]
    lines += [f"> **Error:** {_cell(e)}" for e in result.errors]
    return "\n".join(lines) + "\n"
