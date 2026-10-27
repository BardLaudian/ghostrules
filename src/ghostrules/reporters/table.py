"""Rich terminal report: findings grouped by file, with the hidden text front and centre."""

from __future__ import annotations

import io
import re
from typing import IO

from rich import box
from rich.console import Console, ConsoleOptions, Group, RenderableType, RenderResult
from rich.padding import Padding
from rich.panel import Panel
from rich.rule import Rule
from rich.table import Table
from rich.text import Text

from ghostrules import __version__
from ghostrules.models import Finding, ScanResult, Severity
from ghostrules.reporters.common import (
    SEVERITY_ORDER,
    FileGroup,
    config_notes,
    group_by_file,
    safe,
    severity_counts,
    via_text,
)
from ghostrules.rules.patterns import COLLECTOR_PATTERNS, EXFIL_PATTERNS, INJECTION_PATTERNS

BADGE_STYLE = {
    Severity.CRITICAL: "bold white on red3",
    Severity.HIGH: "bold black on dark_orange",
    Severity.MEDIUM: "bold black on yellow",
    Severity.LOW: "bold white on dodger_blue2",
    Severity.INFO: "bold white on grey42",
}
TEXT_STYLE = {
    Severity.CRITICAL: "bold red",
    Severity.HIGH: "bold dark_orange",
    Severity.MEDIUM: "bold yellow",
    Severity.LOW: "bold dodger_blue1",
    Severity.INFO: "bold grey62",
}
_TOKEN_RE = re.compile(r"⟦[^⟧]*⟧")
_URL_RE = re.compile(r"https?://[^\s)\]>\"']+")
_TOKEN_STYLE = "bold bright_red"
_DECODED_STYLE = "bold bright_yellow"
_MATCH_STYLE = "bold white on red3"
_MAX_WIDTH = 120


def styled_snippet(snippet: str) -> Text:
    """The snippet with every ``⟦U+XXXX⟧`` token highlighted, so invisible characters stand out."""
    text = Text(safe(snippet), no_wrap=False)
    for match in _TOKEN_RE.finditer(text.plain):
        text.stylize(_TOKEN_STYLE, match.start(), match.end())
    return text


def styled_decoded(decoded: str) -> Text:
    """Hidden text with the phrases that look malicious (and URLs) highlighted."""
    text = Text(safe(decoded), style=_DECODED_STYLE)
    plain = text.plain
    patterns = [p for group in INJECTION_PATTERNS.values() for p in group]
    for pattern in (*patterns, *EXFIL_PATTERNS, *COLLECTOR_PATTERNS):
        for match in pattern.finditer(plain):
            text.stylize(_MATCH_STYLE, match.start(), match.end())
    for match in _URL_RE.finditer(plain):
        text.stylize("underline", match.start(), match.end())
    return text


def _badge(severity: Severity) -> Text:
    return Text(f" {severity.label.upper():^8} ", style=BADGE_STYLE[severity])


class _Head:
    """The first line of a finding: badge, rule id, title and ``path:line:col``.

    On one row when it fits. On narrow terminals or with long paths the location moves to a
    second line instead of squeezing the title into a few characters.
    """

    def __init__(self, finding: Finding) -> None:
        self.badge = _badge(finding.severity)
        self.rule_id = Text(finding.rule_id, style="bold")
        self.title = Text(safe(finding.title), style="bold")
        self.location = Text(
            safe(f"{finding.path}:{finding.line}:{finding.column}"), style="dim", no_wrap=True
        )

    def __rich_console__(self, console: Console, options: ConsoleOptions) -> RenderResult:
        needed = (
            self.badge.cell_len
            + self.rule_id.cell_len
            + self.title.cell_len
            + self.location.cell_len
            + 4
        )
        grid = Table.grid(expand=True, padding=(0, 1))
        grid.add_column(no_wrap=True)
        grid.add_column(no_wrap=True)
        grid.add_column(ratio=1)
        if needed <= options.max_width:
            grid.add_column(no_wrap=True, justify="right")
            grid.add_row(self.badge, self.rule_id, self.title, self.location)
            yield grid
            return
        grid.add_row(self.badge, self.rule_id, self.title)
        yield grid
        indent = self.badge.cell_len + 1
        yield Padding(Text.assemble(("at ", "dim"), self.location), (0, 0, 0, indent))


def _finding_block(finding: Finding, repeated_hidden_text: bool) -> RenderableType:
    """One finding. When it was found inside hidden text already shown above, stay compact."""
    parts: list[RenderableType] = [_Head(finding)]
    if finding.via:
        chain = f"via {via_text(finding)}"
        if finding.agents:
            chain += f" · loaded by {', '.join(finding.agents)}"
        parts.append(
            Padding(
                Text(safe(chain), style="yellow"), (0, 0, 0, _badge(finding.severity).cell_len + 1)
            )
        )
    body: list[RenderableType] = []
    if repeated_hidden_text:
        body.append(Text.assemble(("↳ ", "dim"), safe(finding.message)))
    else:
        gutter = Text(f"{finding.line:>4} │ ", style="dim")
        body.append(
            Text.assemble(
                gutter, styled_snippet(finding.snippet), no_wrap=True, overflow="ellipsis"
            )
        )
        if finding.decoded:
            body.append(
                Panel(
                    styled_decoded(finding.decoded),
                    title="Decoded hidden text",
                    title_align="left",
                    border_style="red",
                    box=box.ROUNDED,
                    padding=(0, 1),
                )
            )
        body.append(Text(safe(finding.message)))
    if finding.fix_hint:
        body.append(Text.assemble(("fix  ", "green"), (safe(finding.fix_hint), "dim")))
    parts.append(Padding(Group(*body), (0, 0, 0, 2)))
    parts.append(Text(""))
    return Group(*parts)


def _file_block(group: FileGroup) -> RenderableType:
    count = len(group.findings)
    title = Text.assemble(
        (safe(group.path), "bold cyan"),
        (f"  {count} finding{'s' if count != 1 else ''}", "dim"),
    )
    shown_hidden: set[tuple[int, int, str]] = set()
    blocks: list[RenderableType] = [Rule(title, align="left", style="grey37", characters="─")]
    for finding in group.findings:
        key = (finding.line, finding.column, finding.decoded or "")
        repeated = bool(finding.decoded) and key in shown_hidden
        if finding.decoded:
            shown_hidden.add(key)
        blocks.append(_finding_block(finding, repeated))
    return Group(*blocks)


def _summary(result: ScanResult) -> RenderableType:
    if not result.findings and result.errors:
        return Text.assemble(
            ("✖ Scan incomplete", "bold red"), (f"  (scanned {result.scanned_files} files)", "dim")
        )
    if not result.findings:
        return Text.assemble(
            ("✔ No findings", "bold green"), (f"  (scanned {result.scanned_files} files)", "dim")
        )
    counts = severity_counts(result.findings)
    line = Text()
    for i, severity in enumerate(s for s in SEVERITY_ORDER if s.label in counts):
        if i:
            line.append(" · ", style="dim")
        line.append(f"{counts[severity.label]} {severity.label}", style=TEXT_STYLE[severity])
    files = len({f.path for f in result.findings})
    line.append(
        f" in {files} file{'s' if files != 1 else ''} (scanned {result.scanned_files})", style="dim"
    )
    return line


def build(result: ScanResult, *, target: str | None = None) -> RenderableType:
    """Assemble the whole report as a rich renderable."""
    header = Text.assemble(("◆ ghostrules", "bold"), (f" v{__version__}", "dim"))
    if target:
        header.append(f"  scanning {target}", style="dim")
    parts: list[RenderableType] = [header, Text("")]
    parts.extend(_file_block(group) for group in group_by_file(result.findings))
    parts.append(Rule(style="grey37", characters="─"))
    parts.append(_summary(result))
    for note in config_notes(result):
        parts.append(Text.assemble(("note: ", "bold yellow"), (note, "yellow")))
    for warning in result.warnings:
        parts.append(Text.assemble(("warning: ", "bold yellow"), safe(warning)))
    for error in result.errors:
        parts.append(Text.assemble(("error: ", "bold red"), safe(error)))
    return Group(*parts)


def make_console(
    *, color: bool | None = None, width: int | None = None, file: IO[str] | None = None
) -> Console:
    """Console used for reports: no emoji/markup surprises, bounded width.

    ``color=None`` follows the terminal (and ``NO_COLOR``), ``False`` never emits escape codes,
    ``True`` always does (used when rendering to a string).
    """
    options: dict[str, object] = {
        "file": file,
        "width": width,
        "highlight": False,
        "emoji": False,
        "legacy_windows": False,
    }
    if color is False:
        options["color_system"] = None
    elif color is True:
        options.update(color_system="truecolor", force_terminal=True)
    console = Console(**options)  # type: ignore[arg-type]
    if width is None and console.width > _MAX_WIDTH:
        console.width = _MAX_WIDTH
    return console


def render(
    result: ScanResult, *, color: bool = False, width: int = 100, target: str | None = None
) -> str:
    """Render the table report to a string (plain text unless ``color``)."""
    buffer = io.StringIO()
    console = make_console(color=color, width=width, file=buffer)
    console.print(build(result, target=target))
    return buffer.getvalue()
