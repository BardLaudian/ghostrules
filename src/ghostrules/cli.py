"""Command line interface: ``scan`` (default), ``reveal``, ``clean``, ``rules``, ``version``."""

from __future__ import annotations

import enum
import sys
from dataclasses import replace
from pathlib import Path
from typing import Annotated, Any, NoReturn, Optional

import typer
from rich.console import Console, Group
from rich.table import Table
from rich.text import Text
from typer.core import TyperGroup

from ghostrules import __version__
from ghostrules.clean import clean_text, unified_diff
from ghostrules.config import Config, ConfigError, load_config
from ghostrules.models import ScanResult, Severity
from ghostrules.reporters import json_, markdown, sarif, table
from ghostrules.reporters.common import safe
from ghostrules.reveal import build as build_reveal
from ghostrules.reveal import has_hidden_content
from ghostrules.rules import all_rules
from ghostrules.scanner import scan_paths

EXIT_OK, EXIT_FINDINGS, EXIT_ERROR = 0, 1, 2


class DefaultScanGroup(TyperGroup):
    """Make ``scan`` the default command: ``ghostrules .`` and ``ghostrules --format json``."""

    def parse_args(self, ctx: Any, args: list[str]) -> list[str]:
        first = args[0] if args else None
        if first is None or (first not in self.commands and first not in ctx.help_option_names):
            args = ["scan", *args]
        return super().parse_args(ctx, args)


app = typer.Typer(
    name="ghostrules",
    cls=DefaultScanGroup,
    help="Find the instructions your AI agent sees but you don't.",
    add_completion=False,
    rich_markup_mode=None,
)


class OutputFormat(str, enum.Enum):
    """Report formats for ``scan --format``."""

    table = "table"
    json = "json"
    sarif = "sarif"
    markdown = "markdown"


_RENDERERS = {
    OutputFormat.json: json_.render,
    OutputFormat.sarif: sarif.render,
    OutputFormat.markdown: markdown.render,
}


def _fail(message: str) -> NoReturn:
    typer.echo(f"error: {safe(message)}", err=True)
    raise typer.Exit(EXIT_ERROR)


def _utf8_streams() -> None:
    """Reports contain box-drawing and ⟦U+XXXX⟧ tokens: never crash on a legacy code page."""
    for stream in (sys.stdout, sys.stderr):
        encoding = (getattr(stream, "encoding", None) or "").lower().replace("-", "")
        reconfigure = getattr(stream, "reconfigure", None)
        if reconfigure is not None and encoding != "utf8":
            reconfigure(encoding="utf-8", errors="replace")


def _read_text(path: Path) -> tuple[bytes, str]:
    try:
        data = path.read_bytes()
    except OSError as exc:
        _fail(f"cannot read {path}: {exc.strerror or exc}")
    return data, data.decode("utf-8", errors="surrogateescape")


def _parse_severity(value: str | None, *, allow_none: bool) -> Severity | None:
    if value is None:
        return None
    if allow_none and value.strip().lower() == "none":
        return None
    try:
        return Severity.parse(value)
    except ValueError as exc:
        raise typer.BadParameter(str(exc)) from None


def _console(no_color: bool) -> Console:
    return table.make_console(color=False if no_color else None)


# --- scan ----------------------------------------------------------------------------------


@app.command()
def scan(
    paths: Annotated[
        Optional[list[Path]],  # noqa: UP045 - Typer needs Optional on 3.10
        typer.Argument(help="Files or directories to scan (default: current directory)."),
    ] = None,
    format_: Annotated[
        OutputFormat, typer.Option("--format", help="Report format.", case_sensitive=False)
    ] = OutputFormat.table,
    output: Annotated[
        Optional[Path],  # noqa: UP045
        typer.Option("--output", "-o", help="Write the report to this file instead of stdout."),
    ] = None,
    fail_on: Annotated[
        Optional[str],  # noqa: UP045
        typer.Option(help="Exit 1 if a finding has at least this severity, or 'none'. [high]"),
    ] = None,
    min_severity: Annotated[
        Optional[str],  # noqa: UP045
        typer.Option(help="Hide findings below this severity. [low]"),
    ] = None,
    all_files: Annotated[
        bool, typer.Option("--all-files", help="Also check every text file for hidden Unicode.")
    ] = False,
    home: Annotated[
        bool, typer.Option("--home", help="Also scan your user-level agent configs (read-only).")
    ] = False,
    disable: Annotated[
        Optional[str],  # noqa: UP045
        typer.Option(help="Comma-separated rule IDs to disable, e.g. GR010,GR012."),
    ] = None,
    config: Annotated[
        Optional[Path],  # noqa: UP045
        typer.Option(help="Path to a config file (default: .ghostrules.toml in the scan root)."),
    ] = None,
    no_color: Annotated[bool, typer.Option("--no-color", help="Plain output, no colours.")] = False,
) -> None:
    """Scan agent instruction and configuration files for hidden or dangerous content.

    Exit codes: 0 clean (or below --fail-on), 1 findings at or above --fail-on, 2 error.
    """
    _utf8_streams()
    targets = paths or [Path(".")]
    base = targets[0] if targets[0].is_dir() else targets[0].parent
    try:
        cfg = load_config(base, config)
    except ConfigError as exc:
        _fail(str(exc))
    cfg = _apply_overrides(cfg, fail_on, min_severity, disable)

    result = scan_paths(targets, cfg, all_files=all_files, include_home=home)
    label = ", ".join(str(p) for p in targets)
    _emit(result, format_, output, no_color, label)

    if result.errors:
        raise typer.Exit(EXIT_ERROR)
    if cfg.fail_on is not None and any(f.severity >= cfg.fail_on for f in result.findings):
        raise typer.Exit(EXIT_FINDINGS)


def _apply_overrides(
    cfg: Config, fail_on: str | None, min_severity: str | None, disable: str | None
) -> Config:
    changes: dict[str, object] = {}
    if fail_on is not None:
        changes["fail_on"] = _parse_severity(fail_on, allow_none=True)
    if min_severity is not None:
        changes["min_severity"] = _parse_severity(min_severity, allow_none=False)
    if disable:
        ids = {part.strip().upper() for part in disable.split(",") if part.strip()}
        changes["disable"] = cfg.disable | ids
    return replace(cfg, **changes)  # type: ignore[arg-type]


def _emit(
    result: ScanResult, fmt: OutputFormat, output: Path | None, no_color: bool, label: str
) -> None:
    if fmt is OutputFormat.table:
        if output is None:
            _console(no_color).print(table.build(result, target=label))
            return
        text = table.render(result, color=False, width=100, target=label)
    else:
        text = _RENDERERS[fmt](result)
        for warning in result.warnings:
            typer.echo(f"warning: {safe(warning)}", err=True)
        for error in result.errors:
            typer.echo(f"error: {safe(error)}", err=True)
    if output is None:
        sys.stdout.write(text)
        return
    try:
        output.write_text(text, encoding="utf-8")
    except OSError as exc:
        _fail(f"cannot write {output}: {exc.strerror or exc}")
    typer.echo(f"report written to {output}", err=True)


# --- reveal / clean ------------------------------------------------------------------------


@app.command()
def reveal(
    file: Annotated[Path, typer.Argument(help="File to show.")],
    no_color: Annotated[bool, typer.Option("--no-color", help="Plain output, no colours.")] = False,
) -> None:
    """Print a file with invisible characters made visible, plus the text they hide."""
    _utf8_streams()
    _data, text = _read_text(file)
    console = _console(no_color)
    header = Text.assemble(("◆ ghostrules reveal", "bold"), (f"  {safe(str(file))}", "dim"))
    verdict = (
        Text("hidden content found: see highlighted tokens and decoded text", style="bold red")
        if has_hidden_content(text)
        else Text("✔ nothing hidden: no invisible characters or HTML comments", style="green")
    )
    console.print(Group(header, Text(""), build_reveal(text), Text(""), verdict))


@app.command()
def clean(
    file: Annotated[Path, typer.Argument(help="File to clean.")],
    write: Annotated[
        bool, typer.Option("--write", help="Modify the file (a .ghostrules.bak copy is kept).")
    ] = False,
    keep_bom: Annotated[
        bool, typer.Option("--keep-bom", help="Keep a leading byte-order mark.")
    ] = False,
    no_color: Annotated[bool, typer.Option("--no-color", help="Plain output, no colours.")] = False,
) -> None:
    """Remove invisible characters (GR001-GR004). Without --write only show the diff."""
    _utf8_streams()
    data, text = _read_text(file)
    console = _console(no_color)
    result = clean_text(text, keep_bom=keep_bom)
    if result.kept_bidi:
        console.print(
            Text(
                f"note: kept {result.kept_bidi} bidirectional control(s): the file is mostly "
                "right-to-left text, where they are legitimate.",
                style="yellow",
            )
        )
    if not result.changed:
        console.print(Text("✔ Nothing to clean.", style="green"))
        return
    if not write:
        console.print(_styled_diff(unified_diff(result, safe(str(file)))))
        console.print(
            Text(
                f"{result.removed} character(s) would be removed. Run again with --write.",
                style="bold",
            )
        )
        return
    backup = file.with_name(file.name + ".ghostrules.bak")
    if backup.exists():
        _fail(f"{backup} already exists; move it away first so no earlier backup is lost")
    try:
        backup.write_bytes(data)
        file.write_bytes(result.cleaned.encode("utf-8", errors="surrogateescape"))
    except OSError as exc:
        _fail(f"cannot write {file}: {exc.strerror or exc}")
    console.print(
        Text(f"✔ Removed {result.removed} character(s) from {safe(str(file))}", style="bold green")
    )
    console.print(Text(f"  original saved as {safe(str(backup))}", style="dim"))


def _styled_diff(diff: str) -> Text:
    out = Text()
    for line in diff.splitlines():
        if line.startswith(("+++", "---")):
            style = "bold"
        elif line.startswith("@@"):
            style = "cyan"
        elif line.startswith("+"):
            style = "green"
        elif line.startswith("-"):
            style = "red"
        else:
            style = ""
        out.append(safe(line) + "\n", style=style)
    return out


# --- rules / version -----------------------------------------------------------------------


@app.command()
def rules(
    no_color: Annotated[bool, typer.Option("--no-color", help="Plain output, no colours.")] = False,
) -> None:
    """List every detection rule."""
    _utf8_streams()
    grid = Table(box=None, pad_edge=False, header_style="bold")
    grid.add_column("ID", no_wrap=True)
    grid.add_column("Severity", no_wrap=True)
    grid.add_column("Applies to", no_wrap=True, style="dim")
    grid.add_column("Title")
    for rule in all_rules():
        grid.add_row(
            Text(rule.id, style="bold"),
            Text(rule.severity.label, style=table.TEXT_STYLE[rule.severity]),
            Text(", ".join(sorted(rule.applies_to))),
            Text(rule.title),
        )
    _console(no_color).print(grid)


@app.command()
def version() -> None:
    """Print the ghostrules version."""
    typer.echo(f"ghostrules {__version__}")
