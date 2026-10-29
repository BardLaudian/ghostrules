"""Command line interface: ``scan`` (default), ``context``, ``lock``, ``reveal``, ``clean``..."""

from __future__ import annotations

import enum
import io
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
from ghostrules import lock as lock_mod
from ghostrules.agents.claude_code import DEFAULT_MODE as CLAUDE_DEFAULT_MODE
from ghostrules.agents.claude_code import MODES as CLAUDE_MODES
from ghostrules.changeset import ChangeBase
from ghostrules.clean import clean_text, unified_diff
from ghostrules.config import Config, ConfigError, load_config
from ghostrules.context_command import ContextError, ContextReport, build_report, find_root
from ghostrules.gitref import GitRefError, RefReader, config_at_ref, reviewed_lookup
from ghostrules.models import ScanResult, Severity
from ghostrules.reporters import context as context_report
from ghostrules.reporters import json_, markdown, sarif, table
from ghostrules.reporters import lock as lock_report
from ghostrules.reporters.common import safe
from ghostrules.reveal import build as build_reveal
from ghostrules.reveal import has_hidden_content
from ghostrules.rules import all_rules
from ghostrules.rules.known_installers import KNOWN_INSTALLERS
from ghostrules.scanner import SuppressionPolicy, scan_paths

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
    follow_imports: Annotated[
        Optional[bool],  # noqa: UP045
        typer.Option(
            "--follow-imports/--no-follow-imports",
            help="Scan files that instruction files import with @path. [on]",
        ),
    ] = None,
    config: Annotated[
        Optional[Path],  # noqa: UP045
        typer.Option(help="Path to a config file (default: .ghostrules.toml in the scan root)."),
    ] = None,
    trusted_config: Annotated[
        Optional[Path],  # noqa: UP045
        typer.Option(
            "--trusted-config",
            help="Use this config file and never the scanned repository's own config.",
        ),
    ] = None,
    config_from_ref: Annotated[
        Optional[str],  # noqa: UP045
        typer.Option(
            "--config-from-ref",
            help="Read the config (.ghostrules.toml or [tool.ghostrules]) from this git ref.",
        ),
    ] = None,
    no_inline_suppressions: Annotated[
        bool,
        typer.Option("--no-inline-suppressions", help="Ignore every ghostrules-ignore comment."),
    ] = False,
    suppressions_from_ref: Annotated[
        Optional[str],  # noqa: UP045
        typer.Option(
            "--suppressions-from-ref",
            help="Honour a ghostrules-ignore only if the same line already had it at this git ref.",
        ),
    ] = None,
    strict: Annotated[
        bool,
        typer.Option(
            "--strict",
            help="Report plain visible prose at the rule's own severity (the 0.3 behaviour).",
        ),
    ] = False,
    no_color: Annotated[bool, typer.Option("--no-color", help="Plain output, no colours.")] = False,
) -> None:
    """Scan agent instruction and configuration files for hidden or dangerous content.

    Exit codes: 0 clean (or below --fail-on), 1 findings at or above --fail-on, 2 error.
    """
    _utf8_streams()
    targets = paths or [Path(".")]
    base = targets[0] if targets[0].is_dir() else targets[0].parent
    chosen = [n for n, v in (("--config", config), ("--trusted-config", trusted_config),
                             ("--config-from-ref", config_from_ref)) if v is not None]  # fmt: skip
    if len(chosen) > 1:
        _fail(f"{' and '.join(chosen)} cannot be used together: they all say where the config is")
    config_reader = suppression_reader = None
    if config_from_ref is not None or suppressions_from_ref is not None:
        if len(targets) != 1:
            _fail("--config-from-ref and --suppressions-from-ref take exactly one path to scan")
        try:
            if config_from_ref is not None:
                config_reader = RefReader(base, config_from_ref)
            if suppressions_from_ref is not None:
                suppression_reader = RefReader(base, suppressions_from_ref)
        except GitRefError as exc:
            _fail(str(exc))
    try:
        if config_reader is not None:
            cfg = config_at_ref(config_reader)
        elif trusted_config is not None:
            cfg = replace(load_config(base, trusted_config), source=f"trusted: {trusted_config}")
        else:
            cfg = load_config(base, config)
    except (ConfigError, GitRefError) as exc:
        _fail(str(exc))
    cfg = _apply_overrides(cfg, fail_on, min_severity, disable)
    if follow_imports is not None:
        cfg = replace(cfg, follow_imports=follow_imports)
    if strict:
        cfg = replace(cfg, profile="strict")

    policy = None
    if no_inline_suppressions:
        policy = SuppressionPolicy("off")
    elif suppression_reader is not None:
        policy = SuppressionPolicy("base", reviewed_lookup(suppression_reader))

    # GR030 compares with whichever ref was given; with two refs each part uses its own.
    anchor = config_reader or suppression_reader
    change_base = None
    if anchor is not None:
        ignores = suppression_reader or anchor
        change_base = ChangeBase(anchor.read, ignores.read, anchor.ref, ignores.ref)

    result = scan_paths(
        targets,
        cfg,
        all_files=all_files,
        include_home=home,
        suppressions=policy,
        change_base=change_base,
    )
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


# --- context -------------------------------------------------------------------------------


class ContextFormat(str, enum.Enum):
    """Report formats for ``context --format``."""

    tree = "tree"
    json = "json"
    markdown = "markdown"


@app.command()
def context(
    target: Annotated[
        Optional[Path],  # noqa: UP045
        typer.Argument(help="File the agent is working on (default: session start only)."),
    ] = None,
    agent: Annotated[
        str,
        typer.Option(help="claude-code, copilot-cli, cursor, generic or all. [all]"),
    ] = "all",
    cwd: Annotated[
        Optional[Path],  # noqa: UP045
        typer.Option("--cwd", help="Directory where the agent session starts (default: the root)."),
    ] = None,
    root: Annotated[
        Optional[Path],  # noqa: UP045
        typer.Option("--root", help="Repository root (default: the enclosing git root, or '.')."),
    ] = None,
    format_: Annotated[
        ContextFormat, typer.Option("--format", help="Report format.", case_sensitive=False)
    ] = ContextFormat.tree,
    show_text: Annotated[
        bool, typer.Option("--show-text", help="Also print the text the agent receives.")
    ] = False,
    no_scan: Annotated[
        bool, typer.Option("--no-scan", help="Only show the context; do not run the rules.")
    ] = False,
    home: Annotated[
        bool, typer.Option("--home", help="Include user-level sources such as ~/.claude/CLAUDE.md.")
    ] = False,
    fail_on: Annotated[
        Optional[str],  # noqa: UP045
        typer.Option(help="Exit 1 if a finding has at least this severity, or 'none'. [high]"),
    ] = None,
    claude_instructions_mode: Annotated[
        str,
        typer.Option(
            help="Claude Code 'Project instructions' setting: " + ", ".join(CLAUDE_MODES) + "."
        ),
    ] = CLAUDE_DEFAULT_MODE,
    config: Annotated[
        Optional[Path],  # noqa: UP045
        typer.Option(help="Path to a config file (default: .ghostrules.toml in the root)."),
    ] = None,
    output: Annotated[
        Optional[Path],  # noqa: UP045
        typer.Option("--output", "-o", help="Write the report to this file instead of stdout."),
    ] = None,
    no_color: Annotated[bool, typer.Option("--no-color", help="Plain output, no colours.")] = False,
) -> None:
    """Show, and scan, exactly what an AI agent reads when it works on a file.

    Exit codes: 0 clean (or below --fail-on), 1 findings at or above --fail-on, 2 error.
    """
    _utf8_streams()
    repo_root = root if root is not None else find_root(Path.cwd())
    try:
        cfg = load_config(repo_root, config)
    except ConfigError as exc:
        _fail(str(exc))
    if fail_on is not None:
        cfg = replace(cfg, fail_on=_parse_severity(fail_on, allow_none=True))
    if claude_instructions_mode not in CLAUDE_MODES:
        raise typer.BadParameter(
            f"expected one of: {', '.join(CLAUDE_MODES)}", param_hint="--claude-instructions-mode"
        )
    try:
        report = build_report(
            repo_root,
            cfg,
            agent=agent.strip().lower(),
            cwd=cwd,
            target=target,
            include_home=home,
            scan=not no_scan,
            instructions_mode=claude_instructions_mode,
        )
    except ContextError as exc:
        _fail(str(exc))
    _emit_context(report, format_, show_text, output, no_color)
    if report.errors:
        raise typer.Exit(EXIT_ERROR)
    if cfg.fail_on is not None and any(f.severity >= cfg.fail_on for f in report.findings):
        raise typer.Exit(EXIT_FINDINGS)


def _emit_context(
    report: ContextReport,
    fmt: ContextFormat,
    show_text: bool,
    output: Path | None,
    no_color: bool,
) -> None:
    if fmt is ContextFormat.tree:
        renderables: list[Any] = [context_report.build_tree(report)]
        if show_text:
            renderables.append(context_report.build_text(report))
        if output is None:
            console = _console(no_color)
            for renderable in renderables:
                console.print(renderable)
            return
        buffer = io.StringIO()
        file_console = table.make_console(color=False, width=100, file=buffer)
        for renderable in renderables:
            file_console.print(renderable)
        text = buffer.getvalue()
    elif fmt is ContextFormat.json:
        text = context_report.render_json(report, show_text=show_text)
    else:
        text = context_report.render_markdown(report, show_text=show_text)
    if output is None:
        sys.stdout.write(text)
        return
    try:
        output.write_text(text, encoding="utf-8")
    except OSError as exc:
        _fail(f"cannot write {output}: {exc.strerror or exc}")
    typer.echo(f"report written to {output}", err=True)


# --- lock ----------------------------------------------------------------------------------


class LockFormat(str, enum.Enum):
    """Report formats for ``lock --check``."""

    text = "text"
    markdown = "markdown"
    json = "json"


@app.command()
def lock(
    check: Annotated[
        bool,
        typer.Option("--check", help="Compare the repository with the lock; exit 1 if it differs."),
    ] = False,
    update: Annotated[
        bool, typer.Option("--update", help="Rewrite the lock (the same as running 'lock').")
    ] = False,
    format_: Annotated[
        LockFormat,
        typer.Option("--format", help="Report format for --check.", case_sensitive=False),
    ] = LockFormat.text,
    root: Annotated[
        Optional[Path],  # noqa: UP045
        typer.Option("--root", help="Repository root (default: the enclosing git root, or '.')."),
    ] = None,
    lockfile: Annotated[
        Optional[Path],  # noqa: UP045
        typer.Option("--lockfile", help="Lock file (default: .ghostrules.lock in the root)."),
    ] = None,
    claude_instructions_mode: Annotated[
        str,
        typer.Option(
            help="Claude Code 'Project instructions' setting: " + ", ".join(CLAUDE_MODES) + "."
        ),
    ] = CLAUDE_DEFAULT_MODE,
    config: Annotated[
        Optional[Path],  # noqa: UP045
        typer.Option(help="Path to a config file (default: .ghostrules.toml in the root)."),
    ] = None,
    base: Annotated[
        Optional[str],  # noqa: UP045
        typer.Option(
            "--base",
            help="With --check: compare with the lock and the config at this git ref, "
            "not the ones in the working tree.",
        ),
    ] = None,
    output: Annotated[
        Optional[Path],  # noqa: UP045
        typer.Option("--output", "-o", help="Write the --check report to this file."),
    ] = None,
    no_color: Annotated[bool, typer.Option("--no-color", help="Plain output, no colours.")] = False,
) -> None:
    """Pin what your AI agents read, and review every change to it.

    Without options this writes .ghostrules.lock. With --check it compares the repository with the
    lock and shows what changed. Exit codes for --check: 0 up to date, 1 changed, 2 error.
    """
    _utf8_streams()
    if check and update:
        raise typer.BadParameter("use either --check or --update", param_hint="--check/--update")
    repo_root = root if root is not None else find_root(Path.cwd())
    if base is not None and not check:
        _fail("--base only works with --check")
    if base is not None and config is not None:
        _fail("--base and --config cannot be used together: --base reads the config at the ref")
    reader = None
    try:
        if base is not None:
            reader = RefReader(repo_root, base)
            cfg = config_at_ref(reader)
        else:
            cfg = load_config(repo_root, config)
    except (ConfigError, GitRefError) as exc:
        _fail(str(exc))
    if claude_instructions_mode not in CLAUDE_MODES:
        raise typer.BadParameter(
            f"expected one of: {', '.join(CLAUDE_MODES)}", param_hint="--claude-instructions-mode"
        )
    if not repo_root.is_dir():
        _fail(f"{repo_root} is not a directory")
    lock_path = repo_root / (lockfile if lockfile is not None else Path(cfg.lockfile))
    name = lockfile.as_posix() if lockfile is not None else cfg.lockfile
    snapshot = lock_mod.build_snapshot(repo_root, cfg, instructions_mode=claude_instructions_mode)
    if check:
        try:
            if reader is not None:
                recorded = reader.read(name)
                if recorded is None:
                    raise lock_mod.LockError(
                        f"{reader.ref} has no {name}: there is nothing to compare with. Commit a "
                        "lock to the base first (create it with: ghostrules lock)"
                    )
                pinned = lock_mod.parse_lock(recorded)
            else:
                pinned = lock_mod.read_lock(lock_path)
            diff = lock_mod.diff_lock(pinned, snapshot)
        except lock_mod.LockError as exc:
            _fail(str(exc))
        _emit_lock(diff, name, format_, output, no_color)
        if not diff.empty:
            raise typer.Exit(EXIT_FINDINGS)
        return
    summary = ""
    if lock_path.exists():
        try:
            previous = lock_mod.diff_lock(lock_mod.read_lock(lock_path), snapshot)
        except lock_mod.LockError:
            previous = None
        if previous is not None and not previous.empty:
            summary = f" ({_lock_summary(previous)})"
    try:
        lock_path.write_bytes(lock_mod.to_json(snapshot.lock).encode("utf-8"))
    except OSError as exc:
        _fail(f"cannot write {lock_path}: {exc.strerror or exc}")
    files = len({e.path for items in snapshot.lock.agents.values() for e in items})
    agents = len(snapshot.lock.agents)
    typer.echo(f"wrote {name}: {files} file(s) in the contexts of {agents} agent(s){summary}")


def _lock_summary(diff: lock_mod.LockDiff) -> str:
    counts = {k: 0 for k in ("added", "changed", "removed")}
    for change in diff.changes:
        counts["changed" if change.kind == "hidden" else change.kind] += 1
    for config_change in diff.configs:
        counts[config_change.kind] += 1
    return ", ".join(f"{n} {kind}" for kind, n in counts.items() if n) or "agents changed"


def _emit_lock(
    diff: lock_mod.LockDiff,
    name: str,
    fmt: LockFormat,
    output: Path | None,
    no_color: bool,
) -> None:
    if fmt is LockFormat.text:
        renderable = lock_report.build_report(diff, name)
        if output is None:
            _console(no_color).print(renderable)
            return
        buffer = io.StringIO()
        table.make_console(color=False, width=100, file=buffer).print(renderable)
        text = buffer.getvalue()
    elif fmt is LockFormat.markdown:
        text = lock_report.render_markdown(diff, name)
    else:
        text = lock_report.render_json(diff, name)
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


def _print_installers(console: Console) -> None:
    grid = Table(box=None, pad_edge=False, header_style="bold")
    for name in ("Project", "Host", "Path prefix"):
        grid.add_column(name, no_wrap=True)
    for entry in KNOWN_INSTALLERS:
        grid.add_row(Text(entry.project), Text(entry.host), Text(entry.path_prefix or "-"))
    console.print(grid)


@app.command()
def rules(
    no_color: Annotated[bool, typer.Option("--no-color", help="Plain output, no colours.")] = False,
    installers: Annotated[
        bool,
        typer.Option("--installers", help="List the well-known installers GR012 trusts instead."),
    ] = False,
) -> None:
    """List every detection rule."""
    _utf8_streams()
    if installers:
        _print_installers(_console(no_color))
        return
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
