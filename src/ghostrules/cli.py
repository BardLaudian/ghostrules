"""Command line interface: ``scan`` (default), ``context``, ``lock``, ``reveal``, ``clean``..."""

from __future__ import annotations

import enum
import io
import os
import shutil
import sys
from dataclasses import replace
from pathlib import Path
from typing import Annotated, Any, NamedTuple, NoReturn, Optional

import typer
from rich.console import Console, Group
from rich.table import Table
from rich.text import Text
from typer.core import TyperGroup

from ghostrules import __version__
from ghostrules import baseline as baseline_mod
from ghostrules import lock as lock_mod
from ghostrules.agents.claude_code import DEFAULT_MODE as CLAUDE_DEFAULT_MODE
from ghostrules.agents.claude_code import MODES as CLAUDE_MODES
from ghostrules.changeset import ChangeBase
from ghostrules.clean import clean_text, unified_diff
from ghostrules.config import Config, ConfigError, load_config
from ghostrules.context_command import ContextError, ContextReport, build_report, find_root
from ghostrules.firstparty import first_party_installers
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

# Stable exit codes (docs/USAGE.md "Exit codes"): a CI job can tell "findings" from "broken".
EXIT_OK, EXIT_FINDINGS, EXIT_ERROR, EXIT_INTERNAL = 0, 1, 2, 3


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
    lenient: Annotated[
        bool,
        typer.Option(
            "--lenient",
            help="Report all plain visible prose at low, including a curl | sh instruction (0.4).",
        ),
    ] = False,
    baseline_file: Annotated[
        Optional[Path],  # noqa: UP045
        typer.Option(
            "--baseline",
            help="Leave out the findings listed in this baseline (default: "
            f"{baseline_mod.BASELINE_FILENAME} in the scan root, if there is one).",
        ),
    ] = None,
    no_baseline: Annotated[
        bool, typer.Option("--no-baseline", help="Do not use a baseline.")
    ] = False,
    baseline_from_ref: Annotated[
        Optional[str],  # noqa: UP045
        typer.Option(
            "--baseline-from-ref",
            help="Read the baseline from this git ref, not the working tree.",
        ),
    ] = None,
    max_file_size: Annotated[
        Optional[int],  # noqa: UP045
        typer.Option(
            "--max-file-size",
            min=0,
            help="Skip files larger than this many bytes, with a warning (0 = no limit; "
            "default 1048576).",
        ),
    ] = None,
    no_color: Annotated[bool, typer.Option("--no-color", help="Plain output, no colours.")] = False,
) -> None:
    """Scan agent instruction and configuration files for hidden or dangerous content.

    Exit codes: 0 clean (or below --fail-on), 1 findings at or above --fail-on, 2 usage or
    configuration error, 3 internal failure.
    """
    _utf8_streams()
    targets = paths or [Path(".")]
    base = targets[0] if targets[0].is_dir() else targets[0].parent
    readers = _ref_readers(
        base, targets, config, trusted_config, config_from_ref, suppressions_from_ref,
        baseline_from_ref,
    )  # fmt: skip
    cfg = _scan_config(base, readers, config, trusted_config)
    cfg = _apply_overrides(cfg, fail_on, min_severity, disable)
    if follow_imports is not None:
        cfg = replace(cfg, follow_imports=follow_imports)
    if max_file_size is not None:
        cfg = replace(cfg, max_file_size=max_file_size)
    if strict:
        cfg = replace(cfg, profile="strict")
    elif lenient:
        cfg = replace(cfg, profile="lenient")
    anchor = readers.config or readers.suppressions or readers.baseline
    cfg = replace(cfg, first_party=_first_party(base, anchor))
    result = scan_paths(
        targets,
        cfg,
        all_files=all_files,
        include_home=home,
        suppressions=_suppression_policy(readers, no_inline_suppressions),
        change_base=_change_base(readers),
    )
    known = _known_findings(base, baseline_file, readers.baseline, no_baseline)
    if known is not None:
        # Staleness is only meaningful when the whole directory was scanned: a scan of one file
        # or one folder would call every other entry stale.
        if len(targets) == 1 and targets[0].is_dir() and not result.errors:
            result.baseline_stale = baseline_mod.stale(known, result.findings)
            if result.baseline_stale:
                result.warnings.append(baseline_mod.stale_warning(known, result.baseline_stale))
        result.findings, result.baselined = baseline_mod.apply(result.findings, known.fingerprints)
    _emit(result, format_, output, no_color, ", ".join(str(p) for p in targets))
    _exit_for(result, cfg)


class _RefReaders(NamedTuple):
    """Readers of the git refs that say where the config, suppressions and baseline come from."""

    config: RefReader | None
    suppressions: RefReader | None
    baseline: RefReader | None


def _ref_readers(
    base: Path,
    targets: list[Path],
    config: Path | None,
    trusted_config: Path | None,
    config_from_ref: str | None,
    suppressions_from_ref: str | None,
    baseline_from_ref: str | None,
) -> _RefReaders:
    """Validate the config-source options and open a reader for each git ref given."""
    chosen = [n for n, v in (("--config", config), ("--trusted-config", trusted_config),
                             ("--config-from-ref", config_from_ref)) if v is not None]  # fmt: skip
    if len(chosen) > 1:
        _fail(f"{' and '.join(chosen)} cannot be used together: they all say where the config is")
    refs = (config_from_ref, suppressions_from_ref, baseline_from_ref)
    if all(ref is None for ref in refs):
        return _RefReaders(None, None, None)
    if len(targets) != 1:
        _fail("the options that read a git ref take exactly one path to scan")
    try:
        config_reader, suppression_reader, baseline_reader = (
            RefReader(base, ref) if ref is not None else None for ref in refs
        )
    except GitRefError as exc:
        _fail(str(exc))
    return _RefReaders(config_reader, suppression_reader, baseline_reader)


def _scan_config(
    base: Path, readers: _RefReaders, config: Path | None, trusted_config: Path | None
) -> Config:
    """The configuration the scan starts from, before command-line overrides."""
    try:
        if readers.config is not None:
            return config_at_ref(readers.config)
        if trusted_config is not None:
            return replace(load_config(base, trusted_config), source=f"trusted: {trusted_config}")
        return load_config(base, config)
    except (ConfigError, GitRefError) as exc:
        _fail(str(exc))


def _suppression_policy(readers: _RefReaders, no_inline: bool) -> SuppressionPolicy | None:
    if no_inline:
        return SuppressionPolicy("off")
    if readers.suppressions is not None:
        return SuppressionPolicy("base", reviewed_lookup(readers.suppressions))
    return None


def _change_base(readers: _RefReaders) -> ChangeBase | None:
    """GR030 compares with whichever ref was given; with two refs each part uses its own."""
    anchor = readers.config or readers.suppressions or readers.baseline
    if anchor is None:
        return None
    ignores = readers.suppressions or anchor
    return ChangeBase(anchor.read, ignores.read, anchor.ref, ignores.ref)


def _exit_for(result: ScanResult, cfg: Config) -> None:
    """Exit 2 when a rule crashed, 1 when a finding reaches ``--fail-on``."""
    if result.errors:
        raise typer.Exit(EXIT_ERROR)
    if cfg.fail_on is not None and any(f.severity >= cfg.fail_on for f in result.findings):
        raise typer.Exit(EXIT_FINDINGS)


def _first_party(base: Path, reader: RefReader | None) -> tuple[Any, ...]:
    """The scanned project's own installer hosts. Read at the base ref when the scan has one, so a
    change cannot declare its own domain first-party; ``.git/config`` is not part of a change."""

    def read(name: str) -> str | None:
        if reader is not None:
            return reader.read(name)
        try:
            return (base / name).read_text(encoding="utf-8", errors="replace")
        except OSError:
            return None

    try:
        git_config = (base / ".git" / "config").read_text(encoding="utf-8", errors="replace")
    except OSError:
        git_config = None
    return first_party_installers(read, git_config)


def _known_findings(
    base: Path, explicit: Path | None, reader: RefReader | None, disabled: bool
) -> baseline_mod.BaselineInfo | None:
    """The baseline in use, or ``None`` when there is none."""
    if disabled:
        return None
    try:
        if reader is not None:
            text = reader.read(baseline_mod.BASELINE_FILENAME)
            return (
                baseline_mod.load(text)
                if text is not None
                else baseline_mod.BaselineInfo(frozenset())
            )
        path = explicit if explicit is not None else base / baseline_mod.BASELINE_FILENAME
        if explicit is None and not path.is_file():
            return None
        return baseline_mod.load(path.read_text(encoding="utf-8"))
    except OSError as exc:
        _fail(f"cannot read the baseline {explicit or baseline_mod.BASELINE_FILENAME}: {exc}")
    except baseline_mod.BaselineError as exc:
        _fail(str(exc))
    return None


@app.command()
def baseline(
    paths: Annotated[
        Optional[list[Path]],  # noqa: UP045
        typer.Argument(help="Files or directories to scan (default: current directory)."),
    ] = None,
    output: Annotated[
        Optional[Path],  # noqa: UP045
        typer.Option(
            "--output", "-o", help=f"Baseline file (default: {baseline_mod.BASELINE_FILENAME})."
        ),
    ] = None,
    all_files: Annotated[
        bool, typer.Option("--all-files", help="Also check every text file for hidden Unicode.")
    ] = False,
    config: Annotated[
        Optional[Path],  # noqa: UP045
        typer.Option(help="Path to a config file (default: .ghostrules.toml in the scan root)."),
    ] = None,
    strict: Annotated[
        bool, typer.Option("--strict", help="Baseline the 0.3 severities of visible prose.")
    ] = False,
) -> None:
    """Record today's findings so that later scans fail only on new ones.

    Writes fingerprints, never text. Invisible characters, GR002 and GR030 are listed but never
    hidden by a baseline. In CI the baseline is read from the base ref (scan --baseline-from-ref).
    """
    _utf8_streams()
    targets = paths or [Path(".")]
    base = targets[0] if targets[0].is_dir() else targets[0].parent
    try:
        cfg = load_config(base, config)
    except ConfigError as exc:
        _fail(str(exc))
    if strict:
        cfg = replace(cfg, profile="strict")
    result = scan_paths(targets, cfg, all_files=all_files)
    if result.errors:
        for error in result.errors:
            typer.echo(f"error: {safe(error)}", err=True)
        raise typer.Exit(EXIT_ERROR)
    document = baseline_mod.build(result.findings)
    path = output if output is not None else base / baseline_mod.BASELINE_FILENAME
    try:
        path.write_text(baseline_mod.to_json(document), encoding="utf-8")
    except OSError as exc:
        _fail(f"cannot write {path}: {exc.strerror or exc}")
    count = len(document["findings"])
    typer.echo(
        f"wrote {path}: {count} finding(s) recorded on {document['created']} "
        f"by ghostrules {__version__}"
    )


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
    cfg, reader = _lock_config(repo_root, base, config)
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
        _lock_check(snapshot, reader, name, lock_path, format_, output, no_color)
    else:
        _lock_write(snapshot, lock_path, name)


def _lock_config(
    repo_root: Path, base: str | None, config: Path | None
) -> tuple[Config, RefReader | None]:
    """The configuration for ``lock`` (read at ``base`` when given) and the ref reader, if any."""
    reader = None
    try:
        if base is not None:
            reader = RefReader(repo_root, base)
            return config_at_ref(reader), reader
        return load_config(repo_root, config), reader
    except (ConfigError, GitRefError) as exc:
        _fail(str(exc))


def _lock_check(
    snapshot: lock_mod.Snapshot,
    reader: RefReader | None,
    name: str,
    lock_path: Path,
    format_: LockFormat,
    output: Path | None,
    no_color: bool,
) -> None:
    """``lock --check``: report what changed against the lock; exit 1 when something did."""
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


def _lock_write(snapshot: lock_mod.Snapshot, lock_path: Path, name: str) -> None:
    """``lock`` / ``lock --update``: rewrite the lock and say what changed since the last one."""
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
    if file.is_symlink():
        _fail(f"{file} is a symbolic link; clean the file it points to instead")
    backup = file.with_name(file.name + ".ghostrules.bak")
    if backup.exists():
        _fail(f"{backup} already exists; move it away first so no earlier backup is lost")
    try:
        backup.write_bytes(data)
        # write beside the file and swap it in, so a crash never leaves a half-written file
        staged = file.with_name(file.name + ".ghostrules.tmp")
        staged.write_bytes(result.cleaned.encode("utf-8", errors="surrogateescape"))
        shutil.copymode(file, staged)
        os.replace(staged, file)
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


def main() -> None:
    """Console entry point: run the app; an unexpected exception exits ``3``, never ``1``.

    Python's own exit status for an uncaught exception is 1, which a CI job would read as
    "findings". A crash must not look like a finding, and must not look like a clean scan.
    """
    try:
        app()
    except (KeyboardInterrupt, SystemExit):
        raise
    except Exception as exc:  # noqa: BLE001 - the last line of defence
        typer.echo(
            f"internal error: {type(exc).__name__}: {safe(str(exc))}\n"
            "This is a bug in ghostrules, not a finding. Please report it with the command "
            "you ran: https://github.com/BardLaudian/ghostrules/issues",
            err=True,
        )
        sys.exit(EXIT_INTERNAL)
