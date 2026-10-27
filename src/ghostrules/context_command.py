"""``ghostrules context``: build and scan what agents read for a session and a target file."""

from __future__ import annotations

import os
from collections import Counter
from dataclasses import dataclass, field, replace
from pathlib import Path

from ghostrules.agents import AGENT_NAMES, ContextGraph, Repo, get_model
from ghostrules.agents.claude_code import DEFAULT_MODE
from ghostrules.config import Config
from ghostrules.models import Finding
from ghostrules.scanner import scan_paths


class ContextError(Exception):
    """Bad arguments for ``context`` (a path outside the repository, an unknown agent...)."""


@dataclass
class ContextReport:
    """Everything the renderers need. ``findings`` are those in files that are part of a context;
    ``outside`` counts findings in other files of the repository."""

    root: Path
    cwd: str
    target: str | None
    graphs: dict[str, ContextGraph]
    findings: list[Finding] = field(default_factory=list)
    outside: int = 0
    scanned: bool = True
    warnings: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)

    def findings_for(self, path: str) -> list[Finding]:
        """Findings located in one file."""
        return [f for f in self.findings if f.path == path]

    def severity_counts(self, path: str) -> Counter[str]:
        """Finding count per severity label for one file."""
        return Counter(f.severity.label for f in self.findings_for(path))


def find_root(start: Path) -> Path:
    """The git root above ``start`` (a ``.git`` directory or file), or ``start`` itself."""
    here = Path(os.path.abspath(start))
    for candidate in (here, *here.parents):
        if (candidate / ".git").exists():
            return candidate
    return here


def resolve_inside(raw: Path, root: Path, what: str) -> str:
    """Repo-relative POSIX path of ``raw``, read relative to the current directory and to ``root``.

    Of the readings that fall inside the root, the first that exists on disk wins, else the first
    one. Symlinks are not resolved: this is only path arithmetic.
    """
    base = os.path.abspath(root)
    options = [raw] if raw.is_absolute() else [Path.cwd() / raw, root / raw]
    inside: list[tuple[str, str]] = []
    for option in options:
        full = os.path.normpath(os.path.abspath(option))
        rel = os.path.relpath(full, base)
        if rel == ".":
            inside.append(("", full))
        elif not rel.startswith("..") and not os.path.isabs(rel):
            inside.append((Path(rel).as_posix(), full))
    if not inside:
        raise ContextError(f"{what} {raw} is not inside the repository root {root}")
    return next((rel for rel, full in inside if os.path.lexists(full)), inside[0][0])


def agent_list(agent: str, configured: tuple[str, ...]) -> tuple[str, ...]:
    """The agents to show for ``--agent``."""
    if agent == "all":
        return configured
    if agent not in AGENT_NAMES:
        raise ContextError(
            f"unknown agent {agent!r} (expected one of: {', '.join(AGENT_NAMES)}, all)"
        )
    return (agent,)


def build_report(
    root: Path,
    config: Config,
    *,
    agent: str = "all",
    cwd: Path | None = None,
    target: Path | None = None,
    include_home: bool = False,
    scan: bool = True,
    instructions_mode: str = DEFAULT_MODE,
) -> ContextReport:
    """Run the agent models for a session in ``cwd`` working on ``target`` and scan the result."""
    if not root.is_dir():
        raise ContextError(f"{root} is not a directory")
    cwd_rel = resolve_inside(cwd, root, "--cwd") if cwd is not None else ""
    if cwd_rel and not (root / cwd_rel).is_dir():
        raise ContextError(f"--cwd {cwd} is not a directory")
    target_rel = resolve_inside(target, root, "target") if target is not None else None
    agents = agent_list(agent, config.agents)
    repo = Repo(root)
    home = Repo(Path.home(), "~/") if include_home else None
    try:
        graphs = {
            name: get_model(name, instructions_mode=instructions_mode).build(
                repo, cwd=cwd_rel, target=target_rel or None, home=home
            )
            for name in agents
        }
    except ValueError as exc:
        raise ContextError(str(exc)) from None
    report = ContextReport(root, cwd_rel, target_rel or None, graphs, scanned=scan)
    if not scan:
        return report
    result = scan_paths([root], replace(config, agents=agents), include_home=include_home)
    in_context = {e.path for g in graphs.values() for e in g.entries}
    report.findings = [f for f in result.findings if f.path in in_context]
    report.outside = len(result.findings) - len(report.findings)
    report.warnings, report.errors = result.warnings, result.errors
    return report
