"""The context engine as a library: what an AI agent reads, resolved offline.

``resolve`` is the stable entry point for other tools (and what ``ghostrules context`` prints with
``--format json``). It runs the loading model of each agent for a session in ``cwd`` working on
``target`` (imports followed, conditional rules matched, what each agent strips applied, symlink
aliases resolved) and, unless ``scan=False``, scans the result. Nothing is executed and nothing
leaves the machine. The shape of the returned dict is the JSON schema ``schema()`` returns; fields
are only added within a major version.

    from ghostrules.context import resolve
    report = resolve("path/to/repo", agent="claude-code", target="src/app.py")
    for entry in report["agents"]["claude-code"]["entries"]:
        print(entry["load"], entry["path"], entry["via"])
"""

from __future__ import annotations

import json
from importlib import resources
from pathlib import Path
from typing import Any

from ghostrules.agents import AGENT_NAMES, DEFAULT_AGENTS
from ghostrules.config import Config
from ghostrules.context_command import ContextError, build_report
from ghostrules.reporters.context_data import to_dict

__all__ = ["AGENT_NAMES", "DEFAULT_AGENTS", "ContextError", "resolve", "schema"]


def resolve(
    root: str | Path,
    *,
    agent: str = "all",
    cwd: str | Path | None = None,
    target: str | Path | None = None,
    include_home: bool = False,
    scan: bool = True,
    show_text: bool = False,
    config: Config | None = None,
) -> dict[str, Any]:
    """The context of ``agent`` (a name from ``AGENT_NAMES``, or ``"all"`` for the configured set)
    for a session in ``cwd``. Raises ``ContextError`` for a bad root, agent or path."""
    report = build_report(
        Path(root),
        config or Config(),
        agent=agent,
        cwd=Path(cwd) if cwd is not None else None,
        target=Path(target) if target is not None else None,
        include_home=include_home,
        scan=scan,
    )
    return to_dict(report, show_text=show_text)


def schema() -> dict[str, Any]:
    """The JSON schema (draft 7) of what ``resolve`` returns."""
    text = resources.files("ghostrules").joinpath("schemas/context.schema.json").read_text("utf-8")
    return json.loads(text)
