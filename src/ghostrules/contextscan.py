"""Connects the context engine to ``scan``: which extra files agents read, and who sees them.

For every scan root the loading model of each configured agent is run (session at the root). Every
readable file in those contexts is a scan target: files an import reaches, rules the discovery
globs do not know. Each file also gets the list of agents that load it and how they see its text.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path

from ghostrules.agents import ContextEntry, ContextGraph, Repo, get_model
from ghostrules.config import Config
from ghostrules.models import AgentView
from ghostrules.targets import matches_any


@dataclass
class RootContext:
    """The graphs of one scan root and how to report their paths.

    ``only`` limits a single-file scan to that file and what it imports.
    """

    base: Path
    graphs: dict[str, ContextGraph]
    label_of: Callable[[str], str]
    home: Path | None = None
    only: str | None = None

    def in_scope(self, path: str, via: tuple[str, ...]) -> bool:
        """Whether a graph entry belongs to this scan (all of it, or one file's import tree)."""
        if self.only is None or path.startswith("~/"):
            return True
        return path == self.only or bool(via and via[0].rsplit(":", 1)[0] == self.only)

    def abs_path(self, path: str) -> Path:
        """Where a graph path lives on disk."""
        if path.startswith("~/") and self.home is not None:
            return self.home / path[2:]
        return self.base / path


@dataclass
class FileMeta:
    """What the agent models say about one scanned file."""

    abs_path: Path
    rel: str
    agents: set[str] = field(default_factory=set)
    views: list[AgentView] = field(default_factory=list)
    via: tuple[str, ...] = ()
    rooted: bool = False  # some agent loads it by itself, not only through an import


def build_context(
    base: Path,
    config: Config,
    label_of: Callable[[str], str],
    *,
    home: Repo | None,
    only: str | None,
) -> RootContext:
    """Run every configured agent model for the root ``base``."""
    repo = Repo(base)
    graphs = {name: get_model(name).build(repo, cwd="", home=home) for name in config.agents}
    return RootContext(base, graphs, label_of, home.root if home else None, only)


def collect_meta(contexts: list[RootContext], config: Config) -> dict[str, FileMeta]:
    """Per reported path: who loads the file and how it is reached."""
    meta: dict[str, FileMeta] = {}
    for rc in contexts:
        for agent, graph in rc.graphs.items():
            for entry in graph.entries:
                if not entry.readable or not rc.in_scope(entry.path, entry.via):
                    continue
                if is_excluded(entry, config.exclude):
                    continue
                label = rc.label_of(entry.path)
                item = meta.setdefault(label, FileMeta(rc.abs_path(entry.path), entry.path))
                item.agents.add(agent)
                item.views.append(
                    AgentView(
                        agent,
                        tuple(
                            (r.start_line, r.end_line)
                            for r in entry.removed
                            if r.kind == "html_comment"
                        ),
                        entry.unverified,
                    )
                )
                if entry.via:
                    if not item.via:
                        item.via = tuple(relabel_via(v, rc.label_of) for v in entry.via)
                else:
                    item.rooted = True
    return meta


def is_excluded(entry: ContextEntry, exclude: tuple[str, ...]) -> bool:
    """Whether the user excluded this file, or a file whose import chain leads to it.

    A file that only an excluded file imports is not part of the context being checked either.
    User-level files (``~/``) are never excluded.
    """
    if not exclude or entry.path.startswith("~/"):
        return False
    chain = [step.rsplit(":", 1)[0] for step in entry.via]
    return any(matches_any(path, exclude) for path in (entry.path, *chain))


def relabel_via(via: str, label_of: Callable[[str], str]) -> str:
    path, _, line = via.rpartition(":")
    return f"{label_of(path)}:{line}"
