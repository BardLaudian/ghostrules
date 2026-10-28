"""Reports for ``ghostrules context``: a tree, JSON and Markdown.

The tree mirrors how an agent assembles its context: files it loads by itself are the top level,
imported files hang under the file that imports them, and imports that do not load are shown
where they were written, with the reason.
"""

from __future__ import annotations

import json
from collections import Counter
from dataclasses import dataclass, field
from typing import Any

from rich.console import Group, RenderableType
from rich.padding import Padding
from rich.rule import Rule
from rich.text import Text
from rich.tree import Tree

from ghostrules import __version__
from ghostrules.agents.base import ContextEntry, ContextGraph, ImportEdge
from ghostrules.context_command import ContextReport
from ghostrules.models import Finding
from ghostrules.reporters.common import SEVERITY_ORDER, safe, via_text
from ghostrules.reporters.table import BADGE_STYLE, TEXT_STYLE
from ghostrules.reveal import build as build_reveal
from ghostrules.unicode_utils import render_invisible

_STATES = {
    "always": ("●", "always", "green"),
    "conditional": ("◐", "conditional", "yellow"),
    "on_demand": ("○", "on demand", "cyan"),
    "agent_decides": ("◌", "agent decides", "magenta"),
    "manual": ("◌", "manual", "grey62"),
    "blocked": ("✕", "skipped", "red"),
}
_NOT_READ = ("↗", "not read", "yellow")
_LEAF_NOTES = {
    "missing": ("✕", "missing", "the file does not exist"),
    "directory": ("✕", "directory", "a directory is not loaded"),
    "quoted": ("✕", "ignored", "a quoted path is not imported"),
    "depth": ("✕", "too deep", "beyond the import depth limit"),
    "cycle": ("↺", "cycle", "import cycle"),
    "duplicate": ("↺", "again", "already in the context"),
}


@dataclass
class Node:
    """One line of the tree: a loaded file, or an import that did not load."""

    icon: str
    state: str
    style: str
    path: str
    details: list[str] = field(default_factory=list)
    counts: Counter[str] = field(default_factory=Counter)
    children: list[Node] = field(default_factory=list)


def _lines(entry: ContextEntry) -> str:
    return f"{len(entry.text.splitlines())} lines"


def _short_note(note: str) -> str:
    """The engine's notes are written for JSON; the tree wants the gist."""
    if note.startswith("sensitive file"):
        return "credentials file: never read"
    if note.startswith("external import"):
        return "outside the repository, needs approval, not read"
    if note.startswith("outside the repository"):
        return "outside the repository: the agent does not load it"
    return note


def _entry_node(entry: ContextEntry, report: ContextReport) -> Node:
    if not entry.readable and entry.load != "blocked":
        icon, state, style = _NOT_READ
    else:
        icon, state, style = _STATES[entry.load]
    details: list[str] = []
    if entry.via:
        details.append(f"imported at {entry.via[-1]}")
    if entry.load == "blocked":
        details.append(entry.note or entry.reason)
    elif entry.load == "on_demand" and entry.condition:
        details.append(f"loads when the agent touches {entry.condition}")
    elif entry.load in ("conditional", "on_demand", "agent_decides", "manual"):
        details.append(entry.reason)
    elif not entry.via and entry.readable:
        details.append(_lines(entry))
    if entry.matches is True:
        details.append("✓ matches")
    elif entry.matches is False:
        details.append("✗ not triggered")
    if "strip_html_comments" in entry.transforms:
        details.append("HTML comments stripped")
    if entry.unverified:
        details.append("(unverified)")
    if entry.load != "blocked" and entry.note and (entry.unverified or not entry.readable):
        details.append(_short_note(entry.note))
    name = f"{entry.path} → {entry.alias_of} (symlink)" if entry.alias_of else entry.path
    counts = report.severity_counts(entry.alias_of or entry.path)
    return Node(icon, state, style, name, details, counts)


def _leaf(edge: ImportEdge) -> Node | None:
    spec = _LEAF_NOTES.get(edge.status)
    if spec is None or (
        edge.status in ("missing", "directory", "quoted") and not edge.looks_like_path
    ):
        return None
    icon, state, why = spec
    details = [f"imported at {edge.source}:{edge.line}", edge.hint or why]
    if edge.unverified:
        details.append("(unverified)")
    return Node(icon, state, "red" if icon == "✕" else "grey62", edge.written, details)


def build_nodes(graph: ContextGraph, report: ContextReport) -> list[Node]:
    """The tree of one agent's context as nodes (shared by every renderer)."""
    by_key = {(e.path, e.via): e for e in graph.entries}
    edges_from: dict[str, list[ImportEdge]] = {}
    for edge in graph.edges:
        edges_from.setdefault(edge.source, []).append(edge)

    def expand(entry: ContextEntry) -> Node:
        node = _entry_node(entry, report)
        for edge in edges_from.get(entry.path, []):
            via = (*entry.via, f"{entry.path}:{edge.line}")
            child = by_key.get((edge.target, via))
            if child is not None and edge.status != "duplicate":
                node.children.append(expand(child))
            else:
                leaf = _leaf(edge)
                if leaf is not None:
                    node.children.append(leaf)
        return node

    return [expand(e) for e in graph.entries if not e.via]


# --- tree ---------------------------------------------------------------------------------------


def _counts_text(counts: Counter[str]) -> Text:
    out = Text()
    for sev in SEVERITY_ORDER:
        n = counts.get(sev.label, 0)
        if n:
            out.append(f"  ⚠ {n} {sev.label}", style=TEXT_STYLE[sev])
    return out


def _label(node: Node) -> Text:
    label = Text()
    label.append(f"{node.icon} {node.state:<11} ", style=node.style)
    label.append(safe(node.path), style="bold")
    label.append_text(_counts_text(node.counts))
    if node.details:
        label.append("  " + " · ".join(safe(d) for d in node.details), style="grey62")
    return label


def _attach(branch: Tree, nodes: list[Node]) -> None:
    for node in nodes:
        _attach(branch.add(_label(node), guide_style="grey37"), node.children)


def _header(agent: str, report: ContextReport) -> Text:
    head = Text(agent, style="bold cyan")
    head.append(" · ", style="grey62")
    if report.target:
        head.append(f"working on {report.target}", style="bold")
    else:
        head.append("session start (no target file)", style="grey62")
    if report.cwd:
        head.append(f"   cwd: {report.cwd}", style="grey62")
    return head


def _findings_block(report: ContextReport) -> list[RenderableType]:
    if not report.scanned:
        return []
    if not report.findings:
        out: list[RenderableType] = [
            Text("✔ No findings in what these agents read.", style="green")
        ]
    else:
        out = [Rule(Text("Findings", style="bold"), align="left", style="grey37")]
        for group in _group_findings(report.findings):
            out.append(_finding_group(group))
    if report.outside:
        out.append(
            Text(
                f"(+{report.outside} finding(s) in files these agents do not load; "
                "run ghostrules scan to see them)",
                style="grey62",
            )
        )
    return out


def _group_findings(findings: list[Finding]) -> list[list[Finding]]:
    """Findings from the same hidden text (GR001 and what it decodes to) are shown together."""
    groups: dict[tuple[object, ...], list[Finding]] = {}
    for f in findings:
        key = (f.path, f.line, f.column, f.decoded) if f.decoded else (id(f),)
        groups.setdefault(key, []).append(f)
    return list(groups.values())


def _finding_group(group: list[Finding]) -> RenderableType:
    first = group[0]
    head = Text()
    head.append(f" {first.severity.label.upper():^8} ", style=BADGE_STYLE[first.severity])
    head.append(" " + " ".join(f.rule_id for f in group), style="bold")
    head.append("  ")
    head.append(safe(f"{first.path}:{first.line}"), style="bold cyan")
    lines: list[RenderableType] = [head]
    if first.via:
        lines.append(Padding(Text(safe(f"via {via_text(first)}"), style="yellow"), (0, 0, 0, 10)))
    if first.decoded:
        hidden = Text.assemble(("hidden text: ", "grey62"), (safe(first.decoded), "bold red"))
        lines.append(Padding(hidden, (0, 0, 0, 10)))
    else:
        lines.append(Padding(Text(safe(first.message), style="grey62"), (0, 0, 0, 10)))
    return Group(*lines, Text(""))


def build_tree(report: ContextReport) -> RenderableType:
    """The full tree report as a rich renderable."""
    blocks: list[RenderableType] = []
    for agent, graph in report.graphs.items():
        tree = Tree(_header(agent, report), guide_style="grey37")
        nodes = build_nodes(graph, report)
        if nodes:
            _attach(tree, nodes)
        else:
            tree.add(Text("no instruction files are loaded", style="grey62"))
        blocks += [tree, Text("")]
    blocks += _findings_block(report)
    notes = list(dict.fromkeys(n for g in report.graphs.values() for n in g.notes))
    blocks += [Text(f"note: {safe(n)}", style="grey62") for n in notes]
    blocks += [Text(f"warning: {safe(w)}", style="yellow") for w in report.warnings]
    blocks += [Text(f"error: {safe(e)}", style="red") for e in report.errors]
    return Group(*blocks)


def build_text(report: ContextReport) -> RenderableType:
    """``--show-text``: the text each agent receives, invisible characters revealed. Files whose
    text is identical for several agents are shown once."""
    seen: dict[tuple[str, str], list[str]] = {}
    order: list[tuple[str, str, ContextEntry]] = []
    for agent, graph in report.graphs.items():
        for entry in graph.entries:
            if not entry.readable:
                continue
            key = (entry.path, entry.seen_sha256)
            if key not in seen:
                order.append((entry.path, entry.seen_sha256, entry))
            seen.setdefault(key, []).append(agent)
    blocks: list[RenderableType] = []
    for path, sha, entry in order:
        who = ", ".join(seen[(path, sha)])
        blocks.append(
            Rule(
                Text(f"{safe(path)} · text seen by {who}", style="bold"),
                align="left",
                style="grey37",
            )
        )
        blocks.append(build_reveal(entry.text) if entry.text else Text("(empty)", style="grey62"))
    return Group(*blocks)


# --- json ---------------------------------------------------------------------------------------


def _entry_dict(entry: ContextEntry, show_text: bool) -> dict[str, Any]:
    data: dict[str, Any] = {
        "path": entry.path,
        "load": entry.load,
        "reason": entry.reason,
        "via": list(entry.via),
        "transforms": list(entry.transforms),
        "raw_sha256": entry.raw_sha256,
        "seen_sha256": entry.seen_sha256,
        "readable": entry.readable,
        "unverified": entry.unverified,
        "condition": entry.condition,
        "matches": entry.matches,
        "note": entry.note,
    }
    if entry.alias_of:
        data["alias_of"] = entry.alias_of
    if entry.link_problem:
        data["link_problem"] = entry.link_problem
    if show_text:
        data["text"] = entry.text
    return data


def _edge_dict(edge: ImportEdge) -> dict[str, Any]:
    return {
        "source": edge.source,
        "target": edge.target,
        "written": edge.written,
        "line": edge.line,
        "column": edge.column,
        "status": edge.status,
        "hop": edge.hop,
        "unverified": edge.unverified,
        "note": edge.note,
        "hint": edge.hint,
    }


def to_dict(report: ContextReport, *, show_text: bool = False) -> dict[str, Any]:
    """The report as plain data."""
    return {
        "version": __version__,
        "cwd": report.cwd,
        "target": report.target,
        "agents": {
            agent: {
                "entries": [_entry_dict(e, show_text) for e in g.entries],
                "edges": [_edge_dict(e) for e in g.edges],
                "cycles": [list(c) for c in g.cycles],
                "notes": g.notes,
            }
            for agent, g in report.graphs.items()
        },
        "findings": [f.to_dict() for f in report.findings] if report.scanned else None,
        "summary": {
            "files": len({e.path for g in report.graphs.values() for e in g.entries}),
            "findings": len(report.findings),
            "findings_outside_context": report.outside,
            "by_severity": {
                s.label: n
                for s in SEVERITY_ORDER
                if (n := sum(1 for f in report.findings if f.severity is s))
            },
        },
        "warnings": report.warnings,
        "errors": report.errors,
    }


def render_json(report: ContextReport, *, show_text: bool = False) -> str:
    """JSON text of ``to_dict``."""
    return json.dumps(to_dict(report, show_text=show_text), indent=2, ensure_ascii=False) + "\n"


# --- markdown -----------------------------------------------------------------------------------


def _md(text: str) -> str:
    return " ".join(safe(text).replace("`", "'").replace("<", "&lt;").replace(">", "&gt;").split())


def _md_nodes(nodes: list[Node], depth: int, out: list[str]) -> None:
    for node in nodes:
        detail = f" — {_md(' · '.join(node.details))}" if node.details else ""
        flags = "".join(f" ⚠ {n} {s}" for s, n in node.counts.items())
        out.append(
            f"{'  ' * depth}- {node.icon} **{node.state}** `{_md(node.path)}`{detail}{flags}"
        )
        _md_nodes(node.children, depth + 1, out)


def render_markdown(report: ContextReport, *, show_text: bool = False) -> str:
    """The report as Markdown, for pull-request comments."""
    lines = ["## ghostrules context", ""]
    for agent, graph in report.graphs.items():
        where = f"working on `{_md(report.target)}`" if report.target else "session start"
        lines += [f"### {agent} · {where}", ""]
        nodes = build_nodes(graph, report)
        if nodes:
            _md_nodes(nodes, 0, lines)
        else:
            lines.append("_No instruction files are loaded._")
        lines.append("")
    if report.scanned:
        if report.findings:
            lines += [
                "### Findings",
                "",
                "| Severity | Rule | Location | Finding |",
                "| --- | --- | --- | --- |",
            ]
            for f in report.findings:
                chain = f"<br>via `{_md(via_text(f))}`" if f.via else ""
                lines.append(
                    f"| {f.severity.label} | `{f.rule_id}` | `{_md(f.path)}:{f.line}` | "
                    f"{_md(f.message)}{chain} |"
                )
        else:
            lines.append("✅ **No findings in what these agents read.**")
        if report.outside:
            lines += ["", f"_{report.outside} finding(s) in files these agents do not load._"]
    if show_text:
        for agent, graph in report.graphs.items():
            for entry in (e for e in graph.entries if e.readable):
                shown = render_invisible(entry.text, with_name=False).replace("```", "'''")
                lines += [
                    "",
                    f"<details><summary>{_md(entry.path)} · text seen by {agent}</summary>",
                ]
                lines += ["", "```text", shown.rstrip("\n"), "```", "", "</details>"]
    notes = list(dict.fromkeys(n for g in report.graphs.values() for n in g.notes))
    lines += ["", *[f"> **Note:** {_md(n)}" for n in notes]]
    lines += [f"> **Warning:** {_md(w)}" for w in report.warnings]
    lines += [f"> **Error:** {_md(e)}" for e in report.errors]
    return "\n".join(lines).rstrip("\n") + "\n"
