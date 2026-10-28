"""The terminal tree of ``ghostrules context`` (JSON and Markdown are in ``context_data``).

The tree mirrors how an agent assembles its context: files it loads by itself are the top level,
imported files hang under the file that imports them, and imports that do not load are shown
where they were written, with the reason.
"""

from __future__ import annotations

from collections import Counter

from rich.console import Group, RenderableType
from rich.padding import Padding
from rich.rule import Rule
from rich.text import Text
from rich.tree import Tree

from ghostrules.agents.base import ContextEntry
from ghostrules.context_command import ContextReport
from ghostrules.models import Finding
from ghostrules.reporters.common import SEVERITY_ORDER, safe, via_text
from ghostrules.reporters.context_data import (  # noqa: F401  (re-exported for callers)
    Node,
    build_nodes,
    render_json,
    render_markdown,
    to_dict,
)
from ghostrules.reporters.table import BADGE_STYLE, TEXT_STYLE
from ghostrules.reveal import build as build_reveal


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
