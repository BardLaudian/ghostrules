"""Import-graph rules GR020-GR025 (``docs/v0.2/RULES.md``).

They look at ``@path`` imports across every modelled agent, so a payload cannot hide in a file
that only an import reaches. Findings sit on the importing line; nothing the import points at is
ever read here.
"""

from __future__ import annotations

from collections import defaultdict
from collections.abc import Iterator
from dataclasses import replace

from ghostrules.agents.base import ContextEntry, ImportEdge
from ghostrules.models import Finding, Severity
from ghostrules.rules.helpers import build_finding
from ghostrules.rules.registry import graph_rule
from ghostrules.scancontext import ScanContext
from ghostrules.sensitive import is_sensitive_path

_Key = tuple[str, int, int, str]  # importing file, line, column, path as written


def _grouped(ctx: ScanContext) -> dict[_Key, list[tuple[str, ImportEdge]]]:
    """Every import occurrence with the agents that follow it, in file order."""
    groups: dict[_Key, list[tuple[str, ImportEdge]]] = defaultdict(list)
    for agent, graph in ctx.graphs.items():
        for edge in graph.edges:
            groups[(edge.source, edge.line, edge.column, edge.written)].append((agent, edge))
    return groups


def _at_import(
    ctx: ScanContext,
    key: _Key,
    agents: list[str],
    *,
    rule_id: str,
    severity: Severity,
    title: str,
    message: str,
    fix_hint: str,
) -> Finding | None:
    """A finding on the import's line, or ``None`` if the importing file is not being scanned."""
    source, line, column, written = key
    target = ctx.target(source)
    if target is None:
        return None
    start = target.offset(line, column)
    finding = build_finding(
        target=target,
        rule_id=rule_id,
        severity=severity,
        title=title,
        message=message,
        start=start,
        end=start + len(written) + 1,
        fix_hint=fix_hint,
        limit=120,
    )
    return replace(finding, agents=tuple(sorted(agents)))


def _names(agents: list[str]) -> str:
    return ", ".join(sorted(set(agents)))


# --- GR020 ---------------------------------------------------------------------------------


@graph_rule(
    "GR020",
    Severity.HIGH,
    "External import",
    "An @path import that resolves outside the repository (absolute, ~/ or ../ above the root).",
)
def gr020_external_import(ctx: ScanContext) -> Iterator[Finding]:
    """High; info when the importing file is user-level. The target is never resolved or read."""
    for key, items in _grouped(ctx).items():
        outside = [(a, e) for a, e in items if e.outside_tree and e.status != "quoted"]
        if not outside:
            continue
        effects = []
        for agent, edge in outside:
            if edge.status == "external":
                effects.append(
                    f"{agent} asks for one-time approval (an earlier approval silently covers "
                    "new imports)"
                    if not key[0].startswith("~/")
                    else f"{agent} loads it"
                )
            else:
                effects.append(f"{agent} does not load it")
        user_level = key[0].startswith("~/")
        finding = _at_import(
            ctx,
            key,
            [a for a, _ in outside],
            rule_id="GR020",
            severity=Severity.INFO if user_level else Severity.HIGH,
            title="External import",
            message=f"Import '@{key[3]}' points outside the repository: " + "; ".join(effects),
            fix_hint="Move the file into the repository, or remove the import.",
        )
        if finding:
            yield finding


# --- GR021 ---------------------------------------------------------------------------------


@graph_rule(
    "GR021",
    Severity.CRITICAL,
    "Sensitive file imported into context",
    "An @path import of a secrets or credentials file (.env, ~/.ssh/*, .npmrc, *.pem...).",
)
def gr021_sensitive_import(ctx: ScanContext) -> Iterator[Finding]:
    """Critical: importing it puts the secret into every prompt sent to the model provider."""
    for key, items in _grouped(ctx).items():
        if not is_sensitive_path(key[3]):
            continue
        live = [(a, e) for a, e in items if e.status != "quoted"]
        if not live:
            continue
        uncertain = all(e.unverified for _, e in live)
        finding = _at_import(
            ctx,
            key,
            [a for a, _ in live],
            rule_id="GR021",
            severity=Severity.HIGH if uncertain else Severity.CRITICAL,
            title="Sensitive file imported into context",
            message=(
                f"Import '@{key[3]}' brings a credentials file into the agent's context, so its "
                "contents are sent to the model provider with every prompt"
                + (" (unverified: the import may not be expanded)" if uncertain else "")
            ),
            fix_hint="Remove the import; keep secrets out of the agent's context.",
        )
        if finding:
            yield finding


# --- GR022 ---------------------------------------------------------------------------------

_REASONS = {
    "missing": "the file does not exist",
    "directory": "it is a directory, not a file",
    "depth": "it is deeper than the import depth limit",
    "quoted": "a path in quotes is not imported",
    "too_large": "the file is too large",
}


def _silent_reason(edge: ImportEdge) -> str | None:
    """Why an agent silently ignores this import, or ``None`` if it does not."""
    if edge.hint:
        return edge.hint
    if edge.status not in _REASONS or edge.outside_tree:
        return None
    if edge.status in ("missing", "directory", "quoted") and not edge.looks_like_path:
        return None  # an @mention, not a path
    if edge.status == "missing" and (edge.in_comment or not edge.certain):
        return None
    return _REASONS[edge.status]


@graph_rule(
    "GR022",
    Severity.LOW,
    "Import that silently does not load",
    "An @path the agent ignores: missing file, too deep, quoted path or a path cut at a space.",
)
def gr022_silent_import(ctx: ScanContext) -> Iterator[Finding]:
    """Low: mostly a reliability problem, but the author believes the agent reads something it
    does not."""
    for key, items in _grouped(ctx).items():
        reasons: dict[str, list[str]] = defaultdict(list)
        for agent, edge in items:
            reason = _silent_reason(edge)
            if reason:
                reasons[reason].append(agent)
        if not reasons:
            continue
        detail = "; ".join(f"{_names(a)}: {r}" for r, a in reasons.items())
        finding = _at_import(
            ctx,
            key,
            [a for agents in reasons.values() for a in agents],
            rule_id="GR022",
            severity=Severity.LOW,
            title="Import that silently does not load",
            message=f"'@{key[3]}' is not loaded ({detail})",
            fix_hint="Fix the path, escape spaces with a backslash, or remove the import.",
        )
        if finding:
            yield finding


# --- GR023 ---------------------------------------------------------------------------------


@graph_rule(
    "GR023",
    Severity.INFO,
    "Import cycle",
    "Files that import each other in a loop. Agents stop at the depth limit; it is only noise.",
)
def gr023_import_cycle(ctx: ScanContext) -> Iterator[Finding]:
    """Info: reported once per cycle, on the import that closes it."""
    seen: set[tuple[str, ...]] = set()
    for graph in ctx.graphs.values():
        for cycle in graph.cycles:
            nodes = cycle[:-1]
            pivot = nodes.index(min(nodes))
            canonical = nodes[pivot:] + nodes[:pivot]
            if canonical in seen:
                continue
            seen.add(canonical)
            closing = next(
                (
                    e
                    for e in graph.edges
                    if e.status == "cycle" and e.source == cycle[-2] and e.target == cycle[-1]
                ),
                None,
            )
            if closing is None:
                continue
            key = (closing.source, closing.line, closing.column, closing.written)
            finding = _at_import(
                ctx,
                key,
                [a for a, g in ctx.graphs.items() if cycle in g.cycles],
                rule_id="GR023",
                severity=Severity.INFO,
                title="Import cycle",
                message="Imports form a loop: " + " → ".join(cycle),
                fix_hint="Remove one of the imports.",
            )
            if finding:
                yield finding


# --- GR024 ---------------------------------------------------------------------------------


@graph_rule(
    "GR024",
    Severity.INFO,
    "Payload reached only through an import",
    "Not a detector: findings in a file that only an @import reaches carry the import chain "
    "and the tag reached-via-import. Disabling it stops ghostrules from following imports.",
    tag=True,
)
def gr024_reached_via_import(_ctx: ScanContext) -> Iterator[Finding]:
    """The scanner applies the tag itself; there is nothing to check here."""
    return iter(())


# --- GR025 ---------------------------------------------------------------------------------


def _symlinked(ctx: ScanContext) -> dict[str, list[tuple[str, ContextEntry]]]:
    found: dict[str, list[tuple[str, ContextEntry]]] = defaultdict(list)
    for agent, graph in ctx.graphs.items():
        for entry in graph.entries:
            if entry.symlink_target:
                found[entry.path].append((agent, entry))
    return found


@graph_rule(
    "GR025",
    Severity.MEDIUM,
    "Symlinked instruction source",
    "An instruction file or rules directory that is a symlink. ghostrules never follows it.",
)
def gr025_symlink(ctx: ScanContext) -> Iterator[Finding]:
    """Medium; high when the link leaves the repository."""
    for path, items in _symlinked(ctx).items():
        entry = items[0][1]
        if ctx.excluded(path):
            continue
        outside = any(e.leaves_tree for _, e in items)
        target = entry.symlink_target
        message = (
            f"'{path}' is a symlink to '{target}'"
            + (", which is outside the repository" if outside else "")
            + ". ghostrules does not follow symlinks, so what the agent reads through it is not "
            "scanned here" + ("; Claude Code treats it like an external import" if outside else "")
        )
        yield Finding(
            rule_id="GR025",
            severity=Severity.HIGH if outside else Severity.MEDIUM,
            title="Symlinked instruction source",
            message=message,
            path=path,
            line=1,
            column=1,
            end_column=1,
            snippet=f"{path} -> {target}",
            fix_hint="Commit the real file, or scan the link target explicitly.",
            via=entry.via,
            agents=tuple(sorted({a for a, _ in items})),
        )


def run_graph_rules(ctx: ScanContext, rule_ids: set[str]) -> list[Finding]:
    """Run the graph rules named in ``rule_ids`` (used by the scanner)."""
    from ghostrules.rules.registry import all_rules

    out: list[Finding] = []
    for r in all_rules():
        if r.scope == "graph" and r.check_graph is not None and r.id in rule_ids:
            out.extend(r.check_graph(ctx))
    return out
