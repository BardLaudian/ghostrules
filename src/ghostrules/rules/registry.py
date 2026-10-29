"""The single rule registry. Rules register themselves with the ``@rule`` decorator."""

from __future__ import annotations

from collections.abc import Callable, Iterable
from dataclasses import dataclass
from typing import TYPE_CHECKING, Literal

from ghostrules.models import Finding, Kind, ScanTarget, Severity

if TYPE_CHECKING:
    from ghostrules.changeset import ChangeContext
    from ghostrules.scancontext import ScanContext

CheckFn = Callable[[ScanTarget], Iterable[Finding]]
GraphCheckFn = Callable[["ScanContext"], Iterable[Finding]]
ChangeCheckFn = Callable[["ChangeContext"], Iterable[Finding]]
# "file" rules inspect one file, "graph" rules the import graph and "change" rules what a change
# set altered compared with a base ref; "tag" entries document a mark the scanner puts on findings
# and have no check of their own.
Scope = Literal["file", "graph", "change", "tag"]


@dataclass(frozen=True)
class Rule:
    """A detection rule: metadata plus a pure ``check`` function.

    ``severity`` is the headline severity (as in RULES.md) used for listings and SARIF; a rule may
    report other levels depending on context.
    ``scans_decoded`` marks rules that must also run over hidden text decoded by other rules
    (GR010-GR016); the scanner then bumps the severity of what they find there.
    """

    id: str
    severity: Severity
    title: str
    description: str
    applies_to: frozenset[Kind]
    check: CheckFn
    scans_decoded: bool = False
    scope: Scope = "file"
    check_graph: GraphCheckFn | None = None
    check_change: ChangeCheckFn | None = None


_REGISTRY: dict[str, Rule] = {}


def register(new_rule: Rule) -> Rule:
    """Add a rule to the registry; duplicate ids are a programming error."""
    if new_rule.id in _REGISTRY:
        raise ValueError(f"duplicate rule id {new_rule.id}")
    _REGISTRY[new_rule.id] = new_rule
    return new_rule


def rule(
    rule_id: str,
    severity: Severity,
    title: str,
    description: str,
    applies_to: Iterable[Kind],
    *,
    scans_decoded: bool = False,
) -> Callable[[CheckFn], CheckFn]:
    """Decorator registering a check function as a rule."""

    def decorator(fn: CheckFn) -> CheckFn:
        register(
            Rule(
                id=rule_id,
                severity=severity,
                title=title,
                description=description,
                applies_to=frozenset(applies_to),
                check=fn,
                scans_decoded=scans_decoded,
            )
        )
        return fn

    return decorator


def _no_findings(_target: ScanTarget) -> Iterable[Finding]:
    return ()


def graph_rule(
    rule_id: str,
    severity: Severity,
    title: str,
    description: str,
    *,
    tag: bool = False,
) -> Callable[[GraphCheckFn], GraphCheckFn]:
    """Decorator registering a rule that works on the import graph (a ``ScanContext``).

    With ``tag=True`` the rule documents a mark the scanner applies itself; its check is never
    called.
    """

    def decorator(fn: GraphCheckFn) -> GraphCheckFn:
        register(
            Rule(
                id=rule_id,
                severity=severity,
                title=title,
                description=description,
                applies_to=frozenset({"instructions"}),
                check=_no_findings,
                scope="tag" if tag else "graph",
                check_graph=fn,
            )
        )
        return fn

    return decorator


def change_rule(
    rule_id: str,
    severity: Severity,
    title: str,
    description: str,
    applies_to: Iterable[Kind] = ("instructions", "config"),
) -> Callable[[ChangeCheckFn], ChangeCheckFn]:
    """Decorator registering a rule that compares the scanned tree with a base ref (a
    ``ChangeContext``). It only runs when the scan was given a base."""

    def decorator(fn: ChangeCheckFn) -> ChangeCheckFn:
        register(
            Rule(
                id=rule_id,
                severity=severity,
                title=title,
                description=description,
                applies_to=frozenset(applies_to),
                check=_no_findings,
                scope="change",
                check_change=fn,
            )
        )
        return fn

    return decorator


def all_rules() -> list[Rule]:
    """All registered rules, sorted by id."""
    return sorted(_REGISTRY.values(), key=lambda r: r.id)


def get_rule(rule_id: str) -> Rule | None:
    """Look up one rule by id."""
    return _REGISTRY.get(rule_id)
