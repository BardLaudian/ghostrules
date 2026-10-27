"""The single rule registry. Rules register themselves with the ``@rule`` decorator."""

from __future__ import annotations

from collections.abc import Callable, Iterable
from dataclasses import dataclass

from ghostrules.models import Finding, Kind, ScanTarget, Severity

CheckFn = Callable[[ScanTarget], Iterable[Finding]]


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


def all_rules() -> list[Rule]:
    """All registered rules, sorted by id."""
    return sorted(_REGISTRY.values(), key=lambda r: r.id)


def get_rule(rule_id: str) -> Rule | None:
    """Look up one rule by id."""
    return _REGISTRY.get(rule_id)
