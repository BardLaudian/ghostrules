"""Severity by visibility: what a reviewer can read is the reviewer's job.

ghostrules' value is what people cannot review: invisible text, text reached indirectly and
configuration that executes things. Plain prose in an agent file that the change shows in full is
read by whoever approves the change, so the prose rules (GR010-GR014, GR016) report it at ``low``
when it instructs the agent and ``info`` when it only describes or quotes. Text that is hidden (in
an HTML comment, decoded from invisible characters) or indirect (a file reached only through an
import) keeps the rule's severity, and so does everything else. ``--strict`` turns this off.
"""

from __future__ import annotations

import re
from bisect import bisect_right
from collections.abc import Iterable
from dataclasses import replace

from ghostrules.models import Finding, ScanTarget, Severity
from ghostrules.rules.directive import _inside_quotes
from ghostrules.rules.helpers import _URL_HOST_RE, host_allowed

# GR015 is not here: a base64 blob is on screen but nobody can read it, so it keeps its severity.
VISIBLE_PROSE_RULES = frozenset({"GR010", "GR011", "GR012", "GR013", "GR014", "GR016"})

_NOTE = (
    " Reported at {level} because the text is visible in the file itself; hidden or indirect "
    "text keeps the rule's severity (--strict restores it)."
)


# Combinations inside one paragraph that keep the rule's severity even when the text is visible:
# they read as an attack, not as a rule written for a team. A quotation, an example or a
# description (the rules already lower those, see ``directive.classify``) is never kept high.
_BLANK_LINE = re.compile(r"\n[ \t]*\r?\n")
_COMBINATIONS = (frozenset({"GR013", "GR011"}), frozenset({"GR010", "GR013"}))


def _outside_allowed(text: str, allow_domains: Iterable[str]) -> bool:
    allow = tuple(allow_domains)
    return any(not host_allowed(h, allow) for h in _URL_HOST_RE.findall(text))


def attack_findings(
    findings: list[Finding], target: ScanTarget, allow_domains: Iterable[str] = ()
) -> set[int]:
    """Indexes of ``findings`` that form an attack inside one paragraph (exfiltration + hiding,
    override + exfiltration, a sensitive file + a URL outside ``allow_domains``)."""
    breaks = list(_BLANK_LINE.finditer(target.text))
    starts = [m.end() for m in breaks]
    groups: dict[int, list[int]] = {}
    for index, finding in enumerate(findings):
        if finding.rule_id in VISIBLE_PROSE_RULES and "severity lowered" not in finding.message:
            offset = target.offset(finding.line, finding.column)
            paragraph = bisect_right(starts, offset)
            if _inside_quotes(target.text[starts[paragraph - 1] if paragraph else 0 : offset]):
                continue  # a quotation that opened in an earlier sentence of the paragraph
            groups.setdefault(paragraph, []).append(index)
    kept: set[int] = set()
    for paragraph, indexes in groups.items():
        ids = {findings[i].rule_id for i in indexes}
        begin = starts[paragraph - 1] if paragraph else 0
        end = breaks[paragraph].start() if paragraph < len(breaks) else len(target.text)
        for combination in _COMBINATIONS:
            if combination <= ids:
                kept.update(i for i in indexes if findings[i].rule_id in combination)
        if "GR014" in ids and _outside_allowed(target.text[begin:end], allow_domains):
            kept.update(i for i in indexes if findings[i].rule_id == "GR014")
    return kept


def by_visibility(finding: Finding, target: ScanTarget, *, import_only: bool) -> Finding:
    """``finding`` with the severity its visibility calls for (never raised)."""
    if (
        finding.rule_id not in VISIBLE_PROSE_RULES
        or finding.decoded  # decoded from hidden characters
        or import_only
        or target.kind == "config"
        or target.in_html_comment(target.offset(finding.line, finding.column))
    ):
        return finding
    cap = Severity.INFO if "severity lowered" in finding.message else Severity.LOW
    if finding.severity <= cap:
        return finding
    note = _NOTE.format(level=cap.label)
    return replace(finding, severity=cap, message=finding.message + note)
