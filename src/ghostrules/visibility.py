"""Severity by visibility: what a reviewer can read is the reviewer's job.

ghostrules' value is what people cannot review: invisible text, text reached indirectly and
configuration that executes things. Plain prose in an agent file that the change shows in full is
read by whoever approves the change, so the prose rules (GR010-GR014, GR016) report it at ``low``
when it instructs the agent and ``info`` when it only describes or quotes. Text that is hidden (in
an HTML comment, decoded from invisible characters) or indirect (a file reached only through an
import) keeps the rule's severity, and so does everything else. ``--strict`` turns this off.
"""

from __future__ import annotations

from dataclasses import replace

from ghostrules.models import Finding, ScanTarget, Severity

# GR015 is not here: a base64 blob is on screen but nobody can read it, so it keeps its severity.
VISIBLE_PROSE_RULES = frozenset({"GR010", "GR011", "GR012", "GR013", "GR014", "GR016"})

_NOTE = (
    " Reported at {level} because the text is visible in the file itself; hidden or indirect "
    "text keeps the rule's severity (--strict restores it)."
)


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
