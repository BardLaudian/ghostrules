"""Helpers shared by the reporters (no ``render`` here: this is not a reporter)."""

from __future__ import annotations

import re
from collections import Counter
from dataclasses import dataclass

from ghostrules.models import Finding, ScanResult, Severity

SEVERITY_ORDER = (
    Severity.CRITICAL,
    Severity.HIGH,
    Severity.MEDIUM,
    Severity.LOW,
    Severity.INFO,
)


# Control characters other than tab and newline: ESC and CSI start terminal escape sequences, CR
# and BS overwrite what is already on the line. File content must never reach a terminal as one.
_CONTROLS = re.compile("[\x00-\x08\x0b-\x1f\x7f-\x9f]")


def safe(text: str) -> str:
    """Make ``text`` safe to print: lone surrogates (from undecodable input bytes) are replaced so
    output can always be encoded, and control characters become a visible ``⟦U+XXXX⟧`` token."""
    text = text.encode("utf-8", errors="replace").decode("utf-8")
    return _CONTROLS.sub(lambda m: f"⟦U+{ord(m.group()):04X}⟧", text)


def via_text(finding: Finding) -> str:
    """The import chain of a finding as ``CLAUDE.md:12 → docs/style.md:3`` (empty if none)."""
    return " → ".join(finding.via)


def severity_counts(findings: list[Finding]) -> dict[str, int]:
    """Finding count per severity label, most severe first, omitting zeros."""
    counts = Counter(f.severity for f in findings)
    return {s.label: counts[s] for s in SEVERITY_ORDER if counts[s]}


def summary_line(result: ScanResult) -> str:
    """One-line summary, e.g. ``3 critical · 2 high in 4 files (scanned 17)``."""
    counts = severity_counts(result.findings)
    if not counts and result.errors:
        return f"Scan incomplete (scanned {result.scanned_files} files)"
    if not counts:
        return f"No findings (scanned {result.scanned_files} files)"
    parts = " · ".join(f"{n} {label}" for label, n in counts.items())
    files = len({f.path for f in result.findings})
    noun = "file" if files == 1 else "files"
    return f"{parts} in {files} {noun} (scanned {result.scanned_files})"


@dataclass(frozen=True)
class FileGroup:
    """All findings of one file, ordered for display."""

    path: str
    findings: list[Finding]

    @property
    def worst(self) -> Severity:
        return max(f.severity for f in self.findings)


def group_by_file(findings: list[Finding]) -> list[FileGroup]:
    """Group findings by file. Files with the worst findings come first; among equals, a file
    hiding decoded text comes before one that does not, then files nearer the root, then path."""
    by_path: dict[str, list[Finding]] = {}
    for f in findings:
        by_path.setdefault(f.path, []).append(f)
    groups = [
        FileGroup(
            path, sorted(items, key=lambda f: (-int(f.severity), f.line, f.column, f.rule_id))
        )
        for path, items in by_path.items()
    ]
    return sorted(
        groups,
        key=lambda g: (
            -int(g.worst),
            not any(f.decoded for f in g.findings),
            g.path.count("/"),
            g.path,
        ),
    )


def config_notes(result: ScanResult) -> list[str]:
    """Things a reader should know that can hide findings: repo-supplied config, suppressions."""
    notes = []
    if result.config_source:
        notes.append(f"configuration loaded from {result.config_source}")
    if result.suppressed:
        noun = "finding" if result.suppressed == 1 else "findings"
        notes.append(f"{result.suppressed} {noun} hidden by ghostrules-ignore comments")
    if result.baselined:
        noun = "finding" if result.baselined == 1 else "findings"
        notes.append(f"{result.baselined} known {noun} left out by the baseline")
    if result.baseline_stale:
        noun = "entry" if result.baseline_stale == 1 else "entries"
        notes.append(f"{result.baseline_stale} stale baseline {noun} (they match no finding)")
    return notes
