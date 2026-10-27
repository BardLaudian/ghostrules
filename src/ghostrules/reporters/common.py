"""Helpers shared by the reporters (no ``render`` here: this is not a reporter)."""

from __future__ import annotations

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


def safe(text: str) -> str:
    """Replace lone surrogates (from undecodable input bytes) so output can always be encoded."""
    return text.encode("utf-8", errors="replace").decode("utf-8")


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
    return notes
