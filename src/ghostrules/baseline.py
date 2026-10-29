"""A baseline of known findings, so a team adopting ghostrules fails only on new ones.

The file lists fingerprints (rule, path and the text of the finding; never its line number, so
moving a line does not break it) plus rule, path and severity for a reviewer. It stores no snippet,
so it cannot carry a secret. Hidden text is never baselined, like it is never suppressed: invisible
characters, GR002, GR030 and anything decoded from hidden characters.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Iterable
from typing import Any

from ghostrules import __version__
from ghostrules.models import Finding

BASELINE_FILENAME = ".ghostrules-baseline.json"
NEVER_BASELINE: frozenset[str] = frozenset({"GR001", "GR002", "GR030"})


class BaselineError(Exception):
    """The baseline file is unreadable or not a baseline."""


def fingerprint(finding: Finding) -> str:
    """Stable id of a finding: rule, path and the (already masked) text, not the position."""
    text = " ".join((finding.snippet or finding.title).split())
    raw = "\0".join((finding.rule_id, finding.path, text))
    return hashlib.sha256(raw.encode("utf-8", "surrogatepass")).hexdigest()[:16]


def can_be_baselined(finding: Finding) -> bool:
    return finding.rule_id not in NEVER_BASELINE and not finding.decoded


def build(findings: Iterable[Finding]) -> dict[str, Any]:
    """The baseline document for ``findings`` (sorted, so it diffs cleanly)."""
    entries = {
        fingerprint(f): {
            "fingerprint": fingerprint(f),
            "rule_id": f.rule_id,
            "path": f.path,
            "severity": f.severity.label,
        }
        for f in findings
    }
    ordered = sorted(entries.values(), key=lambda e: (e["path"], e["rule_id"], e["fingerprint"]))
    return {"version": 1, "generator": f"ghostrules {__version__}", "findings": ordered}


def to_json(document: dict[str, Any]) -> str:
    return json.dumps(document, indent=2, ensure_ascii=False) + "\n"


def parse(text: str) -> frozenset[str]:
    """The fingerprints in a baseline file."""
    try:
        data = json.loads(text)
        entries = data["findings"]
        return frozenset(str(e["fingerprint"]) for e in entries)
    except (ValueError, KeyError, TypeError) as exc:
        raise BaselineError(f"invalid baseline file: {exc}") from None


def apply(findings: list[Finding], known: frozenset[str]) -> tuple[list[Finding], int]:
    """``findings`` without the baselined ones, and how many were left out."""
    kept = [f for f in findings if not can_be_baselined(f) or fingerprint(f) not in known]
    return kept, len(findings) - len(kept)
