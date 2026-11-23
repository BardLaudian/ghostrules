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
from dataclasses import dataclass
from datetime import datetime, timezone
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


def build(findings: Iterable[Finding], today: str | None = None) -> dict[str, Any]:
    """The baseline document for ``findings`` (sorted, so it diffs cleanly).

    ``created`` is the UTC date it was written and ``count`` the number of entries, so a reviewer
    can see how old a baseline is and how much it hides without reading it.
    """
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
    return {
        "version": 1,
        "generator": f"ghostrules {__version__}",
        "created": today or datetime.now(timezone.utc).date().isoformat(),
        "count": len(ordered),
        "findings": ordered,
    }


def to_json(document: dict[str, Any]) -> str:
    return json.dumps(document, indent=2, ensure_ascii=False) + "\n"


@dataclass(frozen=True)
class BaselineInfo:
    """What a baseline file says about itself (``created`` and ``generator`` may be absent in
    files written before 0.5)."""

    fingerprints: frozenset[str]
    created: str | None = None
    generator: str | None = None


def load(text: str) -> BaselineInfo:
    """Parse a baseline file: its fingerprints, date and the version that wrote it."""
    try:
        data = json.loads(text)
        entries = data["findings"]
        fingerprints = frozenset(str(e["fingerprint"]) for e in entries)
        created, generator = data.get("created"), data.get("generator")
    except (ValueError, KeyError, TypeError, AttributeError) as exc:
        raise BaselineError(f"invalid baseline file: {exc}") from None
    return BaselineInfo(
        fingerprints,
        created if isinstance(created, str) else None,
        generator if isinstance(generator, str) else None,
    )


def parse(text: str) -> frozenset[str]:
    """The fingerprints in a baseline file."""
    return load(text).fingerprints


def stale(info: BaselineInfo, findings: Iterable[Finding]) -> int:
    """Entries that match no current finding: the text changed, or the file or finding is gone.

    Such an entry hides nothing today but would silently hide the finding if it came back, so a
    baseline with stale entries should be regenerated.
    """
    current = {fingerprint(f) for f in findings}
    return len(info.fingerprints - current)


def stale_warning(info: BaselineInfo, count: int) -> str:
    """The warning shown when ``count`` entries are stale."""
    written = f" (written {info.created})" if info.created else ""
    return (
        f"baseline{written} is stale: {count} of {len(info.fingerprints)} entries no longer "
        "match any finding; regenerate it with 'ghostrules baseline' after reviewing what changed"
    )


def apply(findings: list[Finding], known: frozenset[str]) -> tuple[list[Finding], int]:
    """``findings`` without the baselined ones, and how many were left out."""
    kept = [f for f in findings if not can_be_baselined(f) or fingerprint(f) not in known]
    return kept, len(findings) - len(kept)
