"""``ghostrules clean``: remove the invisible characters the unicode rules flag."""

from __future__ import annotations

import difflib
from dataclasses import dataclass

from ghostrules.rules.unicode import removable
from ghostrules.secrets import mask_secrets
from ghostrules.unicode_utils import render_invisible


@dataclass(frozen=True)
class CleanResult:
    """Outcome of cleaning a text."""

    original: str
    cleaned: str
    removed: int
    kept_bidi: int

    @property
    def changed(self) -> bool:
        return self.original != self.cleaned


def clean_text(text: str, *, keep_bom: bool = False) -> CleanResult:
    """Remove exactly the characters GR001-GR004 flag (see ``rules.unicode.removable``)."""
    removal = removable(text, keep_bom=keep_bom)
    drop = set(removal.offsets)
    cleaned = "".join(ch for i, ch in enumerate(text) if i not in drop)
    return CleanResult(text, cleaned, len(drop), removal.kept_bidi)


def unified_diff(result: CleanResult, name: str) -> str:
    """Unified diff of the change. Invisible characters are shown as tokens so the removed
    ones are actually visible, and secrets are masked."""
    old = result.original.splitlines(keepends=True)
    new = result.cleaned.splitlines(keepends=True)
    diff = difflib.unified_diff(old, new, fromfile=name, tofile=f"{name} (cleaned)")
    return mask_secrets(render_invisible("".join(diff), with_name=False))
