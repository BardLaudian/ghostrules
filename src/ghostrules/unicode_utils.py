"""Helpers to classify, render and decode invisible Unicode characters."""

from __future__ import annotations

import re
import unicodedata
from typing import NamedTuple

TAG = "tag"
BIDI = "bidi"
ZERO_WIDTH = "zero_width"
VARIATION_SELECTOR = "variation_selector"

_RANGES: dict[str, tuple[tuple[int, int], ...]] = {
    # "ASCII smuggling": tag characters mirror ASCII at +0xE0000.
    TAG: ((0xE0000, 0xE007F),),
    # "Trojan Source" bidirectional controls and marks.
    BIDI: ((0x202A, 0x202E), (0x2066, 0x2069), (0x200E, 0x200F), (0x061C, 0x061C)),
    ZERO_WIDTH: (
        (0x200B, 0x200D),
        (0x2060, 0x2064),
        (0x180E, 0x180E),
        (0xFEFF, 0xFEFF),
        (0x00AD, 0x00AD),
    ),
    VARIATION_SELECTOR: ((0xFE00, 0xFE0F), (0xE0100, 0xE01EF)),
}

_TAG_BASE = 0xE0000
_TAG_FALLBACK_NAMES = {0xE0001: "LANGUAGE TAG", 0xE007F: "CANCEL TAG"}


def _class_pattern(kind: str) -> re.Pattern[str]:
    body = "".join(f"\\U{lo:08x}-\\U{hi:08x}" for lo, hi in _RANGES[kind])
    return re.compile(f"[{body}]+")


_RUN_PATTERNS = {kind: _class_pattern(kind) for kind in _RANGES}
_INVISIBLE_RE = re.compile(
    "[" + "".join(f"\\U{lo:08x}-\\U{hi:08x}" for r in _RANGES.values() for lo, hi in r) + "]"
)


class Run(NamedTuple):
    """A contiguous run of characters of one invisible class. ``end`` is exclusive."""

    kind: str
    start: int
    end: int


def classify(ch: str) -> str | None:
    """Return the invisible class of a single character, or ``None`` if it is not invisible."""
    cp = ord(ch)
    for kind, ranges in _RANGES.items():
        if any(lo <= cp <= hi for lo, hi in ranges):
            return kind
    return None


def is_tag(ch: str) -> bool:
    """True for Unicode tag characters (U+E0000-U+E007F)."""
    return 0xE0000 <= ord(ch) <= 0xE007F


def find_runs(text: str, kind: str) -> list[Run]:
    """Find all contiguous runs of characters of the given invisible class."""
    return [Run(kind, m.start(), m.end()) for m in _RUN_PATTERNS[kind].finditer(text)]


def char_name(ch: str) -> str:
    """Unicode name of a character, with fallbacks for characters Python leaves unnamed."""
    name = unicodedata.name(ch, "")
    if name:
        return name
    cp = ord(ch)
    if cp in _TAG_FALLBACK_NAMES:
        return _TAG_FALLBACK_NAMES[cp]
    if is_tag(ch):
        return "TAG CHARACTER"
    return "UNNAMED CHARACTER"


def render_char(ch: str, *, with_name: bool = True) -> str:
    """Render one character as ``⟦U+200B ZERO WIDTH SPACE⟧`` (or ``⟦U+200B⟧``)."""
    label = f"U+{ord(ch):04X}"
    return f"⟦{label} {char_name(ch)}⟧" if with_name else f"⟦{label}⟧"


def render_invisible(text: str, *, with_name: bool = True) -> str:
    """Replace every invisible character in ``text`` with a visible ``⟦U+XXXX NAME⟧`` token."""
    return _INVISIBLE_RE.sub(lambda m: render_char(m.group(), with_name=with_name), text)


def decode_tags(text: str) -> str:
    """Decode tag characters back to the ASCII they smuggle (``chr(cp - 0xE0000)``).

    Non-tag characters are ignored. The tag-block control characters (language tag, cancel tag)
    and non-printable ASCII are dropped; tab, newline and carriage return are kept.
    """
    out: list[str] = []
    for ch in text:
        if not is_tag(ch):
            continue
        value = ord(ch) - _TAG_BASE
        if 0x20 <= value < 0x7F or value in (0x09, 0x0A, 0x0D):
            out.append(chr(value))
    return "".join(out)


def is_mostly_printable(text: str, threshold: float = 0.85) -> bool:
    """True if at least ``threshold`` of the characters are printable (or tab/newline)."""
    if not text:
        return False
    printable = sum(1 for ch in text if ch.isprintable() or ch in "\t\n\r")
    return printable / len(text) >= threshold


def decode_variation_selectors(text: str) -> str | None:
    """Decode variation-selector steganography into text, or ``None`` if it is not text.

    U+FE00-U+FE0F encode bytes 0-15 and U+E0100-U+E01EF encode bytes 16-255. The bytes must
    form (mostly) printable UTF-8 to be reported as decoded text.
    """
    data = bytearray()
    for ch in text:
        cp = ord(ch)
        if 0xFE00 <= cp <= 0xFE0F:
            data.append(cp - 0xFE00)
        elif 0xE0100 <= cp <= 0xE01EF:
            data.append(cp - 0xE0100 + 16)
    if not data:
        return None
    try:
        decoded = data.decode("utf-8")
    except UnicodeDecodeError:
        return None
    return decoded if is_mostly_printable(decoded) else None
