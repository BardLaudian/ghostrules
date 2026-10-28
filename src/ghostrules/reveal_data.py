"""The data behind ``ghostrules reveal``: lines split into visible and invisible segments.

No ``rich`` here, so the core (and the browser playground) can use it. Secrets are masked.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from ghostrules.reporters.common import safe
from ghostrules.secrets import mask_secrets
from ghostrules.unicode_utils import (
    TAG,
    VARIATION_SELECTOR,
    classify,
    decode_tags,
    decode_variation_selectors,
    find_runs,
    render_char,
)

_COMMENT_RE = re.compile(r"<!--.*?(?:-->|\Z)", re.DOTALL)
_VS_MIN_RUN = 3

PLAIN, INVISIBLE, COMMENT = "plain", "invisible", "comment"


@dataclass(frozen=True)
class Segment:
    """A run of one kind: ``plain`` text, an ``invisible`` character shown as a token, or text
    inside an HTML ``comment``."""

    kind: str
    text: str


@dataclass
class Line:
    """One numbered line, its segments and the text hidden in it (``(source, decoded)``)."""

    number: int
    segments: list[Segment]
    decoded: list[tuple[str, str]] = field(default_factory=list)


def is_invisible(ch: str) -> bool:
    """Whether ``ch`` is shown as a token (an invisible character or a soft hyphen)."""
    return classify(ch) is not None or ch == "\u00ad"


def comment_offsets(text: str) -> set[int]:
    """Offsets of every character inside an HTML comment."""
    inside: set[int] = set()
    for match in _COMMENT_RE.finditer(text):
        inside.update(range(match.start(), match.end()))
    return inside


def segments(line: str, base: int, comments: set[int]) -> list[Segment]:
    """Split one line; ``base`` is its offset in the whole text. Adjacent plain/comment characters
    are merged. Tag characters and variation selectors come in long runs, so they carry no name."""
    out: list[Segment] = []
    for i, ch in enumerate(line):
        if is_invisible(ch):
            named = classify(ch) not in (TAG, VARIATION_SELECTOR)
            kind, text = INVISIBLE, render_char(ch, with_name=named)
        else:
            kind, text = (COMMENT if base + i in comments else PLAIN), ch
        if out and out[-1].kind == kind and kind != INVISIBLE:
            out[-1] = Segment(kind, out[-1].text + text)
        else:
            out.append(Segment(kind, text))
    return out


def hidden_text(line: str) -> list[tuple[str, str]]:
    """Decoded ASCII of tag characters and bytes hidden in variation selectors, secrets masked."""
    found: list[tuple[str, str]] = []
    for run in find_runs(line, TAG):
        decoded = decode_tags(line[run.start : run.end])
        if decoded:
            found.append(("tag characters", mask_secrets(decoded)))
    for run in find_runs(line, VARIATION_SELECTOR):
        if run.end - run.start >= _VS_MIN_RUN:
            decoded_vs = decode_variation_selectors(line[run.start : run.end])
            if decoded_vs:
                found.append(("variation selectors", mask_secrets(decoded_vs)))
    return found


def lines(text: str) -> list[Line]:
    """The numbered lines of ``text`` (secrets masked), each with its segments and hidden text."""
    text = safe(mask_secrets(text))
    comments = comment_offsets(text)
    out: list[Line] = []
    offset = 0
    for number, raw in enumerate(text.split("\n"), start=1):
        line = raw.removesuffix("\r")
        out.append(Line(number, segments(line, offset, comments), hidden_text(line)))
        offset += len(raw) + 1
    return out


def has_hidden_content(text: str) -> bool:
    """Whether the text contains invisible characters or HTML comments."""
    return any(is_invisible(ch) for ch in text) or _COMMENT_RE.search(text) is not None
