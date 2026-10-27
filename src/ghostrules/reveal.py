"""``ghostrules reveal``: show a file with its invisible characters made visible."""

from __future__ import annotations

import re

from rich.console import Group, RenderableType
from rich.padding import Padding
from rich.text import Text

from ghostrules.reporters.common import safe
from ghostrules.reporters.table import styled_decoded
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
_TOKEN_STYLE = "bold white on red3"
_COMMENT_STYLE = "black on yellow"
_VS_MIN_RUN = 3


def _is_invisible(ch: str) -> bool:
    return classify(ch) is not None or ch == "\u00ad"


def _comment_offsets(text: str) -> set[int]:
    inside: set[int] = set()
    for match in _COMMENT_RE.finditer(text):
        inside.update(range(match.start(), match.end()))
    return inside


def _line_text(line: str, base: int, comments: set[int]) -> Text:
    out = Text()
    for i, ch in enumerate(line):
        if _is_invisible(ch):
            # Tag characters and variation selectors come in long runs: names would drown them.
            named = classify(ch) not in (TAG, VARIATION_SELECTOR)
            out.append(render_char(ch, with_name=named), style=_TOKEN_STYLE)
        else:
            out.append(ch, style=_COMMENT_STYLE if base + i in comments else "")
    return out


def _hidden_lines(line: str) -> list[RenderableType]:
    """Decoded ASCII for tag characters, and bytes hidden in variation selectors."""
    found: list[RenderableType] = []
    for run in find_runs(line, TAG):
        decoded = decode_tags(line[run.start : run.end])
        if decoded:
            found.append(_decoded_row("tag characters", mask_secrets(decoded)))
    for run in find_runs(line, VARIATION_SELECTOR):
        if run.end - run.start >= _VS_MIN_RUN:
            decoded_vs = decode_variation_selectors(line[run.start : run.end])
            if decoded_vs:
                found.append(_decoded_row("variation selectors", mask_secrets(decoded_vs)))
    return found


def _decoded_row(source: str, decoded: str) -> RenderableType:
    label = Text.assemble(("     ↳ Decoded hidden text", "bold red"), (f" ({source}): ", "dim"))
    return Text.assemble(label, styled_decoded(decoded))


def build(text: str) -> RenderableType:
    """Numbered listing of ``text``; secrets are masked like everywhere else."""
    text = safe(mask_secrets(text))
    comments = _comment_offsets(text)
    rows: list[RenderableType] = []
    offset = 0
    for number, raw in enumerate(text.split("\n"), start=1):
        line = raw.removesuffix("\r")
        row = Text.assemble((f"{number:>4} │ ", "dim"), _line_text(line, offset, comments))
        rows.append(row)
        rows.extend(Padding(extra, (0, 0, 0, 0)) for extra in _hidden_lines(line))
        offset += len(raw) + 1
    return Group(*rows)


def has_hidden_content(text: str) -> bool:
    """Whether the text contains invisible characters or HTML comments."""
    return any(_is_invisible(ch) for ch in text) or _COMMENT_RE.search(text) is not None
