"""``ghostrules reveal``: show a file with its invisible characters made visible."""

from __future__ import annotations

from rich.console import Group, RenderableType
from rich.padding import Padding
from rich.text import Text

from ghostrules.reporters.table import styled_decoded
from ghostrules.reveal_data import COMMENT, INVISIBLE, Line, has_hidden_content, lines

__all__ = ["build", "has_hidden_content"]

_TOKEN_STYLE = "bold white on red3"
_COMMENT_STYLE = "black on yellow"
_STYLES = {INVISIBLE: _TOKEN_STYLE, COMMENT: _COMMENT_STYLE}


def _line_text(line: Line) -> Text:
    out = Text()
    for seg in line.segments:
        out.append(seg.text, style=_STYLES.get(seg.kind, ""))
    return out


def _decoded_row(source: str, decoded: str) -> RenderableType:
    label = Text.assemble(("     ↳ Decoded hidden text", "bold red"), (f" ({source}): ", "dim"))
    return Text.assemble(label, styled_decoded(decoded))


def build(text: str) -> RenderableType:
    """Numbered listing of ``text``; secrets are masked like everywhere else."""
    rows: list[RenderableType] = []
    for line in lines(text):
        rows.append(Text.assemble((f"{line.number:>4} │ ", "dim"), _line_text(line)))
        rows.extend(Padding(_decoded_row(src, dec), (0, 0, 0, 0)) for src, dec in line.decoded)
    return Group(*rows)
