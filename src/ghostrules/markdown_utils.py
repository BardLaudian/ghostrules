"""Small Markdown helpers shared by rules (fenced code block detection)."""

from __future__ import annotations

import re
from typing import NamedTuple

_OPEN_RE = re.compile(r"^ {0,3}(`{3,}|~{3,})(.*)$")


class FencedBlock(NamedTuple):
    """A fenced code block. ``start``/``end`` are character offsets (end exclusive) covering the
    fence lines too; ``lang`` is the first word of the info string (lower-case, may be empty)."""

    start: int
    end: int
    lang: str


def fenced_blocks(text: str) -> list[FencedBlock]:
    """Find fenced code blocks. An unterminated fence runs to the end of the text, as it does
    when rendered."""
    blocks: list[FencedBlock] = []
    offset = 0
    open_fence: tuple[str, int, int, str] | None = None  # (char, length, start, lang)
    for raw in text.split("\n"):
        line = raw.removesuffix("\r")
        line_end = offset + len(raw) + 1
        if open_fence is None:
            match = _OPEN_RE.match(line)
            if match and not (match.group(1)[0] == "`" and "`" in match.group(2)):
                info = match.group(2).strip().split()
                lang = info[0].lower() if info else ""
                open_fence = (match.group(1)[0], len(match.group(1)), offset, lang)
        else:
            char, length, start, lang = open_fence
            stripped = line.strip()
            indent = len(line) - len(line.lstrip(" "))
            if indent <= 3 and len(stripped) >= length and set(stripped) == {char}:
                blocks.append(FencedBlock(start, min(line_end, len(text)), lang))
                open_fence = None
        offset = line_end
    if open_fence is not None:
        blocks.append(FencedBlock(open_fence[2], len(text), open_fence[3]))
    return blocks
