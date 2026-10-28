"""Small Markdown helpers shared by rules and the context engine.

Fenced code blocks and inline code spans, a tiny YAML front matter parser (no PyYAML at runtime),
and the two transforms agents apply before injecting a file: stripping block-level HTML comments
and stripping front matter. Both transforms keep a map from the new line numbers back to the
original ones, so findings in transformed text can still point at the real file.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import NamedTuple

_BOM = chr(0xFEFF)

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


_INLINE_CODE_RE = re.compile(r"(?<!`)(`+)(?!`)(.+?)(?<!`)\1(?!`)")


def inline_code_spans(text: str) -> list[tuple[int, int]]:
    """Spans (start, end offsets) of inline code such as ``<!-- x -->``. A span never crosses a
    line, and an unmatched backtick does not open one."""
    spans: list[tuple[int, int]] = []
    offset = 0
    for raw in text.split("\n"):
        spans.extend((offset + m.start(), offset + m.end()) for m in _INLINE_CODE_RE.finditer(raw))
        offset += len(raw) + 1
    return spans


# --- text transforms --------------------------------------------------------------------------


class RemovedBlock(NamedTuple):
    """A block a transform took out. Lines are 1-based and refer to the original text."""

    kind: str  # "html_comment" | "frontmatter"
    start_line: int
    end_line: int
    text: str


@dataclass(frozen=True)
class Stripped:
    """Text after a transform, plus where each of its lines came from.

    ``line_map[i]`` is the original 1-based line of line ``i + 1`` of ``text``.
    """

    text: str
    line_map: tuple[int, ...]
    removed: tuple[RemovedBlock, ...] = ()
    unterminated_lines: tuple[int, ...] = ()

    def original_line(self, line: int) -> int:
        """Original line number of a 1-based line of the transformed text."""
        if not self.line_map:
            return line
        return self.line_map[min(max(line, 1), len(self.line_map)) - 1]


def _fenced_line_flags(lines: list[str], text: str) -> list[bool]:
    """For each line, whether it lies inside (or on the fence lines of) a fenced code block."""
    blocks = fenced_blocks(text)
    flags: list[bool] = []
    offset = 0
    for raw in lines:
        flags.append(any(b.start <= offset < b.end for b in blocks))
        offset += len(raw) + 1
    return flags


_COMMENT_OPEN = re.compile(r"^ {0,3}<!--")


def strip_html_comments(text: str) -> Stripped:
    """Remove block-level HTML comments, as Claude Code does for ``CLAUDE.md`` files.

    A block-level comment starts a line (up to three spaces of indent) with ``<!--`` and runs to the
    line holding ``-->`` (CommonMark HTML block, type 2). Text after ``-->`` on that line is kept.
    Comments inside fenced code blocks, inside a paragraph or a list item, and comments that never
    close are left alone, so a payload is never assumed hidden on a guess.
    """
    lines = text.split("\n")
    fenced = _fenced_line_flags(lines, text)
    kept: list[str] = []
    line_map: list[int] = []
    removed: list[RemovedBlock] = []
    unterminated: list[int] = []
    i = 0
    while i < len(lines):
        line = lines[i]
        match = None if fenced[i] else _COMMENT_OPEN.match(line)
        if match is None:
            kept.append(line)
            line_map.append(i + 1)
            i += 1
            continue
        start_col = line.index("<!--")
        end_index, end_col = _find_comment_end(lines, i, start_col + 4)
        if end_index is None:
            unterminated.append(i + 1)
            kept.append(line)
            line_map.append(i + 1)
            i += 1
            continue
        pieces = [lines[k] for k in range(i, end_index + 1)]
        pieces[0] = pieces[0][start_col:]
        pieces[-1] = (
            lines[end_index][: end_col + 3] if end_index != i else line[start_col : end_col + 3]
        )
        removed.append(RemovedBlock("html_comment", i + 1, end_index + 1, "\n".join(pieces)))
        rest = lines[end_index][end_col + 3 :]
        if rest.strip():
            lines[end_index] = rest.lstrip()
            i = end_index  # reprocess the remainder: it may open another comment
            fenced[i] = False
            # the remainder keeps the end line's number
            continue
        i = end_index + 1
    return Stripped("\n".join(kept), tuple(line_map), tuple(removed), tuple(unterminated))


def _find_comment_end(lines: list[str], first: int, col: int) -> tuple[int | None, int]:
    """Line index and column of the ``-->`` closing a comment opened on ``lines[first]``."""
    index = lines[first].find("-->", col)
    if index != -1:
        return first, index
    for k in range(first + 1, len(lines)):
        index = lines[k].find("-->")
        if index != -1:
            return k, index
    return None, -1


# --- YAML front matter --------------------------------------------------------------------------

FrontValue = str | bool | list[str]


class Frontmatter(NamedTuple):
    """Parsed front matter. ``unparsed`` is set when any line was outside the supported subset;
    ``data`` still holds everything that did parse (bad scalars are kept as raw strings)."""

    data: dict[str, FrontValue]
    unparsed: bool
    problems: tuple[str, ...]
    end_line: int  # 1-based line of the closing fence
    body_offset: int  # character offset of the first body line


_FENCE_OPEN = re.compile(r"^---[ \t]*$")
_FENCE_CLOSE = re.compile(r"^(?:---|\.\.\.)[ \t]*$")
_KEY = re.compile(r"^([A-Za-z_][\w.\-]*)[ \t]*:(?:[ \t]+(.*))?$")
_LIST_ITEM = re.compile(r"^[ \t]*-(?:[ \t]+(.*))?$")
_TRAILING_COMMENT = re.compile(r"[ \t]+#.*$")
_PLAIN_BAD_START = "*&!|>{[%@`"


def parse_frontmatter(text: str) -> Frontmatter | None:
    """Parse YAML front matter at the very top of ``text``; ``None`` if there is none.

    Only the subset agents' rule files use is understood: ``key: value``, ``key: [a, b]``, block
    lists (``- item``), quoted strings and ``true``/``false``. Anything else (nesting, multi-line
    scalars, anchors, a plain value such as ``**/*.ts`` that strict YAML rejects) is reported in
    ``problems`` and sets ``unparsed``, because a strict parser would fail on it too.
    """
    base = 1 if text.startswith(_BOM) else 0
    lines = text[base:].split("\n")
    if not _FENCE_OPEN.match(lines[0].removesuffix("\r")):
        return None
    close = next(
        (n for n in range(1, len(lines)) if _FENCE_CLOSE.match(lines[n].removesuffix("\r"))),
        None,
    )
    if close is None:
        return None
    data, problems = _parse_block(lines[1:close])
    body_offset = base + sum(len(line) + 1 for line in lines[: close + 1])
    return Frontmatter(
        data, bool(problems), tuple(problems), close + 1, min(body_offset, len(text))
    )


def _parse_block(lines: list[str]) -> tuple[dict[str, FrontValue], list[str]]:
    data: dict[str, FrontValue] = {}
    problems: list[str] = []
    i = 0
    while i < len(lines):
        raw = lines[i].removesuffix("\r")
        number = i + 2  # line 1 is the opening fence
        i += 1
        stripped = raw.strip()
        if not stripped or stripped.startswith("#"):
            continue
        if raw[0] in " \t":
            problems.append(f"line {number}: unexpected indentation")
            continue
        match = _KEY.match(raw)
        if match is None:
            problems.append(f"line {number}: not a 'key: value' line")
            continue
        key, value = match.group(1), _TRAILING_COMMENT.sub("", match.group(2) or "").strip()
        if value.startswith("#"):
            value = ""
        if value == "":
            items, i = _block_list(lines, i, problems)
            data[key] = items if items is not None else ""
        elif value.startswith("["):
            data[key] = _flow_list(value, number, problems)
        else:
            data[key] = _scalar(match.group(2) or "", number, problems)
    return data, problems


def _block_list(lines: list[str], start: int, problems: list[str]) -> tuple[list[str] | None, int]:
    """Items of a ``- item`` list starting at ``lines[start]`` and the index after it."""
    items: list[str] = []
    i = start
    while i < len(lines):
        raw = lines[i].removesuffix("\r")
        stripped = raw.strip()
        if not stripped or stripped.startswith("#"):
            i += 1
            continue
        match = _LIST_ITEM.match(raw)
        if match is None:
            if raw[0] in " \t":  # nested structure under the key
                problems.append(f"line {i + 2}: nested values are not supported")
                i += 1
                continue
            break
        value = _scalar(match.group(1) or "", i + 2, problems)
        items.append(value if isinstance(value, str) else str(value).lower())
        i += 1
    return (items or None), i


def _flow_list(value: str, number: int, problems: list[str]) -> list[str]:
    match = re.match(r"^\[(.*)\][ \t]*(?:#.*)?$", value)
    if match is None:
        problems.append(f"line {number}: unterminated or multi-line [list]")
        return [value]
    items: list[str] = []
    for part in _split_commas(match.group(1)):
        if not part.strip():
            continue
        item = _scalar(part, number, problems)
        items.append(item if isinstance(item, str) else str(item).lower())
    return items


def _split_commas(inner: str) -> list[str]:
    parts: list[str] = []
    quote = ""
    current: list[str] = []
    for ch in inner:
        if quote:
            current.append(ch)
            if ch == quote:
                quote = ""
        elif ch in "\"'":
            quote = ch
            current.append(ch)
        elif ch == ",":
            parts.append("".join(current))
            current = []
        else:
            current.append(ch)
    parts.append("".join(current))
    return parts


def _scalar(text: str, number: int, problems: list[str]) -> str | bool:
    """One scalar: quoted string, boolean or plain text. Bad input is kept raw and reported."""
    value = text.strip()
    if value[:1] in ("'", '"'):
        quote = value[0]
        out: list[str] = []
        i = 1
        while i < len(value):
            ch = value[i]
            if quote == '"' and ch == "\\" and i + 1 < len(value) and value[i + 1] in '"\\':
                out.append(value[i + 1])
                i += 2
            elif quote == "'" and value[i : i + 2] == "''":
                out.append("'")
                i += 2
            elif ch == quote:
                tail = value[i + 1 :].strip()
                if tail and not tail.startswith("#"):
                    problems.append(f"line {number}: text after the closing quote")
                    return value
                return "".join(out)
            else:
                out.append(ch)
                i += 1
        problems.append(f"line {number}: unterminated quoted string")
        return value
    value = _TRAILING_COMMENT.sub("", value).strip()
    if value.lower() in ("true", "false"):
        return value.lower() == "true"
    if value[:1] and value[0] in _PLAIN_BAD_START:
        problems.append(f"line {number}: plain value starting with {value[0]!r} needs quotes")
    elif ": " in value or value.endswith(":"):
        problems.append(f"line {number}: ': ' inside a plain value needs quotes")
    return value


def strip_frontmatter(text: str) -> Stripped:
    """Remove the front matter block, as Claude Code does for rule files."""
    front = parse_frontmatter(text)
    if front is None:
        lines = text.split("\n")
        return Stripped(text, tuple(range(1, len(lines) + 1)))
    lines = text.split("\n")
    kept = lines[front.end_line :]
    removed = RemovedBlock("frontmatter", 1, front.end_line, text[: front.body_offset])
    return Stripped("\n".join(kept), tuple(range(front.end_line + 1, len(lines) + 1)), (removed,))
