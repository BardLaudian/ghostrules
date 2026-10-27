"""JSON with comments: tolerant stripping and a parser that records source offsets."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from typing import Any


def strip_jsonc(text: str) -> str:
    """Blank out ``//`` and ``/* */`` comments and trailing commas, outside of strings.

    Characters are replaced by spaces (newlines kept) so offsets, lines and columns still match
    the original text.
    """
    out: list[str] = []
    pending_comma: int | None = None
    in_string = False
    i, n = 0, len(text)
    while i < n:
        ch = text[i]
        if in_string:
            out.append(ch)
            if ch == "\\" and i + 1 < n:
                out.append(text[i + 1])
                i += 1
            elif ch == '"':
                in_string = False
            i += 1
        elif text.startswith("//", i):
            end = text.find("\n", i)
            end = n if end == -1 else end
            out.append(" " * (end - i))
            i = end
        elif text.startswith("/*", i):
            close = text.find("*/", i + 2)
            end = n if close == -1 else close + 2
            out.append("".join(c if c == "\n" else " " for c in text[i:end]))
            i = end
        else:
            if ch in "}]" and pending_comma is not None:
                out[pending_comma] = " "
            if ch == ",":
                pending_comma = len(out)
            elif not ch.isspace():
                pending_comma = None
            in_string = ch == '"'
            out.append(ch)
            i += 1
    return "".join(out)


@dataclass
class JNode:
    """A parsed JSON value with its source span. ``end`` is exclusive.

    ``members`` (objects) maps each key to ``(key_start, value_node)``; ``elements`` holds array
    items. Both are ``None`` for scalars.
    """

    value: Any
    start: int
    end: int
    members: dict[str, tuple[int, JNode]] | None = None
    elements: list[JNode] | None = None

    def get(self, key: str) -> JNode | None:
        """Child node of an object by key."""
        if self.members is None or key not in self.members:
            return None
        return self.members[key][1]

    def string_span(self) -> tuple[int, int]:
        """Span of a string value without its quotes (or the whole node for other scalars)."""
        if isinstance(self.value, str):
            return self.start + 1, max(self.start + 1, self.end - 1)
        return self.start, self.end


_SCALAR_RE = re.compile(r"-?\d+(?:\.\d+)?(?:[eE][+-]?\d+)?|true|false|null")
_MAX_DEPTH = 100


class _Parser:
    def __init__(self, text: str) -> None:
        self.text = text
        self.pos = 1 if text.startswith("\ufeff") else 0

    def _skip_ws(self) -> None:
        while self.pos < len(self.text) and self.text[self.pos] in " \t\r\n":
            self.pos += 1

    def parse(self) -> JNode:
        node = self._value(0)
        self._skip_ws()
        if self.pos != len(self.text):
            raise ValueError("trailing data")
        return node

    def _value(self, depth: int) -> JNode:
        if depth > _MAX_DEPTH:
            raise ValueError("too deep")
        self._skip_ws()
        if self.pos >= len(self.text):
            raise ValueError("unexpected end")
        ch = self.text[self.pos]
        if ch == "{":
            return self._object(depth)
        if ch == "[":
            return self._array(depth)
        if ch == '"':
            start, raw = self.pos, self._raw_string()
            return JNode(json.loads(raw), start, self.pos)
        match = _SCALAR_RE.match(self.text, self.pos)
        if not match:
            raise ValueError("bad value")
        self.pos = match.end()
        return JNode(json.loads(match.group()), match.start(), match.end())

    def _raw_string(self) -> str:
        start = self.pos
        self.pos += 1
        while self.pos < len(self.text):
            ch = self.text[self.pos]
            if ch == "\\":
                self.pos += 2
                continue
            self.pos += 1
            if ch == '"':
                return self.text[start : self.pos]
        raise ValueError("unterminated string")

    def _object(self, depth: int) -> JNode:
        start = self.pos
        self.pos += 1
        members: dict[str, tuple[int, JNode]] = {}
        value: dict[str, Any] = {}
        self._skip_ws()
        if self.text.startswith("}", self.pos):
            self.pos += 1
            return JNode(value, start, self.pos, members=members)
        while True:
            self._skip_ws()
            if not self.text.startswith('"', self.pos):
                raise ValueError("expected key")
            key_start = self.pos
            key = json.loads(self._raw_string())
            self._skip_ws()
            if not self.text.startswith(":", self.pos):
                raise ValueError("expected colon")
            self.pos += 1
            node = self._value(depth + 1)
            members[key] = (key_start, node)
            value[key] = node.value
            self._skip_ws()
            if self.text.startswith(",", self.pos):
                self.pos += 1
            elif self.text.startswith("}", self.pos):
                self.pos += 1
                return JNode(value, start, self.pos, members=members)
            else:
                raise ValueError("expected comma or brace")

    def _array(self, depth: int) -> JNode:
        start = self.pos
        self.pos += 1
        elements: list[JNode] = []
        self._skip_ws()
        if self.text.startswith("]", self.pos):
            self.pos += 1
            return JNode([], start, self.pos, elements=elements)
        while True:
            elements.append(self._value(depth + 1))
            self._skip_ws()
            if self.text.startswith(",", self.pos):
                self.pos += 1
            elif self.text.startswith("]", self.pos):
                self.pos += 1
                return JNode([e.value for e in elements], start, self.pos, elements=elements)
            else:
                raise ValueError("expected comma or bracket")


def parse_located(text: str) -> JNode | None:
    """Parse JSON (comments and trailing commas tolerated) keeping source offsets.

    Offsets refer to ``text`` itself, because comment stripping preserves length. Returns ``None``
    if the text is not valid JSON.
    """
    try:
        return _Parser(strip_jsonc(text)).parse()
    except (ValueError, RecursionError):
        return None
