"""Find ``@path`` imports in instruction files, following Claude Code's documented rules.

This only *finds* the tokens. Whether a token resolves to a file, how deep the chain goes and
which agents honour it is the context engine's job (``docs/AGENT_MODELS.md``).

Documented: an import is not parsed inside code spans or fenced code blocks; the path ends at the
first unescaped space (``\\ `` escapes one); a path wrapped in quotes is not imported. The rest is
an approximation, recorded in ``docs/DECISIONS.md``: a certain import has ``@`` at the start of a
line or after whitespace (so ``user@example.com`` is never one); an ``@`` after ``(``, ``[``, ``,``
and similar is a *loose* candidate, flagged so callers can scan it as unverified; trailing sentence
punctuation is not part of the path.
"""

from __future__ import annotations

import re
from bisect import bisect_right
from typing import NamedTuple

from ghostrules.markdown_utils import fenced_blocks, inline_code_spans, strip_html_comments

_QUOTES = "\"'“”‘’"
_LOOSE_BEFORE = "([{<,;:>=|*"
_TRAILING = ".,;:!?)]}>*\"'”’"
_KNOWN_EXTENSION = re.compile(r"\.[A-Za-z0-9]{1,6}$")
_PATH_PREFIXES = ("./", "../", "~/", "/", ".\\", "..\\")


class Import(NamedTuple):
    """An ``@path`` token. ``line``/``column`` are 1-based and point at the ``@``.

    ``path`` is the path with ``\\ `` unescaped; ``raw`` is the token as written, ``@`` included.
    ``certain`` is false for loose candidates; ``in_comment`` is true when the token sits in a
    block-level HTML comment (which Claude Code strips); ``quoted`` marks a path wrapped in quotes,
    which Claude Code does not import.
    """

    path: str
    raw: str
    line: int
    column: int
    end_column: int
    certain: bool = True
    in_comment: bool = False
    quoted: bool = False

    @property
    def looks_like_path(self) -> bool:
        """Whether this is likely meant as a file path rather than a ``@mention`` or an npm scope
        (``@n8n/design-system``): it has a file extension, or starts with ``./``, ``../``, ``~/``
        or ``/``. A path with directories and no extension also counts when its first segment
        exists next to the importing file; the context engine checks that."""
        p = self.path
        return p.startswith(_PATH_PREFIXES) or bool(_KNOWN_EXTENSION.search(p))


def _inside(offset: int, spans: list[tuple[int, int]], starts: list[int]) -> bool:
    index = bisect_right(starts, offset) - 1
    return index >= 0 and spans[index][0] <= offset < spans[index][1]


def _read_token(text: str, at: int) -> tuple[str, str]:
    """``(raw, path)`` of the token whose ``@`` is at ``at``; the path may be empty."""
    j = at + 1
    while j < len(text):
        ch = text[j]
        if ch == "\\" and text[j + 1 : j + 2] == " ":
            j += 2
        elif ch.isspace():
            break
        else:
            j += 1
    raw = text[at:j]
    body = raw[1:]
    while body and body[-1] in _TRAILING:
        if body[-1] == ")" and body.count("(") >= body.count(")"):
            break
        body = body[:-1]
    return "@" + body, body.replace("\\ ", " ")


def find_imports(text: str, *, include_quoted: bool = False) -> list[Import]:
    """Every ``@path`` import token in ``text``, in order.

    Tokens in code spans and fenced code blocks are skipped. Quoted paths are left out unless
    ``include_quoted`` (they are not imported, but rule GR022 reports them).
    """
    blocks = fenced_blocks(text)
    block_spans = [(b.start, b.end) for b in blocks]
    block_starts = [s for s, _ in block_spans]
    code = inline_code_spans(text)
    code_starts = [s for s, _ in code]
    comment_lines = [(r.start_line, r.end_line) for r in strip_html_comments(text).removed]
    line_starts = [0] + [m.end() for m in re.finditer("\n", text)]

    found: list[Import] = []
    for m in re.finditer("@", text):
        at = m.start()
        if _inside(at, block_spans, block_starts) or _inside(at, code, code_starts):
            continue
        before = text[at - 1] if at else "\n"
        quoted = before in _QUOTES
        certain = before.isspace() or at == 0
        if not (certain or quoted or before in _LOOSE_BEFORE):
            continue
        raw, path = _read_token(text, at)
        if not path or path[0] == "@" or (quoted and not include_quoted):
            continue
        line = bisect_right(line_starts, at)
        column = at - line_starts[line - 1] + 1
        found.append(
            Import(
                path=path,
                raw=raw,
                line=line,
                column=column,
                end_column=column + len(raw),
                certain=certain,
                in_comment=any(a <= line <= b for a, b in comment_lines),
                quoted=quoted,
            )
        )
    return found
