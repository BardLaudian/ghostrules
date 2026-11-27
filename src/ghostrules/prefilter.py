"""A keyword prefilter for the regular expressions of the rules.

Most patterns cannot match unless the text holds one of a few literal words (``ghostrules`` in
the GR031 pattern for the scanner, ``environment`` in a secret list). ``keys(pattern)`` reads
those words out of the parsed pattern; a rule asks ``may_match(pattern, folded_text)`` and skips
the regular expression when none of them occurs. The words are a necessary condition only: a
pattern with no usable word (or one this reader does not understand) is always run.
"""

from __future__ import annotations

import importlib
import re
from functools import cache

try:  # Python 3.11+
    _c = importlib.import_module("re._constants")
    _p = importlib.import_module("re._parser")
except ImportError:  # pragma: no cover - Python 3.10
    _c = importlib.import_module("sre_constants")
    _p = importlib.import_module("sre_parse")

_MIN_LENGTH = 3  # a shorter word is in almost every text and saves nothing


def _score(words: frozenset[str]) -> tuple[int, int]:
    return (min(map(len, words)), -len(words))


def _required(items: list) -> frozenset[str] | None:  # type: ignore[type-arg]
    """Words of which every match holds at least one, or ``None`` when nothing is certain."""
    best: frozenset[str] | None = None
    run: list[str] = []

    def consider(words: frozenset[str] | None) -> None:
        nonlocal best
        if words and (best is None or _score(words) > _score(best)):
            best = words

    def flush() -> None:
        if run:
            consider(frozenset({"".join(run).casefold()}))
            run.clear()

    for op, arg in items:
        if op is _c.LITERAL:
            run.append(chr(arg))
            continue
        flush()
        if op is _c.SUBPATTERN:
            consider(_required(list(arg[3])))
        elif op is _c.BRANCH:
            parts = [_required(list(branch)) for branch in arg[1]]
            if all(parts):
                consider(frozenset().union(*parts))  # type: ignore[arg-type]
        elif op in (_c.MAX_REPEAT, _c.MIN_REPEAT) and arg[0] >= 1:
            consider(_required(list(arg[2])))
    flush()
    return best


@cache
def keys(pattern: re.Pattern[str]) -> tuple[str, ...] | None:
    """The words, case-folded, of which a match must hold one; ``None`` for no filter."""
    try:
        words = _required(list(_p.parse(pattern.pattern, pattern.flags)))
    except Exception:  # an unreadable pattern is simply not filtered
        return None
    if not words or min(map(len, words)) < _MIN_LENGTH:
        return None
    return tuple(sorted(words))


def may_match(pattern: re.Pattern[str], folded: str) -> bool:
    """False only when ``folded`` (the case-folded text) cannot hold a match of ``pattern``."""
    words = keys(pattern)
    return words is None or any(w in folded for w in words)
