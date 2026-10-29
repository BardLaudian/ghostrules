"""``ghostrules-ignore`` comments: the marker pattern and the set of ignores a trusted ref had."""

from __future__ import annotations

import re
from collections.abc import Sequence
from dataclasses import dataclass

IGNORE_RE = re.compile(r"ghostrules-ignore(?:\s*:\s*((?:GR\d{3}(?:\s*,\s*)?)+))?", re.IGNORECASE)


def normalise_line(line: str) -> str:
    """A line with its whitespace collapsed: re-indenting a reviewed line does not unreview it."""
    return " ".join(line.split())


@dataclass(frozen=True)
class ReviewedMarks:
    """The inline ignores that already existed in a file at a trusted ref: the normalised lines
    that carry one, and the (marker line, next line) pairs: a marker also covers the next line."""

    marks: frozenset[str] = frozenset()
    pairs: frozenset[tuple[str, str]] = frozenset()


def reviewed_marks(lines: Sequence[str]) -> ReviewedMarks:
    """The ignores present in ``lines`` (a file as it is at the trusted ref)."""
    marks: set[str] = set()
    pairs: set[tuple[str, str]] = set()
    for number, line in enumerate(lines, start=1):
        if IGNORE_RE.search(line):
            marker = normalise_line(line)
            following = normalise_line(lines[number]) if number < len(lines) else ""
            marks.add(marker)
            pairs.add((marker, following))
    return ReviewedMarks(frozenset(marks), frozenset(pairs))
