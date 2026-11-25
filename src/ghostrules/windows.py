"""Split a file that is over the size cap into overlapping windows, so it is still scanned.

A file an agent reads must never be skipped just because it is large: padding it past the cap
would hide whatever follows. Each window is scanned as its own text; the overlap makes sure that
an instruction that straddles a cut is whole in at least one window (up to ``OVERLAP`` bytes long).
"""

from __future__ import annotations

from collections.abc import Iterator
from dataclasses import dataclass

# Largest file the scanner reads at all. Above it the file cannot be scanned and the run fails
# (exit 2) instead of passing quietly. Tests lower it; nothing else does.
HARD_FILE_LIMIT = 16 * 1024 * 1024

# Bytes shared by two neighbouring windows: the longest instruction that is still seen whole.
OVERLAP = 64 * 1024


@dataclass(frozen=True)
class Window:
    """Bytes ``data[start:end]`` and where they sit in the file."""

    start: int
    end: int
    line_offset: int  # newlines before ``start``
    column_offset: int  # characters between the last newline before ``start`` and ``start``


def overlap_for(size: int) -> int:
    """The overlap for windows of ``size`` bytes: ``OVERLAP``, but at most a quarter of a window."""
    return max(1, min(OVERLAP, size // 4))


def split(data: bytes, size: int) -> Iterator[Window]:
    """Yield windows of at most ``size`` bytes that cover ``data`` and overlap by ``overlap_for``.

    A cut falls on a newline when there is one in the last quarter of the window, so most lines
    stay whole; a file made of one huge line is cut anywhere.
    """
    if size <= 0 or len(data) <= size:
        yield Window(0, len(data), 0, 0)
        return
    overlap = overlap_for(size)
    start = 0
    while True:
        end = min(start + size, len(data))
        if end < len(data):
            cut = data.rfind(b"\n", start + size - size // 4, end)
            if cut != -1:
                end = cut + 1
        yield Window(
            start,
            end,
            data.count(b"\n", 0, start),
            start - (data.rfind(b"\n", 0, start) + 1),
        )
        if end >= len(data):
            return
        start = max(start + 1, end - overlap)
