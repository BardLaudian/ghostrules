"""Glob matching shared by every agent model (``paths``, ``globs``, ``applyTo``).

Semantics, from Claude Code's rule documentation: patterns are relative to a base directory, ``*``
and ``?`` stay inside one path segment, ``**/`` matches any number of directories, ``{a,b}`` expands
(bounded by a budget of 1,000 patterns; over it the braces stay literal and match nothing useful),
``[abc]`` is a character class, ``\\`` escapes. A pattern with a ``[`` that cannot be read as a
class is invalid and matches nothing. Paths are matched as POSIX strings: backslashes in the
*path* are converted, so Windows paths work.
"""

from __future__ import annotations

import re
from functools import lru_cache

BRACE_BUDGET = 1000


def normalize_path(path: str) -> str:
    """POSIX form of a relative path: ``\\`` becomes ``/``, a leading ``./`` is dropped."""
    path = path.replace("\\", "/")
    while path.startswith("./"):
        path = path[2:]
    return path


def _split_group(pattern: str, start: int) -> tuple[int | None, list[str]]:
    """For the ``{`` at ``start``: index of its closing ``}`` and its top-level alternatives."""
    depth = 0
    parts: list[str] = []
    last = start + 1
    i = start
    while i < len(pattern):
        ch = pattern[i]
        if ch == "\\":
            i += 2
            continue
        if ch == "{":
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0:
                parts.append(pattern[last:i])
                return i, parts
        elif ch == "," and depth == 1:
            parts.append(pattern[last:i])
            last = i + 1
        i += 1
    return None, []


def _expand(pattern: str, counter: list[int]) -> list[str]:
    i = 0
    while i < len(pattern):
        ch = pattern[i]
        if ch == "\\":
            i += 2
            continue
        if ch == "{":
            end, parts = _split_group(pattern, i)
            if end is not None and len(parts) > 1:
                out: list[str] = []
                for part in parts:
                    out.extend(_expand(pattern[:i] + part + pattern[end + 1 :], counter))
                    if counter[0] > BRACE_BUDGET:
                        return [pattern]
                return out
        i += 1
    counter[0] += 1
    return [pattern]


def expand_braces(pattern: str) -> list[str]:
    """Expand ``{a,b}`` groups (nested too). ``{x}`` with no comma is literal. If the result would
    exceed the budget, the pattern is returned unexpanded."""
    counter = [0]
    expanded = _expand(pattern, counter)
    return [pattern] if counter[0] > BRACE_BUDGET else expanded


def _class_end(pattern: str, start: int) -> int | None:
    """Index of the ``]`` closing the class opened at ``start``, or ``None``."""
    i = start + 1
    if i < len(pattern) and pattern[i] in "!^":
        i += 1
    if i < len(pattern) and pattern[i] == "]":
        i += 1  # a leading ] is literal
    while i < len(pattern):
        if pattern[i] == "\\":
            i += 2
            continue
        if pattern[i] == "]":
            return i
        i += 1
    return None


def _to_regex(pattern: str) -> str | None:
    """Regex source for one brace-free glob, or ``None`` if the glob is invalid."""
    out: list[str] = []
    i = 0
    n = len(pattern)
    while i < n:
        ch = pattern[i]
        at_segment_start = i == 0 or pattern[i - 1] == "/"
        if ch == "\\":
            out.append(re.escape(pattern[i + 1] if i + 1 < n else "\\"))
            i += 2
        elif pattern.startswith("**", i) and at_segment_start and pattern[i + 2 : i + 3] == "/":
            out.append("(?:.*/)?")
            i += 3
        elif pattern.startswith("**", i) and at_segment_start and i + 2 == n:
            out.append(".*")
            i += 2
        elif ch == "*":
            out.append("[^/]*")
            i += 1
            while i < n and pattern[i] == "*":  # a stray ** inside a name behaves like *
                i += 1
        elif ch == "?":
            out.append("[^/]")
            i += 1
        elif ch == "[":
            end = _class_end(pattern, i)
            if end is None:
                return None
            body = pattern[i + 1 : end]
            negate = body[:1] in ("!", "^")
            body = body[1:] if negate else body
            body = body.replace("\\", "\\\\").replace("[", "\\[")
            out.append(f"(?!/)[{'^' if negate else ''}{body}]")
            i = end + 1
        else:
            out.append(re.escape(ch))
            i += 1
    return "".join(out)


@lru_cache(maxsize=2048)
def _compiled(pattern: str, ignore_case: bool) -> tuple[re.Pattern[str], ...]:
    flags = re.IGNORECASE if ignore_case else 0
    compiled: list[re.Pattern[str]] = []
    for single in expand_braces(pattern):
        source = _to_regex(single)
        if source is not None:
            try:
                compiled.append(re.compile(source, flags | re.DOTALL))
            except re.error:
                continue
    return tuple(compiled)


def matches_glob(pattern: str, path: str, *, ignore_case: bool = False) -> bool:
    """Whether ``path`` (relative to the pattern's base directory) matches the glob."""
    path = normalize_path(path)
    return any(rx.fullmatch(path) for rx in _compiled(pattern.strip(), ignore_case))


def matches_any(patterns: list[str], path: str, *, ignore_case: bool = False) -> bool:
    """Whether ``path`` matches at least one of the globs."""
    return any(matches_glob(p, path, ignore_case=ignore_case) for p in patterns)


def split_patterns(value: str | list[str]) -> list[str]:
    """Patterns from a ``paths``/``globs``/``applyTo`` value: a list as is, or a comma-separated
    string split on commas that are not inside braces."""
    if isinstance(value, list):
        return [v.strip() for v in value if v.strip()]
    parts: list[str] = []
    depth = 0
    current: list[str] = []
    i = 0
    while i < len(value):
        ch = value[i]
        if ch == "\\" and i + 1 < len(value):
            current.append(value[i : i + 2])
            i += 2
            continue
        if ch == "{":
            depth += 1
        elif ch == "}":
            depth = max(depth - 1, 0)
        if ch == "," and depth == 0:
            parts.append("".join(current))
            current = []
        else:
            current.append(ch)
        i += 1
    parts.append("".join(current))
    return [p.strip() for p in parts if p.strip()]
