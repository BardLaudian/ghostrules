"""Helpers shared by rule implementations: snippets and ``Finding`` construction."""

from __future__ import annotations

import re
import shlex
from collections import defaultdict
from collections.abc import Iterable

from ghostrules.models import Finding, ScanTarget, Severity
from ghostrules.unicode_utils import render_invisible


def make_snippet(
    line: str,
    start: int,
    end: int,
    *,
    context: int = 30,
    limit: int = 8,
    with_name: bool = False,
) -> str:
    """Render the part of ``line`` at ``[start, end)`` with some context, invisibles made visible.

    The matched part is cut to ``limit`` characters (``…(+N more)``) so a long hidden payload
    cannot flood the output; surrounding context is rendered without names.
    """
    middle = line[start:end]
    shown = render_invisible(middle[:limit], with_name=with_name)
    if len(middle) > limit:
        shown += f"…(+{len(middle) - limit} more)"
    before = render_invisible(line[max(0, start - context) : start], with_name=False)
    after = render_invisible(line[end : end + context], with_name=False)
    lead = "…" if start > context else ""
    trail = "…" if end + context < len(line) else ""
    return f"{lead}{before}{shown}{after}{trail}"


def build_finding(
    *,
    target: ScanTarget,
    rule_id: str,
    severity: Severity,
    title: str,
    message: str,
    start: int,
    end: int,
    decoded: str | None = None,
    fix_hint: str = "",
    limit: int = 8,
    with_name: bool = False,
) -> Finding:
    """Build a ``Finding`` for the text at offsets ``[start, end)`` of the target.

    Line/column point at ``start`` (1-based, code points). ``end_column`` is exclusive and is
    clamped to the end of the first line when the match spans several lines.
    """
    line, column = target.position(start)
    text_line = target.lines[line - 1]
    last_line, last_column = target.position(max(end - 1, start))
    end_column = last_column + 1 if last_line == line else len(text_line) + 1
    snippet = make_snippet(text_line, column - 1, end_column - 1, limit=limit, with_name=with_name)
    return Finding(
        rule_id=rule_id,
        severity=severity,
        title=title,
        message=message,
        path=target.path,
        line=line,
        column=column,
        end_column=end_column,
        snippet=snippet,
        decoded=decoded or None,
        fix_hint=fix_hint,
    )


def group_by_line(target: ScanTarget, offsets: Iterable[int]) -> dict[int, list[int]]:
    """Group character offsets by their 1-based line number (offsets stay in order)."""
    grouped: dict[int, list[int]] = defaultdict(list)
    for offset in offsets:
        grouped[target.position(offset)[0]].append(offset)
    return dict(grouped)


def clean_hint(target: ScanTarget) -> str:
    """Standard remediation for invisible characters."""
    return f"Remove the invisible characters: ghostrules clean {shlex.quote(target.path)} --write"


_URL_HOST_RE = re.compile(r"https?://(?:[^/?#\s@]*@)?([^/?#\s:)\]>]+)", re.IGNORECASE)


def host_allowed(host: str, allow_domains: Iterable[str]) -> bool:
    """True if ``host`` is an allowed domain or a subdomain of one."""
    host = host.lower().rstrip(".")
    return any(host == d or host.endswith("." + d) for d in allow_domains)


def urls_allowed(text: str, allow_domains: Iterable[str]) -> bool:
    """True if ``text`` contains URLs and every one of them points at an allowed domain."""
    allow = tuple(allow_domains)
    hosts = _URL_HOST_RE.findall(text)
    return bool(allow and hosts and all(host_allowed(h, allow) for h in hosts))
