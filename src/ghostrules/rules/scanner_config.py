"""GR030: the change under review touches the scanner's own configuration."""

from __future__ import annotations

import difflib
from collections.abc import Iterator
from pathlib import Path
from typing import Any

from ghostrules._compat import tomllib
from ghostrules.baseline import BASELINE_FILENAME
from ghostrules.changeset import ChangeContext
from ghostrules.config import CONFIG_FILENAME
from ghostrules.ignores import IGNORE_RE, normalise_line, reviewed_marks
from ghostrules.models import Finding, Severity
from ghostrules.rules.registry import change_rule

_TITLE = "Scanner configuration changed"
_CONFIG_MESSAGE = (
    "{name} was {how}{keys}. It decides what the scanner excludes, disables or ignores; the change "
    "is reported even when it is legitimate, so a reviewer always reads it."
)


def _head_text(root: Path, rel: str) -> str | None:
    try:
        path = root / rel
        return path.read_text(encoding="utf-8", errors="replace") if path.is_file() else None
    except OSError:
        return None


def _first_changed_line(base: str | None, head: str) -> int:
    """1-based line of ``head`` where it first differs from ``base`` (1 when ``base`` is empty)."""
    old, new = (base or "").splitlines(), head.splitlines()
    for tag, _i1, _i2, j1, _j2 in difflib.SequenceMatcher(None, old, new).get_opcodes():
        if tag != "equal":
            return min(j1 + 1, max(len(new), 1))
    return 1


def _table(text: str | None, *, tool: bool) -> dict[str, Any] | None:
    """The TOML table of a config (the whole file, or ``[tool.ghostrules]`` of a pyproject)."""
    if text is None:
        return {}
    try:
        data = tomllib.loads(text)
    except tomllib.TOMLDecodeError:
        return None
    if tool:
        found = data.get("tool", {}).get("ghostrules")
        return found if isinstance(found, dict) else {}
    return data


def _changed_keys(base: dict[str, Any] | None, head: dict[str, Any] | None) -> str:
    if base is None or head is None:
        return ""
    keys = sorted(k for k in {*base, *head} if base.get(k) != head.get(k))
    return f" (changed: {', '.join(keys)})" if keys else ""


def _finding(path: str, line: int, message: str, snippet: str, hint: str) -> Finding:
    return Finding(
        rule_id="GR030",
        severity=Severity.HIGH,
        title=_TITLE,
        message=message,
        path=path,
        line=line,
        column=1,
        end_column=max(2, len(snippet) + 1),
        snippet=snippet,
        fix_hint=hint,
    )


def _snippet(text: str, line: int) -> str:
    lines = text.splitlines()
    return lines[line - 1].strip()[:200] if 0 < line <= len(lines) else ""


def _config_findings(ctx: ChangeContext) -> Iterator[Finding]:
    read_base = ctx.base.config
    base_ref = ctx.base.config_ref
    hint = f"Review the diff against {base_ref}; merge it only if someone accountable approved it."
    for rel, tool in ((CONFIG_FILENAME, False), ("pyproject.toml", True)):
        head, base = _head_text(ctx.root, rel), read_base(rel)
        if head is None or head == base:
            continue
        old, new = _table(base, tool=tool), _table(head, tool=tool)
        if tool and old == new:
            continue  # the rest of a pyproject is none of our business
        added = (not old) if tool else base is None
        how = "added" if added else "edited"
        line = _first_changed_line(base, head)
        if tool:  # point at the table, not at whatever else in the file moved
            line = next(
                (n for n, ln in enumerate(head.splitlines(), 1) if "tool.ghostrules" in ln), line
            )
        message = _CONFIG_MESSAGE.format(
            name=f"[tool.ghostrules] in {rel}" if tool else rel,
            how=how,
            keys=_changed_keys(old, new),
        )
        yield _finding(rel, line, message, _snippet(head, line), hint)
    baseline_head, baseline_base = (
        _head_text(ctx.root, BASELINE_FILENAME),
        read_base(BASELINE_FILENAME),
    )
    if baseline_head is not None and baseline_head != baseline_base:
        how = "added" if baseline_base is None else "edited"
        line = _first_changed_line(baseline_base, baseline_head)
        message = (
            f"The baseline {BASELINE_FILENAME} was {how}. It lists findings the scan no longer "
            "reports; the change is reported even when it is legitimate."
        )
        yield _finding(
            BASELINE_FILENAME, line, message, "", f"Check every new entry against {base_ref}."
        )
    lock = ctx.lockfile
    head, base = _head_text(ctx.root, lock), read_base(lock)
    if head is not None and head != base:
        how = "added" if base is None else "edited"
        line = _first_changed_line(base, head)
        message = (
            f"The lockfile {lock} was {how}. Its diff is the list of what the agents now read; "
            "the change is reported even when it is legitimate."
        )
        yield _finding(lock, line, message, _snippet(head, line), f"Compare with {base_ref}.")


def _ignore_findings(ctx: ChangeContext) -> Iterator[Finding]:
    for label, target in ctx.targets.items():
        markers = [n for n, ln in enumerate(target.lines, 1) if IGNORE_RE.search(ln)]
        if not markers:
            continue
        base = ctx.base.ignores(label)
        reviewed = reviewed_marks(base.splitlines()).marks if base is not None else frozenset()
        for number in markers:
            line = target.lines[number - 1]
            if normalise_line(line) in reviewed:
                continue
            yield _finding(
                label,
                number,
                "A ghostrules-ignore comment was added or edited. It silences the findings on its "
                "line and the next; the change is reported even when it is legitimate.",
                line.strip()[:200],
                f"Check that it hides nothing real; compare with {ctx.base.ignores_ref}.",
            )


@change_rule(
    "GR030",
    Severity.HIGH,
    _TITLE,
    "The change adds or edits .ghostrules.toml, [tool.ghostrules], the lockfile or a "
    "ghostrules-ignore comment. Reported even when legitimate, so a reviewer always sees it. "
    "Needs a base: --config-from-ref or --suppressions-from-ref.",
)
def gr030_scanner_config_changed(ctx: ChangeContext) -> Iterator[Finding]:
    """Config, lockfile and ignore comments that differ from the trusted base."""
    yield from _config_findings(ctx)
    yield from _ignore_findings(ctx)
