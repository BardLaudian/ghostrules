"""Audit the tool-call log: any access to the held-out test set invalidates the round.

    python bench/redteam/audit_blind.py LOG.jsonl

The log is written by .claude/hooks/log_tool_call.py, one JSON object per line with ``tool_name``
and ``tool_input``. A call is flagged when any string in its input names a ``rounds/**/test/``
path, the external test directory or a ``round-NNN-test`` file. This is a net, not a wall: a shell
command can build a path the audit does not recognise, which is why the deny rules, the blind
prompts and the human review of the round PR all stay. Exit 0: clean. Exit 1: flagged. Exit 2:
no log (an unaudited round is not a clean round).
"""

from __future__ import annotations

import json
import re
import sys
from collections.abc import Iterator
from pathlib import Path
from typing import Any

from redteam_common import DEFAULT_TEST_DIR, TEST_DIR_ENV

PATTERNS = (
    re.compile(r"rounds/[^\s\"']*/test(/|\b)"),
    re.compile(r"round-\d+-test"),
    re.compile(r"ghostrules-redteam-test"),
    re.compile(re.escape(TEST_DIR_ENV)),
    re.compile(re.escape(str(DEFAULT_TEST_DIR))),
)


def _strings(value: Any) -> Iterator[str]:
    if isinstance(value, str):
        yield value
    elif isinstance(value, dict):
        for item in value.values():
            yield from _strings(item)
    elif isinstance(value, list):
        for item in value:
            yield from _strings(item)


def audit_lines(lines: list[str], extra: tuple[str, ...] = ()) -> list[dict[str, Any]]:
    """Return the flagged calls: line number, tool and the text that matched."""
    flagged: list[dict[str, Any]] = []
    extra_patterns = tuple(re.compile(re.escape(e)) for e in extra if e)
    for number, line in enumerate(lines, start=1):
        if not line.strip():
            continue
        try:
            entry = json.loads(line)
        except json.JSONDecodeError:
            flagged.append({"line": number, "tool": "?", "why": "unreadable log line"})
            continue
        for text in _strings(entry.get("tool_input", {})):
            hit = next((p for p in (*PATTERNS, *extra_patterns) if p.search(text)), None)
            if hit:
                flagged.append(
                    {"line": number, "tool": entry.get("tool_name", "?"), "why": hit.pattern}
                )
                break
    return flagged


def audit_file(path: Path, extra: tuple[str, ...] = ()) -> list[dict[str, Any]] | None:
    """None when there is no log to audit."""
    if not path.is_file():
        return None
    return audit_lines(path.read_text(encoding="utf-8").splitlines(), extra)


def main(argv: list[str] | None = None) -> int:
    args = sys.argv[1:] if argv is None else argv
    if len(args) != 1:
        print("usage: audit_blind.py LOG.jsonl", file=sys.stderr)
        return 2
    flagged = audit_file(Path(args[0]))
    if flagged is None:
        print(f"no log at {args[0]}: the round cannot be audited", file=sys.stderr)
        return 2
    print(json.dumps({"clean": not flagged, "flagged": flagged}, indent=1))
    return 1 if flagged else 0


if __name__ == "__main__":
    raise SystemExit(main())
