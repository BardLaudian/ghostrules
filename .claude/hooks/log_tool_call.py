#!/usr/bin/env python3
"""PreToolUse hook: append every tool call to a JSONL log for bench/redteam/audit_blind.py.

Reads the hook payload from stdin; writes ``{"tool_name", "tool_input"}`` to the file named by
``GHOSTRULES_REDTEAM_LOG`` (default ``.claude/redteam-calls.jsonl``). It never blocks a call and
never prints: a failure to log must not stop the work, and the audit treats a missing log as an
unaudited round.
"""

import json
import os
import sys


def main() -> int:
    try:
        payload = json.load(sys.stdin)
        entry = {"tool_name": payload.get("tool_name"), "tool_input": payload.get("tool_input", {})}
        path = os.environ.get("GHOSTRULES_REDTEAM_LOG", ".claude/redteam-calls.jsonl")
        with open(path, "a", encoding="utf-8") as log:
            log.write(json.dumps(entry) + "\n")
    except Exception:  # noqa: BLE001 - logging is best effort
        pass
    return 0


if __name__ == "__main__":
    sys.exit(main())
