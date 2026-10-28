#!/usr/bin/env python3
"""Generate the rules table of docs/RULES.md from the rule registry.

    python scripts/gen_rules_table.py            # print the table
    python scripts/gen_rules_table.py --write    # update docs/RULES.md in place
    python scripts/gen_rules_table.py --check    # exit 1 if docs/RULES.md is out of date

A test runs the same check, so the rule index can never drift from the code.
"""

from __future__ import annotations

import sys
from pathlib import Path

from ghostrules.rules import all_rules

RULES_MD = Path(__file__).resolve().parent.parent / "docs" / "RULES.md"
START = "<!-- rules-table:start -->"
END = "<!-- rules-table:end -->"
_FILES = {"instructions": "instructions", "config": "config", "other": "any file*"}
_ORDER = ("instructions", "config", "other")


def rules_table() -> str:
    """The Markdown table; each ID has an anchor so the SARIF ``helpUri`` (``#gr001``) works."""
    lines = [
        "| ID | Severity | Checks | What it finds |",
        "|---|---|---|---|",
    ]
    for rule in all_rules():
        kinds = ", ".join(_FILES[k] for k in _ORDER if k in rule.applies_to)
        anchor = f'<a id="{rule.id.lower()}"></a>`{rule.id}`'
        text = f"**{rule.title}.** {rule.description}".replace("|", "\\|")
        lines.append(f"| {anchor} | {rule.severity.label} | {kinds} | {text} |")
    return "\n".join(lines)


def replace_block(document: str, table: str) -> str:
    """Return ``document`` with the text between the markers replaced by ``table``."""
    start, end = document.index(START), document.index(END)
    return f"{document[: start + len(START)]}\n{table}\n{document[end:]}"


def main(argv: list[str]) -> int:
    table = rules_table()
    if "--write" in argv or "--check" in argv:
        current = RULES_MD.read_text(encoding="utf-8")
        updated = replace_block(current, table)
        if "--check" in argv:
            if current != updated:
                print("docs/RULES.md is out of date: run scripts/gen_rules_table.py --write")
                return 1
            return 0
        RULES_MD.write_text(updated, encoding="utf-8")
        print("docs/RULES.md updated")
        return 0
    print(table)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
