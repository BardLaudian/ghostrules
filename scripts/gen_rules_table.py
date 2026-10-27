#!/usr/bin/env python3
"""Generate the rules table of the README from the rule registry.

    python scripts/gen_rules_table.py            # print the table
    python scripts/gen_rules_table.py --write    # update README.md in place
    python scripts/gen_rules_table.py --check    # exit 1 if README.md is out of date

A test runs the same check, so the README can never drift from the code.
"""

from __future__ import annotations

import sys
from pathlib import Path

from ghostrules.rules import all_rules

README = Path(__file__).resolve().parent.parent / "README.md"
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


def replace_block(readme: str, table: str) -> str:
    """Return ``readme`` with the text between the markers replaced by ``table``."""
    start, end = readme.index(START), readme.index(END)
    return f"{readme[: start + len(START)]}\n{table}\n{readme[end:]}"


def main(argv: list[str]) -> int:
    table = rules_table()
    if "--write" in argv or "--check" in argv:
        current = README.read_text(encoding="utf-8")
        updated = replace_block(current, table)
        if "--check" in argv:
            if current != updated:
                print(
                    "README.md rules table is out of date: run scripts/gen_rules_table.py --write"
                )
                return 1
            return 0
        README.write_text(updated, encoding="utf-8")
        print("README.md updated")
        return 0
    print(table)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
