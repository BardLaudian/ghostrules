#!/usr/bin/env python3
"""Print the CHANGELOG.md section of one version (used to write GitHub release notes).

Usage: python scripts/changelog_section.py VERSION [CHANGELOG.md]
VERSION may be given as ``0.1.0`` or ``v0.1.0``. Exits 1 if the section is missing or empty, so
a release cannot be published without release notes.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

DEFAULT_FILE = Path(__file__).resolve().parent.parent / "CHANGELOG.md"


def section(changelog: str, version: str) -> str | None:
    """Body of ``## [VERSION]`` up to the next ``## [`` heading, stripped; ``None`` if absent."""
    version = version.removeprefix("v")
    heading = re.compile(rf"^## \[{re.escape(version)}\](?:\s.*)?$", re.MULTILINE)
    match = heading.search(changelog)
    if match is None:
        return None
    rest = changelog[match.end() :]
    following = re.search(r"^## \[", rest, re.MULTILINE)
    body = rest[: following.start()] if following else rest
    return body.strip() or None


def main(argv: list[str]) -> int:
    if len(argv) < 2:
        print(__doc__, file=sys.stderr)
        return 2
    path = Path(argv[2]) if len(argv) > 2 else DEFAULT_FILE
    body = section(path.read_text(encoding="utf-8"), argv[1])
    if body is None:
        print(
            f"error: no non-empty '## [{argv[1].removeprefix('v')}]' section in {path}",
            file=sys.stderr,
        )
        return 1
    print(body)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
