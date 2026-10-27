#!/usr/bin/env python3
"""Replace the ``OWNER`` placeholder in repository URLs with your GitHub user or organisation.

    python scripts/set_owner.py YOUR-GITHUB-NAME [--dry-run]

The README, SECURITY.md, CONTRIBUTING.md, the SARIF help links (``PROJECT_URL``), the issue-form
contact link and the PyPI project URLs all point at ``https://github.com/OWNER/ghostrules`` until
you run this once, before publishing. It only touches text files and is safe to run twice.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

PLACEHOLDER = "OWNER/ghostrules"
ROOT = Path(__file__).resolve().parent.parent
SKIP_DIRS = {".git", ".venv", "node_modules", "__pycache__", "dist", "build"}
SKIP_PREFIXES = ("tests/", "examples/")  # the tests use the placeholder as test data
# GitHub user and organisation names: alphanumerics and single hyphens, at most 39 characters.
_VALID_OWNER = re.compile(r"^(?!-)(?!.*--)[A-Za-z0-9-]{1,39}(?<!-)$")


def candidate_files(root: Path) -> list[Path]:
    """Text files that may contain the placeholder."""
    found = []
    for path in sorted(root.rglob("*")):
        rel = path.relative_to(root).as_posix()
        if not path.is_file() or SKIP_DIRS & set(path.relative_to(root).parts):
            continue
        if rel.startswith(SKIP_PREFIXES) or rel == "scripts/set_owner.py":
            continue
        found.append(path)
    return found


def apply(root: Path, owner: str, *, dry_run: bool = False) -> list[str]:
    """Replace the placeholder under ``root``; returns the relative paths that changed."""
    if not _VALID_OWNER.match(owner):
        raise ValueError(f"{owner!r} is not a valid GitHub user or organisation name")
    changed = []
    for path in candidate_files(root):
        try:
            text = path.read_bytes().decode("utf-8")
        except UnicodeDecodeError:
            continue
        if PLACEHOLDER not in text:
            continue
        changed.append(path.relative_to(root).as_posix())
        if not dry_run:
            path.write_bytes(text.replace(PLACEHOLDER, f"{owner}/ghostrules").encode("utf-8"))
    return changed


def main(argv: list[str]) -> int:
    args = [a for a in argv[1:] if not a.startswith("--")]
    if len(args) != 1:
        print(__doc__, file=sys.stderr)
        return 2
    try:
        changed = apply(ROOT, args[0], dry_run="--dry-run" in argv)
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    verb = "would change" if "--dry-run" in argv else "updated"
    print(f"{verb} {len(changed)} file(s):" + "".join(f"\n  {name}" for name in changed))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
