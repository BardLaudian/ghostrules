"""Deterministic dev/test split by hash of the case id; the test half is kept outside the repo.

    python bench/redteam/split.py 001 cases.toml

``dev`` cases go to bench/redteam/rounds/001/dev.toml (committed; the defender may read them).
``test`` cases go to $GHOSTRULES_REDTEAM_TEST_DIR (default ~/.cache/ghostrules-redteam-test), which
is denied to every subagent in .claude/settings.json and watched by the audit.
"""

from __future__ import annotations

import hashlib
import sys
from pathlib import Path
from typing import Any

from redteam_common import ROUNDS, dump_cases, load_toml, test_dir
from schema import validate_round

TEST_SHARE = 50  # percent of the ids that go to the test set


def side(case_id: str) -> str:
    """``dev`` or ``test``: a pure function of the id, so a case never changes side."""
    digest = hashlib.sha256(case_id.encode("utf-8")).digest()
    return "test" if digest[0] * 100 // 256 < TEST_SHARE else "dev"


def split_cases(cases: list[dict[str, Any]]) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    dev = [c for c in cases if side(c["id"]) == "dev"]
    test = [c for c in cases if side(c["id"]) == "test"]
    return dev, test


def write_split(
    round_id: str, cases: list[dict[str, Any]], rounds: Path = ROUNDS
) -> tuple[Path, Path]:
    problems = validate_round(cases)
    if problems:
        raise ValueError("invalid cases: " + "; ".join(problems[:5]))
    out = test_dir()  # fail before writing anything if it is not outside the repository
    dev, test = split_cases(cases)
    dev_path = rounds / round_id / "dev.toml"
    dev_path.parent.mkdir(parents=True, exist_ok=True)
    dev_path.write_text(dump_cases(dev, f"Round {round_id}: dev cases"), encoding="utf-8")
    out.mkdir(parents=True, exist_ok=True, mode=0o700)
    test_path = out / f"round-{round_id}-test.toml"
    test_path.write_text(dump_cases(test, f"Round {round_id}: test cases"), encoding="utf-8")
    return dev_path, test_path


def main(argv: list[str] | None = None) -> int:
    args = sys.argv[1:] if argv is None else argv
    if len(args) != 2:
        print("usage: split.py ROUND_ID CASES.toml", file=sys.stderr)
        return 2
    cases = load_toml(Path(args[1])).get("case", [])
    dev_path, test_path = write_split(args[0], cases, ROUNDS)
    dev, test = split_cases(cases)
    # Counts only: what is in the test half is not printed.
    print(f"dev {len(dev)} -> {dev_path}; test {len(test)} stored")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
