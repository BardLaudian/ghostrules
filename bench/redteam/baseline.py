"""Baseline per attack class: `python bench/redteam/baseline.py` prints the Markdown table.

Reads bench/attacks/ through bench/lib.py (the same runner as `bench/run.py attacks`) and the
class of each technique from bench/redteam/taxonomy.toml. Nothing here is tuned to the cases.
"""

from __future__ import annotations

import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))

from lib import Outcome, load_cases, run_attacks, share  # noqa: E402

from ghostrules._compat import tomllib  # noqa: E402

TAXONOMY = HERE / "taxonomy.toml"
COMMAND = "python bench/redteam/baseline.py"


def load_taxonomy() -> dict[str, dict]:
    return tomllib.loads(TAXONOMY.read_text(encoding="utf-8"))


def class_of(technique: str, taxonomy: dict[str, dict]) -> str | None:
    entry = taxonomy["technique"].get(technique)
    return entry["class"] if entry else None


def table(outcomes: list[Outcome], taxonomy: dict[str, dict]) -> str:
    rows = []
    for key, info in sorted(taxonomy["class"].items()):
        mine = [o for o in outcomes if class_of(o.case.technique, taxonomy) == key]
        detected = sum(o.reported for o in mine)
        fails = sum(o.fails_ci for o in mine)
        rows.append(
            f"| {key} {info['name']} | {len(mine)} | {share(detected, len(mine))} "
            f"| {share(fails, len(mine))} |"
        )
    head = "| Class | Cases | Reported | Fails the default check |\n|---|---|---|---|"
    return "\n".join([head, *rows])


def main() -> None:
    taxonomy = load_taxonomy()
    outcomes = run_attacks(load_cases())
    print(table(outcomes, taxonomy))


if __name__ == "__main__":
    main()
