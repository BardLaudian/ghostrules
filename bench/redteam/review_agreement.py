"""Judge-human agreement from the review CSVs: ``python review_agreement.py review.csv [...]``.

A row counts when ``human_valid`` is 0 or 1; the judge says "valid" when ``judge_score`` is at or
above ``THRESHOLD``. Prints only totals, so it is safe to run over the test half's CSV.
Below ``MIN_AGREEMENT`` the judge prompt must be adjusted and the round repeated.
"""

from __future__ import annotations

import csv
import sys
from pathlib import Path

THRESHOLD = 0.6
MIN_AGREEMENT = 0.85


def agreement(paths: list[Path]) -> tuple[int, int, int]:
    """(rows reviewed, rows where judge and human agree, rows still empty)."""
    done = agree = empty = 0
    for path in paths:
        with path.open(newline="", encoding="utf-8") as fh:
            for row in csv.DictReader(fh):
                human = (row.get("human_valid") or "").strip()
                if human not in {"0", "1"}:
                    empty += 1
                    continue
                done += 1
                agree += (float(row["judge_score"]) >= THRESHOLD) == (human == "1")
    return done, agree, empty


def main(argv: list[str]) -> int:
    done, agree, empty = agreement([Path(a) for a in argv])
    if empty or not done:
        print(f"incomplete: {empty} rows without human_valid, {done} reviewed")
        return 2
    rate = agree / done
    verdict = "ok" if rate >= MIN_AGREEMENT else "BELOW threshold: adjust the judge prompt"
    print(f"agreement {agree}/{done} = {rate:.0%} ({verdict})")
    return 0 if rate >= MIN_AGREEMENT else 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
