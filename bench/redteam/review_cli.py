"""Review the rows of a review CSV one by one in a terminal: ``python review_cli.py review.csv``.

Shows the declared payload, the files and what the judge read; you type 1 (the files hide the
declared instruction and the judge read it) or 0, or ``s`` to skip and ``q`` to quit. Answers are
saved after every row, so you can stop and resume. Run it in your own terminal, not in a Claude
Code session, when the CSV is the test half.
"""

from __future__ import annotations

import base64
import csv
import re
import sys
from pathlib import Path


def hints(files: str) -> list[str]:
    """Mechanical decodings that help to read a row: hidden variation selectors and base64 runs."""
    out = []
    cps = [int(m, 16) for m in re.findall(r"U\+(E01[0-9A-F]{2})", files)]
    if cps:
        out.append("variation selectors: " + "".join(chr(c - 0xE0100 + 16) for c in cps))
    for run in re.findall(r"[A-Za-z0-9+/]{24,}={0,2}", files):
        try:
            text = base64.b64decode(run, validate=True).decode("utf-8")
        except ValueError:
            continue
        out.append(f"base64: {text}  |  reversed: {text[::-1]}")
    return out


def main(path: Path) -> int:
    with path.open(newline="", encoding="utf-8") as fh:
        rows = list(csv.DictReader(fh))
    names = list(rows[0].keys())
    todo = [r for r in rows if (r["human_valid"] or "").strip() not in {"0", "1"}]
    for i, r in enumerate(todo, 1):
        print(f"\n=== {i}/{len(todo)}  {r['id']}  ({r['class']}, {r['technique']})")
        print("DECLARED:", r["declared_payload"])
        print("FILES:\n" + r["files_as_seen"])
        for h in hints(r["files_as_seen"]):
            print("HINT:", h)
        print("JUDGE READ:", r["judge_decoded"])
        while True:
            ans = input("valid? 1 / 0 / s skip / q quit: ").strip().lower()
            if ans in {"0", "1", "s", "q"}:
                break
        if ans == "q":
            break
        if ans in {"0", "1"}:
            r["human_valid"] = ans
            with path.open("w", newline="", encoding="utf-8") as fh:
                w = csv.DictWriter(fh, fieldnames=names)
                w.writeheader()
                w.writerows(rows)
    return 0


if __name__ == "__main__":
    raise SystemExit(main(Path(sys.argv[1])))
