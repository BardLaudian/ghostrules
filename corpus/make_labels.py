"""Write ``bench/labels-0.6.csv``: the findings that fail the default check, for a person to label.

    python corpus/make_labels.py [--results DIR] [--sample-gr114 150] [--seed 16]

Failing the default check means severity high or critical. Every such finding of every rule goes in,
except GR114, which fires too often for one reviewer: a seeded random sample is taken (the count
of the whole population is written in the ``population`` column, so a per-rule precision can be
scaled back). ``human_label`` is left EMPTY on purpose: tp | fp | dubious.
The context (3 lines each side) is fetched with ``gh api`` for display only; for secret rules
(GR017, GR101, GR021) nothing is fetched, only the already-masked snippet is written.
"""

from __future__ import annotations

import argparse
import csv
import random
import sys
from collections import Counter
from collections.abc import Sequence
from pathlib import Path
from typing import Any

from common import (
    CORPUS_DIR,
    REPO_ROOT,
    CorpusError,
    latest_results_dir,
    read_json,
    safe_text,
    subprocess_runner,
)
from triage import gh_fetch

FAILING = ("critical", "high")
SECRET_RULES = frozenset({"GR017", "GR101", "GR021"})
SAMPLED = "GR114"
OUT = REPO_ROOT / "bench" / "labels-0.6.csv"
COLUMNS = (
    "repo",
    "rule_id",
    "severity",
    "location",
    "snippet",
    "context",
    "population",
    "fingerprint",
    "human_label",
)


def failing_findings(run_dir: Path) -> list[dict[str, Any]]:
    """Every high/critical finding of a run, with its repository and commit."""
    out: list[dict[str, Any]] = []
    for path in sorted(run_dir.glob("*.json")):
        if path.name == "summary.json":
            continue
        record = read_json(path)
        for f in record.get("findings", []):
            if f["severity"] in FAILING:
                out.append({**f, "repo": record["repo"], "sha": record.get("sha", "")})
    return out


def select(
    findings: list[dict[str, Any]], sample: int, seed: int
) -> tuple[list[dict[str, Any]], Counter[str]]:
    """All findings, but a seeded sample of ``SAMPLED``. Returns the rows and the populations."""
    population = Counter(f["rule_id"] for f in findings)
    big = sorted((f for f in findings if f["rule_id"] == SAMPLED), key=lambda f: f["fingerprint"])
    rest = [f for f in findings if f["rule_id"] != SAMPLED]
    picked = random.Random(seed).sample(big, min(sample, len(big)))
    rows = sorted(
        rest + picked, key=lambda f: (f["rule_id"], f["repo"], f["path"], f.get("line") or 0)
    )
    return rows, population


def main(argv: Sequence[str] | None = None) -> int:
    p = argparse.ArgumentParser(description=(__doc__ or "").splitlines()[0])
    p.add_argument("--results", type=Path, default=CORPUS_DIR / "results")
    p.add_argument("--sample-gr114", type=int, default=150)
    p.add_argument("--seed", type=int, default=16)
    p.add_argument("--out", type=Path, default=OUT)
    args = p.parse_args(argv)
    run_dir = latest_results_dir(args.results)
    if run_dir is None:
        raise CorpusError(f"no run found in {args.results}")
    findings = failing_findings(run_dir)
    rows, population = select(findings, args.sample_gr114, args.seed)
    fetch = gh_fetch(subprocess_runner)
    with args.out.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=COLUMNS)
        writer.writeheader()
        for f in rows:
            context = ""
            if f["rule_id"] not in SECRET_RULES:
                context = fetch(f["repo"], f["sha"], f["path"], int(f.get("line") or 1))
            writer.writerow(
                {
                    "repo": f["repo"],
                    "rule_id": f["rule_id"],
                    "severity": f["severity"],
                    "location": f"{f['path']}:{f.get('line')}",
                    "snippet": safe_text(f["snippet"], 300),
                    "context": context,
                    "population": population[f["rule_id"]],
                    "fingerprint": f["fingerprint"],
                    "human_label": "",
                }
            )
    print(f"{len(rows)} rows -> {args.out}; population {dict(population)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
