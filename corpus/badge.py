"""Build the public files of a corpus run: a shields.io endpoint badge and an aggregate summary.

    python corpus/badge.py --out DIR [--results DIR] [--labels FILE]

Writes ``DIR/badge.json`` and ``DIR/summary.json``. Only counts are published: no repository names,
no paths, no snippets, no per-repository timings.
"""

from __future__ import annotations

import argparse
import sys
from collections.abc import Sequence
from pathlib import Path
from typing import Any

from check import evaluate, load_run
from common import (
    CORPUS_DIR,
    CorpusError,
    Label,
    latest_results_dir,
    load_labels,
    write_json,
)

PUBLIC_KEYS = ("date", "tier", "ghostrules_version", "repos", "findings", "by_rule", "by_severity")


def public_summary(summary: dict[str, Any], counts: dict[str, int], passed: bool) -> dict[str, Any]:
    """The aggregate numbers that are safe to publish."""
    out = {k: summary[k] for k in PUBLIC_KEYS if k in summary}
    out["unlabelled_critical_high"] = counts.get("unlabelled_blocking", 0)
    out["gate"] = "pass" if passed else "fail"
    return out


def badge(summary: dict[str, Any], passed: bool) -> dict[str, Any]:
    """A shields.io endpoint badge. It states what is measured (critical findings across the
    scanned repositories, and that every critical/high one has been reviewed), not that there are
    no false positives."""
    critical = summary.get("by_severity", {}).get("critical", 0)
    repos = summary.get("repos", 0)
    if not passed:
        return {
            "schemaVersion": 1,
            "label": "corpus",
            "message": "gate failing",
            "color": "red",
        }
    return {
        "schemaVersion": 1,
        "label": "corpus",
        "message": f"{repos} repos · {critical} critical",
        "color": "brightgreen" if critical == 0 else "yellow",
    }


def build(
    results: Path, labels: dict[str, Label], out: Path
) -> tuple[dict[str, Any], dict[str, Any]]:
    """Write ``badge.json`` and ``summary.json`` into ``out`` and return both."""
    run_dir = latest_results_dir(results)
    if run_dir is None:
        raise CorpusError(f"no run found in {results}")
    summary, records = load_run(run_dir)
    crashes, violations, counts = evaluate(records, labels)
    passed = not crashes and not violations
    pub = public_summary(summary, dict(counts), passed)
    shield = badge(summary, passed)
    write_json(out / "summary.json", pub)
    write_json(out / "badge.json", shield)
    return shield, pub


def main(argv: Sequence[str] | None = None) -> int:
    p = argparse.ArgumentParser(description="Write the badge and aggregate summary of a run.")
    p.add_argument("--out", type=Path, required=True)
    p.add_argument("--results", type=Path, default=CORPUS_DIR / "results")
    p.add_argument("--labels", type=Path, default=CORPUS_DIR / "labels.toml")
    args = p.parse_args(argv)
    try:
        shield, _ = build(args.results, load_labels(args.labels), args.out)
    except CorpusError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    print(f"{shield['label']}: {shield['message']} ({shield['color']})")
    return 0


if __name__ == "__main__":
    sys.exit(main())
