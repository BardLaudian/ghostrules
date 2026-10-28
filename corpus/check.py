"""The regression gate: compare the latest corpus run with ``labels.toml``.

    python corpus/check.py [--results DIR] [--labels FILE]

Exit 0: pass. Exit 1: a finding broke the gate. Exit 2: a scan crashed or there is nothing to check.
Prints a markdown table (also appended to ``$GITHUB_STEP_SUMMARY`` when that is set).
"""

from __future__ import annotations

import argparse
import os
import sys
from collections import Counter
from collections.abc import Sequence
from pathlib import Path
from typing import Any

from common import (
    CORPUS_DIR,
    LABELS,
    REPO_ROOT,
    SEVERITIES,
    CorpusError,
    Label,
    latest_results_dir,
    load_labels,
    read_json,
    safe_text,
    test_exists,
)

BLOCKING = ("critical", "high")
CRASHED = ("scan_failed", "context_failed", "timeout")


def rank(severity: str) -> int:
    """Higher is more severe; unknown severities rank below ``info``."""
    return len(SEVERITIES) - SEVERITIES.index(severity) if severity in SEVERITIES else 0


def load_run(run_dir: Path) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    """The summary and every per-repository record of a run."""
    summary = read_json(run_dir / "summary.json")
    records = [read_json(p) for p in sorted(run_dir.glob("*.json")) if p.name != "summary.json"]
    return summary, records


def evaluate(
    records: list[dict[str, Any]],
    labels: dict[str, Label],
    repo_root: Path = REPO_ROOT,
) -> tuple[list[str], list[str], Counter[str]]:
    """Return ``(crashes, violations, counts)``. Messages never name a repository together with a
    finding: they carry the fingerprint, which is what ``triage.py`` accepts."""
    crashes = [
        f"{safe_text(r['repo'], 80)}: {r['status']}" for r in records if r["status"] in CRASHED
    ]
    violations: list[str] = []
    counts: Counter[str] = Counter()
    for known in labels.values():
        if known.label == "fp" and (not known.test or not test_exists(known.test, repo_root)):
            violations.append(f"{known.fingerprint}: fp label without an existing test")
    for record in records:
        for f in record.get("findings", []):
            fp, sev = f["fingerprint"], f["severity"]
            label = labels.get(fp)
            if label is None:
                counts["unlabelled"] += 1
                if sev in BLOCKING:
                    counts["unlabelled_blocking"] += 1
                    violations.append(f"{fp}: unlabelled {sev} {f['rule_id']} finding")
                continue
            counts[label.label] += 1
            if label.label == "fp" and (not label.severity or rank(sev) >= rank(label.severity)):
                violations.append(f"{fp}: false positive still reported at {sev} ({f['rule_id']})")
    return crashes, violations, counts


def render(
    summary: dict[str, Any], counts: Counter[str], crashes: list[str], violations: list[str]
) -> str:
    """The markdown report."""
    sev = summary.get("by_severity", {})
    lines = [
        f"## Corpus check — {summary.get('tier', '?')} · {summary.get('date', '?')}",
        "",
        f"ghostrules {summary.get('ghostrules_version', '?')} · "
        f"{summary.get('repos', 0)} repos · {summary.get('findings', 0)} findings",
        "",
        "| Severity | Findings |",
        "|---|---:|",
        *(f"| {s} | {sev.get(s, 0)} |" for s in SEVERITIES),
        "",
        "| Label | Findings |",
        "|---|---:|",
        *(f"| {k} | {counts.get(k, 0)} |" for k in ("unlabelled", *LABELS)),
        "",
        f"Clone failures (not a gate): {summary.get('status', {}).get('clone_failed', 0)}",
        "",
    ]
    if crashes:
        lines += ["**Crashed scans**", "", *(f"- {c}" for c in crashes), ""]
    if violations:
        lines += ["**Violations**", "", *(f"- {v}" for v in violations), ""]
    lines.append("**FAIL**" if crashes or violations else "**PASS**")
    return "\n".join(lines) + "\n"


def main(argv: Sequence[str] | None = None) -> int:
    p = argparse.ArgumentParser(description="Gate the latest corpus run against labels.toml.")
    p.add_argument("--results", type=Path, default=CORPUS_DIR / "results")
    p.add_argument("--labels", type=Path, default=CORPUS_DIR / "labels.toml")
    args = p.parse_args(argv)
    try:
        run_dir = latest_results_dir(args.results)
        if run_dir is None:
            raise CorpusError(f"no run found in {args.results}")
        summary, records = load_run(run_dir)
        crashes, violations, counts = evaluate(records, load_labels(args.labels))
    except CorpusError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    report = render(summary, counts, crashes, violations)
    print(report, end="")
    step_summary = os.environ.get("GITHUB_STEP_SUMMARY")
    if step_summary:
        with open(step_summary, "a", encoding="utf-8") as handle:
            handle.write(report)
    if crashes:
        return 2
    return 1 if violations else 0


if __name__ == "__main__":
    sys.exit(main())
