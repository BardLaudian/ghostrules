#!/usr/bin/env python3
"""Recall on the attack set and precision on the held-out set (docs/design/v0.4, W6).

    python bench/run.py attacks                 # recall per technique, misses listed
    python bench/run.py heldout [--workers 4]   # clone, scan and print findings per rule
    python bench/run.py report                  # both, with the labels of bench/heldout-labels.toml

``heldout`` clones the repositories of ``bench/heldout.toml`` shallowly (the only networked step),
scans them with the default settings and an empty configuration, and keeps the findings in
``bench/.cache`` (ignored by git: it holds snippets of third-party files). Never tune a rule on the
held-out set: it exists to be reported on. Nothing a repository contains is executed.
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
import tempfile
from collections.abc import Sequence
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Any

import tomllib

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import lib  # noqa: E402

CACHE = HERE / ".cache"
LABELS_FILE = HERE / "heldout-labels.toml"


def fingerprint(f: dict[str, Any]) -> str:
    """The id ghostrules baseline uses, from a finding's JSON form."""
    from ghostrules.baseline import fingerprint as fp
    from ghostrules.models import Finding, Severity

    return fp(
        Finding(
            f["rule_id"],
            Severity.parse(f["severity"]),
            f["title"],
            f["message"],
            f["path"],
            f["line"],
            f["column"],
            f["end_column"],
            f["snippet"],
        )  # fmt: skip
    )


def attacks_report(outcomes: list[lib.Outcome]) -> str:
    rows = lib.recall_table(outcomes)
    by_rule = lib.recall_by_rule(outcomes)
    total = len(outcomes)
    reported = sum(o.reported for o in outcomes)
    fails = sum(o.fails_ci for o in outcomes)
    detected = [o for o in outcomes if o.case.status == "detected"]
    lines = [
        "| Technique | Cases | Reported | Fails the default check |",
        "|---|---:|---:|---:|",
        *(f"| {r['technique']} | {r['cases']} | {r['reported']} | {r['fails_ci']} |" for r in rows),
        f"| **All** | {total} | {reported} ({reported / total:.0%}) | {fails} ({fails / total:.0%}) |",
        "",
        f"{len(detected)} of {total} cases are detected and {total - len(detected)} are known misses.",
        "",
        "| Rule | Cases naming it | Reported | Fails the default check |",
        "|---|---:|---:|---:|",
        *(f"| {r['rule']} | {r['cases']} | {r['reported']} | {r['fails_ci']} |" for r in by_rule),
        "",
        "Known misses:",
        "",
    ]
    for o in outcomes:
        if not o.reported:
            lines.append(
                f"- `{o.case.id}` ({o.case.technique}, {o.case.origin}): {o.case.note or o.case.description}"
            )
    return "\n".join(lines) + "\n"


def clone_and_scan(name: str, work: Path, empty: Path) -> dict[str, Any]:
    env = {
        **os.environ,
        "GIT_TERMINAL_PROMPT": "0",
        "GIT_LFS_SKIP_SMUDGE": "1",
        "GIT_ASKPASS": "true",
    }
    clone = Path(tempfile.mkdtemp(prefix="heldout-", dir=work)) / "repo"
    try:
        done = subprocess.run(
            ["git", "clone", "--depth", "1", "--filter=blob:limit=2m", "--no-tags", "--single-branch",
             "--quiet", "--", f"https://github.com/{name}.git", str(clone)],
            capture_output=True, text=True, env=env, timeout=600, check=False,
        )  # fmt: skip
        if done.returncode != 0:
            return {"repo": name, "status": "clone_failed"}
        scan = subprocess.run(
            [sys.executable, "-c", "from ghostrules.cli import app; app()", "scan", str(clone),
             "--format", "json",
             "--fail-on", "none", "--config", str(empty), "--no-color"],
            capture_output=True, text=True, timeout=900, check=False,
        )  # fmt: skip
        try:
            data = json.loads(scan.stdout)
        except ValueError:
            return {"repo": name, "status": "scan_failed"}
        findings = [{**f, "fingerprint": fingerprint(f)} for f in data["findings"]]
        return {"repo": name, "status": "ok", "files": data["scanned_files"], "findings": findings}
    finally:
        shutil.rmtree(clone.parent, ignore_errors=True)


def run_heldout(workers: int) -> Path:
    repos = [r["name"] for r in tomllib.loads((HERE / "heldout.toml").read_text("utf-8"))["repo"]]
    CACHE.mkdir(exist_ok=True)
    work = Path(tempfile.mkdtemp(prefix="bench-", dir=CACHE))
    empty = work / "empty.toml"
    empty.write_text("", encoding="utf-8")
    try:
        with ThreadPoolExecutor(max_workers=workers) as pool:
            results = list(pool.map(lambda n: clone_and_scan(n, work, empty), repos))
    finally:
        shutil.rmtree(work, ignore_errors=True)
    (CACHE / "heldout-findings.json").write_text(json.dumps(results), encoding="utf-8")
    out = HERE / "heldout-results.json"
    out.write_text(json.dumps(aggregate(results), indent=2) + "\n", encoding="utf-8")
    return out


def load_labels() -> dict[str, str]:
    if not LABELS_FILE.exists():
        return {}
    data = tomllib.loads(LABELS_FILE.read_text(encoding="utf-8"))
    return {entry["fingerprint"]: entry["label"] for entry in data.get("label", [])}


def aggregate(results: list[dict[str, Any]]) -> dict[str, Any]:
    """What may be committed: counts and fingerprints, never repository names, paths or snippets."""
    import datetime as dt

    from ghostrules import __version__

    ok = [r for r in results if r["status"] == "ok"]
    shown = [f for r in ok for f in r["findings"] if f["severity"] != "info"]  # shown by default
    return {
        "date": dt.date.today().isoformat(),
        "ghostrules_version": __version__,
        "commit": subprocess.run(
            ["git", "-C", str(HERE), "rev-parse", "--short", "HEAD"],
            capture_output=True,
            text=True,
            check=False,
        ).stdout.strip(),
        "repos_total": len(results),
        "repos_scanned": len(ok),
        "files_scanned": sum(r["files"] for r in ok),
        "repos_failing_default_check": sum(
            1 for r in ok if any(f["severity"] in ("high", "critical") for f in r["findings"])
        ),
        "findings": sorted(
            ({k: f[k] for k in ("rule_id", "severity", "fingerprint")} for f in shown),
            key=lambda f: (f["rule_id"], f["fingerprint"]),
        ),
    }


def heldout_report(data: dict[str, Any], labels: dict[str, str]) -> str:
    rows, unlabelled = lib.precision_table(data["findings"], labels)
    tp = sum(r["tp"] for r in rows)
    bc = sum(r["benign-context"] for r in rows)
    fp = sum(r["fp"] for r in rows)
    lines = [
        f"{data['repos_scanned']} of {data['repos_total']} repositories scanned ({data['files_scanned']} agent "
        f"files), ghostrules {data['ghostrules_version']} at commit {data.get('commit', '?')}, "
        f"{data['date']}, default settings and an empty configuration. "
        f"{len(data['findings'])} findings shown by default; {data['repos_failing_default_check']} "
        f"repositories would fail `--fail-on high`; {unlabelled} findings unlabelled.",
        "",
        "| Rule | Findings | True positive | Benign context | False positive | Unlabelled | Precision for a user |",
        "|---|---:|---:|---:|---:|---:|---:|",
    ]
    for r in rows:
        p = r["precision"]
        n = r["tp"] + r["benign-context"] + r["fp"]
        shown = f"{p:.0%} ({r['tp']} of {n})" if p is not None else "n/a"
        lines.append(
            f"| {r['rule']} | {r['findings']} | {r['tp']} | {r['benign-context']} | {r['fp']} | {r['unlabelled']} | {shown} |"
        )
    total = tp + bc + fp
    overall = f"{tp / total:.0%} ({tp} of {total})" if total else "n/a"
    lines.append(
        f"| **All** | {len(data['findings'])} | {tp} | {bc} | {fp} | {unlabelled} | {overall} |"
    )
    return "\n".join(lines) + "\n"


def render_results(data: dict[str, Any], labels: dict[str, str]) -> str:
    """bench/RESULTS.md: recall on the attack set, precision on the held-out set, misses listed."""
    return (
        "# Benchmark results\n\n"
        "Generated by `python bench/run.py report --write`; see [bench/README.md](README.md) for what is\n"
        "measured and how. Nothing here was tuned on the held-out set.\n\n"
        "## Recall on the attack set\n\n"
        + attacks_report(lib.run_attacks(lib.load_cases()))
        + "\n## Precision on the held-out set\n\n"
        + heldout_report(data, labels)
    )


def main(argv: Sequence[str] | None = None) -> int:
    p = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    p.add_argument("command", choices=("attacks", "heldout", "report"))
    p.add_argument("--workers", type=int, default=4)
    p.add_argument("--write", action="store_true", help="report: write bench/RESULTS.md")
    args = p.parse_args(argv)
    if args.command == "report":
        results = HERE / "heldout-results.json"
        if not results.exists():
            print("no held-out results: run `python bench/run.py heldout` first", file=sys.stderr)
            return 2
        text = render_results(json.loads(results.read_text("utf-8")), load_labels())
        if args.write:
            (HERE / "RESULTS.md").write_text(text, encoding="utf-8")
            print("bench/RESULTS.md written")
        else:
            print(text, end="")
        return 0
    if args.command == "attacks":
        print(attacks_report(lib.run_attacks(lib.load_cases())))
    if args.command == "heldout":
        print(run_heldout(args.workers))
    return 0


if __name__ == "__main__":
    sys.exit(main())
