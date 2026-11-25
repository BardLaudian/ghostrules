"""The gate: a deterministic script that decides whether a defender's patch may go to a PR.

    python bench/redteam/gate.py snapshot 001            # before the patch: record the verdicts
    python bench/redteam/gate.py check 001 --base main --log calls.jsonl

``snapshot`` runs the oracle on the round's dev cases and twins and stores the verdicts. ``check``
runs after the patch and fails when: a command of gate_thresholds.toml fails, a dev case that was
detected is no longer detected, a benign twin that was clean now fires, the diff under ``src/``
is over the limit, or the tool-call log shows access to the test set. Output is JSON; exit 1 if
any check failed. Nothing is merged by this script: a person reviews the PR.
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path
from typing import Any

from audit_blind import audit_file
from oracle import check
from redteam_common import ROOT, ROUNDS, load_toml

DEFAULT_THRESHOLDS = Path(__file__).resolve().parent / "gate_thresholds.toml"


def verdicts_for(round_dir: Path) -> dict[str, bool]:
    """``{"dev:<id>": detected, "twin:<id>": detected}`` for the dev cases and the twins."""
    out: dict[str, bool] = {}
    for prefix, name in (("dev", "dev.toml"), ("twin", "twins.toml")):
        path = round_dir / name
        if path.is_file():
            for case in load_toml(path).get("case", []):
                out[f"{prefix}:{case['id']}"] = check(case["files"], case.get("symlinks"))[
                    "detected"
                ]
    return out


def regressions(before: dict[str, bool], after: dict[str, bool]) -> list[str]:
    """Dev cases that stopped being detected, and twins that started to be."""
    lost = [k for k, v in before.items() if k.startswith("dev:") and v and not after.get(k, False)]
    new_fp = [
        k for k, v in after.items() if k.startswith("twin:") and v and not before.get(k, False)
    ]
    return sorted(lost + new_fp)


def diff_lines(base: str, root: Path = ROOT) -> int:
    """Added plus removed lines under src/ relative to ``base``."""
    proc = subprocess.run(
        ["git", "diff", "--numstat", base, "--", "src"],
        cwd=root,
        capture_output=True,
        text=True,
        check=True,
    )
    total = 0
    for line in proc.stdout.splitlines():
        added, removed, _ = line.split("\t", 2)
        total += (int(added) if added.isdigit() else 0) + (int(removed) if removed.isdigit() else 0)
    return total


def run_command(argv: list[str], root: Path = ROOT) -> tuple[bool, str]:
    proc = subprocess.run(argv, cwd=root, capture_output=True, text=True, check=False)
    tail = (proc.stdout + proc.stderr).strip().splitlines()[-3:]
    return proc.returncode == 0, " | ".join(tail)


def run_checks(
    round_id: str,
    base: str,
    log: Path | None,
    thresholds: Path = DEFAULT_THRESHOLDS,
    rounds: Path = ROUNDS,
    root: Path = ROOT,
) -> dict[str, Any]:
    config = load_toml(thresholds)
    results: list[dict[str, Any]] = []

    def add(name: str, passed: bool, detail: str = "") -> None:
        results.append({"name": name, "passed": passed, "detail": detail})

    for name, argv in config.get("commands", {}).items():
        ok, tail = run_command(list(argv), root)
        add(name, ok, "" if ok else tail)
    round_dir = rounds / round_id
    snapshot = round_dir / "verdicts_before.json"
    if snapshot.is_file():
        bad = regressions(json.loads(snapshot.read_text("utf-8")), verdicts_for(round_dir))
        add("dev_and_twins", not bad, ", ".join(bad))
    else:
        add("dev_and_twins", False, f"no snapshot at {snapshot.name}: run `gate.py snapshot` first")
    limit = int(config["limits"]["max_src_diff_lines"])
    lines = diff_lines(base, root)
    add("diff_size", lines <= limit, f"{lines} lines under src/ (limit {limit})")
    flagged = audit_file(log) if log else None
    add("blind_audit", flagged == [], "no log" if flagged is None else f"{len(flagged)} flagged")
    return {"round": round_id, "passed": all(r["passed"] for r in results), "checks": results}


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    sub = p.add_subparsers(dest="action", required=True)
    s = sub.add_parser("snapshot")
    s.add_argument("round")
    c = sub.add_parser("check")
    c.add_argument("round")
    c.add_argument("--base", default="main")
    c.add_argument("--log", type=Path)
    c.add_argument("--thresholds", type=Path, default=DEFAULT_THRESHOLDS)
    ns = p.parse_args(sys.argv[1:] if argv is None else argv)
    if ns.action == "snapshot":
        out = ROUNDS / ns.round / "verdicts_before.json"
        out.write_text(json.dumps(verdicts_for(ROUNDS / ns.round), indent=1, sort_keys=True))
        print(f"wrote {out}")
        return 0
    report = run_checks(ns.round, ns.base, ns.log, ns.thresholds)
    print(json.dumps(report, indent=1))
    return 0 if report["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
