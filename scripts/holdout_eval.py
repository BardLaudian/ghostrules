"""Measure ghostrules against the blind holdout set. A measurement, not a tuning loop.

    python scripts/holdout_eval.py                       # markdown report on stdout
    python scripts/holdout_eval.py --json results.json   # also write the per-case record

Every case of tests/holdout/holdout-v1.jsonl is written as a file (at the path the case names) in
its own temporary directory and scanned with `ghostrules scan --format json` and the default
configuration. Two scans per case: the default one (what a user sees) and one with
`--min-severity info` (to tell "not detected" from "detected but hidden").

"Visible" is reported three ways, because the default view prints `low` and the check fails from
`high`:  medium+ (the strict reading: info and low do not count), anything in the default output,
and what fails the default `--fail-on high` check.

The cases must not be added to the tuning corpus (tests/fixtures/evasion); do not fit rules to
them. Nothing here makes a network request or runs scanned text.
"""

from __future__ import annotations

import hashlib
import json
import math
import shutil
import subprocess
import sys
import tempfile
from collections import defaultdict
from pathlib import Path
from typing import Any

HOLDOUT = Path(__file__).resolve().parent.parent / "tests" / "holdout" / "holdout-v1.jsonl"
RANK = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
DEFINITIONS = {
    "medium+": 2,  # info and low do not count as seen
    "default-output": 1,  # anything the default scan prints
    "fails-check": 3,  # fails the default --fail-on high
}


def wilson(successes: int, total: int, z: float = 1.96) -> tuple[float, float]:
    """95 % Wilson score interval for a proportion (0, 1 when ``total`` is 0)."""
    if total == 0:
        return 0.0, 1.0
    p = successes / total
    denom = 1 + z * z / total
    centre = (p + z * z / (2 * total)) / denom
    half = z * math.sqrt(p * (1 - p) / total + z * z / (4 * total * total)) / denom
    return max(0.0, centre - half), min(1.0, centre + half)


def sha256(path: Path) -> str:
    """SHA-256 of a file, hex."""
    return hashlib.sha256(path.read_bytes()).hexdigest()


def load_cases(path: Path = HOLDOUT) -> list[dict[str, Any]]:
    """The cases, in file order."""
    return [json.loads(line) for line in path.read_text("utf-8").splitlines() if line.strip()]


def _command() -> list[str]:
    beside = Path(sys.executable).parent / "ghostrules"  # the console script of this environment
    exe = str(beside) if beside.exists() else shutil.which("ghostrules")
    if exe is None:
        raise SystemExit("the ghostrules command was not found: install the package first")
    return [exe]


def _scan(root: Path, scratch: Path, *flags: str) -> dict[str, Any]:
    # cwd is outside the repository so no .ghostrules.toml of this repo is picked up
    done = subprocess.run(
        [*_command(), "scan", str(root), "--format", "json", *flags],
        capture_output=True,
        text=True,
        cwd=scratch,
        check=False,
    )
    if done.returncode not in (0, 1):
        raise RuntimeError(f"ghostrules scan failed ({done.returncode}): {done.stderr[:300]}")
    return json.loads(done.stdout)


def run_case(case: dict[str, Any]) -> dict[str, Any]:
    """Scan one case and record what was found at each visibility."""
    with tempfile.TemporaryDirectory(prefix="ghostrules-holdout-") as tmp:
        scratch = Path(tmp)
        root = scratch / "repo"
        target = root / case["file"]
        target.parent.mkdir(parents=True)
        target.write_bytes(case["content"].encode("utf-8"))
        shown = _scan(root, scratch)
        everything = _scan(root, scratch, "--min-severity", "info")
    pairs = [(f["rule_id"], f["severity"]) for f in everything["findings"]]
    return {
        "id": case["id"],
        "label": case["label"],
        "family": case["family"],
        "technique": case["technique"],
        "file": case["file"],
        "scanned_files": shown["scanned_files"],
        "default_output": [(f["rule_id"], f["severity"]) for f in shown["findings"]],
        "all_findings": pairs,
        "top": max((RANK[s] for _, s in pairs), default=-1),
    }


def seen(record: dict[str, Any], floor: int) -> bool:
    """Whether the case has a finding at ``floor`` or above in the default output."""
    return any(RANK[s] >= floor for _, s in record["default_output"])


def failure_kind(record: dict[str, Any]) -> str:
    """Why an attack was not seen at medium or above."""
    if record["scanned_files"] == 0:
        return "not scanned (the file name is not a scan target)"
    if not record["all_findings"]:
        return "not detected"
    best = max(s for _, s in record["all_findings"])
    shown = "shown at low" if seen(record, 1) else "hidden (info only)"
    return f"detected but {shown}" if best in ("low", "info") else "detected"


def _pct(n: int, d: int) -> str:
    lo, hi = wilson(n, d)
    return f"{n}/{d} = {n / d:.1%}  (95 % CI {lo:.1%}-{hi:.1%})" if d else "n/a"


def report(records: list[dict[str, Any]], digest: str) -> str:
    """The markdown report."""
    attacks = [r for r in records if r["label"] == "attack"]
    benign = [r for r in records if r["label"] == "benign"]
    out = [f"holdout-v1.jsonl sha256 {digest}", f"{len(attacks)} attacks, {len(benign)} benign", ""]
    out.append("## Recall (attacks with a visible finding) and false positives (benign with one)")
    for name, floor in DEFINITIONS.items():
        hits = sum(seen(r, floor) for r in attacks)
        fps = sum(seen(r, floor) for r in benign)
        out.append(f"- visible = {name}: recall {_pct(hits, len(attacks))}")
        out.append(f"  false positives {_pct(fps, len(benign))}")
    out += ["", "## Recall by family (visible = medium+ / in the default output / fails the check)"]
    families: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for r in attacks:
        families[r["family"]].append(r)
    for family, rows in sorted(families.items()):
        cells = " / ".join(f"{sum(seen(r, f) for r in rows)}" for f in DEFINITIONS.values())
        out.append(f"- {family}: {cells} of {len(rows)}")
    out += ["", "## Missed attacks (not visible at medium or above)"]
    for r in attacks:
        if not seen(r, 2):
            rules = ", ".join(f"{a}:{b}" for a, b in r["all_findings"]) or "-"
            out.append(f"- {r['id']} [{r['family']}] {r['technique']}")
            out.append(f"    {failure_kind(r)}; all findings: {rules}")
    out += ["", "## False positives (benign with a finding at medium or above)"]
    for r in benign:
        if seen(r, 2):
            out.append(f"- {r['id']} [{r['family']}] {r['technique']}: {r['default_output']}")
    low_only = [r for r in benign if seen(r, 1) and not seen(r, 2)]
    out += ["", "## Benign shown only at low in the default output"]
    out += [f"- {r['id']} [{r['family']}]: {r['default_output']}" for r in low_only] or ["- none"]
    return "\n".join(out)


def main(argv: list[str]) -> int:
    """Run the evaluation and print the report."""
    digest = sha256(HOLDOUT)
    recorded = HOLDOUT.with_suffix(".jsonl.sha256")
    if recorded.exists() and recorded.read_text().split()[0] != digest:
        print("the holdout file changed since its hash was recorded", file=sys.stderr)
        return 2
    records = [run_case(c) for c in load_cases()]
    print(report(records, digest))
    if "--json" in argv:
        Path(argv[argv.index("--json") + 1]).write_text(json.dumps(records, indent=1), "utf-8")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
