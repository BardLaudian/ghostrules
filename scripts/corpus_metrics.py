"""Precision and recall of the scanner on the labelled evasion corpus.

    python scripts/corpus_metrics.py            # table by technique and the open cases
    python scripts/corpus_metrics.py --json     # the same, machine readable

The corpus is tests/fixtures/evasion/cases.toml. An *attack* case counts as caught when its
`rule` is reported (and as failing the default check when that finding is high or critical); a
*benign* case is a false positive when anything is reported. Cases marked `status = "open"` are
known misses or false positives: they count against the numbers and are listed. Nothing here makes a
network request or runs scanned text.
"""

from __future__ import annotations

import json
import sys
import tempfile
from collections import defaultdict
from pathlib import Path
from typing import Any

try:
    import tomllib
except ModuleNotFoundError:  # Python 3.10
    import tomli as tomllib  # type: ignore[no-redef]

from ghostrules.config import Config
from ghostrules.reporters import json_
from ghostrules.scanner import scan_paths

CORPUS = Path(__file__).resolve().parent.parent / "tests" / "fixtures" / "evasion" / "cases.toml"
GATE = {"high", "critical"}  # what fails the default `--fail-on high` check


def load_cases(path: Path = CORPUS) -> list[dict[str, Any]]:
    """The cases of the corpus, in file order."""
    return tomllib.loads(path.read_text("utf-8"))["case"]


def scan_case(case: dict[str, Any]) -> list[dict[str, Any]]:
    """The findings the default scan reports for one case."""
    with tempfile.TemporaryDirectory(prefix="ghostrules-corpus-") as tmp:
        root = Path(tmp)
        target = root / case["file"]
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(case["text"].encode("utf-8", "surrogatepass"))
        return json_.to_dict(scan_paths([root], Config()))["findings"]


def judge(case: dict[str, Any]) -> dict[str, Any]:
    """``{"ok": the label holds, "caught": bool, "gates": bool, "rules": [...]}``."""
    findings = scan_case(case)
    rules = sorted({f["rule_id"] for f in findings})
    if case["label"] == "attack":
        hits = [f for f in findings if f["rule_id"] == case["rule"]]
        return {
            "ok": bool(hits),
            "caught": bool(hits),
            "gates": any(f["severity"] in GATE for f in hits),
            "rules": rules,
        }
    return {"ok": not findings, "caught": bool(findings), "gates": False, "rules": rules}


def summarise(rows: list[tuple[dict[str, Any], dict[str, Any]]]) -> dict[str, Any]:
    """Counts, precision, recall and the per-technique breakdown."""
    tp = sum(1 for c, r in rows if c["label"] == "attack" and r["caught"])
    fn = sum(1 for c, r in rows if c["label"] == "attack" and not r["caught"])
    fp = sum(1 for c, r in rows if c["label"] == "benign" and r["caught"])
    tn = sum(1 for c, r in rows if c["label"] == "benign" and not r["caught"])
    gates = sum(1 for c, r in rows if c["label"] == "attack" and r["gates"])
    by_technique: dict[str, list[int]] = defaultdict(lambda: [0, 0])
    for case, result in rows:
        if case["label"] == "attack":
            by_technique[case["technique"]][1] += 1
            by_technique[case["technique"]][0] += result["caught"]
    return {
        "attacks": tp + fn,
        "benign": fp + tn,
        "tp": tp,
        "fn": fn,
        "fp": fp,
        "tn": tn,
        "fail_default_check": gates,
        "precision": tp / (tp + fp) if tp + fp else None,
        "recall": tp / (tp + fn) if tp + fn else None,
        "by_technique": {k: v for k, v in sorted(by_technique.items())},
        "open": [c["id"] for c, r in rows if not r["ok"]],
    }


def main(argv: list[str]) -> int:
    """Print the metrics; exit 0 always (the gate is tests/test_evasion_corpus.py)."""
    rows = [(case, judge(case)) for case in load_cases()]
    summary = summarise(rows)
    if "--json" in argv:
        print(json.dumps(summary, indent=2))
        return 0
    print(f"attacks {summary['attacks']}  benign {summary['benign']}")
    print(
        f"caught {summary['tp']}  missed {summary['fn']}  (fail the default check: "
        f"{summary['fail_default_check']})"
    )
    print(f"false positives {summary['fp']}  quiet {summary['tn']}")
    for name in ("precision", "recall"):
        value = summary[name]
        print(f"{name}: {'n/a' if value is None else f'{value:.1%}'}")
    print("\nopen cases (a miss or a false positive):")
    for case, result in rows:
        if not result["ok"]:
            what = "MISSED" if case["label"] == "attack" else "FALSE POSITIVE"
            print(
                f"  {case['id']}  {what:15} {case['technique']}  expected={case.get('rule', '-')}"
                f" got={result['rules']}"
            )
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
