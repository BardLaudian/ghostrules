"""Scan a folder of cloned repositories with both visibility variants (read-only).

    python scripts/realworld_scan.py CLONES_DIR OUT_DIR

Each sub-folder of CLONES_DIR is one repository (named ``owner@name``). It is scanned with
``ghostrules scan --format json --min-severity info`` twice, with ``--visibility default`` and
``--visibility root-medium``, and the findings are written to ``OUT_DIR/results-<variant>.json``:
repository, file, line, rule, severity and a short snippet (secrets are already masked by the
scanner). Nothing here makes a network request or runs scanned text, and no rule is adjusted from
what it finds: this measures, it does not tune.
"""

from __future__ import annotations

import json
import subprocess
import sys
import tempfile
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

VARIANTS = ("default", "root-medium")


def _command() -> str:
    beside = Path(sys.executable).parent / "ghostrules"
    return str(beside) if beside.exists() else "ghostrules"


def scan(repo: Path, variant: str) -> dict:
    """The JSON report of one repository, scanned from a neutral working directory."""
    with tempfile.TemporaryDirectory(prefix="ghostrules-realworld-") as cwd:
        done = subprocess.run(
            [_command(), "scan", str(repo), "--format", "json", "--min-severity", "info",
             "--visibility", variant],
            capture_output=True, text=True, cwd=cwd, timeout=900, check=False,
        )  # fmt: skip
    if done.returncode not in (0, 1):
        return {"error": done.stderr[:200], "findings": [], "scanned_files": 0}
    return json.loads(done.stdout)


def main(argv: list[str]) -> int:
    """Write one results file per variant."""
    clones, out = Path(argv[1]), Path(argv[2])
    out.mkdir(parents=True, exist_ok=True)
    repos = sorted(p for p in clones.iterdir() if p.is_dir())
    for variant in VARIANTS:
        with ThreadPoolExecutor(8) as pool:
            reports = list(pool.map(lambda r, v=variant: scan(r, v), repos))
        rows = []
        for repo, report in zip(repos, reports, strict=True):
            name = repo.name.replace("@", "/", 1)
            rows.append(
                {
                    "repo": name,
                    "scanned_files": report["scanned_files"],
                    "error": report.get("error"),
                    "findings": [
                        {
                            "path": f["path"],
                            "line": f["line"],
                            "rule": f["rule_id"],
                            "severity": f["severity"],
                            "snippet": f["snippet"][:160],
                        }
                        for f in report["findings"]
                    ],
                }
            )
        (out / f"results-{variant}.json").write_text(json.dumps(rows, indent=1), "utf-8")
        total = sum(len(r["findings"]) for r in rows)
        files = sum(r["scanned_files"] for r in rows)
        print(
            f"{variant}: {len(rows)} repos, {files} agent files, {total} findings (all severities)"
        )
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
