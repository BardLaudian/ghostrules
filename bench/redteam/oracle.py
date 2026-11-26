"""The oracle: scan a case in an isolated directory and say only whether it was caught.

    python bench/redteam/oracle.py cases.toml      # prints {"id": {"detected": ..., ...}} as JSON

It returns ``detected`` (any finding at high or critical, the severities that fail the default
check) and ``max_severity``. Never a rule id, a message or a location: the attacker adapts to the
verdict, not to the rules. The scan reads the files like any repository; nothing is executed and
there is no network.
"""

from __future__ import annotations

import json
import subprocess
import sys
import tempfile
from collections.abc import Mapping
from pathlib import Path
from typing import Any

from redteam_common import expand, load_toml
from schema import validate_round

from ghostrules.config import ConfigError, load_config
from ghostrules.models import Severity
from ghostrules.scanner import scan_paths

VERDICT_KEYS = ("detected", "max_severity")


def write_case(root: Path, files: Mapping[str, str], symlinks: Mapping[str, str]) -> None:
    for name, text in files.items():
        target = root / name
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(expand(text).encode("utf-8"))
    for name, destination in symlinks.items():
        link = root / name
        link.parent.mkdir(parents=True, exist_ok=True)
        link.symlink_to(destination)


def check(files: Mapping[str, str], symlinks: Mapping[str, str] | None = None) -> dict[str, Any]:
    """Scan ``files`` in a fresh temporary git repository and return the blind verdict."""
    with tempfile.TemporaryDirectory(prefix="ghostrules-oracle-") as tmp:
        root = Path(tmp)
        subprocess.run(["git", "init", "-q", str(root)], check=True, capture_output=True)
        write_case(root, files, symlinks or {})
        try:
            config = load_config(root)
        except ConfigError:
            # A config the scanner rejects is not an evasion; the round excludes the case.
            return {"detected": False, "max_severity": None, "invalid_config": True}
        result = scan_paths([root], config)
    top = max((f.severity for f in result.findings), default=None)
    return {
        "detected": top is not None and top >= Severity.HIGH,
        "max_severity": top.label if top is not None else None,
    }


def check_round(cases: list[dict[str, Any]]) -> dict[str, dict[str, Any]]:
    problems = validate_round(cases)
    if problems:
        raise ValueError("invalid cases: " + "; ".join(problems[:5]))
    return {c["id"]: check(c["files"], c.get("symlinks")) for c in cases}


def main(argv: list[str] | None = None) -> int:
    args = sys.argv[1:] if argv is None else argv
    if len(args) != 1:
        print("usage: oracle.py CASES.toml", file=sys.stderr)
        return 2
    verdicts = check_round(load_toml(Path(args[0])).get("case", []))
    print(json.dumps(verdicts, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
