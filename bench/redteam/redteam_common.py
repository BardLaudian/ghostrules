"""Shared helpers of the red-team infrastructure: paths, case loading, a small TOML writer."""

from __future__ import annotations

import os
import re
import sys
import unicodedata
from pathlib import Path
from typing import Any

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent.parent
sys.path.insert(0, str(HERE.parent))
sys.path.insert(0, str(ROOT / "src"))

from lib import Case, expand  # noqa: E402,F401  (re-exported for the other scripts)

from ghostrules._compat import tomllib  # noqa: E402

ROUNDS = HERE / "rounds"
TEST_DIR_ENV = "GHOSTRULES_REDTEAM_TEST_DIR"
DEFAULT_TEST_DIR = Path.home() / ".cache" / "ghostrules-redteam-test"
CLASSES = ("C1", "C2", "C3", "C4", "C5")
ORIGIN = "ai-redteam"
_ID = re.compile(r"^[a-z0-9][a-z0-9-]{1,58}[a-z0-9]$")


def test_dir() -> Path:
    """Where the held-out ``test`` cases live: outside the repository, never committed."""
    path = Path(os.environ.get(TEST_DIR_ENV) or DEFAULT_TEST_DIR).expanduser().resolve()
    if path == ROOT or ROOT in path.parents:
        raise ValueError(f"the test set must live outside the repository, not in {path}")
    return path


def valid_id(value: object) -> bool:
    return isinstance(value, str) and bool(_ID.match(value))


def load_toml(path: Path) -> dict[str, Any]:
    return tomllib.loads(path.read_text(encoding="utf-8"))


def _escape(text: str) -> str:
    out: list[str] = []
    for ch in text:
        cat = unicodedata.category(ch)
        if ch == "\\":
            out.append("\\\\")
        elif ch == '"':
            out.append('\\"')
        elif ch == "\n":
            out.append("\\n")
        elif ch == "\t":
            out.append("\\t")
        elif cat[0] in "CZ" and ch != " " or cat == "Mn":
            out.append(f"\\u{ord(ch):04X}" if ord(ch) <= 0xFFFF else f"\\U{ord(ch):08X}")
        else:
            out.append(ch)
    return '"' + "".join(out) + '"'


def _key(name: str) -> str:
    return name if re.fullmatch(r"[A-Za-z0-9_-]+", name) else _escape(name)


def dump_cases(cases: list[dict[str, Any]], header: str = "") -> str:
    """Write cases as TOML. Invisible characters are escaped, so a reviewer sees them."""
    lines = [f"# {line}" for line in header.splitlines()] + [""] if header else []
    for case in cases:
        lines.append("[[case]]")
        for key, value in case.items():
            if isinstance(value, dict):
                continue
            lines.append(f"{_key(key)} = {_escape(str(value))}")
        for key, value in case.items():
            if isinstance(value, dict) and value:
                lines.append(f"[case.{_key(key)}]")
                lines.extend(f"{_escape(k)} = {_escape(str(v))}" for k, v in value.items())
        lines.append("")
    return "\n".join(lines)
