"""Metamorphic tests: rewriting only the *form* of a file must not change what is found.

The base is examples/poisoned-repo (every rule fires there). Each transform keeps the meaning of
the file: line endings, a BOM, trailing tabs, and for JSON minifying, reversing the key order and
spelling every string character as a \\u escape.
"""

from __future__ import annotations

import codecs
import json
import re
from collections.abc import Callable
from pathlib import Path

import pytest

from ghostrules.config import Config
from ghostrules.reporters import json_
from ghostrules.scanner import scan_paths

ROOT = Path(__file__).resolve().parent.parent / "examples" / "poisoned-repo"
BOM = codecs.BOM_UTF8.decode("utf-8")
_STRING = re.compile(r'"(?:[^"\\]|\\.)*"')


def _files() -> dict[str, str]:
    return {
        p.relative_to(ROOT).as_posix(): p.read_text("utf-8")
        for p in sorted(ROOT.rglob("*"))
        if p.is_file()
    }


def _scan(files: dict[str, str], tmp_path: Path) -> list[tuple[str, str, str]]:
    for name, text in files.items():
        target = tmp_path / name
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(text.encode("utf-8"))
    data = json_.to_dict(scan_paths([tmp_path], Config()))
    return sorted((f["rule_id"], f["severity"], f["path"]) for f in data["findings"])


def _escape_strings(text: str) -> str:
    """Spell every character of every JSON string as a \\uXXXX escape."""

    def spell(m: re.Match[str]) -> str:
        body = m.group()[1:-1]
        if "\\" in body:  # already has escapes: leave it
            return m.group()
        return '"' + "".join(f"\\u{ord(c):04x}" for c in body) + '"'

    return _STRING.sub(spell, text)


def _reverse(obj: object) -> object:
    if isinstance(obj, dict):
        return {k: _reverse(v) for k, v in reversed(list(obj.items()))}
    if isinstance(obj, list):
        return [_reverse(v) for v in obj]
    return obj


def _json_only(f: Callable[[str], str]) -> Callable[[str, str], str]:
    return lambda name, text: f(text) if name.endswith(".json") else text


TRANSFORMS: dict[str, Callable[[str, str], str]] = {
    "crlf": lambda name, text: text.replace("\n", "\r\n"),
    "bom": lambda name, text: BOM + text,
    "trailing-tab": lambda name, text: text.replace("\n", "\t\n"),
    "json-minified": _json_only(lambda t: json.dumps(json.loads(t), separators=(",", ":"))),
    "json-reversed-keys": _json_only(lambda t: json.dumps(_reverse(json.loads(t)), indent=2)),
    "json-unicode-escapes": _json_only(lambda t: _escape_strings(json.dumps(json.loads(t)))),
}


def test_the_baseline_is_not_empty(tmp_path: Path) -> None:
    assert len(_scan(_files(), tmp_path)) >= 25


@pytest.mark.parametrize("name", TRANSFORMS)
def test_form_changes_keep_the_findings(name: str, tmp_path: Path) -> None:
    files = _files()
    base = _scan(files, tmp_path / "base")
    changed = _scan({p: TRANSFORMS[name](p, t) for p, t in files.items()}, tmp_path / "changed")
    assert changed == base
