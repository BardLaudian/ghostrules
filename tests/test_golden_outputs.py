"""Characterisation (golden) tests: the exact output of ``scan``, ``context`` and ``lock`` on
``examples/*``. They pin behaviour while the large functions behind these commands are split;
a refactor must leave every golden file unchanged.

Regenerate deliberately with ``GHOSTRULES_UPDATE_GOLDEN=1 pytest tests/test_golden_outputs.py``
and review the diff.
"""

import os
import re
import shutil
from pathlib import Path

import pytest
from typer.testing import CliRunner

from ghostrules.cli import app

ROOT = Path(__file__).resolve().parent.parent
GOLDEN = Path(__file__).parent / "fixtures" / "golden"
EXAMPLES = ("poisoned-repo", "import-chain-repo", "clean-repo")

CASES: dict[str, list[str]] = {}
for _ex in EXAMPLES:
    for _fmt in ("table", "json", "sarif", "markdown"):
        CASES[f"scan-{_ex}-{_fmt}"] = ["scan", f"examples/{_ex}", "--format", _fmt]
    CASES[f"scan-{_ex}-strict"] = ["scan", f"examples/{_ex}", "--strict", "--format", "json"]
    CASES[f"scan-{_ex}-lenient"] = ["scan", f"examples/{_ex}", "--lenient", "--format", "json"]
    CASES[f"scan-{_ex}-fail-on-low"] = ["scan", f"examples/{_ex}", "--fail-on", "low"]
    CASES[f"scan-{_ex}-small-limit"] = ["scan", f"examples/{_ex}", "--max-file-size", "200"]
    for _fmt in ("tree", "json", "markdown"):
        CASES[f"context-{_ex}-{_fmt}"] = ["context", "--root", f"examples/{_ex}", "--format", _fmt]
    CASES[f"context-{_ex}-text"] = [
        "context",
        "--root",
        f"examples/{_ex}",
        "--show-text",
        "--no-scan",
    ]


def _run(args: list[str], monkeypatch: pytest.MonkeyPatch) -> str:
    monkeypatch.chdir(ROOT)
    monkeypatch.setenv("COLUMNS", "120")
    monkeypatch.setenv("NO_COLOR", "1")
    result = CliRunner().invoke(app, [*args, "--no-color"], catch_exceptions=False)
    output = re.sub(r"\S*pytest-\d+[/\\]\w+[/\\]", "<tmp>/", result.output)  # pytest temp dirs
    output = re.sub(r"examples\\([\w.-]+)", r"examples/\1", output)  # Windows path separators
    return f"exit={result.exit_code}\n{output}"


def _check(name: str, actual: str) -> None:
    path = GOLDEN / f"{name}.txt"
    if os.environ.get("GHOSTRULES_UPDATE_GOLDEN"):
        path.write_text(actual, encoding="utf-8")
    assert path.read_text(encoding="utf-8") == actual


@pytest.mark.parametrize("name", list(CASES))
def test_command_output_is_unchanged(name: str, monkeypatch: pytest.MonkeyPatch) -> None:
    _check(name, _run(CASES[name], monkeypatch))


@pytest.mark.parametrize("example", EXAMPLES)
def test_lock_update_and_check_are_unchanged(
    example: str, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # A copy of the example with a relative lockfile name: the length of an absolute temp path
    # (long on macOS and Windows) must not change where Rich wraps the report.
    repo = tmp_path / "repo"
    shutil.copytree(ROOT / "examples" / example, repo)
    lockfile = repo / "lock"
    base = ["--root", str(repo), "--lockfile", "lock"]
    run = lambda a: _run(a, monkeypatch)  # noqa: E731
    out = [run(["lock", "--update", *base])]
    out.append(lockfile.read_text(encoding="utf-8"))
    for fmt in ("text", "markdown", "json"):
        out.append(run(["lock", "--check", "--format", fmt, *base]))
    # a changed file is reported
    work = tmp_path / "work"
    shutil.copytree(repo, work)
    (work / "AGENTS.md").write_text("changed\n", encoding="utf-8")
    drift = ["--root", str(work), "--lockfile", "lock"]
    for fmt in ("text", "json"):
        out.append(run(["lock", "--check", "--format", fmt, *drift]))
    _check(f"lock-{example}", "\n=====\n".join(out))
