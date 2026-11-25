"""The limits the docs state (size cap, windows, hard limit, exit codes) match the code."""

import re
from pathlib import Path

import pytest
from typer.testing import CliRunner

from ghostrules import windows
from ghostrules.cli import app
from ghostrules.config import DEFAULT_MAX_FILE_SIZE

ROOT = Path(__file__).resolve().parent.parent
USAGE = (ROOT / "docs" / "USAGE.md").read_text(encoding="utf-8")
SECURITY = (ROOT / "SECURITY.md").read_text(encoding="utf-8")
THREAT = (ROOT / "docs" / "THREAT_MODEL.md").read_text(encoding="utf-8")
MIB = 1024 * 1024


def test_the_default_cap_is_what_the_docs_say() -> None:
    assert DEFAULT_MAX_FILE_SIZE == MIB
    assert f"`{MIB}`" in USAGE and f"max_file_size = {MIB}" in USAGE
    assert "1 MiB" in SECURITY and "1 MiB" in THREAT


def test_the_hard_limit_and_overlap_are_what_the_docs_say() -> None:
    assert windows.HARD_FILE_LIMIT == 16 * MIB and "16 MiB" in USAGE and "16 MiB" in SECURITY
    assert windows.OVERLAP == 64 * 1024 and "64 KiB" in SECURITY


def test_usage_documents_exactly_the_four_exit_codes() -> None:
    section = USAGE.split("#### Exit codes", 1)[1].split("\n####", 1)[0]
    assert set(re.findall(r"^\| `(\d)` \|", section, re.M)) == {"0", "1", "2", "3"}


def test_an_unscannable_agent_file_exits_2_as_the_docs_say(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(windows, "HARD_FILE_LIMIT", 2000)
    (tmp_path / "CLAUDE.md").write_text("Run the tests.\n" * 400, encoding="utf-8")
    result = CliRunner().invoke(app, ["scan", "--max-file-size", "1000", str(tmp_path)])
    assert result.exit_code == 2
    assert "cannot be scanned" in result.output
