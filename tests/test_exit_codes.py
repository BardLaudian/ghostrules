"""Exit codes are a contract: 0 clean, 1 findings, 2 usage or configuration, 3 internal failure."""

import sys
from pathlib import Path

import pytest
from typer.testing import CliRunner

from ghostrules import cli
from ghostrules._compat import tomllib
from ghostrules.cli import EXIT_ERROR, EXIT_FINDINGS, EXIT_INTERNAL, EXIT_OK, app

ROOT = Path(__file__).resolve().parent.parent
runner = CliRunner()


def test_the_values_are_fixed() -> None:
    assert (EXIT_OK, EXIT_FINDINGS, EXIT_ERROR, EXIT_INTERNAL) == (0, 1, 2, 3)


def test_clean_scan_is_0() -> None:
    assert runner.invoke(app, ["scan", str(ROOT / "examples" / "clean-repo")]).exit_code == 0


def test_findings_at_the_threshold_are_1() -> None:
    result = runner.invoke(app, ["scan", str(ROOT / "examples" / "poisoned-repo")])
    assert result.exit_code == 1


def test_findings_below_the_threshold_are_0() -> None:
    args = ["scan", str(ROOT / "examples" / "poisoned-repo"), "--fail-on", "none"]
    assert runner.invoke(app, args).exit_code == 0


@pytest.mark.parametrize(
    "args",
    [
        ["scan", "/no/such/path/anywhere"],
        ["scan", "--fail-on", "urgent", "."],
        ["scan", "--format", "xml", "."],
        ["scan", "--max-file-size", "-1", "."],
    ],
)
def test_usage_errors_are_2(args: list[str]) -> None:
    assert runner.invoke(app, args).exit_code == 2


def test_a_bad_config_is_2(tmp_path: Path) -> None:
    (tmp_path / ".ghostrules.toml").write_text("nope = 1\n", encoding="utf-8")
    assert runner.invoke(app, ["scan", str(tmp_path)]).exit_code == 2


def test_an_unexpected_exception_is_3_not_1(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    def boom(*_a: object, **_k: object) -> None:
        raise RuntimeError("kaput")

    monkeypatch.setattr(cli, "scan_paths", boom)
    monkeypatch.setattr(sys, "argv", ["ghostrules", "scan", str(ROOT / "examples" / "clean-repo")])
    with pytest.raises(SystemExit) as stop:
        cli.main()
    assert stop.value.code == 3
    err = capsys.readouterr().err
    assert "internal error" in err and "RuntimeError" in err and "not a finding" in err


def test_main_passes_normal_exit_codes_through(monkeypatch: pytest.MonkeyPatch) -> None:
    poisoned = str(ROOT / "examples" / "poisoned-repo")
    monkeypatch.setattr(sys, "argv", ["ghostrules", "scan", poisoned])
    with pytest.raises(SystemExit) as stop:
        cli.main()
    assert stop.value.code == 1


def test_the_console_script_points_at_main() -> None:
    data = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    assert data["project"]["scripts"]["ghostrules"] == "ghostrules.cli:main"
