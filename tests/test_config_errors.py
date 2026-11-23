"""A bad configuration names the file, the line and the key (phase 8)."""

from pathlib import Path

import pytest
from typer.testing import CliRunner

from ghostrules.cli import app
from ghostrules.config import ConfigError, load_config

CASES = {
    "unknown key": ('# c\nfail_on = "high"\nfail_onn = "low"\n', 3, "fail_onn"),
    "wrong type (list)": ('disable = "GR001"\n', 1, "'disable' must be a list"),
    "wrong type (bool)": ("# c\n\nfollow_imports = 3\n", 3, "'follow_imports' must be"),
    "wrong type (trust)": ('trust_known_installers = "yes"\n', 1, "'trust_known_installers'"),
    "bad severity": ('fail_on = "urgent"\n', 1, "'fail_on'"),
    "bad min severity": ('fail_on = "low"\nmin_severity = "x"\n', 2, "'min_severity'"),
    "severity not a string": ("min_severity = 4\n", 1, "'min_severity' must be a string"),
    "unknown agent": ('agents = ["vim"]\n', 1, "unknown agent"),
    "empty lockfile": ('lockfile = ""\n', 1, "'lockfile'"),
    "bad profile": ('profile = "loud"\n', 1, "'profile'"),
    "bad size": ("max_file_size = -3\n", 1, "'max_file_size'"),
}


@pytest.mark.parametrize("name", list(CASES))
def test_dotfile_errors_carry_file_line_and_key(tmp_path: Path, name: str) -> None:
    text, line, needle = CASES[name]
    (tmp_path / ".ghostrules.toml").write_text(text, encoding="utf-8")
    with pytest.raises(ConfigError) as caught:
        load_config(tmp_path)
    message = str(caught.value)
    assert message.startswith(".ghostrules.toml:"), message
    if needle:
        assert needle in message
        assert f".ghostrules.toml:{line}:" in message, message


def test_pyproject_error_points_at_the_line_inside_the_table(tmp_path: Path) -> None:
    (tmp_path / "pyproject.toml").write_text(
        '[project]\nname = "x"\nfail_on = "decoy"\n\n[tool.ghostrules]\nmax_file_size = "big"\n',
        encoding="utf-8",
    )
    with pytest.raises(ConfigError, match=r"pyproject\.toml:6: 'max_file_size'"):
        load_config(tmp_path)


def test_a_valid_config_is_untouched(tmp_path: Path) -> None:
    (tmp_path / ".ghostrules.toml").write_text('fail_on = "medium"\n', encoding="utf-8")
    assert load_config(tmp_path).fail_on is not None


def test_invalid_toml_syntax_names_the_line(tmp_path: Path) -> None:
    (tmp_path / ".ghostrules.toml").write_text("a = 1\nb = = 2\n", encoding="utf-8")
    with pytest.raises(ConfigError, match=r"line 2"):
        load_config(tmp_path)


def test_the_cli_prints_the_location_and_exits_2(tmp_path: Path) -> None:
    (tmp_path / ".ghostrules.toml").write_text("\nbogus = 1\n", encoding="utf-8")
    result = CliRunner().invoke(app, ["scan", str(tmp_path)])
    assert result.exit_code == 2
    assert ".ghostrules.toml:2:" in result.output and "bogus" in result.output
