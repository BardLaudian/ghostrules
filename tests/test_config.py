from pathlib import Path

import pytest

from ghostrules.config import Config, ConfigError, load_config, parse_config
from ghostrules.models import Severity


def test_defaults_when_no_config(tmp_path: Path) -> None:
    config = load_config(tmp_path)
    assert config == Config()
    assert config.fail_on is Severity.HIGH
    assert config.min_severity is Severity.LOW


def test_dotfile_is_loaded(tmp_path: Path) -> None:
    (tmp_path / ".ghostrules.toml").write_text(
        'disable = ["gr014"]\nfail_on = "critical"\nmin_severity = "medium"\n'
        'exclude = ["vendor/**"]\nextra_targets = ["docs/ai/*.md"]\n'
        'allow_domains = ["MyCompany.com"]\n'
    )
    config = load_config(tmp_path)
    assert config.disable == {"GR014"}
    assert config.fail_on is Severity.CRITICAL
    assert config.min_severity is Severity.MEDIUM
    assert config.exclude == ("vendor/**",)
    assert config.extra_targets == ("docs/ai/*.md",)
    assert config.allow_domains == ("mycompany.com",)
    assert config.source == ".ghostrules.toml"


def test_trust_known_installers_defaults_to_true_and_can_be_disabled() -> None:
    assert parse_config({}).trust_known_installers is True
    assert parse_config({"trust_known_installers": False}).trust_known_installers is False


def test_fail_on_none_means_never_fail() -> None:
    assert parse_config({"fail_on": "none"}).fail_on is None


def test_pyproject_table_is_used_and_dotfile_wins(tmp_path: Path) -> None:
    (tmp_path / "pyproject.toml").write_text('[tool.ghostrules]\nfail_on = "medium"\n')
    assert load_config(tmp_path).fail_on is Severity.MEDIUM
    (tmp_path / ".ghostrules.toml").write_text('fail_on = "low"\n')
    assert load_config(tmp_path).fail_on is Severity.LOW


def test_pyproject_without_table_is_ignored(tmp_path: Path) -> None:
    (tmp_path / "pyproject.toml").write_text('[project]\nname = "x"\n')
    assert load_config(tmp_path) == Config()


def test_explicit_path_takes_priority(tmp_path: Path) -> None:
    (tmp_path / ".ghostrules.toml").write_text('fail_on = "low"\n')
    other = tmp_path / "custom.toml"
    other.write_text('fail_on = "critical"\n')
    assert load_config(tmp_path, explicit=other).fail_on is Severity.CRITICAL


@pytest.mark.parametrize(
    "table",
    [
        {"fail_on": "urgent"},
        {"min_severity": 3},
        {"disable": "GR014"},
        {"exclude": [1]},
        {"typo_key": True},
        {"trust_known_installers": "yes"},
    ],
)
def test_invalid_config_raises(table: dict) -> None:
    with pytest.raises(ConfigError):
        parse_config(table)


def test_invalid_toml_and_missing_explicit_file(tmp_path: Path) -> None:
    (tmp_path / ".ghostrules.toml").write_text("not = [valid")
    with pytest.raises(ConfigError, match="invalid TOML"):
        load_config(tmp_path)
    with pytest.raises(ConfigError, match="cannot read"):
        load_config(tmp_path, explicit=tmp_path / "missing.toml")
