"""Configuration loading: ``--config``, ``.ghostrules.toml`` or ``[tool.ghostrules]``."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any

from ghostrules._compat import tomllib
from ghostrules.models import Severity

CONFIG_FILENAME = ".ghostrules.toml"
_LIST_KEYS = ("disable", "exclude", "extra_targets", "allow_domains")
_KNOWN_KEYS = {*_LIST_KEYS, "fail_on", "min_severity", "trust_known_installers"}


class ConfigError(Exception):
    """Raised for unreadable or invalid configuration."""


@dataclass(frozen=True)
class Config:
    """Effective configuration. ``fail_on=None`` means never fail."""

    disable: frozenset[str] = frozenset()
    fail_on: Severity | None = Severity.HIGH
    min_severity: Severity = Severity.LOW
    exclude: tuple[str, ...] = ()
    extra_targets: tuple[str, ...] = ()
    allow_domains: tuple[str, ...] = ()
    trust_known_installers: bool = True
    source: str | None = None


def _string_list(table: dict[str, Any], key: str) -> list[str]:
    value = table.get(key, [])
    if not isinstance(value, list) or not all(isinstance(v, str) for v in value):
        raise ConfigError(f"'{key}' must be a list of strings")
    return value


def parse_config(table: dict[str, Any], source: str | None = None) -> Config:
    """Build a ``Config`` from an already-parsed TOML table, validating keys and values."""
    unknown = sorted(set(table) - _KNOWN_KEYS)
    if unknown:
        raise ConfigError(f"unknown config key(s): {', '.join(unknown)}")
    try:
        fail_on_raw = table.get("fail_on", "high")
        if not isinstance(fail_on_raw, str):
            raise ConfigError("'fail_on' must be a string")
        fail_on = None if fail_on_raw.strip().lower() == "none" else Severity.parse(fail_on_raw)
        min_raw = table.get("min_severity", "low")
        if not isinstance(min_raw, str):
            raise ConfigError("'min_severity' must be a string")
        min_severity = Severity.parse(min_raw)
    except ValueError as exc:
        raise ConfigError(str(exc)) from None
    trust = table.get("trust_known_installers", True)
    if not isinstance(trust, bool):
        raise ConfigError("'trust_known_installers' must be true or false")
    return Config(
        disable=frozenset(rule.strip().upper() for rule in _string_list(table, "disable")),
        fail_on=fail_on,
        min_severity=min_severity,
        exclude=tuple(_string_list(table, "exclude")),
        extra_targets=tuple(_string_list(table, "extra_targets")),
        allow_domains=tuple(d.lower() for d in _string_list(table, "allow_domains")),
        trust_known_installers=trust,
        source=source,
    )


def _read_toml(path: Path) -> dict[str, Any]:
    try:
        with path.open("rb") as handle:
            return tomllib.load(handle)
    except OSError as exc:
        raise ConfigError(f"cannot read {path}: {exc.strerror or exc}") from None
    except tomllib.TOMLDecodeError as exc:
        raise ConfigError(f"invalid TOML in {path}: {exc}") from None


def load_config(base_dir: Path, explicit: Path | None = None) -> Config:
    """Load configuration, trying in order: ``explicit``, ``.ghostrules.toml``, pyproject.

    Returns defaults when none is found. A pyproject without ``[tool.ghostrules]`` is skipped.
    """
    if explicit is not None:
        return parse_config(_read_toml(explicit), source=str(explicit))
    dotfile = base_dir / CONFIG_FILENAME
    if dotfile.is_file():
        return parse_config(_read_toml(dotfile), source=CONFIG_FILENAME)
    pyproject = base_dir / "pyproject.toml"
    if pyproject.is_file():
        table = _read_toml(pyproject).get("tool", {}).get("ghostrules")
        if isinstance(table, dict):
            return parse_config(table, source="pyproject.toml [tool.ghostrules]")
    return Config()
