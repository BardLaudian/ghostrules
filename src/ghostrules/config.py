"""Configuration loading: ``--config``, ``.ghostrules.toml`` or ``[tool.ghostrules]``."""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from ghostrules._compat import tomllib
from ghostrules.models import Severity

CONFIG_FILENAME = ".ghostrules.toml"
DEFAULT_MAX_FILE_SIZE = 1024 * 1024  # bytes; 0 means no limit
_LIST_KEYS = ("disable", "exclude", "extra_targets", "allow_domains")
_KNOWN_KEYS = {
    *_LIST_KEYS,
    "fail_on",
    "min_severity",
    "trust_known_installers",
    "follow_imports",
    "agents",
    "lockfile",
    "profile",
    "visibility",
    "max_file_size",
}
# Every modelled agent, and the ones used when the config does not say. A new model is opt-in:
# adding it to the default would change every existing lockfile.
DEFAULT_AGENTS = ("claude-code", "copilot-cli", "cursor", "generic")
AGENT_NAMES = (*DEFAULT_AGENTS, "codex", "gemini-cli")


# "root-medium" also shows GR014 and GR032 at medium in a root instruction file
# (the default shows only GR010, GR011, GR033 and GR035 there); see visibility.py
VISIBILITY_MODES = ("default", "root-medium")


class ConfigError(Exception):
    """Raised for unreadable or invalid configuration.

    ``key`` names the offending configuration key when there is one; the loader uses it to add
    the file and line to the message (``.ghostrules.toml:3: 'fail_on' must be a string``).
    """

    def __init__(self, message: str, key: str | None = None) -> None:
        super().__init__(message)
        self.key = key


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
    follow_imports: bool = True
    agents: tuple[str, ...] = DEFAULT_AGENTS
    lockfile: str = ".ghostrules.lock"
    profile: str = "default"
    visibility: str = "default"
    max_file_size: int = DEFAULT_MAX_FILE_SIZE
    first_party: tuple[Any, ...] = ()  # set by the CLI from the repository, not from TOML
    source: str | None = None


def _string_list(table: dict[str, Any], key: str) -> list[str]:
    value = table.get(key, [])
    if not isinstance(value, list) or not all(isinstance(v, str) for v in value):
        raise ConfigError(f"'{key}' must be a list of strings", key)
    return value


def _severity_text(table: dict[str, Any], key: str, default: str) -> str:
    value = table.get(key, default)
    if not isinstance(value, str):
        raise ConfigError(f"'{key}' must be a string", key)
    return value


def _severity(text: str, key: str) -> Severity:
    try:
        return Severity.parse(text)
    except ValueError as exc:
        raise ConfigError(f"'{key}': {exc}", key) from None


def parse_config(table: dict[str, Any], source: str | None = None) -> Config:
    """Build a ``Config`` from an already-parsed TOML table, validating keys and values."""
    unknown = sorted(set(table) - _KNOWN_KEYS)
    if unknown:
        known = ", ".join(sorted(_KNOWN_KEYS))
        raise ConfigError(
            f"unknown config key(s): {', '.join(unknown)} (known: {known})", unknown[0]
        )
    fail_on_raw = _severity_text(table, "fail_on", "high")
    fail_on = None if fail_on_raw.strip().lower() == "none" else _severity(fail_on_raw, "fail_on")
    min_severity = _severity(_severity_text(table, "min_severity", "low"), "min_severity")
    trust = table.get("trust_known_installers", True)
    if not isinstance(trust, bool):
        raise ConfigError(
            "'trust_known_installers' must be true or false", "trust_known_installers"
        )
    follow = table.get("follow_imports", True)
    if not isinstance(follow, bool):
        raise ConfigError("'follow_imports' must be true or false", "follow_imports")
    agents = tuple(a.strip().lower() for a in _string_list(table, "agents")) or DEFAULT_AGENTS
    unknown_agents = [a for a in agents if a not in AGENT_NAMES]
    if unknown_agents:
        raise ConfigError(
            f"unknown agent(s) in 'agents': {', '.join(unknown_agents)} "
            f"(expected: {', '.join(AGENT_NAMES)})",
            "agents",
        )
    lockfile = table.get("lockfile", ".ghostrules.lock")
    if not isinstance(lockfile, str) or not lockfile.strip():
        raise ConfigError("'lockfile' must be a non-empty string", "lockfile")
    profile = table.get("profile", "default")
    if profile not in ("default", "strict", "lenient"):
        raise ConfigError('\'profile\' must be "default", "strict" or "lenient"', "profile")
    visibility = table.get("visibility", "default")
    if visibility not in VISIBILITY_MODES:
        raise ConfigError('\'visibility\' must be "default" or "root-medium"', "visibility")
    max_size = table.get("max_file_size", DEFAULT_MAX_FILE_SIZE)
    if isinstance(max_size, bool) or not isinstance(max_size, int) or max_size < 0:
        raise ConfigError(
            "'max_file_size' must be a number of bytes (0 for no limit)", "max_file_size"
        )
    return Config(
        disable=frozenset(rule.strip().upper() for rule in _string_list(table, "disable")),
        fail_on=fail_on,
        min_severity=min_severity,
        exclude=tuple(_string_list(table, "exclude")),
        extra_targets=tuple(_string_list(table, "extra_targets")),
        allow_domains=tuple(d.lower() for d in _string_list(table, "allow_domains")),
        trust_known_installers=trust,
        follow_imports=follow,
        agents=agents,
        lockfile=lockfile.strip(),
        profile=profile,
        visibility=visibility,
        max_file_size=max_size,
        source=source,
    )


def _read_toml(path: Path) -> dict[str, Any]:
    try:
        with path.open("rb") as handle:
            data: dict[str, Any] = tomllib.load(handle)
            return data
    except OSError as exc:
        raise ConfigError(f"cannot read {path}: {exc.strerror or exc}") from None
    except tomllib.TOMLDecodeError as exc:
        raise ConfigError(f"invalid TOML in {path}: {exc}") from None


def _located(error: ConfigError, path: Path | str, text: str, section: str | None) -> ConfigError:
    """``error`` with ``path:line:`` in front when its key can be found in ``text``."""
    if error.key is None:
        return ConfigError(f"{path}: {error}")
    lines = text.splitlines()
    start = 0
    if section is not None:
        start = next((i for i, ln in enumerate(lines) if ln.strip() == section), -1) + 1
    pattern = re.compile(rf"^\s*[\"']?{re.escape(error.key)}[\"']?\s*=")
    for number in range(start, len(lines)):
        if section is not None and number > start and lines[number].lstrip().startswith("["):
            break
        if pattern.match(lines[number]):
            return ConfigError(f"{path}:{number + 1}: {error}", error.key)
    return ConfigError(f"{path}: {error}", error.key)


def _parse_file(path: Path, label: str, section: str | None = None) -> Config:
    table = _read_toml(path)
    if section is not None:
        table = table.get("tool", {}).get("ghostrules")
        if not isinstance(table, dict):
            return Config()
    try:
        return parse_config(table, source=label)
    except ConfigError as exc:
        raise _located(exc, label if section is None else path.name, _text(path), section) from None


def _text(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return ""


def load_config(base_dir: Path, explicit: Path | None = None) -> Config:
    """Load configuration, trying in order: ``explicit``, ``.ghostrules.toml``, pyproject.

    Returns defaults when none is found. A pyproject without ``[tool.ghostrules]`` is skipped.
    """
    if explicit is not None:
        return _parse_file(explicit, str(explicit))
    dotfile = base_dir / CONFIG_FILENAME
    if dotfile.is_file():
        return _parse_file(dotfile, CONFIG_FILENAME)
    pyproject = base_dir / "pyproject.toml"
    if pyproject.is_file():
        return _parse_file(pyproject, "pyproject.toml [tool.ghostrules]", "[tool.ghostrules]")
    return Config()
