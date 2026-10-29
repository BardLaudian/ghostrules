"""Read files from a git ref, so trusted settings can come from what was already reviewed.

Used by ``scan --config-from-ref`` and ``--suppressions-from-ref``: the scanned change (the working
tree of a pull request) must not decide what the scanner ignores. Only ``git rev-parse`` and
``git cat-file`` run, with fixed arguments; nothing from the repository is executed or evaluated.
"""

from __future__ import annotations

import os
import subprocess
from collections.abc import Callable
from pathlib import Path

from ghostrules._compat import tomllib
from ghostrules.config import CONFIG_FILENAME, Config, ConfigError, parse_config
from ghostrules.scanner import ReviewedMarks, reviewed_marks

_TIMEOUT = 30
_SHALLOW_HINT = (
    "in a shallow clone, fetch it first (for example actions/checkout with fetch-depth: 0)"
)


class GitRefError(Exception):
    """A ref cannot be resolved or read. The scan must stop: never a silent pass."""


def _git(root: Path, *args: str) -> subprocess.CompletedProcess[bytes]:
    env = {**os.environ, "GIT_TERMINAL_PROMPT": "0", "GIT_OPTIONAL_LOCKS": "0"}
    try:
        return subprocess.run(
            ["git", "-C", str(root), *args],
            capture_output=True,
            timeout=_TIMEOUT,
            env=env,
            check=False,
        )
    except FileNotFoundError:
        raise GitRefError("git is not installed, so a git ref cannot be read") from None
    except subprocess.TimeoutExpired:
        raise GitRefError(f"git did not answer within {_TIMEOUT} s") from None


def resolve_ref(root: Path, ref: str) -> str:
    """The commit ``ref`` names, or ``GitRefError`` (an unknown ref is an error, not a pass)."""
    if not ref.strip() or ref.startswith("-"):
        raise GitRefError(f"invalid git ref {ref!r}")
    done = _git(root, "rev-parse", "--verify", "--quiet", f"{ref}^{{commit}}")
    sha = done.stdout.decode("ascii", "replace").strip()
    if done.returncode != 0 or not sha:
        detail = done.stderr.decode("utf-8", "replace").strip().splitlines()
        reason = f": {detail[-1]}" if detail else ""
        raise GitRefError(f"cannot resolve git ref {ref!r}{reason}; {_SHALLOW_HINT}")
    return sha


class RefReader:
    """Files of one commit, addressed relative to the directory being scanned."""

    def __init__(self, root: Path, ref: str) -> None:
        self.root, self.ref = root, ref
        self.sha = resolve_ref(root, ref)
        done = _git(root, "rev-parse", "--show-prefix")
        if done.returncode != 0:
            raise GitRefError(f"{root} is not inside a git repository")
        self.prefix = done.stdout.decode("utf-8", "replace").strip()

    def read(self, relpath: str) -> str | None:
        """The file as it is at the ref, or ``None`` when it does not exist there."""
        done = _git(self.root, "cat-file", "blob", f"{self.sha}:{self.prefix}{relpath}")
        if done.returncode != 0:
            return None
        return done.stdout.decode("utf-8", errors="replace")


def config_at_ref(reader: RefReader) -> Config:
    """The configuration as it is at the ref: ``.ghostrules.toml``, else ``[tool.ghostrules]`` in
    ``pyproject.toml``, else the defaults. The working tree's configuration is never read."""
    try:
        text = reader.read(CONFIG_FILENAME)
        if text is not None:
            return parse_config(tomllib.loads(text), source=f"{CONFIG_FILENAME} at {reader.ref}")
        text = reader.read("pyproject.toml")
        if text is not None:
            table = tomllib.loads(text).get("tool", {}).get("ghostrules")
            if isinstance(table, dict):
                source = f"pyproject.toml [tool.ghostrules] at {reader.ref}"
                return parse_config(table, source=source)
    except tomllib.TOMLDecodeError as exc:
        raise ConfigError(f"invalid TOML in the configuration at {reader.ref}: {exc}") from None
    return Config()


def reviewed_lookup(reader: RefReader) -> Callable[[str], ReviewedMarks]:
    """``label -> the ignores that file had at the ref``. Paths outside the scanned directory
    (``~/`` or absolute) have none, so their ignore comments are not honoured."""
    cache: dict[str, ReviewedMarks] = {}

    def lookup(label: str) -> ReviewedMarks:
        if label not in cache:
            absolute = label.startswith(("~/", "/")) or (len(label) > 1 and label[1] == ":")
            text = None if absolute else reader.read(label)
            cache[label] = (
                reviewed_marks(text.splitlines()) if text is not None else ReviewedMarks()
            )
        return cache[label]

    return lookup
