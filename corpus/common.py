"""Shared helpers for the corpus tooling (see ``corpus/README.md``).

Everything that talks to the outside world (``git``, ``gh``, the ``ghostrules`` command) goes
through a ``Runner``, so the tests replace it with a fake and never touch the network.

This directory is not part of the published package.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import subprocess
import unicodedata
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Protocol

from ghostrules._compat import tomllib

CORPUS_DIR = Path(__file__).resolve().parent
REPO_ROOT = CORPUS_DIR.parent
TIERS = ("regression", "study")
SEVERITIES = ("critical", "high", "medium", "low", "info")
# GitHub names: owner = alphanumerics and hyphens, repo = those plus dots and underscores. A name
# starting with "-" or "." is refused, so it can never be read as an option by git or gh.
REPO_RE = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9-]{0,38})/[A-Za-z0-9_][A-Za-z0-9._-]{0,99}$")
FINGERPRINT_CHARS = 16
STORE_DECODED_FOR = frozenset({"GR001", "GR004"})


@dataclass(frozen=True)
class Proc:
    """The result of running a command."""

    returncode: int
    stdout: str = ""
    stderr: str = ""


class Runner(Protocol):
    """Runs a command. The default is ``subprocess_runner``; tests pass a fake."""

    def __call__(
        self,
        args: Sequence[str],
        *,
        timeout: float = 120,
        cwd: Path | None = None,
        env: Mapping[str, str] | None = None,
    ) -> Proc: ...


def subprocess_runner(
    args: Sequence[str],
    *,
    timeout: float = 120,
    cwd: Path | None = None,
    env: Mapping[str, str] | None = None,
) -> Proc:
    """Run ``args`` (never through a shell). A timeout is exit code 124, a missing program 127."""
    try:
        done = subprocess.run(
            list(args),
            capture_output=True,
            encoding="utf-8",
            errors="replace",
            timeout=timeout,
            cwd=cwd,
            env=None if env is None else dict(env),
            check=False,
        )
    except subprocess.TimeoutExpired:
        return Proc(124, "", f"timed out after {timeout:g}s")
    except OSError as exc:
        return Proc(127, "", str(exc))
    return Proc(done.returncode, done.stdout, done.stderr)


def git_env() -> dict[str, str]:
    """The environment for ``git``: never prompt, never download LFS content."""
    env = dict(os.environ)
    env.update({"GIT_TERMINAL_PROMPT": "0", "GIT_LFS_SKIP_SMUDGE": "1", "GIT_ASKPASS": "true"})
    return env


def valid_repo(name: str) -> bool:
    """Whether ``name`` is a well-formed ``owner/repo``."""
    return bool(REPO_RE.match(name)) and name.split("/", 1)[1] not in (".", "..")


def repo_slug(name: str) -> str:
    """A file-name-safe form of ``owner/repo``."""
    return name.replace("/", "__")


def safe_text(text: str, limit: int = 400) -> str:
    """``text`` that is safe to print or store in TOML: control, format (bidi, zero-width, tag),
    private-use and unassigned characters become ``⟦U+XXXX⟧``. Repository content can carry
    terminal escape sequences; nothing from it reaches a terminal unfiltered."""
    out: list[str] = []
    for ch in text:
        if ch in "\n\t" or unicodedata.category(ch)[0] not in "CZ" or ch == " ":
            out.append(ch)
        elif unicodedata.category(ch) == "Zs":
            out.append(" ")
        else:
            out.append(f"⟦U+{ord(ch):04X}⟧")
    shown = "".join(out)
    return shown if len(shown) <= limit else shown[:limit] + "…"


def fingerprint(repo: str, path: str, rule_id: str, snippet: str) -> str:
    """A finding's stable identity: no line numbers, so unrelated edits do not change it, and the
    snippet is whitespace-normalised."""
    normal = " ".join(snippet.split())
    digest = hashlib.sha256("\0".join((repo, path, rule_id, normal)).encode("utf-8", "replace"))
    return digest.hexdigest()[:FINGERPRINT_CHARS]


def toml_string(value: str) -> str:
    """A TOML basic string. ``value`` goes through ``safe_text`` first, so it holds no character
    TOML forbids."""
    return json.dumps(safe_text(value, limit=2000), ensure_ascii=False)


# --- repos.toml ---------------------------------------------------------------------------------


@dataclass(frozen=True)
class RepoEntry:
    """One ``[[repo]]`` of ``repos.toml``."""

    name: str
    tier: str


class CorpusError(Exception):
    """A problem with the corpus files or arguments that the user must fix."""


def load_repos(path: Path) -> list[RepoEntry]:
    """The pinned corpus. Names are validated; duplicates are refused."""
    try:
        data = tomllib.loads(path.read_text(encoding="utf-8"))
    except OSError as exc:
        raise CorpusError(f"cannot read {path}: {exc.strerror or exc}") from None
    except tomllib.TOMLDecodeError as exc:
        raise CorpusError(f"{path} is not valid TOML: {exc}") from None
    entries: list[RepoEntry] = []
    seen: set[str] = set()
    for item in data.get("repo", []):
        name, tier = item.get("name"), item.get("tier")
        if not isinstance(name, str) or not valid_repo(name):
            raise CorpusError(f"{path}: invalid repository name {name!r}")
        if tier not in TIERS:
            raise CorpusError(f"{path}: {name}: tier must be one of {', '.join(TIERS)}")
        if name in seen:
            raise CorpusError(f"{path}: {name} is listed twice")
        seen.add(name)
        entries.append(RepoEntry(name, tier))
    return entries


# --- results ------------------------------------------------------------------------------------


def latest_results_dir(results_root: Path) -> Path | None:
    """The newest ``results/<date>/`` that holds a ``summary.json``."""
    if not results_root.is_dir():
        return None
    runs = sorted(
        p for p in results_root.iterdir() if p.is_dir() and (p / "summary.json").is_file()
    )
    return runs[-1] if runs else None


def read_json(path: Path) -> Any:
    """Parse a JSON file, raising ``CorpusError`` with the path on any problem."""
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except OSError as exc:
        raise CorpusError(f"cannot read {path}: {exc.strerror or exc}") from None
    except json.JSONDecodeError as exc:
        raise CorpusError(f"{path} is not valid JSON: {exc}") from None


def write_json(path: Path, data: Any) -> None:
    """Write JSON atomically (sorted keys, so runs diff cleanly)."""
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(json.dumps(data, indent=2, sort_keys=True, ensure_ascii=False) + "\n", "utf-8")
    tmp.replace(path)


# --- labels.toml --------------------------------------------------------------------------------

LABELS = ("tp", "fp", "benign-context", "reported")


@dataclass(frozen=True)
class Label:
    """A triaged finding. ``reported`` labels carry nothing but the fingerprint: the repository is
    never named in a public file."""

    fingerprint: str
    label: str
    rule: str = ""
    severity: str = ""
    repo: str = ""
    reason: str = ""
    test: str = ""


def load_labels(path: Path) -> dict[str, Label]:
    """``labels.toml`` keyed by fingerprint. An ``fp`` without a ``test`` is refused here."""
    if not path.exists():
        return {}
    try:
        data = tomllib.loads(path.read_text(encoding="utf-8"))
    except tomllib.TOMLDecodeError as exc:
        raise CorpusError(f"{path} is not valid TOML: {exc}") from None
    labels: dict[str, Label] = {}
    for item in data.get("label", []):
        fp, kind = item.get("fingerprint"), item.get("label")
        if not isinstance(fp, str) or not re.fullmatch(f"[0-9a-f]{{{FINGERPRINT_CHARS}}}", fp):
            raise CorpusError(f"{path}: invalid fingerprint {fp!r}")
        if kind not in LABELS:
            raise CorpusError(f"{path}: {fp}: label must be one of {', '.join(LABELS)}")
        if fp in labels:
            raise CorpusError(f"{path}: {fp} is labelled twice")
        label = Label(
            fp,
            kind,
            str(item.get("rule", "")),
            str(item.get("severity", "")),
            str(item.get("repo", "")),
            str(item.get("reason", "")),
            str(item.get("test", "")),
        )
        if kind == "reported" and (label.repo or label.reason):
            raise CorpusError(f"{path}: {fp}: a 'reported' label must not name the repository")
        labels[fp] = label
    return labels


def format_label(label: Label) -> str:
    """One ``[[label]]`` block for appending to ``labels.toml``."""
    lines = ["[[label]]", f'fingerprint = "{label.fingerprint}"', f'label = "{label.label}"']
    if label.label != "reported":
        for key in ("rule", "severity", "repo", "reason", "test"):
            value = getattr(label, key)
            if value:
                lines.append(f"{key} = {toml_string(value)}")
    elif label.rule:
        lines.append(f"rule = {toml_string(label.rule)}")
    return "\n".join(lines) + "\n"


def test_exists(spec: str, repo_root: Path = REPO_ROOT) -> bool:
    """Whether ``tests/x.py::name`` (or ``::Class::name``) names a test that exists. The path must
    stay inside ``repo_root``."""
    path_part, *names = spec.split("::")
    if not path_part or not names or Path(path_part).is_absolute() or ".." in Path(path_part).parts:
        return False
    file = repo_root / path_part
    try:
        text = file.read_text(encoding="utf-8")
    except OSError:
        return False
    return all(
        re.search(rf"^\s*(?:async\s+)?(?:def|class)\s+{re.escape(n)}\b", text, re.M) for n in names
    )
