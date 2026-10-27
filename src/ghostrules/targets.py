"""Which files ghostrules scans, and how it finds them. Extend the glob lists below."""

from __future__ import annotations

import os
import re
import sys
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from functools import cache
from pathlib import Path

from ghostrules.models import Kind

INSTRUCTION_GLOBS: tuple[str, ...] = (
    "AGENTS.md",
    "**/AGENTS.md",
    "AGENT.md",
    "CLAUDE.md",
    "CLAUDE.local.md",
    "**/CLAUDE.md",
    ".claude/commands/**/*.md",
    ".claude/agents/**/*.md",
    ".claude/skills/**/*.md",
    "**/SKILL.md",
    ".cursorrules",
    ".cursor/rules/**/*.mdc",
    ".cursor/rules/**/*.md",
    ".github/copilot-instructions.md",
    ".github/instructions/**/*.instructions.md",
    ".github/prompts/**/*.prompt.md",
    ".github/chatmodes/**/*.md",
    ".windsurfrules",
    ".windsurf/rules/**",
    ".clinerules",
    ".clinerules/**",
    ".roo/rules*/**",
    ".roorules",
    "GEMINI.md",
    ".gemini/**/*.md",
    ".junie/guidelines.md",
    ".kiro/steering/**/*.md",
    ".continue/rules/**",
    "CONVENTIONS.md",
)

CONFIG_GLOBS: tuple[str, ...] = (
    ".mcp.json",
    "mcp.json",
    ".cursor/mcp.json",
    ".vscode/mcp.json",
    ".gemini/settings.json",
    "claude_desktop_config.json",
    ".roo/mcp.json",
    ".claude/settings.json",
    ".claude/settings.local.json",
    ".aider.conf.yml",
)

SKIP_DIRS: frozenset[str] = frozenset({".git", "node_modules", ".venv"})
MAX_OTHER_FILE_BYTES = 2 * 1024 * 1024
_BINARY_SNIFF_BYTES = 8192


@dataclass(frozen=True)
class Candidate:
    """A file selected for scanning. ``rel`` is the display path (POSIX separators)."""

    abs_path: Path
    rel: str
    kind: Kind


def glob_to_regex(pattern: str) -> re.Pattern[str]:
    """Compile a glob into a case-insensitive regex over POSIX relative paths.

    ``*`` and ``?`` stay within one path segment; ``**/`` matches zero or more directories and a
    trailing ``**`` matches everything below.
    """
    out: list[str] = []
    i = 0
    while i < len(pattern):
        if pattern.startswith("**/", i):
            out.append("(?:.*/)?")
            i += 3
        elif pattern.startswith("**", i):
            out.append(".*")
            i += 2
        elif pattern[i] == "*":
            out.append("[^/]*")
            i += 1
        elif pattern[i] == "?":
            out.append("[^/]")
            i += 1
        else:
            out.append(re.escape(pattern[i]))
            i += 1
    return re.compile("".join(out), re.IGNORECASE)


@cache
def _compile_all(globs: tuple[str, ...]) -> tuple[re.Pattern[str], ...]:
    return tuple(glob_to_regex(g) for g in globs)


def matches_any(rel: str, globs: Iterable[str]) -> bool:
    """True if the relative POSIX path matches any glob."""
    return any(p.fullmatch(rel) for p in _compile_all(tuple(globs)))


def classify_path(rel: str, extra_targets: Iterable[str] = ()) -> Kind | None:
    """Kind of a known target file, or ``None`` if the path is not a default/extra target."""
    if matches_any(rel, INSTRUCTION_GLOBS) or matches_any(rel, extra_targets):
        return "instructions"
    if matches_any(rel, CONFIG_GLOBS):
        return "config"
    return None


def looks_binary(path: Path) -> bool:
    """Heuristic: a NUL byte in the first 8 KiB means binary."""
    try:
        with path.open("rb") as handle:
            return b"\x00" in handle.read(_BINARY_SNIFF_BYTES)
    except OSError:
        return True


def _acceptable_other(path: Path) -> bool:
    """Whether an unrecognised file is worth scanning under ``--all-files``."""
    try:
        if path.stat().st_size > MAX_OTHER_FILE_BYTES:
            return False
    except OSError:
        return False
    return not looks_binary(path)


def discover(
    root: Path,
    *,
    all_files: bool = False,
    exclude: Iterable[str] = (),
    extra_targets: Iterable[str] = (),
) -> list[Candidate]:
    """Find scannable files under ``root`` (or the single file ``root``).

    Symlinks are never followed. Known targets are always selected whatever their size or
    content, so padding a file cannot hide it; the size and binary checks only gate the
    unrecognised files that ``all_files`` adds. An explicitly named file is always scanned.
    """
    excludes = tuple(exclude)
    extras = tuple(extra_targets)
    if root.is_file():
        kind = classify_path(root.name, extras) or "other"
        return [Candidate(root, root.name, kind)]

    found: list[Candidate] = []
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        dirnames[:] = sorted(d for d in dirnames if d not in SKIP_DIRS)
        base = Path(dirpath)
        for name in sorted(filenames):
            path = base / name
            if path.is_symlink():
                continue
            rel = path.relative_to(root).as_posix()
            if excludes and matches_any(rel, excludes):
                continue
            known = classify_path(rel, extras)
            if known is not None:
                found.append(Candidate(path, rel, known))
            elif all_files and _acceptable_other(path):
                found.append(Candidate(path, rel, "other"))
    return found


def _desktop_config(home: Path, platform: str, env: Mapping[str, str]) -> Path:
    if platform == "darwin":
        return home / "Library/Application Support/Claude/claude_desktop_config.json"
    if platform == "win32":
        appdata = env.get("APPDATA")
        base = Path(appdata) if appdata else home / "AppData/Roaming"
        return base / "Claude/claude_desktop_config.json"
    return home / ".config/Claude/claude_desktop_config.json"


def home_targets(
    home: Path | None = None,
    platform: str | None = None,
    env: Mapping[str, str] | None = None,
) -> list[Candidate]:
    """User-level agent configs that exist on this machine (``--home``). Missing ones are skipped.

    Unlike repo scanning, symlinks are accepted here: dotfile managers commonly symlink these.
    """
    home = home or Path.home()
    platform = platform or sys.platform
    env = os.environ if env is None else env
    entries: list[tuple[Path, Kind]] = [
        (home / ".claude.json", "config"),
        (home / ".claude/settings.json", "config"),
        (home / ".claude/CLAUDE.md", "instructions"),
        (home / ".cursor/mcp.json", "config"),
        (home / ".codeium/windsurf/mcp_config.json", "config"),
        (home / ".gemini/settings.json", "config"),
        (home / ".codex/config.toml", "config"),
        (_desktop_config(home, platform, env), "config"),
    ]
    out: list[Candidate] = []
    for path, kind in entries:
        if not path.is_file():
            continue
        try:
            label = "~/" + path.relative_to(home).as_posix()
        except ValueError:
            label = path.as_posix()
        out.append(Candidate(path, label, kind))
    return out
