"""Per-file numbers for the study: which agent files a clone has and how big they are.

Only counts, hashes and repo-relative names are produced, never a file's text. Symbolic links are
inspected with ``lstat`` and never followed.
"""

from __future__ import annotations

import hashlib
import os
import re
from collections.abc import Iterable
from pathlib import Path, PureWindowsPath
from typing import Any

from common import safe_text

from ghostrules.targets import classify_path

EXTRA_TARGETS = (".claude/rules/**/*.md",)
SKIP_DIRS = frozenset({".git", "node_modules", ".venv", "venv", "__pycache__"})
MAX_FILES = 2000
MAX_READ = 2 * 1024 * 1024
_HTML_COMMENT = re.compile(r"<!--")


def agent_paths(clone: Path) -> list[str]:
    """Repo-relative POSIX paths of the agent files under ``clone`` (no symlinked directories)."""
    found: list[str] = []
    for folder, dirs, names in os.walk(clone, followlinks=False):
        dirs[:] = sorted(d for d in dirs if d not in SKIP_DIRS)
        base = Path(folder).relative_to(clone)
        for name in sorted(names):
            rel = (base / name).as_posix()
            if classify_path(rel, EXTRA_TARGETS):
                found.append(rel)
            if len(found) >= MAX_FILES:
                return found
    return found


def file_stats(clone: Path, rel: str, kind: str) -> dict[str, Any] | None:
    """Numbers for one file, or ``None`` when it does not exist. ``kind`` is ``agent`` for a file
    in the target list and ``imported`` for one only reached through an import."""
    path = clone / rel
    try:
        info = path.lstat()
    except OSError:
        return None
    out: dict[str, Any] = {"path": rel, "kind": kind, "symlink": path.is_symlink()}
    if out["symlink"]:
        raw = os.readlink(path)
        target = os.path.normpath(os.path.join(os.path.dirname(rel), raw))
        # A leading slash is rooted on Windows too, but os.path.isabs() says no there since 3.13.
        rooted = os.path.isabs(raw) or raw.startswith(("/", "\\")) or PureWindowsPath(raw).drive
        inside = not rooted and not target.startswith("..")
        out["link_target"] = Path(target).as_posix() if inside else None
        return out
    out["size"] = info.st_size
    if info.st_size > MAX_READ or not path.is_file():
        return out
    data = path.read_bytes()
    out["lines"] = data.count(b"\n") + (1 if data and not data.endswith(b"\n") else 0)
    out["sha"] = hashlib.sha256(data).hexdigest()[:16]
    out["html_comments"] = len(_HTML_COMMENT.findall(data.decode("utf-8", "replace")))
    return out


def collect(clone: Path, context_paths: Iterable[str]) -> list[dict[str, Any]]:
    """Stats for every agent file of the clone plus every other file an agent context reaches."""
    agents = set(agent_paths(clone))
    rest = sorted(set(context_paths) - agents)
    rows = [file_stats(clone, p, "agent") for p in sorted(agents)]
    rows += [file_stats(clone, p, "imported") for p in rest[:MAX_FILES]]
    out = [r for r in rows if r]
    for row in out:  # names come from an untrusted clone: make them printable
        row["path"] = safe_text(row["path"])
        if row.get("link_target"):
            row["link_target"] = safe_text(row["link_target"])
    return out
