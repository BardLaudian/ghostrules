"""Read-only view of a directory tree for the context engine.

Nothing here follows a symlink: a link (to a file, or as a parent directory of the path asked for)
is reported as ``"symlink"`` and never read, so the engine cannot be pointed outside the tree.
"""

from __future__ import annotations

import os
import stat
from functools import cached_property
from pathlib import Path
from typing import Literal

SKIP_DIRS = frozenset({".git", "node_modules", ".venv"})

Kind = Literal["file", "dir", "symlink", "other"]


class Repo:
    """A tree rooted at ``root``. ``prefix`` is prepended to paths shown for it (``"~/"`` for the
    user's home), so entries from different trees do not collide."""

    def __init__(self, root: Path, prefix: str = "") -> None:
        self.root = root
        self.prefix = prefix

    def label(self, rel: str) -> str:
        """The path as shown to users."""
        return self.prefix + rel

    @cached_property
    def _walk(self) -> tuple[tuple[str, ...], frozenset[str]]:
        files: list[str] = []
        linked_dirs: set[str] = set()
        for dirpath, dirnames, filenames in os.walk(self.root, followlinks=False):
            base = Path(dirpath)
            rel_base = base.relative_to(self.root).as_posix()
            prefix = "" if rel_base == "." else rel_base + "/"
            kept = []
            for name in sorted(dirnames):
                if name in SKIP_DIRS:
                    continue
                if (base / name).is_symlink():
                    linked_dirs.add(prefix + name)
                else:
                    kept.append(name)
            dirnames[:] = kept
            files.extend(prefix + name for name in sorted(filenames))
        return tuple(sorted(files)), frozenset(linked_dirs)

    @property
    def files(self) -> tuple[str, ...]:
        """Every file (and file-level symlink) in the tree, as sorted POSIX relative paths."""
        return self._walk[0]

    @property
    def linked_dirs(self) -> frozenset[str]:
        """Directories that are symlinks (never descended into)."""
        return self._walk[1]

    def kind(self, rel: str) -> Kind | None:
        """What ``rel`` is, or ``None`` if it does not exist. A path through a symlink is a
        ``"symlink"``."""
        if not rel or rel.startswith("/") or ".." in rel.split("/"):
            return None
        current = self.root
        parts = rel.split("/")
        for index, part in enumerate(parts):
            current = current / part
            try:
                mode = os.lstat(current).st_mode
            except (FileNotFoundError, NotADirectoryError):
                return None
            except OSError:
                return "other"
            if stat.S_ISLNK(mode):
                return "symlink"
            last = index == len(parts) - 1
            if last:
                if stat.S_ISREG(mode):
                    return "file"
                return "dir" if stat.S_ISDIR(mode) else "other"
            if not stat.S_ISDIR(mode):
                return None
        return None

    def size(self, rel: str) -> int:
        """Size in bytes of a regular file."""
        return os.lstat(self.root / rel).st_size

    def read(self, rel: str) -> bytes | None:
        """The bytes of a regular file, or ``None`` if it is not one or cannot be read."""
        if self.kind(rel) != "file":
            return None
        try:
            return (self.root / rel).read_bytes()
        except OSError:
            return None

    def symlink_target(self, rel: str) -> str | None:
        """Where a symlink points (as written), without following it."""
        try:
            return os.readlink(self.root / rel)
        except OSError:
            return None

    def link_leaves_tree(self, rel: str) -> bool:
        """Whether a symlink's target resolves outside this tree (or cannot be resolved)."""
        target = self.symlink_target(rel)
        if target is None:
            return True
        resolved = os.path.normpath(os.path.join(os.path.dirname(self.root / rel), target))
        root = os.path.normpath(self.root)
        return not (resolved == root or resolved.startswith(root + os.sep))
