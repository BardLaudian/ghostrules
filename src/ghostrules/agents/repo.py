"""Read-only view of a directory tree for the context engine.

``kind`` never follows a symlink: a link (to a file, or as a parent directory of the path asked for)
is reported as ``"symlink"``. ``resolve`` follows links by hand, hop by hop, and only inside the
tree: a link whose final target is a regular file in the tree is an *alias* the agent reads under
the link's name; anything that leaves the tree, is broken or loops is never read, so the engine
cannot be pointed outside the tree.
"""

from __future__ import annotations

import os
import stat
from dataclasses import dataclass
from functools import cached_property
from pathlib import Path
from typing import Literal

SKIP_DIRS = frozenset({".git", "node_modules", ".venv"})

Kind = Literal["file", "dir", "symlink", "other"]
LinkStatus = Literal["file", "dir", "outside", "broken", "cycle", "too_deep", "missing"]

MAX_LINK_HOPS = 8


@dataclass(frozen=True)
class Resolution:
    """Where a path ends up once its symlinks are followed inside the tree.

    ``target`` is the repo-relative path of the final file or directory (``""`` when it is the root
    or the path did not resolve), ``hops`` the links crossed, ``written`` the text of the first one.
    """

    status: LinkStatus
    target: str = ""
    hops: tuple[str, ...] = ()
    written: str = ""


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
        real = tuple(files)
        for link in sorted(linked_dirs):  # files under an in-tree directory link are aliases
            res = self.resolve(link)
            if res.status != "dir":
                continue
            under = res.target + "/" if res.target else ""
            files.extend(f"{link}/{f[len(under) :]}" for f in real if f.startswith(under))
        return tuple(sorted(set(files))), frozenset(linked_dirs)

    @property
    def files(self) -> tuple[str, ...]:
        """Every file (and file-level symlink) in the tree, as sorted POSIX relative paths. Files
        under a directory link that stays in the tree are listed under the link's name too."""
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

    def resolve(self, rel: str) -> Resolution:
        """Follow the symlinks in ``rel`` by hand, never leaving the tree.

        Every hop is resolved against the directory the link lives in; at most ``MAX_LINK_HOPS``
        links are crossed and none twice. ``outside`` means a hop points out of the tree (absolute
        or through ``..``), ``broken`` a missing target, ``cycle`` a loop, ``too_deep`` a chain
        that is too long. Nothing outside the tree is ever opened or examined.
        """
        if not rel or rel.startswith("/") or ".." in rel.split("/"):
            return Resolution("missing")
        pending = rel.split("/")
        done: list[str] = []
        hops: list[str] = []
        written = ""
        while pending:
            part = pending.pop(0)
            if part in ("", "."):
                continue
            if part == "..":
                if not done:
                    return Resolution("outside", hops=tuple(hops), written=written)
                done.pop()
                continue
            current = "/".join([*done, part])
            try:
                mode = os.lstat(self.root / current).st_mode
            except OSError:
                status: LinkStatus = "broken" if hops else "missing"
                return Resolution(status, hops=tuple(hops), written=written)
            if not stat.S_ISLNK(mode):
                if pending and not stat.S_ISDIR(mode):
                    return Resolution("broken", hops=tuple(hops), written=written)
                done.append(part)
                continue
            if current in hops:
                return Resolution("cycle", hops=tuple(hops), written=written)
            if len(hops) >= MAX_LINK_HOPS:
                return Resolution("too_deep", hops=tuple(hops), written=written)
            hops.append(current)
            try:
                target = os.readlink(self.root / current)
            except OSError:
                return Resolution("broken", hops=tuple(hops), written=written)
            written = written or target
            moved = self._link_parts(target)
            if moved is None:
                return Resolution("outside", hops=tuple(hops), written=written)
            absolute, parts = moved
            if absolute:
                done = []
            pending = [*parts, *pending]
        final = "/".join(done)
        try:
            mode = os.lstat(self.root / final if final else self.root).st_mode
        except OSError:
            return Resolution("broken", hops=tuple(hops), written=written)
        if stat.S_ISREG(mode):
            return Resolution("file", final, tuple(hops), written)
        if stat.S_ISDIR(mode):
            return Resolution("dir", final, tuple(hops), written)
        return Resolution("broken", hops=tuple(hops), written=written)

    def _link_parts(self, target: str) -> tuple[bool, list[str]] | None:
        """A link's target as path parts; ``(True, parts)`` for an absolute target inside the tree,
        ``None`` for one outside it."""
        if os.name == "nt":
            target = target.replace("\\", "/")
        if not (target.startswith("/") or os.path.isabs(target)):
            return False, target.split("/")
        normal = os.path.normpath(target)
        for root in {os.path.normpath(self.root), os.path.realpath(self.root)}:
            if normal == root:
                return True, []
            if normal.startswith(root + os.sep):
                return True, normal[len(root) + 1 :].replace(os.sep, "/").split("/")
        return None

    def is_file(self, rel: str) -> bool:
        """Whether ``rel`` is a regular file, or a link that ends at one inside the tree."""
        kind = self.kind(rel)
        return kind == "file" or (kind == "symlink" and self.resolve(rel).status == "file")

    def size(self, rel: str) -> int:
        """Size in bytes of a regular file (or of the file a link resolves to)."""
        target = self.resolve(rel).target if self.kind(rel) == "symlink" else rel
        return os.lstat(self.root / target).st_size

    def read(self, rel: str) -> bytes | None:
        """The bytes of a regular file, or of the in-tree file a symlink resolves to; ``None`` if
        it is neither or cannot be read."""
        kind = self.kind(rel)
        if kind == "symlink":
            res = self.resolve(rel)
            rel, kind = res.target, "file" if res.status == "file" else None
        if kind != "file":
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
