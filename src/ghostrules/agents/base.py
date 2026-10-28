"""Context engine core: entries, the import graph and the builder every agent model uses.

An agent model decides *which files* an agent loads and *when*; this module does the shared work:
reading files safely, applying the agent's text transforms, following ``@`` imports (relative to the
importing file, bounded depth, cycle-safe, nothing outside the tree is ever read) and hashing.
See ``docs/AGENT_MODELS.md`` for the rules each model implements.
"""

from __future__ import annotations

import hashlib
import posixpath
import re
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Literal, NamedTuple, Protocol

from ghostrules.agents.repo import MAX_LINK_HOPS, Repo, Resolution
from ghostrules.imports import Import, find_imports
from ghostrules.markdown_utils import (
    RemovedBlock,
    parse_frontmatter,
    strip_frontmatter,
    strip_html_comments,
)
from ghostrules.sensitive import is_sensitive_path

Load = Literal["always", "conditional", "on_demand", "agent_decides", "manual", "blocked"]
ImportStatus = Literal[
    "loaded",  # the file is in the context
    "duplicate",  # already in the context through another path
    "missing",
    "directory",
    "quoted",  # a quoted path, which agents do not import
    "external",  # outside the working directory / tree: recorded, never read
    "blocked",  # the agent refuses it (e.g. Copilot CLI and absolute paths)
    "symlink",  # a symlink: never followed
    "too_large",
    "depth",  # deeper than the agent's limit
    "cycle",
    "sensitive",  # a secrets file: the agent would load it, ghostrules never reads it
]


@dataclass(frozen=True)
class ContextEntry:
    """One file an agent would load. ``text`` is what the model receives after the agent's
    transforms (CRLF normalised to LF); ``via`` is the import chain (``"CLAUDE.md:12"``, ...)."""

    path: str
    load: Load
    reason: str
    agent: str
    via: tuple[str, ...] = ()
    transforms: tuple[str, ...] = ()
    text: str = ""
    raw_sha256: str = ""
    seen_sha256: str = ""
    note: str = ""
    readable: bool = True
    unverified: bool = False
    condition: str = ""
    matches: bool | None = None
    line_map: tuple[int, ...] = ()
    removed: tuple[RemovedBlock, ...] = ()
    symlink_target: str = ""
    leaves_tree: bool = False
    alias_of: str = ""  # a symlink to a file in the tree: the agent reads that file as this name
    link_problem: str = ""  # why a symlink is not followed: outside, broken, cycle or too_deep

    @property
    def hop(self) -> int:
        """Import depth: 0 for files the agent loads by itself."""
        return len(self.via)


@dataclass(frozen=True)
class ImportEdge:
    """One ``@path`` occurrence. ``target`` is the repo-relative path when the import resolved
    inside the tree, otherwise the path as written."""

    source: str
    target: str
    written: str
    line: int
    column: int
    status: ImportStatus
    hop: int
    note: str = ""
    unverified: bool = False
    looks_like_path: bool = True
    certain: bool = True
    in_comment: bool = False
    outside_tree: bool = False
    hint: str = ""


@dataclass
class ContextGraph:
    """The context of one agent: ordered entries, import edges and import cycles."""

    agent: str
    cwd: str
    target: str | None
    entries: list[ContextEntry] = field(default_factory=list)
    edges: list[ImportEdge] = field(default_factory=list)
    cycles: list[tuple[str, ...]] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)

    def get(self, path: str) -> ContextEntry | None:
        """The entry for ``path``, if it is in the context."""
        return next((e for e in self.entries if e.path == path), None)

    def roots(self) -> list[ContextEntry]:
        """Entries the agent loads itself, not through an import."""
        return [e for e in self.entries if not e.via]

    def children(self, path: str) -> list[ImportEdge]:
        """Import edges starting at ``path``, in file order."""
        return [e for e in self.edges if e.source == path]


class Rendered(NamedTuple):
    """The text an agent receives for a file, and how it was derived."""

    text: str
    line_map: tuple[int, ...] = ()
    removed: tuple[RemovedBlock, ...] = ()
    transforms: tuple[str, ...] = ()
    unverified: bool = False
    note: str = ""


Render = Callable[[str], Rendered]


def render_raw(text: str, *, comments_unverified: bool = True) -> Rendered:
    """No transform. When the file holds block-level HTML comments and it is not documented
    whether the agent strips them, the entry is marked unverified (the comment counts as seen)."""
    if comments_unverified and strip_html_comments(text).removed:
        return Rendered(
            text,
            unverified=True,
            note="unverified whether HTML comments are stripped here: kept as seen",
        )
    return Rendered(text)


def render_stripping_comments(text: str) -> Rendered:
    """Claude Code on CLAUDE.md files: block-level HTML comments are stripped."""
    stripped = strip_html_comments(text)
    if not stripped.removed:
        return Rendered(text)
    return Rendered(
        stripped.text,
        stripped.line_map,
        stripped.removed,
        ("strip_html_comments",),
    )


def render_dropping_frontmatter(text: str, *, lenient: bool = False) -> Rendered:
    """Rule files: the front matter is metadata and is removed.

    If it does not parse as strict YAML, Claude Code ignores it (the whole file is kept as text and
    the rule loads without ``paths``); with ``lenient`` (Cursor) it is removed anyway but marked
    unverified.
    """
    front = parse_frontmatter(text)
    if front is None:
        return render_raw(text)
    if front.unparsed and not lenient:
        return Rendered(
            text,
            unverified=True,
            note="front matter did not parse: the agent ignores it and loads the whole file",
        )
    stripped = strip_frontmatter(text)
    inner = render_raw(stripped.text)
    return Rendered(
        stripped.text,
        stripped.line_map,
        stripped.removed,
        ("strip_frontmatter",),
        unverified=front.unparsed or inner.unverified,
        note=inner.note or ("front matter is not strict YAML" if front.unparsed else ""),
    )


@dataclass(frozen=True)
class ImportPolicy:
    """How an agent handles ``@`` imports.

    ``max_hops`` is the deepest hop certain to load; hops in ``uncertain_hops`` are loaded but
    marked unverified; anything deeper is not loaded. ``external_needs_approval`` is Claude Code's
    behaviour (a file outside the working directory loads after approval); otherwise a path
    outside the tree is blocked. ``imports_from`` says which files can contain imports.
    """

    max_hops: int = 4
    uncertain_hops: frozenset[int] = frozenset()
    all_unverified: bool = False
    external_needs_approval: bool = True
    external_base: Literal["cwd", "repo"] = "cwd"
    imports_from: Callable[[str], bool] = lambda path: True  # noqa: E731
    render_imported: Render = render_raw
    max_bytes: int | None = None
    large_chars: int | None = None


class Resolved(NamedTuple):
    """Where an import points: ``repo`` (inside the tree, ``rel`` is the path), ``outside`` (``..``
    out of the tree), ``home`` (``~``) or ``absolute``."""

    kind: Literal["repo", "outside", "home", "absolute"]
    rel: str


_DRIVE = re.compile(r"^[A-Za-z]:/")


def resolve_import(written: str, importer: str) -> Resolved:
    """Resolve ``written`` relative to the importing file (not the working directory).

    ``~`` and absolute paths are recorded, never resolved. Backslashes are read as separators so a
    Windows-style path resolves the same everywhere.
    """
    p = written.replace("\\", "/")
    if p.startswith("~"):
        return Resolved("home", written)
    if p.startswith("/") or _DRIVE.match(p):
        return Resolved("absolute", written)
    joined = posixpath.normpath(posixpath.join(posixpath.dirname(importer), p))
    if joined == ".." or joined.startswith("../"):
        return Resolved("outside", joined)
    return Resolved("repo", joined)


def under(path: str, directory: str) -> bool:
    """Whether ``path`` is ``directory`` or inside it (``directory`` ``""`` is the root)."""
    return directory == "" or path == directory or path.startswith(directory + "/")


def chain_dirs(cwd: str) -> list[str]:
    """Directories from the root down to ``cwd``: ``"a/b"`` gives ``["", "a", "a/b"]``."""
    out = [""]
    for part in (p for p in cwd.split("/") if p):
        out.append(f"{out[-1]}/{part}".lstrip("/"))
    return out


def join(directory: str, name: str) -> str:
    """``directory/name`` without a leading slash for the root."""
    return f"{directory}/{name}" if directory else name


def parent_dir(path: str) -> str:
    """Directory of a repo-relative path (``""`` for the root)."""
    return posixpath.dirname(path)


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


_LINK_PROBLEMS = ("outside", "broken", "cycle", "too_deep")


class Builder:
    """Collects entries and edges for one agent. Models call ``add_file``/``add_blocked``."""

    def __init__(
        self,
        agent: str,
        repo: Repo,
        *,
        cwd: str = "",
        target: str | None = None,
        policy: ImportPolicy | None = None,
    ) -> None:
        self.agent = agent
        self.repo = repo
        self.cwd = cwd
        self.target = target
        self.policy = policy or ImportPolicy()
        self.graph = ContextGraph(agent, cwd, target)
        self._by_path: dict[str, ContextEntry] = {}
        self._by_real: dict[str, str] = {}
        self._stack: list[str] = []

    def has(self, label: str) -> bool:
        """Whether a file (by displayed path) is already in the context."""
        return label in self._by_path

    def loaded_as(self, repo: Repo, rel: str) -> str | None:
        """The name ``rel`` was loaded under (its own, or that of a symlink to it), if any."""
        return self._by_real.get(repo.label(rel))

    # --- adding files ------------------------------------------------------------------------

    def _append(self, entry: ContextEntry) -> ContextEntry:
        self.graph.entries.append(entry)
        self._by_path[entry.path] = entry
        return entry

    def add_blocked(
        self,
        repo: Repo,
        rel: str,
        reason: str,
        note: str,
        *,
        via: tuple[str, ...] = (),
        symlink_target: str = "",
        leaves_tree: bool = False,
        link_problem: str = "",
    ) -> ContextEntry:
        """Record a file the agent skips or refuses, or that ghostrules will not read."""
        return self._append(
            ContextEntry(
                repo.label(rel),
                "blocked",
                reason,
                self.agent,
                via=via,
                note=note,
                readable=False,
                symlink_target=symlink_target,
                leaves_tree=leaves_tree,
                link_problem=link_problem,
            )
        )

    def add_file(
        self,
        repo: Repo,
        rel: str,
        load: Load,
        reason: str,
        render: Render,
        *,
        follow: bool = True,
        condition: str = "",
        matches: bool | None = None,
        note: str = "",
        unverified: bool = False,
        via: tuple[str, ...] = (),
    ) -> tuple[ContextEntry | None, ImportStatus]:
        """Read ``rel``, apply ``render`` and add it (then its imports) to the context.

        Returns the entry (``None`` if the file does not exist or is a directory) and the status
        callers use for an import edge.
        """
        label = repo.label(rel)
        if label in self._by_path:
            return self._by_path[label], "duplicate"
        kind = repo.kind(rel)
        if kind is None:
            return None, "missing"
        if kind == "dir":
            return None, "directory"
        alias_of = ""
        real = rel
        if kind == "symlink":
            res = repo.resolve(rel)
            if res.status == "dir":
                return None, "directory"
            if res.status != "file":
                return self._blocked_link(repo, rel, res, reason, via), "symlink"
            real = alias_of = res.target
            earlier = self._by_real.get(repo.label(real))
            if earlier is not None:  # the file is already in the context under another name
                return self._by_path[earlier], "duplicate"
        elif kind == "other":
            return self.add_blocked(repo, rel, reason, "not a regular file: skipped", via=via), (
                "symlink"
            )
        size_limit = self.policy.max_bytes
        if size_limit is not None and repo.size(real) > size_limit:
            entry = self.add_blocked(
                repo,
                rel,
                reason,
                f"file is over {size_limit // (1024 * 1024)} MiB: skipped",
                via=via,
            )
            return entry, "too_large"
        data = repo.read(rel)
        if data is None:
            entry = self.add_blocked(repo, rel, reason, "cannot be read", via=via)
            return entry, "blocked"
        raw_text = data.decode("utf-8", errors="surrogateescape").replace("\r\n", "\n")
        rendered = render(raw_text)
        notes = [n for n in (note, rendered.note) if n]
        if (
            self.policy.large_chars
            and load in ("on_demand", "conditional")
            and len(rendered.text) > self.policy.large_chars
        ):
            notes.append(
                f"{len(rendered.text)} characters: may be truncated when loaded on demand "
                f"(limit {self.policy.large_chars} on a 200K window)"
            )
        entry = self._append(
            ContextEntry(
                label,
                load,
                reason,
                self.agent,
                via=via,
                transforms=rendered.transforms,
                text=rendered.text,
                raw_sha256=_sha(data.replace(b"\r\n", b"\n")),
                seen_sha256=_sha(rendered.text.encode("utf-8", errors="surrogateescape")),
                note="; ".join(notes),
                unverified=(
                    unverified or rendered.unverified or (self.policy.all_unverified and bool(via))
                ),
                condition=condition,
                matches=matches,
                line_map=rendered.line_map,
                removed=rendered.removed,
                symlink_target=alias_of,
                alias_of=alias_of,
            )
        )
        self._by_real.setdefault(repo.label(real), label)
        if follow and (via or self.policy.imports_from(rel)):
            self._expand(repo, entry, raw_text)
        return entry, "loaded"

    def _blocked_link(
        self, repo: Repo, rel: str, res: Resolution, reason: str, via: tuple[str, ...]
    ) -> ContextEntry:
        """A symlink that is not followed: it leaves the tree, is broken, loops or is too long."""
        written = res.written or repo.symlink_target(rel) or ""
        arrow = f" -> {written}" if written else ""
        why = {
            "outside": " outside the tree: not followed",
            "broken": " is broken: the target does not exist",
            "cycle": " is part of a cycle",
            "too_deep": f" crosses more than {MAX_LINK_HOPS} links",
        }.get(res.status, ": not followed")
        problem = res.status if res.status in _LINK_PROBLEMS else "broken"
        return self.add_blocked(
            repo,
            rel,
            reason,
            f"symlink{arrow}{why}",
            via=via,
            symlink_target=written or "?",
            leaves_tree=res.status == "outside",
            link_problem=problem,
        )

    def note_linked_dir(self, repo: Repo, rel: str, reason: str) -> None:
        """A directory the agent reads that is a symlink: fine inside the tree (its files are
        aliases), recorded as a blocked entry when it leaves the tree, is broken or loops."""
        if repo.kind(rel) != "symlink":
            return
        res = repo.resolve(rel)
        if res.status != "dir":
            self._blocked_link(repo, rel, res, reason, ())

    # --- imports -----------------------------------------------------------------------------

    def _is_external(self, repo: Repo, rel: str) -> bool:
        """Claude Code: outside the working directory. Copilot: outside the repository."""
        if repo.prefix or self.policy.external_base == "repo":
            return False
        return not under(rel, self.cwd)

    def _expand(self, repo: Repo, parent: ContextEntry, raw_text: str) -> None:
        parent_rel = parent.path.removeprefix(repo.prefix)
        self._stack.append(parent.path)
        try:
            for imp in find_imports(raw_text, include_quoted=True):
                self._follow(repo, parent, parent_rel, imp, raw_text)
        finally:
            self._stack.pop()

    def _edge(
        self,
        parent: ContextEntry,
        imp: Import,
        target: str,
        status: ImportStatus,
        note: str = "",
        unverified: bool = False,
        slot: int | None = None,
        outside_tree: bool = False,
        hint: str = "",
    ) -> None:
        edge = ImportEdge(
            parent.path,
            target,
            imp.path,
            imp.line,
            imp.column,
            status,
            parent.hop + 1,
            note,
            unverified or not imp.certain or imp.in_comment,
            imp.looks_like_path,
            imp.certain,
            imp.in_comment,
            outside_tree,
            hint,
        )
        self.graph.edges.insert(len(self.graph.edges) if slot is None else slot, edge)

    def _follow(
        self, repo: Repo, parent: ContextEntry, parent_rel: str, imp: Import, raw_text: str
    ) -> None:
        if imp.quoted:
            self._edge(parent, imp, imp.path, "quoted", "a quoted path is not imported")
            return
        resolved = resolve_import(imp.path, parent_rel)
        hop = parent.hop + 1
        via = (*parent.via, f"{parent.path}:{imp.line}")
        if resolved.kind != "repo":
            if imp.certain:
                self._external(repo, parent, imp, resolved, via)
            return
        rel = resolved.rel
        label = repo.label(rel)
        if not imp.certain and not repo.is_file(rel):
            return  # a loose candidate that is not a file is just text
        if hop > self.policy.max_hops and hop not in self.policy.uncertain_hops:
            self._edge(parent, imp, label, "depth", f"deeper than {self.policy.max_hops} hops")
            return
        if label in self._stack:
            start = self._stack.index(label)
            self.graph.cycles.append((*self._stack[start:], label))
            self._edge(parent, imp, label, "cycle", "import cycle")
            return
        slot = len(self.graph.edges)  # the edge goes before those of the file it loads
        if is_sensitive_path(rel) and repo.kind(rel) is not None:
            self._sensitive(parent, imp, label, via, slot)
            return
        notes: list[str] = []
        uncertain = hop in self.policy.uncertain_hops
        if uncertain:
            notes.append(
                f"hop {hop}: loaded only if the {self.policy.max_hops}-hop limit counts from 0"
            )
        if imp.in_comment:
            notes.append("import inside an HTML comment: unverified whether it is expanded")
        if not imp.certain:
            notes.append("loose '@' (after punctuation): unverified whether it is an import")
        if self._is_external(repo, rel):
            notes.append("external import: requires approval (outside the working directory)")
        entry, status = self.add_file(
            repo,
            rel,
            parent.load,
            f"imported by {parent.path}:{imp.line}",
            self.policy.render_imported,
            condition=parent.condition,
            matches=parent.matches,
            note="; ".join(notes),
            unverified=uncertain or imp.in_comment or not imp.certain,
            via=via,
        )
        hint = self._space_hint(repo, parent_rel, imp, raw_text) if status == "missing" else ""
        self._edge(
            parent,
            imp,
            label,
            status,
            "; ".join(notes),
            unverified=uncertain or self.policy.all_unverified,
            slot=slot,
            hint=hint,
        )

    def _sensitive(
        self, parent: ContextEntry, imp: Import, label: str, via: tuple[str, ...], slot: int
    ) -> None:
        """An import of a secrets file: the agent would load it; ghostrules never reads it."""
        note = "sensitive file: would be loaded into the context; not read by ghostrules"
        if label not in self._by_path:
            self._append(
                ContextEntry(
                    label,
                    parent.load,
                    f"imported by {parent.path}:{imp.line}",
                    self.agent,
                    via=via,
                    note=note,
                    readable=False,
                    condition=parent.condition,
                    matches=parent.matches,
                    unverified=self.policy.all_unverified,
                )
            )
        self._edge(parent, imp, label, "sensitive", note, slot=slot)

    @staticmethod
    def _space_hint(repo: Repo, parent_rel: str, imp: Import, raw_text: str) -> str:
        """If extending the path with the words after it names a file, the author forgot to
        escape a space."""
        line = raw_text.split("\n")[imp.line - 1]
        tail = line[imp.column - 1 + len(imp.raw) :]
        if not tail.startswith(" "):
            return ""
        candidate = imp.path
        for word in tail.split(" ")[1:5]:
            if not word:
                break
            candidate = f"{candidate} {word}"
            for trimmed in (candidate, candidate.rstrip(".,;:!?)")):
                resolved = resolve_import(trimmed, parent_rel)
                if resolved.kind == "repo" and repo.is_file(resolved.rel):
                    escaped = trimmed.replace(" ", "\\ ")
                    return f"the path is cut at an unescaped space; write @{escaped}"
        return ""

    def _external(
        self,
        repo: Repo,
        parent: ContextEntry,
        imp: Import,
        resolved: Resolved,
        via: tuple[str, ...],
    ) -> None:
        """An import that leaves the tree: recorded, never read."""
        user_scope = bool(repo.prefix)
        if self.policy.external_needs_approval:
            note = (
                "outside the tree: not read"
                if user_scope
                else "external import: requires approval; outside the tree, not read"
            )
            load: Load = parent.load
            status: ImportStatus = "external"
        else:
            note = "outside the repository: the agent does not load it"
            load = "blocked"
            status = "blocked"
        label = resolved.rel
        if label not in self._by_path:
            self._append(
                ContextEntry(
                    label,
                    load,
                    f"imported by {parent.path}:{imp.line}",
                    self.agent,
                    via=via,
                    note=note,
                    readable=False,
                    condition=parent.condition,
                    matches=parent.matches,
                    unverified=self.policy.all_unverified,
                )
            )
        self._edge(
            parent,
            imp,
            label,
            status,
            note,
            unverified=self.policy.all_unverified,
            outside_tree=True,
        )

    def finish(self) -> ContextGraph:
        """The completed graph."""
        return self.graph


class AgentModel(Protocol):
    """An agent's loading rules. ``cwd`` and ``target`` are repo-relative POSIX paths (``""`` is
    the root); ``home`` is the user's home as a ``Repo`` with prefix ``~/`` (``--home``)."""

    name: str

    def build(
        self,
        repo: Repo,
        *,
        cwd: str = "",
        target: str | None = None,
        home: Repo | None = None,
    ) -> ContextGraph:
        """The ordered context for a session started in ``cwd`` working on ``target``."""
        ...
