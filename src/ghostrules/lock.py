"""``.ghostrules.lock``: pin what agents read, and review every change to it.

The lock records, for each modelled agent, every file in its context (session start plus every
conditional and on-demand file): where it is, how it is reached, a hash of the file and a hash of
the text the agent actually receives. ``lock --check`` recomputes it and reports the difference.

It is a *visibility* control, not a guarantee: the lock lives in the repository, so a pull request
can update it too. What it guarantees is that any change to what an agent reads shows up as an
explicit lock diff, with invisible characters revealed.

The file is deterministic: sorted keys, no timestamps, hashes taken after CRLF is normalised to LF.
Each file also stores a short fingerprint of every line of the seen text (``lines``), which is what
lets a check show *which lines are new* without keeping the text itself in the lock.
"""

from __future__ import annotations

import difflib
import hashlib
import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Literal

from ghostrules import __version__
from ghostrules.agents import ContextEntry, Repo, get_model
from ghostrules.agents.claude_code import DEFAULT_MODE
from ghostrules.config import Config
from ghostrules.contextscan import is_excluded
from ghostrules.targets import discover

LOCK_VERSION = 1
LOCK_FILENAME = ".ghostrules.lock"
MAX_FINGERPRINT_LINES = 5000
_FINGERPRINT_CHARS = 16


class LockError(Exception):
    """The lock file is missing, unreadable or not a ghostrules lock."""


@dataclass(frozen=True)
class LockEntry:
    """A file in one agent's context, as recorded in the lock.

    ``via`` is the chain of importing *paths* (no line numbers, so adding a line to CLAUDE.md does
    not churn every file it imports). Hashes are ``None`` for entries ghostrules does not read
    (symlinks, external or sensitive imports, files the agent skips).
    """

    path: str
    via: tuple[str, ...]
    load: str
    conditions: tuple[str, ...]
    raw_sha256: str | None
    seen_sha256: str | None
    lines: str | None

    @property
    def key(self) -> tuple[str, tuple[str, ...]]:
        """Identity of the entry within an agent: the file and how it is reached."""
        return self.path, self.via


@dataclass(frozen=True)
class LockConfig:
    """An MCP or agent settings file (hashed, never modelled)."""

    path: str
    sha256: str
    lines: str | None


@dataclass
class Lock:
    """The parsed lock file."""

    agents: dict[str, list[LockEntry]]
    configs: list[LockConfig]
    generator: str = f"ghostrules {__version__}"
    version: int = LOCK_VERSION


@dataclass
class Snapshot:
    """A freshly computed lock plus the text behind it (needed to show what changed)."""

    lock: Lock
    entries: dict[tuple[str, str, tuple[str, ...]], ContextEntry] = field(default_factory=dict)
    config_text: dict[str, str] = field(default_factory=dict)


# --- building -----------------------------------------------------------------------------------


def _sha(data: bytes) -> str:
    return hashlib.sha256(data.replace(b"\r\n", b"\n")).hexdigest()


def fingerprint(text: str) -> str | None:
    """One short hash per line of ``text``, space separated (``None`` if it has too many lines)."""
    lines = text.replace("\r\n", "\n").split("\n")
    if lines and lines[-1] == "":
        lines.pop()
    if len(lines) > MAX_FINGERPRINT_LINES:
        return None
    return " ".join(
        hashlib.sha256(line.encode("utf-8", errors="surrogateescape")).hexdigest()[
            :_FINGERPRINT_CHARS
        ]
        for line in lines
    )


def _via_paths(entry: ContextEntry) -> tuple[str, ...]:
    return tuple(step.rsplit(":", 1)[0] for step in entry.via)


def _record(entry: ContextEntry) -> LockEntry:
    readable = entry.readable
    return LockEntry(
        path=entry.path,
        via=_via_paths(entry),
        load=entry.load,
        conditions=(entry.condition,) if entry.condition else (),
        raw_sha256=entry.raw_sha256 if readable else None,
        seen_sha256=entry.seen_sha256 if readable else None,
        lines=fingerprint(entry.text) if readable else None,
    )


def build_snapshot(
    root: Path, config: Config, *, instructions_mode: str = DEFAULT_MODE
) -> Snapshot:
    """Compute the lock for the repository at ``root`` (session at the root, no user files)."""
    repo = Repo(root)
    agents: dict[str, list[LockEntry]] = {}
    entries: dict[tuple[str, str, tuple[str, ...]], ContextEntry] = {}
    for name in config.agents:
        graph = get_model(name, instructions_mode=instructions_mode).build(repo, cwd="", home=None)
        records = []
        for entry in graph.entries:
            if is_excluded(entry, config.exclude):
                continue
            record = _record(entry)
            records.append(record)
            entries[(name, record.path, record.via)] = entry
        agents[name] = sorted(records, key=lambda r: r.key)
    configs: list[LockConfig] = []
    config_text: dict[str, str] = {}
    for cand in discover(root, exclude=config.exclude, extra_targets=config.extra_targets):
        if cand.kind != "config":
            continue
        data = cand.abs_path.read_bytes()
        text = data.decode("utf-8", errors="surrogateescape")
        config_text[cand.rel] = text
        configs.append(LockConfig(cand.rel, _sha(data), fingerprint(text)))
    configs.sort(key=lambda c: c.path)
    return Snapshot(Lock(agents, configs), entries, config_text)


# --- file format --------------------------------------------------------------------------------


def _entry_dict(e: LockEntry) -> dict[str, Any]:
    return {
        "path": e.path,
        "via": list(e.via),
        "load": e.load,
        "conditions": list(e.conditions),
        "raw_sha256": e.raw_sha256,
        "seen_sha256": e.seen_sha256,
        "lines": e.lines,
    }


def to_json(lock: Lock) -> str:
    """The lock as text: sorted keys, two-space indent, trailing newline, ASCII only."""
    data = {
        "lock_version": lock.version,
        "generator": lock.generator,
        "agents": {name: [_entry_dict(e) for e in items] for name, items in lock.agents.items()},
        "configs": [{"path": c.path, "sha256": c.sha256, "lines": c.lines} for c in lock.configs],
    }
    return json.dumps(data, indent=2, sort_keys=True, ensure_ascii=True) + "\n"


def _need(data: Any, kind: type, what: str) -> Any:
    if not isinstance(data, kind):
        raise LockError(f"invalid lock file: {what} must be a {kind.__name__}")
    return data


def _opt_str(value: Any, what: str) -> str | None:
    if value is not None and not isinstance(value, str):
        raise LockError(f"invalid lock file: {what} must be a string or null")
    return value


def parse_lock(text: str) -> Lock:
    """Parse lock text, raising ``LockError`` on anything unexpected."""
    try:
        data = json.loads(text)
    except json.JSONDecodeError as exc:
        raise LockError(f"invalid lock file: {exc}") from None
    _need(data, dict, "the top level")
    if data.get("lock_version") != LOCK_VERSION:
        raise LockError(
            f"unsupported lock_version {data.get('lock_version')!r} (this ghostrules reads "
            f"{LOCK_VERSION}); regenerate it with: ghostrules lock"
        )
    agents: dict[str, list[LockEntry]] = {}
    for name, items in _need(data.get("agents"), dict, "'agents'").items():
        records = []
        for item in _need(items, list, f"agents.{name}"):
            _need(item, dict, f"an entry of agents.{name}")
            records.append(
                LockEntry(
                    path=_need(item.get("path"), str, "path"),
                    via=tuple(_need(item.get("via", []), list, "via")),
                    load=_need(item.get("load"), str, "load"),
                    conditions=tuple(_need(item.get("conditions", []), list, "conditions")),
                    raw_sha256=_opt_str(item.get("raw_sha256"), "raw_sha256"),
                    seen_sha256=_opt_str(item.get("seen_sha256"), "seen_sha256"),
                    lines=_opt_str(item.get("lines"), "lines"),
                )
            )
        agents[name] = records
    configs = []
    for item in _need(data.get("configs", []), list, "'configs'"):
        _need(item, dict, "a config entry")
        configs.append(
            LockConfig(
                _need(item.get("path"), str, "path"),
                _need(item.get("sha256"), str, "sha256"),
                _opt_str(item.get("lines"), "lines"),
            )
        )
    generator = data.get("generator")
    return Lock(agents, configs, generator if isinstance(generator, str) else "unknown")


def read_lock(path: Path) -> Lock:
    """Read and parse a lock file."""
    try:
        text = path.read_text(encoding="utf-8")
    except FileNotFoundError:
        raise LockError(f"no lock file at {path} (create it with: ghostrules lock)") from None
    except OSError as exc:
        raise LockError(f"cannot read {path}: {exc.strerror or exc}") from None
    return parse_lock(text)


# --- comparing ----------------------------------------------------------------------------------

ChangeKind = Literal["added", "removed", "changed", "hidden"]


@dataclass(frozen=True)
class Hunk:
    """Lines of the seen text that are new, and how many old ones went away."""

    added: tuple[tuple[int, str], ...]
    removed_count: int
    removed_range: tuple[int, int] | None


@dataclass
class Change:
    """One difference between the lock and the repository.

    ``agents`` are the agents it applies to. ``entry`` is the current state (for added/changed
    entries) and ``old`` the recorded one (removed/changed).
    """

    kind: ChangeKind
    path: str
    via: tuple[str, ...]
    agents: list[str]
    details: list[str] = field(default_factory=list)
    entry: ContextEntry | None = None
    old: LockEntry | None = None
    hunks: list[Hunk] | None = None


@dataclass
class ConfigChange:
    """A config or settings file that was added, removed or edited."""

    kind: Literal["added", "removed", "changed"]
    path: str
    hunks: list[Hunk] | None = None


@dataclass
class LockDiff:
    """Everything that differs, ready to render."""

    changes: list[Change] = field(default_factory=list)
    configs: list[ConfigChange] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)
    old_generator: str = ""
    new_generator: str = ""
    files: int = 0

    @property
    def empty(self) -> bool:
        """Whether the lock is up to date."""
        return (
            not self.changes
            and not self.configs
            and not any(n.startswith("agents:") for n in self.notes)
        )

    @property
    def visible_changes(self) -> list[Change]:
        """Changes to text some agent receives, or to what loads."""
        return [c for c in self.changes if c.kind != "hidden"]

    @property
    def hidden_changes(self) -> list[Change]:
        """Changes that only touch text the agent strips before the model sees it."""
        return [c for c in self.changes if c.kind == "hidden"]


def line_hunks(
    old_lines: str | None, text: str, line_map: tuple[int, ...] = ()
) -> list[Hunk] | None:
    """What is new in ``text`` compared with the recorded line fingerprints.

    Added lines come with their number in the original file (``line_map`` undoes comment
    stripping). Removed lines are only counted: the lock does not keep their text.
    ``None`` when either side is too large to compare.
    """
    new_lines = text.replace("\r\n", "\n").split("\n")
    if new_lines and new_lines[-1] == "":
        new_lines.pop()
    new_tokens = fingerprint(text)
    if old_lines is None or new_tokens is None:
        return None
    old = old_lines.split()
    new = new_tokens.split()
    hunks: list[Hunk] = []
    matcher = difflib.SequenceMatcher(None, old, new, autojunk=False)
    for tag, i1, i2, j1, j2 in matcher.get_opcodes():
        if tag == "equal":
            continue
        added = tuple(
            (line_map[j] if j < len(line_map) else j + 1, new_lines[j]) for j in range(j1, j2)
        )
        hunks.append(Hunk(added, i2 - i1, (i1 + 1, i2) if i2 > i1 else None))
    return hunks


def _condition_text(e: LockEntry) -> str:
    return ", ".join(e.conditions)


def _compare(old: LockEntry, new: LockEntry, agent: str, snap: Snapshot) -> Change | None:
    details: list[str] = []
    if old.load != new.load:
        details.append(f"load: {old.load} → {new.load}")
    if old.conditions != new.conditions:
        details.append(
            f"condition: {_condition_text(old) or 'none'} → {_condition_text(new) or 'none'}"
        )
    current = snap.entries[(agent, new.path, new.via)]
    if old.seen_sha256 != new.seen_sha256 or details:
        change = Change("changed", new.path, new.via, [agent], details, current, old)
        if old.seen_sha256 != new.seen_sha256 and new.seen_sha256 is not None:
            before = old.lines if old.seen_sha256 is not None else ""
            change.hunks = line_hunks(before, current.text, current.line_map)
        return change
    if old.raw_sha256 != new.raw_sha256:
        return Change("hidden", new.path, new.via, [agent], [], current, old)
    return None


def _merge(changes: list[Change]) -> list[Change]:
    """One change per file and kind: agents that are affected the same way are listed together."""
    merged: dict[tuple[object, ...], Change] = {}
    for c in changes:
        sig = (
            c.kind,
            c.path,
            c.via,
            tuple(c.details),
            c.old.seen_sha256 if c.old else None,
            c.entry.seen_sha256 if c.entry else None,
            c.old.load if c.old else None,
        )
        if sig in merged:
            merged[sig].agents.append(c.agents[0])
        else:
            merged[sig] = c
    order = {"added": 0, "changed": 1, "removed": 2, "hidden": 3}
    return sorted(merged.values(), key=lambda c: (order[c.kind], c.path, c.via))


def diff_lock(old: Lock, snap: Snapshot) -> LockDiff:
    """Compare a recorded lock with the repository as it is now."""
    new = snap.lock
    diff = LockDiff(old_generator=old.generator, new_generator=new.generator)
    diff.files = len({e.path for items in new.agents.values() for e in items})
    only_old = sorted(set(old.agents) - set(new.agents))
    only_new = sorted(set(new.agents) - set(old.agents))
    if only_old or only_new:
        diff.notes.append(
            "agents: the lock models "
            + (", ".join(sorted(old.agents)) or "none")
            + " but the configuration models "
            + (", ".join(sorted(new.agents)) or "none")
            + "; regenerate it with: ghostrules lock"
        )
    raw: list[Change] = []
    for agent in sorted(set(old.agents) & set(new.agents)):
        before = {e.key: e for e in old.agents[agent]}
        after = {e.key: e for e in new.agents[agent]}
        for key in sorted(after.keys() - before.keys()):
            entry = snap.entries[(agent, key[0], key[1])]
            raw.append(Change("added", key[0], key[1], [agent], [], entry, None))
        for key in sorted(before.keys() - after.keys()):
            raw.append(Change("removed", key[0], key[1], [agent], [], None, before[key]))
        for key in sorted(before.keys() & after.keys()):
            change = _compare(before[key], after[key], agent, snap)
            if change is not None:
                raw.append(change)
    diff.changes = _merge(raw)
    for change in diff.changes:
        if change.kind == "added" and change.entry is not None and change.entry.seen_sha256:
            change.hunks = line_hunks("", change.entry.text, change.entry.line_map)
    _diff_configs(old, snap, diff)
    return diff


def _diff_configs(old: Lock, snap: Snapshot, diff: LockDiff) -> None:
    before = {c.path: c for c in old.configs}
    after = {c.path: c for c in snap.lock.configs}
    for path in sorted(after.keys() - before.keys()):
        diff.configs.append(ConfigChange("added", path, line_hunks("", snap.config_text[path])))
    for path in sorted(before.keys() - after.keys()):
        diff.configs.append(ConfigChange("removed", path))
    for path in sorted(before.keys() & after.keys()):
        if before[path].sha256 != after[path].sha256:
            hunks = line_hunks(before[path].lines, snap.config_text[path])
            diff.configs.append(ConfigChange("changed", path, hunks))
