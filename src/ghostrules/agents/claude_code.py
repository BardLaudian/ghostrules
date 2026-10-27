"""Claude Code: CLAUDE.md files, AGENTS.md fallback, ``.claude/rules`` and ``@`` imports.

Source of truth: ``docs/v0.2/AGENT_MODELS.md`` (section claude-code), from
https://code.claude.com/docs/en/memory.
"""

from __future__ import annotations

from ghostrules.agents.base import (
    Builder,
    ContextGraph,
    ImportPolicy,
    Load,
    Render,
    chain_dirs,
    join,
    render_dropping_frontmatter,
    render_raw,
    render_stripping_comments,
    under,
)
from ghostrules.agents.repo import Repo
from ghostrules.globs import matches_any, split_patterns
from ghostrules.markdown_utils import parse_frontmatter

NAME = "claude-code"
MODES = ("claude-md-or-agents-md", "claude-md-and-agents-md", "claude-md", "managed-only")
DEFAULT_MODE = MODES[0]
MAX_FILE_BYTES = 4 * 1024 * 1024
ON_DEMAND_LIMIT_CHARS = 40_000

_CLAUDE_FILES = ("CLAUDE.md", ".claude/CLAUDE.md", "CLAUDE.local.md")
_AGENTS_FILES = ("AGENTS.md", ".claude/AGENTS.md")
_RULES_DIR = ".claude/rules"


def _policy() -> ImportPolicy:
    return ImportPolicy(
        max_hops=4,
        uncertain_hops=frozenset({5}),
        external_needs_approval=True,
        external_base="cwd",
        render_imported=render_raw,
        max_bytes=MAX_FILE_BYTES,
        large_chars=ON_DEMAND_LIMIT_CHARS,
    )


def _rule_base(rel: str) -> str | None:
    """Directory holding the ``.claude`` folder of a rule file, or ``None`` if it is not a rule."""
    if not rel.endswith(".md"):
        return None
    if rel.startswith(_RULES_DIR + "/"):
        return ""
    marker = "/" + _RULES_DIR + "/"
    index = rel.find(marker)
    return rel[:index] if index >= 0 else None


class ClaudeCode:
    """The Claude Code loading model."""

    name = NAME

    def __init__(self, instructions_mode: str = DEFAULT_MODE) -> None:
        if instructions_mode not in MODES:
            raise ValueError(f"unknown instructions mode {instructions_mode!r}")
        self.mode = instructions_mode

    def build(
        self,
        repo: Repo,
        *,
        cwd: str = "",
        target: str | None = None,
        home: Repo | None = None,
    ) -> ContextGraph:
        """The context of a Claude Code session started in ``cwd``, working on ``target``."""
        b = Builder(NAME, repo, cwd=cwd, target=target, policy=_policy())
        if self.mode == "managed-only":
            b.graph.notes.append(
                'instructions mode "managed-only": project and user files are not loaded at launch'
            )
        else:
            if home is not None:
                self._user(b, home)
            self._ancestors(b)
            self._rules(b)
        self._on_demand(b)
        b.graph.notes.append(
            "directories above the repository root, managed policy files, claudeMdExcludes and "
            "--add-dir are not examined"
        )
        return b.finish()

    # --- user level --------------------------------------------------------------------------

    def _user(self, b: Builder, home: Repo) -> None:
        b.add_file(
            home,
            ".claude/CLAUDE.md",
            "always",
            "user CLAUDE.md",
            render_stripping_comments,
            follow=True,
        )
        for rel in home.files:
            if rel.startswith(_RULES_DIR + "/") and rel.endswith(".md"):
                self._add_rule(b, home, rel, base="", user=True)

    # --- project files at launch -------------------------------------------------------------

    def _ancestors(self, b: Builder) -> None:
        repo, cwd = b.repo, b.cwd
        chain = chain_dirs(cwd)
        has_claude = any(repo.kind(join(d, f)) for d in chain for f in _CLAUDE_FILES)
        for d in chain:
            where = "working directory" if d == cwd else f"ancestor {d or 'root'}"
            for name in _CLAUDE_FILES:
                rel = join(d, name)
                if repo.kind(rel) is None:
                    continue
                b.add_file(repo, rel, "always", f"{name} in {where}", render_stripping_comments)
            for name in _AGENTS_FILES:
                rel = join(d, name)
                if repo.kind(rel) is None:
                    continue
                self._agents_file(b, rel, where, has_claude)

    def _agents_file(self, b: Builder, rel: str, where: str, has_claude: bool) -> None:
        repo = b.repo
        reason = f"{rel} in {where}"
        if b.has(repo.label(rel)):
            return  # already loaded through an import: not read twice
        if self.mode == "claude-md":
            b.add_blocked(repo, rel, reason, 'instructions mode "claude-md"')
        elif self.mode == "claude-md-or-agents-md" and has_claude:
            b.add_blocked(
                repo,
                rel,
                reason,
                'a CLAUDE.md exists (default "claude-md-or-agents-md"): AGENTS.md is not read',
            )
        else:  # a file already loaded through an import is a "duplicate" and is not added twice
            b.add_file(repo, rel, "always", reason, render_raw)

    # --- rules -------------------------------------------------------------------------------

    def _rules(self, b: Builder) -> None:
        repo = b.repo
        if _RULES_DIR in repo.linked_dirs:
            b.add_blocked(
                repo,
                _RULES_DIR,
                "rules directory",
                "symlinked directory: not followed",
                symlink_target=repo.symlink_target(_RULES_DIR) or "?",
                leaves_tree=repo.link_leaves_tree(_RULES_DIR),
            )
        for rel in repo.files:
            base = _rule_base(rel)
            if base is None:
                continue
            self._add_rule(b, repo, rel, base=base, user=False)

    def _add_rule(self, b: Builder, repo: Repo, rel: str, *, base: str, user: bool) -> None:
        cwd, target = b.cwd, b.target
        if not user and base and not (under(base, cwd) or under(cwd, base)):
            return  # a sibling directory's rules never load for this session
        raw = repo.read(rel)
        front = parse_frontmatter(raw.decode("utf-8", errors="replace")) if raw else None
        patterns: list[str] = []
        notes: list[str] = []
        if front is not None and front.unparsed:
            notes.append("front matter did not parse: the rule loads without 'paths'")
        elif front is not None and isinstance(front.data.get("paths"), (str, list)):
            patterns = split_patterns(front.data["paths"])  # type: ignore[arg-type]
        nested = bool(base) and base != cwd and under(base, cwd)
        ancestor = bool(base) and base != cwd and under(cwd, base)
        if ancestor:
            notes.append("rules in an ancestor directory are not documented: assumed to load")
        inside = target is not None and under(target, base)
        if patterns:
            rel_target = target or ""
            local = rel_target[len(base) + 1 :] if base else rel_target
            matches = None if target is None else (inside and matches_any(patterns, local))
            joined = ", ".join(patterns)
            self._rule_entry(
                b, repo, rel, "conditional", f"paths: {joined}", joined, matches, notes
            )
        elif nested:
            matches = None if target is None else inside
            reason = f"loads when the agent touches files under {base}/"
            self._rule_entry(b, repo, rel, "on_demand", reason, base + "/", matches, notes)
        else:
            self._rule_entry(b, repo, rel, "always", "rule without paths", "", None, notes)

    @staticmethod
    def _rule_entry(
        b: Builder,
        repo: Repo,
        rel: str,
        load: Load,
        reason: str,
        condition: str,
        matches: bool | None,
        notes: list[str],
    ) -> None:
        b.add_file(
            repo,
            rel,
            load,
            reason,
            render_dropping_frontmatter,
            condition=condition,
            matches=matches,
            note="; ".join(notes),
            unverified=bool(notes),
        )

    # --- on demand ---------------------------------------------------------------------------

    def _on_demand(self, b: Builder) -> None:
        repo, cwd, target = b.repo, b.cwd, b.target
        names = () if self.mode == "managed-only" else _CLAUDE_FILES
        dirs: dict[str, list[str]] = {}
        for rel in repo.files:
            name = _claude_name(rel)
            if name is None:
                continue
            d = rel[: -len(name)].rstrip("/")
            if d and d != cwd and under(d, cwd) and (name in names or name in _AGENTS_FILES):
                dirs.setdefault(d, []).append(rel)
        for d in sorted(dirs, key=lambda x: (x.count("/"), x)):
            has_claude = any(_claude_name(r) in _CLAUDE_FILES for r in dirs[d])
            matches = None if target is None else under(target, d)
            reason = f"loads when the agent touches files under {d}/"
            for rel in sorted(dirs[d], key=_on_demand_order):
                if _claude_name(rel) in _AGENTS_FILES:
                    if self.mode == "claude-md" or (
                        self.mode == "claude-md-or-agents-md" and has_claude
                    ):
                        b.add_blocked(
                            repo,
                            rel,
                            reason,
                            "a CLAUDE.md exists in this directory: AGENTS.md is not read",
                        )
                        continue
                    render: Render = render_raw
                else:
                    render = render_stripping_comments
                b.add_file(
                    repo, rel, "on_demand", reason, render, condition=d + "/", matches=matches
                )


def _claude_name(rel: str) -> str | None:
    for name in sorted((*_CLAUDE_FILES, *_AGENTS_FILES), key=len, reverse=True):
        if rel == name or rel.endswith("/" + name):
            return name
    return None


def _on_demand_order(rel: str) -> tuple[int, str]:
    name = _claude_name(rel)
    order = (*_CLAUDE_FILES, *_AGENTS_FILES)
    return (order.index(name) if name else len(order), rel)
