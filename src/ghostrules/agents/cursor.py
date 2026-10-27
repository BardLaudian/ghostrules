"""Cursor: ``.cursor/rules/*.mdc``, the legacy ``.cursorrules`` and AGENTS.md.

Source of truth: ``docs/v0.2/AGENT_MODELS.md`` (section cursor), from https://cursor.com/docs/context/rules.
``@file`` references inside rules are not expanded by Cursor, so this model has no imports.
"""

from __future__ import annotations

from ghostrules.agents.base import (
    Builder,
    ContextGraph,
    ImportPolicy,
    Load,
    chain_dirs,
    join,
    render_dropping_frontmatter,
    render_raw,
    under,
)
from ghostrules.agents.repo import Repo
from ghostrules.globs import matches_any, split_patterns
from ghostrules.markdown_utils import parse_frontmatter

NAME = "cursor"
_RULES_DIR = ".cursor/rules"


class Cursor:
    """The Cursor loading model (project rules only; User and Team Rules live outside the repo)."""

    name = NAME

    def build(
        self,
        repo: Repo,
        *,
        cwd: str = "",
        target: str | None = None,
        home: Repo | None = None,
    ) -> ContextGraph:
        """The context of a Cursor chat in ``cwd`` about ``target``."""
        policy = ImportPolicy(imports_from=lambda path: False)
        b = Builder(NAME, repo, cwd=cwd, target=target, policy=policy)
        if repo.kind(".cursorrules") is not None:
            b.add_file(
                repo,
                ".cursorrules",
                "always",
                "legacy .cursorrules",
                render_raw,
                note="legacy file: not mentioned in the current Rules docs (unverified)",
                unverified=True,
                follow=False,
            )
        if _RULES_DIR in repo.linked_dirs:
            b.add_blocked(repo, _RULES_DIR, "rules directory", "symlinked directory: not followed")
        for rel in repo.files:
            if rel.startswith(_RULES_DIR + "/"):
                self._rule(b, rel)
        self._agents_md(b)
        b.graph.notes.append("User Rules and Team Rules are configured outside the repository")
        return b.finish()

    def _rule(self, b: Builder, rel: str) -> None:
        repo, target = b.repo, b.target
        if rel.endswith(".md"):
            b.add_blocked(
                repo, rel, "rule file", "Cursor ignores .md files in .cursor/rules (use .mdc)"
            )
            return
        if not rel.endswith(".mdc"):
            return
        raw = repo.read(rel)
        front = parse_frontmatter(raw.decode("utf-8", errors="replace")) if raw else None
        data = front.data if front else {}
        notes: list[str] = []
        if front is not None and front.unparsed:
            notes.append("front matter is not strict YAML: Cursor's parser may differ (unverified)")
        always = data.get("alwaysApply") is True
        globs = split_patterns(g) if isinstance((g := data.get("globs")), (str, list)) else []
        description = data.get("description")
        load: Load
        condition = ""
        matches: bool | None = None
        if always:
            load, reason = "always", "alwaysApply: true"
        elif globs:
            load, condition = "conditional", ", ".join(globs)
            reason = f"globs: {condition}"
            matches = None if target is None else matches_any(globs, target)
        elif isinstance(description, str) and description:
            load, reason = "agent_decides", "description only: the agent decides"
        else:
            load, reason = "manual", "no alwaysApply, globs or description: only when @-mentioned"
        b.add_file(
            repo,
            rel,
            load,
            reason,
            lambda text: render_dropping_frontmatter(text, lenient=True),
            follow=False,
            condition=condition,
            matches=matches,
            note="; ".join(notes),
            unverified=bool(notes),
        )

    def _agents_md(self, b: Builder) -> None:
        repo, cwd, target = b.repo, b.cwd, b.target
        chain = chain_dirs(cwd)
        for d in chain:
            rel = join(d, "AGENTS.md")
            if repo.kind(rel) is not None:
                b.add_file(repo, rel, "always", "AGENTS.md", render_raw, follow=False)
        for rel in repo.files:
            if rel.endswith("/AGENTS.md"):
                d = rel[: -len("/AGENTS.md")]
                if d not in chain and under(d, cwd):
                    matches = None if target is None else under(target, d)
                    b.add_file(
                        repo,
                        rel,
                        "on_demand",
                        f"nested AGENTS.md: applies to files under {d}/",
                        render_raw,
                        follow=False,
                        condition=d + "/",
                        matches=matches,
                    )
