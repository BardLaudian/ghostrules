"""GitHub Copilot CLI: repository and agent files, path-specific instructions and ``@`` references.

Source of truth: ``docs/v0.2/AGENT_MODELS.md`` (section copilot-cli), from GitHub Docs "Adding
custom instructions for GitHub Copilot CLI". Several details are undocumented (the base of relative
imports, the depth limit, code-span handling, comment stripping) and are modelled conservatively:
imported entries are marked unverified.
"""

from __future__ import annotations

import posixpath

from ghostrules.agents.base import (
    Builder,
    ContextGraph,
    ImportPolicy,
    chain_dirs,
    join,
    render_dropping_frontmatter,
    render_raw,
    under,
)
from ghostrules.agents.repo import Repo
from ghostrules.globs import matches_any, split_patterns
from ghostrules.markdown_utils import parse_frontmatter

NAME = "copilot-cli"
_AGENT_FILES = ("AGENTS.md", "CLAUDE.md", ".claude/CLAUDE.md", "GEMINI.md")
_REPO_WIDE = ".github/copilot-instructions.md"
_INSTRUCTIONS_DIR = ".github/instructions"


def _can_import(rel: str) -> bool:
    """``@`` references are expanded in copilot-instructions.md, AGENTS.md and CLAUDE.md only."""
    return rel.endswith(_REPO_WIDE) or posixpath.basename(rel) in ("AGENTS.md", "CLAUDE.md")


def _policy() -> ImportPolicy:
    return ImportPolicy(
        max_hops=4,
        all_unverified=True,
        external_needs_approval=False,
        external_base="repo",
        imports_from=_can_import,
        render_imported=render_raw,
    )


def _location_files(d: str) -> list[str]:
    return [join(d, _REPO_WIDE), *(join(d, n) for n in _AGENT_FILES)]


class CopilotCli:
    """The Copilot CLI loading model."""

    name = NAME

    def build(
        self,
        repo: Repo,
        *,
        cwd: str = "",
        target: str | None = None,
        home: Repo | None = None,
    ) -> ContextGraph:
        """The context of a Copilot CLI session started in ``cwd``, working on ``target``."""
        b = Builder(NAME, repo, cwd=cwd, target=target, policy=_policy())
        if home is not None:
            self._user(b, home)
        chain = chain_dirs(cwd)
        for d in chain:
            where = "working directory" if d == cwd else f"intermediate directory {d or 'root'}"
            if d == "":
                where = "repository root" if cwd != "" else "repository root and working directory"
            for rel in _location_files(d):
                if repo.kind(rel) is not None:
                    b.add_file(repo, rel, "always", f"{rel} in the {where}", render_raw)
        self._below_cwd(b)
        self._path_instructions(b, chain)
        b.graph.notes.append(
            "COPILOT_CUSTOM_INSTRUCTIONS_DIRS and instructions disabled with /instructions are "
            "not examined"
        )
        return b.finish()

    def _user(self, b: Builder, home: Repo) -> None:
        b.add_file(
            home, ".copilot/copilot-instructions.md", "always", "user instructions", render_raw
        )
        for rel in home.files:
            if rel.startswith(".copilot/instructions/") and rel.endswith(".instructions.md"):
                self._instructions_file(b, home, rel, "user path-specific instructions")

    def _below_cwd(self, b: Builder) -> None:
        repo, cwd, target = b.repo, b.cwd, b.target
        found: dict[str, list[str]] = {}
        for rel in repo.files:
            for name in (_REPO_WIDE, *_AGENT_FILES):
                if rel.endswith("/" + name):
                    d = rel[: -len(name)].rstrip("/")
                    if d and d != cwd and under(d, cwd):
                        found.setdefault(d, []).append(rel)
                    break
        for d in sorted(found, key=lambda x: (x.count("/"), x)):
            matches = None if target is None else under(target, d)
            reason = f"loads when the agent works on files under {d}/"
            for rel in sorted(found[d]):
                b.add_file(
                    repo, rel, "on_demand", reason, render_raw, condition=d + "/", matches=matches
                )

    def _path_instructions(self, b: Builder, chain: list[str]) -> None:
        repo, cwd = b.repo, b.cwd
        # standard locations only: the root, the working directory and anything below it
        for rel in repo.files:
            if not rel.endswith(".instructions.md"):
                continue
            marker = "/" + _INSTRUCTIONS_DIR + "/"
            if rel.startswith(_INSTRUCTIONS_DIR + "/"):
                d = ""
            elif marker in rel:
                d = rel[: rel.index(marker)]
            else:
                continue
            if d in chain and d not in ("", cwd):
                continue  # intermediate directories are not searched
            if d and not under(d, cwd):
                continue
            self._instructions_file(b, repo, rel, "path-specific instructions")

    def _instructions_file(self, b: Builder, repo: Repo, rel: str, what: str) -> None:
        raw = repo.read(rel)
        front = parse_frontmatter(raw.decode("utf-8", errors="replace")) if raw else None
        apply_to = front.data.get("applyTo") if front else None
        notes: list[str] = []
        exclude = front.data.get("excludeAgent") if front else None
        if isinstance(exclude, str) and exclude:
            notes.append(f"excludeAgent: {exclude} (effect on the CLI is not documented)")
        if front is not None and front.unparsed:
            notes.append("front matter did not parse as strict YAML")
        patterns = split_patterns(apply_to) if isinstance(apply_to, (str, list)) else []
        target = b.target
        if patterns:
            joined = ", ".join(patterns)
            matches = None if target is None else matches_any(patterns, target)
            b.add_file(
                repo,
                rel,
                "conditional",
                f"applyTo: {joined}",
                render_dropping_frontmatter,
                condition=joined,
                matches=matches,
                note="; ".join(notes),
                unverified=front is not None and front.unparsed,
                follow=False,
            )
        else:
            notes.append("no applyTo: not applied automatically (unverified)")
            b.add_file(
                repo,
                rel,
                "manual",
                f"{what} without applyTo",
                render_dropping_frontmatter,
                note="; ".join(notes),
                unverified=True,
                follow=False,
            )
