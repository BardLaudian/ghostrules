"""OpenAI Codex CLI: ``AGENTS.override.md`` / ``AGENTS.md`` from the root down to the cwd.

Source of truth: ``docs/AGENT_MODELS.md`` (section codex), from
https://developers.openai.com/codex/guides/agents-md and the config reference, read 2026-10-29.
Per directory Codex uses at most one file: ``AGENTS.override.md``, else ``AGENTS.md``, else a name
from ``project_doc_fallback_filenames`` (a user-level setting); empty files are skipped; the user's
``~/.codex`` directory contributes its first non-empty file; the combined project text stops at
``project_doc_max_bytes`` (32 KiB by default). The docs mention no imports and no transforms.
"""

from __future__ import annotations

from typing import Any

from ghostrules._compat import tomllib
from ghostrules.agents.base import (
    Builder,
    ContextGraph,
    ImportPolicy,
    chain_dirs,
    join,
    render_raw,
)
from ghostrules.agents.repo import Repo

NAME = "codex"
DEFAULT_MAX_BYTES = 32 * 1024
_NAMES = ("AGENTS.override.md", "AGENTS.md")


def user_config(home: Repo | None) -> dict[str, Any]:
    """``~/.codex/config.toml`` as a dict (empty when there is none or it does not parse)."""
    raw = home.read(".codex/config.toml") if home is not None else None
    if raw is None:
        return {}
    try:
        return tomllib.loads(raw.decode("utf-8", errors="replace"))
    except tomllib.TOMLDecodeError:
        return {}


class Codex:
    """The Codex CLI loading model (project scope only; trust and profiles live in config)."""

    name = NAME

    def build(
        self,
        repo: Repo,
        *,
        cwd: str = "",
        target: str | None = None,
        home: Repo | None = None,
    ) -> ContextGraph:
        """The instruction chain of a Codex session started in ``cwd``."""
        b = Builder(NAME, repo, cwd=cwd, target=target, policy=ImportPolicy(imports_from=_never))
        config = user_config(home)
        fallbacks = [
            n for n in config.get("project_doc_fallback_filenames", []) if isinstance(n, str)
        ]
        configured = config.get("project_doc_max_bytes")
        cap = configured if isinstance(configured, int) and configured > 0 else DEFAULT_MAX_BYTES
        if home is not None:
            self._pick(b, home, ".codex", _NAMES, "global instructions in ~/.codex", None)
        used = [0]
        for directory in chain_dirs(cwd):
            where = f"{directory}/" if directory else "the repository root"
            self._pick(
                b, repo, directory, (*_NAMES, *fallbacks), f"instructions in {where}", (used, cap)
            )
        b.graph.notes.append(
            "Codex builds this chain once per run and reads nothing below the working directory; "
            "project-scoped .codex/ layers load only for trusted projects"
        )
        return b.finish()

    def _pick(
        self,
        b: Builder,
        repo: Repo,
        directory: str,
        names: tuple[str, ...] | list[str],
        reason: str,
        budget: tuple[list[int], int] | None,
    ) -> None:
        """Load the first non-empty of ``names`` in ``directory``; the rest are not read."""
        chosen: str | None = None
        for name in names:
            rel = join(directory, name)
            if repo.kind(rel) is None:
                continue
            if chosen is not None:
                b.add_blocked(repo, rel, reason, f"ignored: {chosen} is used in this directory")
                continue
            data = repo.read(rel)
            if data is None or not data.strip():
                b.add_blocked(repo, rel, reason, "empty file: Codex skips empty files")
                continue
            chosen = name
            if budget is None:
                b.add_file(repo, rel, "always", reason, render_raw, follow=False)
                continue
            used, cap = budget
            if used[0] >= cap:
                b.add_blocked(
                    repo, rel, reason,
                    f"past project_doc_max_bytes ({cap // 1024} KiB): Codex stops adding files",
                )  # fmt: skip
                continue
            truncated = used[0] + len(data) > cap
            used[0] = min(cap, used[0] + len(data))
            b.add_file(
                repo, rel, "always", reason, render_raw, follow=False,
                note=f"may be truncated at project_doc_max_bytes ({cap // 1024} KiB)"
                if truncated
                else "",
                unverified=truncated,
            )  # fmt: skip


def _never(_path: str) -> bool:
    return False
