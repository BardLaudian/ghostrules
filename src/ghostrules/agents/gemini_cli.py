"""Gemini CLI: ``GEMINI.md`` files, global, along the path to the cwd, and just in time.

Source of truth: ``docs/AGENT_MODELS.md`` (section gemini-cli), from
https://geminicli.com/docs/cli/gemini-md/ and the configuration reference, read 2026-10-29. The CLI
concatenates ``~/.gemini/GEMINI.md``, the files in the workspace directories and their parents, and
the files in directories a tool touches ("up to a trusted root"). ``@file.md`` lines import other
files (relative and absolute paths); depth, cycles and code blocks are not documented, so every
import is marked unverified. ``context.fileName`` in ``settings.json`` changes the file names.
"""

from __future__ import annotations

import json
from typing import Any

from ghostrules.agents.base import (
    Builder,
    ContextGraph,
    ImportPolicy,
    chain_dirs,
    join,
    parent_dir,
    render_raw,
    under,
)
from ghostrules.agents.repo import Repo
from ghostrules.jsonloc import strip_jsonc

NAME = "gemini-cli"
DEFAULT_NAMES = ("GEMINI.md",)


def _settings(repo: Repo | None) -> dict[str, Any]:
    raw = repo.read(".gemini/settings.json") if repo is not None else None
    if raw is None:
        return {}
    try:
        data = json.loads(strip_jsonc(raw.decode("utf-8", errors="replace")))
    except ValueError:
        return {}
    return data if isinstance(data, dict) else {}


def context_names(*sources: Repo | None) -> tuple[str, ...]:
    """``context.fileName`` from the project settings, else the user's, else ``GEMINI.md``."""
    for repo in sources:
        context = _settings(repo).get("context")
        name = context.get("fileName") if isinstance(context, dict) else None
        if isinstance(name, str) and name:
            return (name,)
        if isinstance(name, list) and all(isinstance(n, str) for n in name) and name:
            return tuple(name)
    return DEFAULT_NAMES


class GeminiCli:
    """The Gemini CLI loading model."""

    name = NAME

    def build(
        self,
        repo: Repo,
        *,
        cwd: str = "",
        target: str | None = None,
        home: Repo | None = None,
    ) -> ContextGraph:
        """The context files of a Gemini CLI session in ``cwd``, working on ``target``."""
        policy = ImportPolicy(max_hops=4, all_unverified=True, external_needs_approval=True)
        b = Builder(NAME, repo, cwd=cwd, target=target, policy=policy)
        names = context_names(repo, home)
        if home is not None:
            for name in names:
                rel = join(".gemini", name)
                if home.kind(rel) is not None:
                    b.add_file(home, rel, "always", "global instructions in ~/.gemini", render_raw)
        chain = chain_dirs(cwd)
        for directory in chain:
            where = f"{directory}/" if directory else "the repository root"
            for name in names:
                rel = join(directory, name)
                if repo.kind(rel) is not None:
                    b.add_file(repo, rel, "always", f"{name} in {where}", render_raw)
        for rel in repo.files:
            directory = parent_dir(rel)
            if rel.rsplit("/", 1)[-1] in names and directory not in chain and directory:
                b.add_file(
                    repo, rel, "on_demand", f"{rel.rsplit('/', 1)[-1]} for work under {directory}/",
                    render_raw, condition=directory + "/",
                    matches=None if target is None else under(target, directory),
                )  # fmt: skip
        b.graph.notes.append(
            "Files in a directory load when a tool touches it (up to a trusted root); "
            "import depth, cycles and code blocks are undocumented, so imports are unverified"
        )
        return b.finish()
