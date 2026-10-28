"""The AGENTS.md convention (https://agents.md).

Documented: "the closest AGENTS.md to the edited file wins". Not documented: whether files higher
in the tree are read as well. The nearest file is verified; the others on the path are included
as unverified so a security scan does not miss them. No imports, no transforms.
"""

from __future__ import annotations

from ghostrules.agents.base import (
    Builder,
    ContextGraph,
    ImportPolicy,
    chain_dirs,
    join,
    parent_dir,
    render_raw,
)
from ghostrules.agents.repo import Repo

NAME = "generic"


class Generic:
    """The generic AGENTS.md model."""

    name = NAME

    def build(
        self,
        repo: Repo,
        *,
        cwd: str = "",
        target: str | None = None,
        home: Repo | None = None,
    ) -> ContextGraph:
        """The AGENTS.md files for work on ``target`` (or in ``cwd`` when there is none)."""
        policy = ImportPolicy(imports_from=lambda path: False)
        b = Builder(NAME, repo, cwd=cwd, target=target, policy=policy)
        base = parent_dir(target) if target is not None else cwd
        chain = chain_dirs(base)
        present = [d for d in chain if repo.kind(join(d, "AGENTS.md")) is not None]
        nearest = present[-1] if present else None
        for d in present:
            rel = join(d, "AGENTS.md")
            if d == nearest:
                b.add_file(
                    repo,
                    rel,
                    "always",
                    "nearest AGENTS.md to the edited file",
                    lambda text: render_raw(text, comments_unverified=False),
                    follow=False,
                )
            else:
                b.add_file(
                    repo,
                    rel,
                    "always",
                    "AGENTS.md higher in the tree",
                    lambda text: render_raw(text, comments_unverified=False),
                    follow=False,
                    note="agents.md documents only the nearest file; included to be safe",
                    unverified=True,
                )
        for rel in repo.files:
            if rel == "AGENTS.md" or rel.endswith("/AGENTS.md"):
                d = parent_dir(rel)
                if d not in chain:
                    b.add_file(
                        repo,
                        rel,
                        "on_demand",
                        f"AGENTS.md for work under {d}/",
                        lambda text: render_raw(text, comments_unverified=False),
                        follow=False,
                        condition=d + "/",
                        matches=None if target is None else target.startswith(d + "/"),
                    )
        return b.finish()
