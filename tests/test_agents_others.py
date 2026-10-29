from pathlib import Path

import pytest

from ghostrules.agents import (
    AGENT_NAMES,
    ClaudeCode,
    CopilotCli,
    Cursor,
    Generic,
    Repo,
    get_model,
)
from ghostrules.agents.base import ContextGraph


def make(tmp_path: Path, files: dict[str, str]) -> Repo:
    for rel, content in files.items():
        path = tmp_path / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(content.encode("utf-8"))
    return Repo(tmp_path)


def entry(graph: ContextGraph, path: str):
    found = graph.get(path)
    assert found is not None, f"{path} not in {[e.path for e in graph.entries]}"
    return found


def loads(graph: ContextGraph) -> list[tuple[str, str]]:
    return [(e.path, e.load) for e in graph.entries]


def front(block: str, body: str = "body\n") -> str:
    return f"---\n{block}\n---\n{body}"


def test_registry() -> None:
    assert AGENT_NAMES == ("claude-code", "copilot-cli", "cursor", "generic", "codex", "gemini-cli")
    assert isinstance(get_model("claude-code"), ClaudeCode)
    assert isinstance(get_model("copilot-cli"), CopilotCli)
    assert isinstance(get_model("cursor"), Cursor)
    assert isinstance(get_model("generic"), Generic)
    assert get_model("claude-code", instructions_mode="claude-md").mode == "claude-md"  # type: ignore[attr-defined]
    with pytest.raises(ValueError):
        get_model("vim")


# --- copilot-cli -------------------------------------------------------------------------------


def copilot(tmp_path, files, **kw):
    return CopilotCli().build(make(tmp_path, files), **kw)


def test_copilot_reads_all_the_documented_agent_files(tmp_path) -> None:
    g = copilot(
        tmp_path,
        {
            ".github/copilot-instructions.md": "w",
            "AGENTS.md": "a",
            "CLAUDE.md": "c",
            ".claude/CLAUDE.md": "dc",
            "GEMINI.md": "g",
        },
    )
    assert loads(g) == [
        (".github/copilot-instructions.md", "always"),
        ("AGENTS.md", "always"),
        ("CLAUDE.md", "always"),
        (".claude/CLAUDE.md", "always"),
        ("GEMINI.md", "always"),
    ]


def test_copilot_has_no_precedence_it_is_a_union(tmp_path) -> None:
    g = copilot(tmp_path, {"AGENTS.md": "a", "CLAUDE.md": "c"})
    assert [e.load for e in g.entries] == ["always", "always"]


def test_copilot_standard_locations_root_intermediate_and_cwd(tmp_path) -> None:
    g = copilot(
        tmp_path,
        {"AGENTS.md": "r", "a/AGENTS.md": "mid", "a/b/AGENTS.md": "cwd", "a/b/c/AGENTS.md": "deep"},
        cwd="a/b",
    )
    assert loads(g) == [
        ("AGENTS.md", "always"),
        ("a/AGENTS.md", "always"),
        ("a/b/AGENTS.md", "always"),
        ("a/b/c/AGENTS.md", "on_demand"),
    ]


def test_copilot_nested_directory_matches_the_target(tmp_path) -> None:
    g = copilot(tmp_path, {"sub/AGENTS.md": "s", "other/AGENTS.md": "o"}, target="sub/x.py")
    assert entry(g, "sub/AGENTS.md").matches is True
    assert entry(g, "other/AGENTS.md").matches is False


def test_copilot_path_specific_instructions(tmp_path) -> None:
    files = {
        ".github/instructions/py.instructions.md": front('applyTo: "**/*.py,**/*.pyi"'),
        ".github/instructions/ts.instructions.md": front("applyTo: src/**/*.{ts,tsx}"),
        ".github/instructions/free.instructions.md": front("description: no applyTo"),
        ".github/instructions/sub/ex.instructions.md": front(
            'applyTo: "**"\nexcludeAgent: "code-review"'
        ),
    }
    g = copilot(tmp_path, files, target="src/app/main.py")
    py = entry(g, ".github/instructions/py.instructions.md")
    assert py.load == "conditional" and py.matches is True and py.text == "body\n"
    assert entry(g, ".github/instructions/ts.instructions.md").matches is False
    free = entry(g, ".github/instructions/free.instructions.md")
    assert free.load == "manual" and free.unverified
    ex = entry(g, ".github/instructions/sub/ex.instructions.md")
    assert "excludeAgent: code-review" in ex.note and ex.matches is True


def test_copilot_instructions_in_intermediate_directories_are_not_searched(tmp_path) -> None:
    ins = front('applyTo: "**"')
    g = copilot(
        tmp_path,
        {
            ".github/instructions/r.instructions.md": ins,
            "a/.github/instructions/mid.instructions.md": ins,
            "a/b/.github/instructions/cwd.instructions.md": ins,
            "a/b/c/.github/instructions/deep.instructions.md": ins,
        },
        cwd="a/b",
    )
    paths = [e.path for e in g.entries]
    assert ".github/instructions/r.instructions.md" in paths
    assert "a/b/.github/instructions/cwd.instructions.md" in paths
    assert "a/b/c/.github/instructions/deep.instructions.md" in paths
    assert "a/.github/instructions/mid.instructions.md" not in paths


def test_copilot_imports_work_in_the_allowed_files_only_and_are_unverified(tmp_path) -> None:
    g = copilot(
        tmp_path,
        {
            ".github/copilot-instructions.md": "@../docs/a.md",
            "AGENTS.md": "@docs/b.md",
            "GEMINI.md": "@docs/c.md",
            ".github/instructions/x.instructions.md": front('applyTo: "**"', "@docs/d.md\n"),
            "docs/a.md": "@e.md",
            "docs/b.md": "",
            "docs/c.md": "",
            "docs/d.md": "",
            "docs/e.md": "",
        },
    )
    paths = [e.path for e in g.entries]
    assert "docs/a.md" in paths and "docs/b.md" in paths and "docs/e.md" in paths
    assert "docs/c.md" not in paths and "docs/d.md" not in paths
    assert entry(g, "docs/a.md").unverified and entry(g, "docs/e.md").unverified
    assert not entry(g, ".github/copilot-instructions.md").unverified


@pytest.mark.parametrize("written", ["/etc/passwd", "~/notes.md", "../outside.md"])
def test_copilot_does_not_load_absolute_home_or_outside_imports(tmp_path, written) -> None:
    g = copilot(tmp_path, {"AGENTS.md": f"@{written}\n"})
    e = g.entries[1]
    assert e.load == "blocked" and not e.readable and "does not load" in e.note
    assert [x.status for x in g.edges] == ["blocked"]


def test_copilot_imports_have_no_working_directory_approval(tmp_path) -> None:
    g = copilot(tmp_path, {"sub/AGENTS.md": "@../shared/x.md", "shared/x.md": "x"}, cwd="sub")
    assert "requires approval" not in entry(g, "shared/x.md").note


def test_copilot_html_comments_are_kept_and_flagged_unverified(tmp_path) -> None:
    g = copilot(tmp_path, {"AGENTS.md": "<!-- c -->\nx"})
    assert "<!-- c -->" in g.entries[0].text and g.entries[0].unverified


def test_copilot_user_level_files(tmp_path) -> None:
    home = make(
        tmp_path / "h",
        {
            ".copilot/copilot-instructions.md": "u",
            ".copilot/instructions/a.instructions.md": front('applyTo: "**/*.py"'),
        },
    )
    home = Repo(tmp_path / "h", "~/")
    g = CopilotCli().build(make(tmp_path / "r", {"AGENTS.md": "p"}), home=home, target="x.py")
    assert loads(g) == [
        ("~/.copilot/copilot-instructions.md", "always"),
        ("~/.copilot/instructions/a.instructions.md", "conditional"),
        ("AGENTS.md", "always"),
    ]


# --- cursor ------------------------------------------------------------------------------------


def cursor(tmp_path, files, **kw):
    return Cursor().build(make(tmp_path, files), **kw)


@pytest.mark.parametrize(
    ("block", "load"),
    [
        ("alwaysApply: true", "always"),
        ("alwaysApply: true\nglobs: *.py\ndescription: x", "always"),
        ('alwaysApply: false\nglobs: ["**/*.py"]', "conditional"),
        ('globs: "**/*.py"', "conditional"),
        ("alwaysApply: false\ndescription: Use for database code", "agent_decides"),
        ("alwaysApply: false", "manual"),
        ("description:", "manual"),
    ],
)
def test_cursor_rule_types(tmp_path, block, load) -> None:
    g = cursor(tmp_path, {".cursor/rules/r.mdc": front(block)})
    assert [(e.path, e.load) for e in g.entries] == [(".cursor/rules/r.mdc", load)]
    assert g.entries[0].text == "body\n"


def test_cursor_rule_without_frontmatter_is_manual(tmp_path) -> None:
    g = cursor(tmp_path, {".cursor/rules/r.mdc": "just text\n"})
    assert g.entries[0].load == "manual" and g.entries[0].text == "just text\n"


def test_cursor_globs_match_the_target(tmp_path) -> None:
    files = {".cursor/rules/py.mdc": front('globs: "**/*.py"')}
    assert cursor(tmp_path, files, target="a/b.py").entries[0].matches is True
    assert cursor(tmp_path, files, target="a/b.ts").entries[0].matches is False
    assert cursor(tmp_path, files).entries[0].matches is None


def test_cursor_unquoted_star_glob_is_used_but_flagged(tmp_path) -> None:
    g = cursor(tmp_path, {".cursor/rules/r.mdc": front("globs: **/*.ts")}, target="x/y.ts")
    e = g.entries[0]
    assert e.load == "conditional" and e.matches is True and e.unverified
    assert e.text == "body\n"


def test_cursor_ignores_plain_md_rules_and_other_files(tmp_path) -> None:
    g = cursor(tmp_path, {".cursor/rules/a.md": "x", ".cursor/rules/b.txt": "x"})
    assert loads(g) == [(".cursor/rules/a.md", "blocked")]
    assert "ignores .md" in g.entries[0].note


def test_cursor_nested_rule_folders(tmp_path) -> None:
    g = cursor(tmp_path, {".cursor/rules/frontend/c.mdc": front("alwaysApply: true")})
    assert loads(g) == [(".cursor/rules/frontend/c.mdc", "always")]


def test_cursor_legacy_cursorrules_is_always_and_unverified(tmp_path) -> None:
    g = cursor(tmp_path, {".cursorrules": "legacy"})
    assert loads(g) == [(".cursorrules", "always")] and g.entries[0].unverified


def test_cursor_agents_md_root_and_nested(tmp_path) -> None:
    g = cursor(tmp_path, {"AGENTS.md": "r", "pkg/AGENTS.md": "p"}, target="pkg/x.py")
    assert loads(g) == [("AGENTS.md", "always"), ("pkg/AGENTS.md", "on_demand")]
    assert g.entries[1].matches is True


def test_cursor_does_not_expand_at_references(tmp_path) -> None:
    g = cursor(
        tmp_path,
        {
            ".cursor/rules/r.mdc": front("alwaysApply: true", "see @docs/a.md\n"),
            "AGENTS.md": "@docs/a.md",
            "docs/a.md": "x",
        },
    )
    assert "docs/a.md" not in [e.path for e in g.entries]
    assert g.edges == []


def test_cursor_notes_mention_rules_outside_the_repo(tmp_path) -> None:
    assert any("Team Rules" in n for n in cursor(tmp_path, {}).notes)


# --- generic -----------------------------------------------------------------------------------


def generic(tmp_path, files, **kw):
    return Generic().build(make(tmp_path, files), **kw)


def test_generic_the_nearest_agents_md_is_verified_and_the_others_on_the_path_are_not(
    tmp_path,
) -> None:
    g = generic(
        tmp_path,
        {"AGENTS.md": "r", "pkg/AGENTS.md": "p", "pkg/sub/AGENTS.md": "s", "other/AGENTS.md": "o"},
        target="pkg/sub/x.py",
    )
    assert loads(g) == [
        ("AGENTS.md", "always"),
        ("pkg/AGENTS.md", "always"),
        ("pkg/sub/AGENTS.md", "always"),
        ("other/AGENTS.md", "on_demand"),
    ]
    assert [e.unverified for e in g.entries] == [True, True, False, False]
    assert g.entries[2].reason == "nearest AGENTS.md to the edited file"
    assert g.entries[3].matches is False


def test_generic_uses_the_working_directory_without_a_target(tmp_path) -> None:
    g = generic(tmp_path, {"AGENTS.md": "r", "pkg/AGENTS.md": "p"}, cwd="pkg")
    assert [(e.path, e.unverified) for e in g.entries] == [
        ("AGENTS.md", True),
        ("pkg/AGENTS.md", False),
    ]


def test_generic_nearest_can_be_an_ancestor(tmp_path) -> None:
    g = generic(tmp_path, {"AGENTS.md": "r"}, target="deep/er/x.py")
    assert [(e.path, e.unverified) for e in g.entries] == [("AGENTS.md", False)]


def test_generic_has_no_imports_and_keeps_html_comments(tmp_path) -> None:
    g = generic(tmp_path, {"AGENTS.md": "<!-- c -->\n@docs/a.md", "docs/a.md": "x"})
    assert [e.path for e in g.entries] == ["AGENTS.md"]
    assert "<!-- c -->" in g.entries[0].text and not g.entries[0].unverified
