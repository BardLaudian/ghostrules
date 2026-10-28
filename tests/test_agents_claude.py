import hashlib
import os
from pathlib import Path

import pytest

from ghostrules.agents import ClaudeCode, Repo
from ghostrules.agents.base import ContextGraph, resolve_import


def make(tmp_path: Path, files: dict[str, str | bytes]) -> Repo:
    for rel, content in files.items():
        path = tmp_path / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        if isinstance(content, str):
            path.write_bytes(content.encode("utf-8"))
        else:
            path.write_bytes(content)
    return Repo(tmp_path)


def build(tmp_path: Path, files: dict[str, str | bytes], *, mode: str | None = None, **kw):
    model = ClaudeCode(mode) if mode else ClaudeCode()
    return model.build(make(tmp_path, files), **kw)


def loads(graph: ContextGraph) -> list[tuple[str, str]]:
    return [(e.path, e.load) for e in graph.entries]


def entry(graph: ContextGraph, path: str):
    found = graph.get(path)
    assert found is not None, f"{path} not in {[e.path for e in graph.entries]}"
    return found


# --- ordering of CLAUDE.md files ---------------------------------------------------------------


def test_project_files_in_one_directory_are_ordered_claude_dotclaude_local(tmp_path) -> None:
    g = build(
        tmp_path,
        {"CLAUDE.local.md": "l", ".claude/CLAUDE.md": "d", "CLAUDE.md": "c"},
    )
    assert loads(g) == [
        ("CLAUDE.md", "always"),
        (".claude/CLAUDE.md", "always"),
        ("CLAUDE.local.md", "always"),
    ]


def test_ancestors_come_root_first_and_siblings_are_left_out(tmp_path) -> None:
    g = build(
        tmp_path,
        {
            "CLAUDE.md": "root",
            "src/CLAUDE.md": "src",
            "src/api/CLAUDE.md": "api",
            "src/web/CLAUDE.md": "sibling",
            "other/CLAUDE.md": "elsewhere",
        },
        cwd="src/api",
    )
    assert loads(g) == [
        ("CLAUDE.md", "always"),
        ("src/CLAUDE.md", "always"),
        ("src/api/CLAUDE.md", "always"),
    ]
    assert entry(g, "src/api/CLAUDE.md").reason == "CLAUDE.md in working directory"


def test_subdirectories_below_cwd_load_on_demand_and_match_the_target(tmp_path) -> None:
    files = {"CLAUDE.md": "root", "src/legacy/CLAUDE.md": "legacy", "src/new/CLAUDE.md": "new"}
    g = build(tmp_path, files, target="src/legacy/old.py")
    assert entry(g, "src/legacy/CLAUDE.md").load == "on_demand"
    assert entry(g, "src/legacy/CLAUDE.md").matches is True
    assert entry(g, "src/new/CLAUDE.md").matches is False
    assert entry(g, "src/legacy/CLAUDE.md").condition == "src/legacy/"
    g2 = build(tmp_path, files)
    assert entry(g2, "src/new/CLAUDE.md").matches is None


# --- AGENTS.md versus CLAUDE.md ----------------------------------------------------------------


def test_agents_md_alone_is_loaded(tmp_path) -> None:
    g = build(tmp_path, {"AGENTS.md": "a"})
    assert loads(g) == [("AGENTS.md", "always")]


@pytest.mark.parametrize("claude", ["CLAUDE.md", ".claude/CLAUDE.md", "CLAUDE.local.md"])
def test_any_claude_file_blocks_agents_md(tmp_path, claude: str) -> None:
    g = build(tmp_path, {"AGENTS.md": "a", claude: "c"})
    assert entry(g, "AGENTS.md").load == "blocked"
    assert "claude-md-or-agents-md" in entry(g, "AGENTS.md").note
    assert entry(g, claude).load == "always"


def test_a_claude_md_in_an_ancestor_blocks_agents_md_in_the_working_directory(tmp_path) -> None:
    g = build(tmp_path, {"CLAUDE.md": "c", "pkg/AGENTS.md": "a"}, cwd="pkg")
    assert entry(g, "pkg/AGENTS.md").load == "blocked"


def test_claude_md_below_cwd_does_not_block_the_root_agents_md(tmp_path) -> None:
    g = build(tmp_path, {"AGENTS.md": "a", "pkg/CLAUDE.md": "c"})
    assert entry(g, "AGENTS.md").load == "always"
    assert entry(g, "pkg/CLAUDE.md").load == "on_demand"


def test_subdirectory_agents_md_loads_on_demand_only_without_a_claude_file(tmp_path) -> None:
    g = build(
        tmp_path,
        {"AGENTS.md": "root", "a/AGENTS.md": "a", "b/AGENTS.md": "b", "b/CLAUDE.md": "c"},
    )
    assert entry(g, "a/AGENTS.md").load == "on_demand"
    assert entry(g, "b/AGENTS.md").load == "blocked"
    assert entry(g, "b/CLAUDE.md").load == "on_demand"


def test_dotclaude_agents_md_is_read_too(tmp_path) -> None:
    g = build(tmp_path, {".claude/AGENTS.md": "a"})
    assert loads(g) == [(".claude/AGENTS.md", "always")]


def test_mode_and_loads_both_with_claude_first(tmp_path) -> None:
    g = build(tmp_path, {"AGENTS.md": "a", "CLAUDE.md": "c"}, mode="claude-md-and-agents-md")
    assert loads(g) == [("CLAUDE.md", "always"), ("AGENTS.md", "always")]


def test_mode_and_does_not_read_an_imported_agents_md_twice(tmp_path) -> None:
    g = build(
        tmp_path,
        {"CLAUDE.md": "@AGENTS.md\n", "AGENTS.md": "a"},
        mode="claude-md-and-agents-md",
    )
    assert loads(g) == [("CLAUDE.md", "always"), ("AGENTS.md", "always")]
    assert entry(g, "AGENTS.md").via == ("CLAUDE.md:1",)


def test_default_mode_with_an_import_of_agents_md(tmp_path) -> None:
    g = build(tmp_path, {"CLAUDE.md": "@AGENTS.md\n", "AGENTS.md": "a"})
    assert loads(g) == [("CLAUDE.md", "always"), ("AGENTS.md", "always")]
    assert entry(g, "AGENTS.md").via == ("CLAUDE.md:1",)


def test_mode_claude_md_blocks_agents_md(tmp_path) -> None:
    g = build(tmp_path, {"AGENTS.md": "a"}, mode="claude-md")
    assert entry(g, "AGENTS.md").load == "blocked"


def test_mode_managed_only_loads_no_project_files_but_keeps_on_demand_rules(tmp_path) -> None:
    g = build(
        tmp_path,
        {"CLAUDE.md": "c", "AGENTS.md": "a", "sub/CLAUDE.md": "s"},
        mode="managed-only",
    )
    assert [e.path for e in g.entries] == []
    assert any("managed-only" in n for n in g.notes)


def test_unknown_mode_is_rejected() -> None:
    with pytest.raises(ValueError):
        ClaudeCode("nope")


# --- imports -----------------------------------------------------------------------------------


def test_imports_resolve_relative_to_the_importing_file_and_nest(tmp_path) -> None:
    g = build(
        tmp_path,
        {
            "CLAUDE.md": "See @docs/style.md\n",
            "docs/style.md": "more @../shared/team.md\n",
            "shared/team.md": "leaf",
        },
    )
    assert loads(g) == [
        ("CLAUDE.md", "always"),
        ("docs/style.md", "always"),
        ("shared/team.md", "always"),
    ]
    leaf = entry(g, "shared/team.md")
    assert leaf.via == ("CLAUDE.md:1", "docs/style.md:1")
    assert leaf.hop == 2
    assert leaf.reason == "imported by docs/style.md:1"
    assert [(e.source, e.target, e.status) for e in g.edges] == [
        ("CLAUDE.md", "docs/style.md", "loaded"),
        ("docs/style.md", "shared/team.md", "loaded"),
    ]


def test_imports_are_inlined_right_after_their_importer(tmp_path) -> None:
    g = build(
        tmp_path,
        {
            "CLAUDE.md": "@a.md\n@b.md\n",
            "a.md": "@c.md",
            "b.md": "",
            "c.md": "",
            ".claude/CLAUDE.md": "",
        },
    )
    assert [e.path for e in g.entries] == [
        "CLAUDE.md",
        "a.md",
        "c.md",
        "b.md",
        ".claude/CLAUDE.md",
    ]


def test_an_imported_file_inherits_the_load_state_of_its_importer(tmp_path) -> None:
    g = build(tmp_path, {"sub/CLAUDE.md": "@x.md", "sub/x.md": "x"}, target="sub/a.py")
    child = entry(g, "sub/x.md")
    assert child.load == "on_demand" and child.matches is True and child.condition == "sub/"


def test_four_hop_limit(tmp_path) -> None:
    files = {"CLAUDE.md": "@f1.md\n"}
    for i in range(1, 7):
        files[f"f{i}.md"] = f"@f{i + 1}.md\n" if i < 6 else "end"
    files["f7.md"] = "never"
    g = build(tmp_path, files)
    paths = [e.path for e in g.entries]
    assert paths == ["CLAUDE.md", "f1.md", "f2.md", "f3.md", "f4.md", "f5.md"]
    assert [entry(g, f"f{i}.md").unverified for i in range(1, 6)] == [False] * 4 + [True]
    assert "counts from 0" in entry(g, "f5.md").note
    depth = [e for e in g.edges if e.status == "depth"]
    assert [(e.source, e.target) for e in depth] == [("f5.md", "f6.md")]


def test_cycles_are_reported_once_and_do_not_loop(tmp_path) -> None:
    g = build(tmp_path, {"CLAUDE.md": "@a.md", "a.md": "@b.md", "b.md": "@a.md"})
    assert [e.path for e in g.entries] == ["CLAUDE.md", "a.md", "b.md"]
    assert g.cycles == [("a.md", "b.md", "a.md")]
    assert [e.status for e in g.edges] == ["loaded", "loaded", "cycle"]


def test_a_file_imported_twice_is_loaded_once(tmp_path) -> None:
    g = build(tmp_path, {"CLAUDE.md": "@a.md @b.md", "a.md": "@c.md", "b.md": "@c.md", "c.md": ""})
    assert [e.path for e in g.entries] == ["CLAUDE.md", "a.md", "c.md", "b.md"]
    assert [e.status for e in g.edges if e.target == "c.md"] == ["loaded", "duplicate"]


def test_code_spans_blocks_and_quotes_are_not_imports(tmp_path) -> None:
    g = build(
        tmp_path,
        {
            "CLAUDE.md": '`@a.md`\n```\n@b.md\n```\n"@c.md"\n',
            "a.md": "",
            "b.md": "",
            "c.md": "",
        },
    )
    assert [e.path for e in g.entries] == ["CLAUDE.md"]
    assert [e.status for e in g.edges] == ["quoted"]


def test_missing_and_directory_targets(tmp_path) -> None:
    g = build(tmp_path, {"CLAUDE.md": "@nope.md @docs", "docs/a.md": ""})
    assert [(e.written, e.status) for e in g.edges] == [
        ("nope.md", "missing"),
        ("docs", "directory"),
    ]
    assert [e.path for e in g.entries] == ["CLAUDE.md"]


def test_loose_candidates_that_are_not_files_are_ignored_silently(tmp_path) -> None:
    g = build(tmp_path, {"CLAUDE.md": "(@types/node) and [x](@docs/a.md)", "docs/a.md": "ok"})
    assert [e.path for e in g.entries] == ["CLAUDE.md", "docs/a.md"]
    (edge,) = g.edges
    assert edge.unverified and "loose" in entry(g, "docs/a.md").note


def test_import_inside_an_html_comment_is_followed_but_unverified(tmp_path) -> None:
    g = build(tmp_path, {"CLAUDE.md": "<!--\n@a.md\n-->\n", "a.md": "x"})
    assert entry(g, "a.md").unverified
    assert "HTML comment" in entry(g, "a.md").note


def test_external_imports_are_recorded_and_never_read(tmp_path) -> None:
    g = build(
        tmp_path,
        {"CLAUDE.md": "@/etc/passwd @~/secrets.md @../out.md @C:\\\\x\\\\y.md\n"},
    )
    statuses = [(e.written, e.status) for e in g.edges]
    assert statuses == [
        ("/etc/passwd", "external"),
        ("~/secrets.md", "external"),
        ("../out.md", "external"),
        ("C:\\\\x\\\\y.md", "external"),
    ]
    for e in g.entries[1:]:
        assert not e.readable and e.text == "" and "requires approval" in e.note
        assert e.load == "always"


def test_inside_the_repo_but_outside_cwd_needs_approval(tmp_path) -> None:
    g = build(
        tmp_path,
        {"src/CLAUDE.md": "@../shared/x.md", "shared/x.md": "x"},
        cwd="src",
    )
    child = entry(g, "shared/x.md")
    assert child.readable and child.text == "x"
    assert "requires approval" in child.note


def test_user_scope_imports_need_no_approval_note(tmp_path) -> None:
    home = make(
        tmp_path / "home", {".claude/CLAUDE.md": "@notes.md @/abs.md", ".claude/notes.md": "n"}
    )
    home = Repo(tmp_path / "home", "~/")
    repo = make(tmp_path / "repo", {"CLAUDE.md": "p"})
    g = ClaudeCode().build(repo, home=home)
    assert [e.path for e in g.entries][:2] == ["~/.claude/CLAUDE.md", "~/.claude/notes.md"]
    external = entry(g, "/abs.md")
    assert "requires approval" not in external.note


def test_resolve_import_rules() -> None:
    assert resolve_import("a.md", "").kind == "repo"
    assert resolve_import("../a.md", "dir/x.md").rel == "a.md"
    assert resolve_import("./x/../y.md", "d/f.md").rel == "d/y.md"
    assert resolve_import("..", "d/f.md").kind == "repo"
    assert resolve_import("../../a.md", "d/f.md").kind == "outside"
    assert resolve_import("docs\\style.md", "").rel == "docs/style.md"
    assert resolve_import("/etc/x", "d").kind == "absolute"
    assert resolve_import("C:\\x", "d").kind == "absolute"
    assert resolve_import("~/x", "d").kind == "home"


# --- transforms --------------------------------------------------------------------------------


def test_html_comments_are_stripped_from_claude_md_but_the_raw_hash_is_of_the_file(
    tmp_path,
) -> None:
    raw = "# T\n<!-- hidden note -->\nvisible\n"
    g = build(tmp_path, {"CLAUDE.md": raw})
    e = entry(g, "CLAUDE.md")
    assert e.text == "# T\nvisible\n"
    assert e.transforms == ("strip_html_comments",)
    assert e.raw_sha256 == hashlib.sha256(raw.encode()).hexdigest()
    assert e.seen_sha256 == hashlib.sha256(e.text.encode()).hexdigest()
    assert e.raw_sha256 != e.seen_sha256
    assert e.line_map == (1, 3, 4)
    assert [r.text for r in e.removed] == ["<!-- hidden note -->"]


def test_html_comments_in_imported_files_are_kept_as_seen_and_marked_unverified(tmp_path) -> None:
    g = build(tmp_path, {"CLAUDE.md": "@a.md", "a.md": "<!-- x -->\nbody\n"})
    e = entry(g, "a.md")
    assert "<!-- x -->" in e.text and e.unverified and e.transforms == ()


def test_agents_md_comments_are_kept_as_seen_and_marked_unverified(tmp_path) -> None:
    e = entry(build(tmp_path, {"AGENTS.md": "<!-- x -->\nb"}), "AGENTS.md")
    assert "<!-- x -->" in e.text and e.unverified


def test_crlf_and_lf_checkouts_have_identical_hashes_and_text(tmp_path) -> None:
    text = "# T\n<!-- c -->\n@a.md\nlast\n"
    lf = build(tmp_path / "lf", {"CLAUDE.md": text, "a.md": "a\nb\n"})
    crlf = build(
        tmp_path / "crlf",
        {"CLAUDE.md": text.replace("\n", "\r\n"), "a.md": "a\r\nb\r\n"},
    )
    assert [(e.path, e.raw_sha256, e.seen_sha256, e.text) for e in lf.entries] == [
        (e.path, e.raw_sha256, e.seen_sha256, e.text) for e in crlf.entries
    ]
    assert [(e.line, e.column) for e in lf.edges] == [(e.line, e.column) for e in crlf.edges]


def test_file_over_4_mib_is_skipped(tmp_path) -> None:
    g = build(tmp_path, {"CLAUDE.md": b"x" * (4 * 1024 * 1024 + 1)})
    e = entry(g, "CLAUDE.md")
    assert e.load == "blocked" and not e.readable and "4 MiB" in e.note


def test_large_on_demand_file_gets_a_note(tmp_path) -> None:
    g = build(tmp_path, {"sub/CLAUDE.md": "x" * 40_001, "CLAUDE.md": "x" * 40_001})
    assert "may be truncated" in entry(g, "sub/CLAUDE.md").note
    assert entry(g, "CLAUDE.md").note == ""


# --- rules -------------------------------------------------------------------------------------


def rule(paths: str | None, body: str = "Rule body\n") -> str:
    return body if paths is None else f"---\n{paths}\n---\n{body}"


def test_rules_without_paths_are_always_loaded_and_frontmatter_is_removed(tmp_path) -> None:
    g = build(
        tmp_path,
        {
            ".claude/rules/style.md": rule("other: ignored"),
            ".claude/rules/sub/deep.md": rule(None),
            ".claude/rules/notes.txt": "not a rule",
        },
    )
    assert loads(g) == [
        (".claude/rules/style.md", "always"),
        (".claude/rules/sub/deep.md", "always"),
    ]
    assert entry(g, ".claude/rules/style.md").text == "Rule body\n"
    assert entry(g, ".claude/rules/style.md").transforms == ("strip_frontmatter",)


@pytest.mark.parametrize(
    ("front", "target", "matches"),
    [
        ('paths:\n  - "src/api/**"', "src/api/users.ts", True),
        ('paths:\n  - "src/api/**"', "src/web/x.ts", False),
        ('paths: ["**/*.ts", "docs/**"]', "a/b/c.ts", True),
        ("paths: 'src/**/*.{ts,tsx}'", "src/a/b.tsx", True),
        ('paths: "src/**/*.{ts,tsx}, docs/*.md"', "docs/a.md", True),
        ('paths: "*.md"', "docs/a.md", False),
        ('paths: "src/**"', None, None),
    ],
)
def test_path_scoped_rules_are_conditional(tmp_path, front, target, matches) -> None:
    g = build(tmp_path, {".claude/rules/api.md": rule(front)}, target=target)
    e = entry(g, ".claude/rules/api.md")
    assert e.load == "conditional" and e.matches is matches
    assert e.reason.startswith("paths: ") and e.condition


def test_invalid_frontmatter_loads_the_rule_without_paths(tmp_path) -> None:
    g = build(tmp_path, {".claude/rules/api.md": rule("paths: **/*.ts")}, target="a.ts")
    e = entry(g, ".claude/rules/api.md")
    assert e.load == "always" and e.unverified
    assert "did not parse" in e.note
    assert "paths:" in e.text  # the file is kept whole


def test_nested_rules_load_on_demand_and_their_globs_are_relative_to_their_directory(
    tmp_path,
) -> None:
    files = {
        "pkg/.claude/rules/a.md": rule(None),
        "pkg/.claude/rules/b.md": rule('paths: "src/**"'),
    }
    g = build(tmp_path, files, target="pkg/src/x.py")
    assert entry(g, "pkg/.claude/rules/a.md").load == "on_demand"
    assert entry(g, "pkg/.claude/rules/a.md").matches is True
    assert entry(g, "pkg/.claude/rules/b.md").load == "conditional"
    assert entry(g, "pkg/.claude/rules/b.md").matches is True
    g2 = build(tmp_path, files, target="other/src/x.py")
    assert entry(g2, "pkg/.claude/rules/b.md").matches is False


def test_a_sibling_directorys_rules_are_not_part_of_the_session(tmp_path) -> None:
    g = build(
        tmp_path,
        {"a/.claude/rules/x.md": rule(None), "b/.claude/rules/y.md": rule(None)},
        cwd="a",
    )
    assert [e.path for e in g.entries] == ["a/.claude/rules/x.md"]


def test_rules_come_after_the_claude_files(tmp_path) -> None:
    g = build(tmp_path, {".claude/rules/r.md": rule(None), "CLAUDE.md": "c"})
    assert [e.path for e in g.entries] == ["CLAUDE.md", ".claude/rules/r.md"]


def test_rules_can_import_files_marked_as_loaded_with_the_rules_state(tmp_path) -> None:
    g = build(
        tmp_path,
        {".claude/rules/r.md": rule('paths: "src/**"', "@../../docs/x.md\n"), "docs/x.md": "x"},
    )
    child = entry(g, "docs/x.md")
    assert child.load == "conditional" and child.via == (".claude/rules/r.md:4",)


# --- home --------------------------------------------------------------------------------------


def test_user_files_come_first_and_are_prefixed(tmp_path) -> None:
    home = make(
        tmp_path / "h",
        {".claude/CLAUDE.md": "u", ".claude/rules/mine.md": rule(None), ".claude/other.md": "x"},
    )
    home = Repo(tmp_path / "h", "~/")
    repo = make(tmp_path / "r", {"CLAUDE.md": "p"})
    g = ClaudeCode().build(repo, home=home)
    assert [e.path for e in g.entries] == [
        "~/.claude/CLAUDE.md",
        "~/.claude/rules/mine.md",
        "CLAUDE.md",
    ]


def test_without_home_no_user_files(tmp_path) -> None:
    g = build(tmp_path, {"CLAUDE.md": "p"})
    assert all(not e.path.startswith("~/") for e in g.entries)


# --- symlinks ----------------------------------------------------------------------------------


def link(tmp_path: Path, name: str, target: str, *, is_dir: bool = False) -> None:
    try:
        (tmp_path / name).parent.mkdir(parents=True, exist_ok=True)
        os.symlink(target, tmp_path / name, target_is_directory=is_dir)
    except (OSError, NotImplementedError):
        pytest.skip("symlinks are not available here")


def test_a_symlinked_claude_md_is_reported_and_not_read(tmp_path) -> None:
    make(tmp_path, {"AGENTS.md": "real"})
    link(tmp_path, "CLAUDE.md", "AGENTS.md")
    g = ClaudeCode().build(Repo(tmp_path))
    e = entry(g, "CLAUDE.md")
    assert e.load == "blocked" and not e.readable
    assert "symlink -> AGENTS.md" in e.note and "outside" not in e.note
    assert entry(g, "AGENTS.md").load == "blocked"  # a CLAUDE.md exists, so AGENTS.md is skipped


def test_a_symlink_leaving_the_tree_is_called_out(tmp_path) -> None:
    outside = tmp_path / "outside.md"
    outside.write_text("secret", encoding="utf-8")
    repo_dir = tmp_path / "repo"
    repo_dir.mkdir()
    link(repo_dir, "CLAUDE.md", str(outside))
    e = entry(ClaudeCode().build(Repo(repo_dir)), "CLAUDE.md")
    assert "outside the tree" in e.note and e.text == ""


def test_an_imported_symlink_is_not_followed(tmp_path) -> None:
    make(tmp_path, {"CLAUDE.md": "@link.md", "real.md": "x"})
    link(tmp_path, "link.md", "real.md")
    g = ClaudeCode().build(Repo(tmp_path))
    assert [(e.target, e.status) for e in g.edges] == [("link.md", "symlink")]
    assert entry(g, "link.md").load == "blocked"


def test_a_symlinked_directory_is_never_entered(tmp_path) -> None:
    make(tmp_path, {"CLAUDE.md": "@docs/a.md", "real/a.md": "x"})
    link(tmp_path, "docs", "real", is_dir=True)
    g = ClaudeCode().build(Repo(tmp_path))
    assert [(e.target, e.status) for e in g.edges] == [("docs/a.md", "symlink")]


def test_a_symlinked_rules_directory_is_reported(tmp_path) -> None:
    make(tmp_path, {"shared/r.md": "x"})
    link(tmp_path, ".claude/rules", "../shared", is_dir=True)
    g = ClaudeCode().build(Repo(tmp_path))
    e = entry(g, ".claude/rules")
    assert e.load == "blocked" and "symlinked directory" in e.note
