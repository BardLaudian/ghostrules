import pytest

from ghostrules.imports import Import, find_imports


def paths(text: str, **kwargs) -> list[str]:
    return [i.path for i in find_imports(text, **kwargs)]


# --- what Claude Code documents --------------------------------------------------------------


def test_the_documented_examples() -> None:
    text = (
        "See @README for project overview and @package.json for available npm commands.\n\n"
        "# Additional Instructions\n- git workflow @docs/git-instructions.md\n"
    )
    assert paths(text) == ["README", "package.json", "docs/git-instructions.md"]


def test_position_points_at_the_at_sign() -> None:
    (imp,) = find_imports("intro\n  use @docs/a.md now\n")
    assert (imp.line, imp.column, imp.end_column) == (2, 7, 17)
    assert imp.raw == "@docs/a.md"


def test_import_at_the_very_start_of_the_text() -> None:
    assert paths("@AGENTS.md\n") == ["AGENTS.md"]


def test_relative_parent_absolute_and_home_paths_are_returned_as_written() -> None:
    text = "@../shared/rules.md @/etc/passwd @~/notes.md @./local.md"
    assert paths(text) == ["../shared/rules.md", "/etc/passwd", "~/notes.md", "./local.md"]


def test_backslash_space_escapes_a_space_in_the_path() -> None:
    (imp,) = find_imports("- API conventions @Design\\ Docs/api-conventions.md and more\n")
    assert imp.path == "Design Docs/api-conventions.md"
    assert imp.raw == "@Design\\ Docs/api-conventions.md"


def test_without_the_backslash_the_path_ends_at_the_first_space() -> None:
    assert paths("@Design Docs/api.md\n") == ["Design"]


def test_the_path_ends_at_a_line_end_even_with_a_trailing_backslash_space_free_line() -> None:
    assert paths("@docs/a.md\n@docs/b.md\n") == ["docs/a.md", "docs/b.md"]


def test_crlf_does_not_leak_into_the_path() -> None:
    assert paths("@docs/a.md\r\n@docs/b.md\r\n") == ["docs/a.md", "docs/b.md"]


# --- code spans and blocks are not parsed ----------------------------------------------------


def test_inline_code_is_not_an_import_but_the_same_text_outside_is() -> None:
    assert paths("Mention `@README` literally, but import @README.\n") == ["README"]


def test_double_backtick_spans_and_unmatched_backticks() -> None:
    assert paths("``@a.md`` and @b.md\n") == ["b.md"]
    assert paths("a ` stray @c.md\n") == ["c.md"]


def test_fenced_blocks_are_skipped_whatever_the_fence() -> None:
    text = "```md\n@a.md\n```\n~~~\n@b.md\n~~~\n@c.md\n"
    assert paths(text) == ["c.md"]


def test_an_unterminated_fence_runs_to_the_end() -> None:
    assert paths("@a.md\n```\n@b.md\n") == ["a.md"]


def test_inline_code_does_not_hide_a_later_import_on_the_same_line() -> None:
    assert paths("`x` @a.md `y` @b.md") == ["a.md", "b.md"]


# --- quotes -----------------------------------------------------------------------------------


@pytest.mark.parametrize("text", ['"@docs/a.md"', "'@docs/a.md'", '(see "@docs/a.md")'])
def test_quoted_paths_are_not_imported(text: str) -> None:
    assert paths(text) == []
    (imp,) = find_imports(text, include_quoted=True)
    assert imp.quoted and imp.path == "docs/a.md"


def test_quoted_with_escaped_spaces_is_still_not_imported() -> None:
    assert paths('"@Design\\ Docs/a.md"') == []


# --- false imports ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "text",
    [
        "mail user@example.com now",
        "git@github.com:org/repo.git",
        "price 5@10",
        "@",
        "@ alone",
        "a @@double",
        "**@README**",  # emphasis glued to the token: loose, not certain
    ],
)
def test_text_that_is_not_an_import(text: str) -> None:
    assert [i for i in find_imports(text) if i.certain] == []


def test_email_is_never_reported_even_as_loose() -> None:
    assert find_imports("user@example.com") == []


def test_mentions_and_npm_scopes_are_returned_but_do_not_look_like_paths() -> None:
    found = {i.path: i.looks_like_path for i in find_imports("ping @alice, use @types/node\n")}
    assert found == {"alice": False, "types/node": False}


@pytest.mark.parametrize(
    ("path", "expected"),
    [
        ("README", False),
        ("alice", False),
        ("docs/a.md", True),
        ("a.md", True),
        ("../x", True),
        ("~/x", True),
        (".env", True),
        ("v1.2", True),
    ],
)
def test_looks_like_path(path: str, expected: bool) -> None:
    assert Import(path, "@" + path, 1, 1, 2).looks_like_path is expected


# --- trailing punctuation and loose candidates -----------------------------------------------


def test_sentence_punctuation_is_not_part_of_the_path() -> None:
    assert paths("Read @docs/a.md. Then @docs/b.md, and (@docs/c.md)!") == [
        "docs/a.md",
        "docs/b.md",
        "docs/c.md",
    ]


def test_a_balanced_parenthesis_in_the_path_is_kept() -> None:
    assert paths("@docs/a(1).md") == ["docs/a(1).md"]
    assert paths("@docs/notes(draft)") == ["docs/notes(draft)"]


def test_certain_versus_loose() -> None:
    found = {i.path: i.certain for i in find_imports("see @a.md and (@b.md) and [x](@c.md)")}
    assert found == {"a.md": True, "b.md": False, "c.md": False}


def test_markdown_link_to_an_at_path_is_a_loose_candidate() -> None:
    (imp,) = find_imports("[style](@docs/style.md)")
    assert not imp.certain and imp.path == "docs/style.md"


# --- comments --------------------------------------------------------------------------------


def test_imports_in_block_comments_are_flagged() -> None:
    text = "@a.md\n<!--\n@b.md\n-->\n@c.md\n"
    assert {i.path: i.in_comment for i in find_imports(text)} == {
        "a.md": False,
        "b.md": True,
        "c.md": False,
    }


def test_several_imports_on_many_lines_have_right_lines() -> None:
    text = "one\n\n@a.md @b.md\n\n  @c.md\n"
    assert [(i.path, i.line, i.column) for i in find_imports(text)] == [
        ("a.md", 3, 1),
        ("b.md", 3, 7),
        ("c.md", 5, 3),
    ]


def test_non_ascii_paths_and_columns_count_code_points() -> None:
    (imp,) = find_imports("ñandú @docs/caf\u00e9.md")
    assert imp.path == "docs/caf\u00e9.md" and imp.column == 7
