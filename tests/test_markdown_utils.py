import pytest

from ghostrules.markdown_utils import fenced_blocks, inline_code_spans
from ghostrules.models import ScanTarget


def test_backtick_block_with_language() -> None:
    text = "intro\n```Python\ncode\n```\noutro\n"
    (block,) = fenced_blocks(text)
    assert block.lang == "python"
    assert text[block.start : block.end] == "```Python\ncode\n```\n"


def test_tilde_fence_and_longer_closing_fence() -> None:
    text = "~~~\na\n~~~~\nafter\n"
    (block,) = fenced_blocks(text)
    assert text[block.end :] == "after\n"


def test_closing_fence_must_match_char_and_length() -> None:
    text = "````\n```\nstill code\n````\nout\n"
    (block,) = fenced_blocks(text)
    assert "still code" in text[block.start : block.end]
    assert text[block.end :] == "out\n"


def test_unterminated_fence_runs_to_end() -> None:
    text = "```\nnever closed\nmore"
    (block,) = fenced_blocks(text)
    assert (block.start, block.end) == (0, len(text))


def test_inline_triple_backticks_are_not_a_fence() -> None:
    assert fenced_blocks("```not a fence``` here\ntext\n") == []


def test_indented_four_spaces_is_not_a_fence() -> None:
    assert fenced_blocks("    ```\ncode\n") == []


def test_crlf_text() -> None:
    text = "a\r\n```sh\r\nls\r\n```\r\nb\r\n"
    (block,) = fenced_blocks(text)
    assert block.lang == "sh"
    assert text[block.end :] == "b\r\n"


def test_target_code_block_lookup() -> None:
    target = ScanTarget("a.md", "instructions", "out\n```\nin\n```\nout\n")
    assert target.code_block_at(0) is None
    assert target.code_block_at(target.text.index("in")) is not None
    assert target.code_block_at(len(target.text) - 2) is None


def test_inline_code_spans() -> None:
    text = "use `<!-- x -->` here and ``a ` b`` there, not `unclosed\nnext `line` ok"
    spans = [text[s:e] for s, e in inline_code_spans(text)]
    assert spans == ["`<!-- x -->`", "``a ` b``", "`line`"]


def test_inline_code_never_spans_lines_and_unmatched_backtick_opens_nothing() -> None:
    assert inline_code_spans("a ` b\nc ` d") == []
    assert inline_code_spans("plain text") == []


def test_target_inline_code_lookup() -> None:
    target = ScanTarget("a.md", "instructions", "x `<!--` y <!--")
    assert target.in_inline_code(target.text.index("<!--"))
    assert not target.in_inline_code(target.text.rindex("<!--"))


def test_target_code_span_at_handles_backtick_runs_of_any_length() -> None:
    text = "a ``x ` y`` b `c` d"
    target = ScanTarget("AGENTS.md", "instructions", text)
    assert target.code_span_at(text.index("x")) == (2, 11)
    assert target.code_span_at(text.index("y")) == (2, 11)
    assert target.code_span_at(text.index("c")) == (14, 17)
    assert target.code_span_at(text.index("b")) is None


# --- strip_html_comments ----------------------------------------------------------------------

from ghostrules.markdown_utils import (  # noqa: E402
    parse_frontmatter,
    strip_frontmatter,
    strip_html_comments,
)


def test_block_comment_is_removed_and_line_numbers_map_back() -> None:
    text = "# T\n<!-- maintainer\nnotes -->\nkeep\n"
    out = strip_html_comments(text)
    assert out.text == "# T\nkeep\n"
    assert out.line_map == (1, 4, 5)
    assert out.original_line(2) == 4
    (block,) = out.removed
    assert (block.start_line, block.end_line) == (2, 3)
    assert block.text == "<!-- maintainer\nnotes -->"


def test_single_line_comment_and_indentation_up_to_three_spaces() -> None:
    assert strip_html_comments("a\n   <!-- x -->\nb").text == "a\nb"
    assert strip_html_comments("a\n    <!-- x -->\nb").text == "a\n    <!-- x -->\nb"


def test_text_after_the_closing_marker_is_kept() -> None:
    out = strip_html_comments("<!-- x --> keep me\nnext")
    assert out.text == "keep me\nnext"
    assert out.line_map == (1, 2)


def test_two_comments_on_one_line() -> None:
    out = strip_html_comments("<!-- a --><!-- b -->\nz")
    assert out.text == "z"
    assert len(out.removed) == 2


def test_comments_in_code_blocks_inline_and_mid_paragraph_are_kept() -> None:
    text = "```md\n<!-- code -->\n```\ntext <!-- inline --> more\n`<!-- span -->`\n"
    assert strip_html_comments(text).text == text


def test_comment_inside_list_item_is_kept() -> None:
    text = "- <!-- in a list -->\n"
    assert strip_html_comments(text).text == text


def test_unterminated_comment_is_not_stripped() -> None:
    out = strip_html_comments("a\n<!-- never closed\nb\n")
    assert out.text == "a\n<!-- never closed\nb\n"
    assert out.unterminated_lines == (2,)
    assert out.removed == ()


def test_a_comment_opened_after_a_fence_closes_is_stripped() -> None:
    out = strip_html_comments("```\nx\n```\n<!-- gone -->\ny")
    assert out.text == "```\nx\n```\ny"


def test_crlf_text_keeps_its_carriage_returns() -> None:
    out = strip_html_comments("a\r\n<!-- c -->\r\nb\r\n")
    assert out.text == "a\r\nb\r\n"


def test_no_comment_means_identity() -> None:
    out = strip_html_comments("plain\ntext")
    assert out.text == "plain\ntext" and out.line_map == (1, 2)
    assert out.original_line(99) == 2


# --- front matter -----------------------------------------------------------------------------


def front(text: str):
    result = parse_frontmatter(text)
    assert result is not None
    return result


def test_no_front_matter() -> None:
    assert parse_frontmatter("# Title\n") is None
    assert parse_frontmatter("text\n---\na: b\n---\n") is None
    assert parse_frontmatter("---\na: b\nno closing fence\n") is None


def test_scalars_booleans_and_quotes() -> None:
    f = front(
        "---\n"
        "description: Use for API code\n"
        "alwaysApply: false\n"
        "flag: TRUE\n"
        'q1: "quoted: with colon"\n'
        "q2: 'it''s'\n"
        'esc: "a \\"b\\""\n'
        "empty:\n"
        "trailing: value # comment\n"
        "---\nbody\n"
    )
    assert not f.unparsed and f.problems == ()
    assert f.data == {
        "description": "Use for API code",
        "alwaysApply": False,
        "flag": True,
        "q1": "quoted: with colon",
        "q2": "it's",
        "esc": 'a "b"',
        "empty": "",
        "trailing": "value",
    }
    assert f.end_line == 10


def test_flow_and_block_lists() -> None:
    f = front(
        "---\n"
        "paths: [\"src/**/*.ts\", 'lib/*.js', plain]\n"
        'globs:\n  - a/**\n  - "b/*.md"\n'
        "other:\n- x\n- y\n"
        'applyTo: "**/*.py,**/*.pyi"\n'
        "---\n"
    )
    assert not f.unparsed
    assert f.data["paths"] == ["src/**/*.ts", "lib/*.js", "plain"]
    assert f.data["globs"] == ["a/**", "b/*.md"]
    assert f.data["other"] == ["x", "y"]
    assert f.data["applyTo"] == "**/*.py,**/*.pyi"


def test_comma_inside_quotes_does_not_split_a_flow_item() -> None:
    f = front('---\npaths: ["a,b", c]\n---\n')
    assert f.data["paths"] == ["a,b", "c"]


def test_comments_and_blank_lines_are_ignored() -> None:
    f = front("---\n# note\n\na: b\n---\n")
    assert f.data == {"a": "b"} and not f.unparsed


@pytest.mark.parametrize(
    "block",
    [
        "paths: **/*.ts",  # strict YAML reads * as an alias
        "paths: [a, b",  # unterminated flow list
        "a: 'open",
        'a: "x" y',
        "a: b: c",
        "a:\n  nested: 1",
        "just a line",
        "  indented: 1",
        "a: |",
        "a: &anchor x",
    ],
)
def test_unsupported_yaml_is_marked_unparsed(block: str) -> None:
    f = front(f"---\n{block}\n---\n")
    assert f.unparsed and f.problems


def test_unparsed_keeps_the_raw_value_and_the_rest() -> None:
    f = front("---\nok: 1\npaths: **/*.ts\n---\n")
    assert f.unparsed
    assert f.data == {"ok": "1", "paths": "**/*.ts"}


def test_bom_and_crlf_and_dots_closing() -> None:
    bom = chr(0xFEFF)
    f = front(f"{bom}---\r\na: b\r\n...\r\nbody")
    assert f.data == {"a": "b"} and f.end_line == 3


def test_body_offset_and_strip_frontmatter() -> None:
    text = "---\na: b\n---\nline4\nline5\n"
    f = front(text)
    assert text[f.body_offset :] == "line4\nline5\n"
    out = strip_frontmatter(text)
    assert out.text == "line4\nline5\n"
    assert out.line_map == (4, 5, 6)
    assert out.original_line(1) == 4
    (block,) = out.removed
    assert (block.kind, block.start_line, block.end_line) == ("frontmatter", 1, 3)


def test_strip_frontmatter_without_front_matter_is_identity() -> None:
    out = strip_frontmatter("a\nb")
    assert out.text == "a\nb" and out.line_map == (1, 2) and out.removed == ()
