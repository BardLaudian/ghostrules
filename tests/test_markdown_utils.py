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
