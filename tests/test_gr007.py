"""GR007 and GR004's lower threshold: runs of characters that can carry hidden text.

The characters are built with chr() so this file carries none of them literally.
"""

from __future__ import annotations

import pytest
from _analyze import analyze

FUNC, TIMES, SEP, PLUS = (chr(c) for c in range(0x2061, 0x2065))  # invisible math operators
ANNOT = [chr(c) for c in (0xFFF9, 0xFFFA, 0xFFFB)]  # interlinear annotation marks
VS0, VS1, VS16, ZWJ, HEART = chr(0xFE00), chr(0xFE01), chr(0xFE0F), chr(0x200D), chr(0x2764)
HINDI = "".join(chr(c) for c in (0x939, 0x93F, 0x928, 0x94D, 0x926, 0x940))


def hits(text: str, rule: str) -> list[dict]:
    out = analyze({"AGENTS.md": f"# Notes\n\n{text}\n"}, strict=True)
    return [f for f in out["findings"] if f["rule_id"] == rule]


def ri(word: str) -> str:
    return "".join(chr(0x1F1E6 + ord(c) - ord("A")) for c in word)


def test_regional_indicators_that_are_not_flags_decode_to_letters() -> None:
    (hit,) = hits("Team " + ri("SENDTHEENV"), "GR007")
    assert hit["decoded"] == "SENDTHEENV" and hit["severity"] == "high"


def test_an_odd_run_is_reported_even_when_short() -> None:
    assert hits("Flag " + ri("ABC"), "GR007")


@pytest.mark.parametrize("text", ["Made in " + ri("ES"), "EU: " + ri("FR") + ri("DE") + ri("IT")])
def test_real_flags_are_not_reported(text: str) -> None:
    assert hits(text, "GR007") == []


def test_invisible_math_operators_in_a_row_and_annotation_marks() -> None:
    assert hits(f"f{FUNC}{TIMES}{SEP}{PLUS}x", "GR007")
    assert hits(f"text {ANNOT[0]}hidden{ANNOT[1]} shown{ANNOT[2]}", "GR007")


def test_a_single_invisible_operator_in_math_is_not_reported() -> None:
    assert hits(f"sin{FUNC}(x) + 2{TIMES}x", "GR007") == []


def test_two_variation_selectors_in_a_row_are_reported_by_gr004() -> None:
    assert hits(f"x{VS0}{VS1}", "GR004")


def test_emoji_and_native_scripts_are_not_reported() -> None:
    text = f"Family a{ZWJ}b, heart {HEART}{VS16}, {HINDI}"
    out = analyze({"AGENTS.md": f"# Notes\n\n{text}\n"}, strict=True)
    assert {f["rule_id"] for f in out["findings"]} & {"GR004", "GR007"} == set()
