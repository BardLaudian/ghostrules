"""The labelled evasion corpus is a CI gate: a known attack that stops being reported fails here.

Cases marked `status = "open"` are known misses or false positives and are expected to fail; one
that starts passing fails the run (strict xfail) so the marker is removed.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))
import corpus_metrics as corpus  # noqa: E402

from ghostrules.rules import all_rules  # noqa: E402

CASES = corpus.load_cases()


def _param(case: dict) -> pytest.ParameterSet:
    marks = []
    if case.get("status") == "open":
        marks.append(pytest.mark.xfail(strict=True, reason=case.get("why", "open")))
    return pytest.param(case, id=f"{case['id']}-{case['technique']}", marks=marks)


@pytest.mark.parametrize("case", [_param(c) for c in CASES])
def test_the_scanner_still_agrees_with_the_label(case: dict) -> None:
    result = corpus.judge(case)
    expected = case["rule"] if case["label"] == "attack" else "nothing"
    assert result["ok"], f"expected {expected}, got {result['rules']}"


def test_the_corpus_is_big_and_labelled_both_ways() -> None:
    labels = [c["label"] for c in CASES]
    assert len(CASES) >= 100
    assert labels.count("attack") >= 70 and labels.count("benign") >= 30
    assert len({c["id"] for c in CASES}) == len(CASES)


def test_every_attack_names_a_real_rule_and_covers_many_rules() -> None:
    known = {r.id for r in all_rules()}
    expected = {c["rule"] for c in CASES if c["label"] == "attack"}
    assert expected <= known
    assert len(expected) >= 25


def test_the_corpus_file_is_ascii_so_no_invisible_character_hides_in_it() -> None:
    corpus.CORPUS.read_bytes().decode("ascii")


def test_the_metrics_add_up() -> None:
    rows = [(c, corpus.judge(c)) for c in CASES]
    summary = corpus.summarise(rows)
    assert summary["tp"] + summary["fn"] == summary["attacks"]
    assert summary["fp"] + summary["tn"] == summary["benign"]
    assert set(summary["open"]) == {c["id"] for c in CASES if c.get("status") == "open"}
    assert 0 < summary["precision"] <= 1 and 0 < summary["recall"] <= 1
