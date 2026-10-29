"""The held-out benign set (W6.1): frozen, disjoint from the corpus, and dated."""

import re

from conftest import ROOT

from ghostrules._compat import tomllib

HELDOUT = ROOT / "bench" / "heldout.toml"


def names() -> list[str]:
    return [r["name"] for r in tomllib.loads(HELDOUT.read_text("utf-8"))["repo"]]


def test_heldout_has_100_unique_valid_repositories_with_the_freeze_date() -> None:
    listed = names()
    assert len(listed) == 100 and len(set(listed)) == 100
    assert all(re.fullmatch(r"[\w.-]+/[\w.-]+", n) for n in listed)
    assert "# date = 2026-10-29" in HELDOUT.read_text("utf-8")


def test_heldout_shares_no_repository_with_the_corpus_or_the_study() -> None:
    pinned = {
        r["name"] for r in tomllib.loads((ROOT / "corpus/repos.toml").read_text("utf-8"))["repo"]
    }
    assert not set(names()) & pinned  # repos.toml carries both tiers: regression and study


def test_the_two_replaced_candidates_are_not_in_the_set() -> None:
    assert "elder-plinius/V3R1T4S" not in names()
    assert "Eyadkelleh/awesome-skills-security" not in names()
