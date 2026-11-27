"""The real-world scan v2 is a record: every finding at medium or above has a verdict, and the files
agree with each other."""

from __future__ import annotations

import json
from pathlib import Path

V2 = Path(__file__).resolve().parent / "realworld" / "v2"
RANK = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


def _load(name: str) -> object:
    return json.loads((V2 / name).read_text("utf-8"))


def _findings(name: str) -> dict[tuple[str, str, int, str], str]:
    rows = _load(name)
    assert isinstance(rows, list)
    return {
        (r["repo"], f["path"], f["line"], f["rule"]): f["severity"]
        for r in rows
        for f in r["findings"]
    }


def test_forty_repositories_each_with_the_commit_that_was_scanned() -> None:
    data = _load("repos.json")
    assert isinstance(data, dict) and len(data["repos"]) == 40
    assert all(len(r["commit"]) == 40 for r in data["repos"])
    assert len({r["repo"] for r in data["repos"]}) == 40


def test_both_variants_found_the_same_findings_and_only_severities_differ() -> None:
    assert _findings("results-default.json").keys() == _findings("results-root-medium.json").keys()


def test_every_finding_at_medium_or_above_has_a_verdict() -> None:
    default, promoted = _findings("results-default.json"), _findings("results-root-medium.json")
    at_least_medium = {
        key
        for key in default
        if RANK[default[key]] >= RANK["medium"] or RANK[promoted[key]] >= RANK["medium"]
    }
    verdicts = _load("verdicts.json")
    assert isinstance(verdicts, list)
    judged = {(v["repo"], v["path"], v["line"], v["rule"]) for v in verdicts}
    assert judged == at_least_medium
    assert all(v["verdict"] in {"TP", "FP"} and v["why"] for v in verdicts)


def test_the_original_scan_is_marked_as_used_for_tuning() -> None:
    tuning = _load("tuning.json")
    assert isinstance(tuning, dict) and tuning["status"] == "used for tuning"
    assert all(
        (V2 / name).exists()
        for key in ("original_results", "after_fixes_results")
        for name in tuning[key]
    )


def test_after_the_fixes_nothing_reaches_medium_and_nothing_is_new() -> None:
    for variant in ("default", "root-medium"):
        before = _findings(f"results-{variant}.json")
        after = _findings(f"results-after-{variant}.json")
        assert set(after) <= set(before)
        assert all(RANK[s] < RANK["medium"] for s in after.values())
