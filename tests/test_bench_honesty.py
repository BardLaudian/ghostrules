"""Phase 7: Wilson intervals, assistant vs human labels, and the blind review sheet."""

import csv
import json
import sys

from conftest import ROOT

sys.path.insert(0, str(ROOT / "bench"))
import lib  # noqa: E402
from test_bench import load_bench_run  # noqa: E402

run = load_bench_run()


# --- Wilson interval ---------------------------------------------------------------------------


def test_wilson_matches_known_values() -> None:
    lo, hi = lib.wilson(1, 4)
    assert (round(lo, 3), round(hi, 3)) == (0.046, 0.699)
    lo, hi = lib.wilson(4, 21)
    assert (round(lo, 3), round(hi, 3)) == (0.077, 0.4)


def test_wilson_edges_stay_inside_zero_one_and_empty_is_none() -> None:
    assert lib.wilson(0, 10)[0] == 0.0 and lib.wilson(10, 10)[1] == 1.0
    assert lib.wilson(0, 0) is None


def test_share_always_carries_the_sample_size() -> None:
    assert lib.share(1, 4) == "1 of 4 (25 %, 95 % CI 5–70 %)"
    assert lib.share(0, 0) == "0 of 0 (n/a)"


# --- labels: who gave them ---------------------------------------------------------------------


def test_every_committed_label_names_its_labeler() -> None:
    sources = run.load_label_sources()
    assert set(sources.values()) <= {"assistant", "human"}
    assert set(sources) == set(run.load_labels())


def test_a_human_label_in_the_sheet_overrides_and_is_counted_as_human(
    tmp_path, monkeypatch
) -> None:
    sheet = tmp_path / "labels-review.csv"
    first = next(iter(run.load_labels()))
    sheet.write_text(
        f"fingerprint,human_label\n{first},fp\nffffffffffffffff,not-a-label\n",
        encoding="utf-8",
    )
    monkeypatch.setattr(run, "REVIEW_SHEET", sheet)
    assert run.load_labels()[first] == "fp"
    assert run.load_label_sources()[first] == "human"
    assert "ffffffffffffffff" not in run.load_labels()  # an invalid value is ignored


def test_precision_block_reports_assistant_and_human_labels_separately() -> None:
    data = {
        "repos_scanned": 2,
        "files_scanned": 3,
        "repos_failing_default_check": 0,
        "findings": [
            {"rule_id": "GR011", "fingerprint": "a"},
            {"rule_id": "GR011", "fingerprint": "b"},
            {"rule_id": "GR012", "fingerprint": "c"},
        ],
    }
    labels = {"a": "tp", "b": "fp", "c": "tp"}
    text = run.precision_block(data, labels, {"a": "assistant", "b": "human", "c": "assistant"})
    assert "Reviewed by a human: 0 of 1" in text
    assert "assistant" in text and "95 % CI" in text
    none = run.precision_block(data, labels, {k: "assistant" for k in labels})
    assert "no label has been reviewed by a human" in none


def test_recall_headline_has_interval_and_sample_size() -> None:
    head = run.readme_block(lib.run_attacks(lib.load_cases()))
    assert "95 % CI" in head.split("\n")[0]


# --- the review sheet --------------------------------------------------------------------------


def test_review_sheet_rows_cover_every_finding_and_labels_are_valid_or_empty() -> None:
    data = json.loads((ROOT / "bench" / "heldout-results.json").read_text(encoding="utf-8"))
    sheet = ROOT / "bench" / "labels-review.csv"
    rows = list(csv.DictReader(sheet.open(encoding="utf-8")))
    assert {r["fingerprint"] for r in rows} == {f["fingerprint"] for f in data["findings"]}
    assert len(rows) == len(data["findings"])
    # filled only by a person: empty (undecided) or one of the three labels
    assert {r["human_label"] for r in rows} <= {"", *lib.LABELS}
    assert {"repo", "rule_id", "location", "context", "human_label"} <= set(rows[0])
    assert "assistant_label" not in rows[0]  # blind review: no anchor


def test_sheet_row_builder_takes_three_lines_of_context_and_flags_drift() -> None:
    text = "one\ntwo needle here\nthree\nfour\n"
    row = run.sheet_row(
        "o/r",
        {
            "rule_id": "GR1",
            "severity": "low",
            "path": "A.md",
            "line": 2,
            "snippet": "…needle…",
            "fingerprint": "x",
        },
        text,
    )
    assert row["context"].splitlines() == ["one", "two needle here", "three"]
    assert row["location"] == "A.md:2" and row["human_label"] == ""
    drift = run.sheet_row(
        "o/r",
        {
            "rule_id": "GR1",
            "severity": "low",
            "path": "A.md",
            "line": 2,
            "snippet": "…absent…",
            "fingerprint": "x",
        },
        text,
    )
    assert drift["context"].startswith("[file changed since the scan]")


def test_when_every_label_is_human_the_report_says_so_without_an_empty_assistant_figure() -> None:
    data = {"findings": [{"rule_id": "GR011", "fingerprint": "a"}]}
    text = run.provenance_sentence(data, {"a": "tp"}, {"a": "human"})
    assert text.startswith("All 1 labels were given by a human") and "n/a" not in text
