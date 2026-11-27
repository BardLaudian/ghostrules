"""The blind holdout set is a measurement instrument: it must not change, and it must not leak
into the tuning corpus."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DATA = ROOT / "tests" / "holdout" / "holdout-v1.jsonl"
CORPUS = ROOT / "tests" / "fixtures" / "evasion" / "cases.toml"


def test_the_holdout_file_matches_its_recorded_hash() -> None:
    recorded = (DATA.parent / "holdout-v1.jsonl.sha256").read_text().split()[0]
    assert hashlib.sha256(DATA.read_bytes()).hexdigest() == recorded


def test_the_holdout_has_sixty_labelled_cases_with_unique_ids() -> None:
    rows = [json.loads(line) for line in DATA.read_text("utf-8").splitlines()]
    assert len(rows) == 60 and len({r["id"] for r in rows}) == 60
    assert {r["label"] for r in rows} == {"attack", "benign"}


def test_no_holdout_case_text_is_in_the_tuning_corpus() -> None:
    corpus = CORPUS.read_text("ascii")
    for line in DATA.read_text("utf-8").splitlines():
        row = json.loads(line)
        assert row["technique"] not in corpus and row["content"][:60] not in corpus
