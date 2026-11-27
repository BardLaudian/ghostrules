"""The keyword prefilter: it never hides a match, and it keeps the scan fast.

``keys(pattern)`` is a necessary condition, so a scan with it must report exactly what a scan
without it reports; the time test fails if the filter stops working or the scan gets slower per
megabyte than the generous budget below (about 2x what a laptop needs).
"""

from __future__ import annotations

import re
import sys
import time
from pathlib import Path

import pytest

from ghostrules import prefilter
from ghostrules.config import Config
from ghostrules.rules import injection, patterns
from ghostrules.scanner import scan_paths

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))
import corpus_metrics  # noqa: E402


def _all_patterns() -> list[re.Pattern[str]]:
    found: list[re.Pattern[str]] = []
    for value in vars(patterns).values():
        if isinstance(value, tuple) and value and isinstance(value[0], re.Pattern):
            found += list(value)
        elif isinstance(value, dict):
            for item in value.values():
                if isinstance(item, tuple):
                    found += [p for p in item if isinstance(p, re.Pattern)]
    return found


def _texts() -> list[str]:
    texts = [c["text"] for c in corpus_metrics.load_cases()]
    texts += [p.read_text("utf-8") for p in (ROOT / "docs").glob("*.md")]
    return texts


def test_almost_every_pattern_has_a_keyword_and_the_words_are_lowercase() -> None:
    every = _all_patterns()
    assert len(every) > 150
    words = [prefilter.keys(p) for p in every]
    assert sum(w is None for w in words) <= 5
    assert all(w == w.casefold() for ws in words if ws for w in ws)


def test_a_match_always_holds_one_of_the_keywords_of_its_pattern() -> None:
    """The soundness of the filter, on every pattern and every text of the corpus and the docs."""
    texts = _texts()
    for pattern in _all_patterns():
        words = prefilter.keys(pattern)
        if words is None:
            continue
        for text in texts:
            if not prefilter.may_match(pattern, text.casefold()):
                assert pattern.search(text) is None, pattern.pattern
            for m in pattern.finditer(text):
                assert any(w in m.group().casefold() for w in words), pattern.pattern


def test_the_reader_handles_the_pattern_shapes_it_meets() -> None:
    assert prefilter.keys(re.compile(r"\bghostrules-ignore\b", re.I)) == ("ghostrules-ignore",)
    assert prefilter.keys(re.compile(r"(?:curl|wget)\s+\d", re.I)) == ("curl", "wget")
    assert prefilter.keys(re.compile(r"(?:ab|c)xyz", re.I)) == ("xyz",)  # a short branch is dropped
    assert prefilter.keys(re.compile(r"\d+")) is None
    assert prefilter.keys(re.compile(r"(?:a|bcd)?hello")) == ("hello",)
    assert prefilter.may_match(re.compile(r"\d+"), "anything")
    assert not prefilter.may_match(re.compile(r"ghostrules"), "nothing here")


def _agent_files(tmp_path: Path, size: int = 40_000, docs: bool = False) -> int:
    """Instruction files of ordinary text (the build notes of a project, or our own docs, which
    name every attack on purpose); returns the bytes written."""
    if docs:
        text = "\n\n".join(p.read_text("utf-8") for p in sorted((ROOT / "docs").glob("*.md")))
    else:
        text = "\n".join(
            f"- Module {n}: run `make test-{n}` before a commit, keep functions short, name the "
            f"file after its class, and write the changelog entry for change {n} in the "
            f"pull request description; the build uses version {n}.{n % 7} of the toolchain."
            for n in range(1, 900)
        )
    chunks = [text[i : i + size] for i in range(0, len(text), size)]
    for n, chunk in enumerate(chunks):
        (tmp_path / f"agents{n}").mkdir()
        (tmp_path / f"agents{n}" / "AGENTS.md").write_text(chunk, encoding="utf-8")
    return sum(len(c.encode()) for c in chunks)


def _timed(root: Path) -> tuple[float, list[tuple[str, int, str]]]:
    started = time.perf_counter()
    result = scan_paths([root], Config())
    return time.perf_counter() - started, sorted(
        (f.path, f.line, f.rule_id) for f in result.findings
    )


def test_the_filter_changes_the_speed_not_the_findings(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    size = _agent_files(tmp_path)
    fast, with_filter = _timed(tmp_path)
    monkeypatch.setattr(injection, "may_match", lambda pattern, folded: True)
    slow, without = _timed(tmp_path)
    assert with_filter == without
    assert fast < 0.6 * slow, f"filter {fast:.1f}s, no filter {slow:.1f}s over {size} bytes"


def test_the_scan_stays_inside_a_generous_time_per_megabyte(tmp_path: Path) -> None:
    """The v2 scan took 135 s for 62 MB with the regression and about 60 s without it; this is
    the same measure on a small input with 2x the slowest healthy machine we measured."""
    size = _agent_files(tmp_path, docs=True)
    seconds, _ = _timed(tmp_path)
    per_mb = seconds / (size / 1_000_000)
    assert per_mb < 30, f"{per_mb:.1f} s/MB"
