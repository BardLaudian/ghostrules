"""bench/perf.py works at small scale and its documents agree with the code (phase 8)."""

import importlib.util
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
spec = importlib.util.spec_from_file_location("perf", ROOT / "bench" / "perf.py")
assert spec and spec.loader
perf = importlib.util.module_from_spec(spec)
sys.modules["perf"] = perf
spec.loader.exec_module(perf)


def test_every_scenario_runs_quickly_at_small_scale_and_stays_in_budget() -> None:
    rows = perf.run(quick=True, repeat=1)
    assert [r[0].name for r in rows] == [s.name for s in perf.SCENARIOS]
    assert all(files > 0 for _, files, _, _ in rows)
    assert perf.over_budget(rows) == []


def test_the_synthetic_repositories_are_reproducible(tmp_path: Path) -> None:
    for scenario in perf.SCENARIOS:
        a, b = tmp_path / f"{scenario.name}-a", tmp_path / f"{scenario.name}-b"
        a.mkdir()
        b.mkdir()
        scenario.build(a, True)
        scenario.build(b, True)
        files_a = sorted((p.relative_to(a), p.read_bytes()) for p in a.rglob("*") if p.is_file())
        files_b = sorted((p.relative_to(b), p.read_bytes()) for p in b.rglob("*") if p.is_file())
        assert files_a == files_b, scenario.name


def test_over_budget_names_the_scenario() -> None:
    scenario = perf.SCENARIOS[0]
    assert perf.over_budget([(scenario, 1, scenario.budget + 1, 0)])[0].startswith(scenario.name)
    assert perf.over_budget([(scenario, 1, scenario.budget - 1, 0)]) == []


def test_main_exits_1_only_with_check_and_a_scenario_over_budget(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    scenario = perf.SCENARIOS[0]
    monkeypatch.setattr(perf, "run", lambda **_: [(scenario, 1, scenario.budget * 2, 0)])
    assert perf.main(["--quick"]) == 0
    assert perf.main(["--quick", "--check"]) == 1
    assert "over budget" in capsys.readouterr().err


def test_the_performance_doc_lists_every_scenario_and_ci_runs_the_check() -> None:
    doc = (ROOT / "docs" / "PERFORMANCE.md").read_text(encoding="utf-8")
    assert all(f"`{s.name}`" in doc for s in perf.SCENARIOS)
    ci = (ROOT / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8")
    assert "python bench/perf.py --check" in ci
