"""Reproducible speed benchmark (docs/PERFORMANCE.md).

    python bench/perf.py                 # run every scenario and print a table
    python bench/perf.py --check         # fail if a scenario is over its budget (CI)
    python bench/perf.py --write         # regenerate docs/PERFORMANCE.md
    python bench/perf.py --quick         # tiny sizes, for the tests

The repositories are synthetic and built in a temporary directory from a fixed seed, so two runs
scan the same bytes. Time is wall-clock seconds of ``scan_paths`` in this process (the median of
``--repeat`` runs); import and start-up are not included. The budgets are 6 to 10 times the
reference measurement: they catch a change that turns a rule quadratic, not a slower runner.
"""

from __future__ import annotations

import argparse
import platform
import random
import statistics
import sys
import tempfile
import time
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

from ghostrules import __version__
from ghostrules.config import Config
from ghostrules.scanner import scan_paths

ROOT = Path(__file__).resolve().parent.parent
DOC = ROOT / "docs" / "PERFORMANCE.md"
SEED = 20261124

PROSE = (
    "Run the tests before committing.",
    "Prefer small functions and descriptive names.",
    "Never commit secrets; use the environment instead.",
    "Use `ruff` for formatting and `pytest -q` for tests.",
    "Open a pull request for every change and keep it focused.",
    "When unsure about an API, read the source before guessing.",
)


@dataclass(frozen=True)
class Scenario:
    """A repository shape, how to scan it, and the most seconds it may take."""

    name: str
    description: str
    build: Callable[[Path, bool], int]  # (root, quick) -> number of files written
    budget: float  # seconds
    all_files: bool = False


def _paragraphs(rng: random.Random, lines: int) -> str:
    return "\n".join(rng.choice(PROSE) for _ in range(lines)) + "\n"


def _many_files(root: Path, quick: bool) -> int:
    """3,000 ordinary source files, 30 CLAUDE.md and a few other agent files."""
    rng = random.Random(SEED)
    plain, agents = (60, 3) if quick else (3000, 30)
    for i in range(plain):
        pkg = root / "src" / f"pkg{i % 50}"
        pkg.mkdir(parents=True, exist_ok=True)
        (pkg / f"mod{i}.py").write_text(f"def f{i}():\n    return {i}\n", encoding="utf-8")
    for i in range(agents):
        d = root / "services" / f"svc{i}"
        d.mkdir(parents=True, exist_ok=True)
        (d / "CLAUDE.md").write_text(f"# svc{i}\n" + _paragraphs(rng, 40), encoding="utf-8")
    (root / "AGENTS.md").write_text(_paragraphs(rng, 60), encoding="utf-8")
    (root / ".cursorrules").write_text(_paragraphs(rng, 60), encoding="utf-8")
    return plain + agents + 2


def _thirty_claude_md(root: Path, quick: bool) -> int:
    """30 CLAUDE.md of 400 lines each, every one importing the next (an import chain)."""
    rng = random.Random(SEED + 1)
    count = 4 if quick else 30
    for i in range(count):
        d = root / f"area{i}"
        d.mkdir(parents=True, exist_ok=True)
        nxt = f"\n@../area{i + 1}/NOTES.md\n" if i + 1 < count else "\n"
        (d / "CLAUDE.md").write_text(_paragraphs(rng, 400) + nxt, encoding="utf-8")
        (d / "NOTES.md").write_text(_paragraphs(rng, 100), encoding="utf-8")
    return count * 2


def _large_repo(root: Path, quick: bool) -> int:
    """A large repository: many directories, deep nesting, few agent files."""
    rng = random.Random(SEED + 2)
    total = 300 if quick else 20000
    for i in range(total):
        d = root / f"a{i % 20}" / f"b{i % 40}" / f"c{i % 80}"
        d.mkdir(parents=True, exist_ok=True)
        (d / f"f{i}.txt").write_text("x\n", encoding="utf-8")
    (root / "CLAUDE.md").write_text(_paragraphs(rng, 80), encoding="utf-8")
    return total + 1


def _big_instruction_file(root: Path, quick: bool) -> int:
    """One CLAUDE.md just under the default 1 MiB limit, ordinary prose."""
    rng = random.Random(SEED + 3)
    target = 20_000 if quick else 1024 * 1024 - 1024
    parts: list[str] = []
    size = 0
    while size < target:
        line = rng.choice(PROSE) + "\n"
        parts.append(line)
        size += len(line)
    (root / "CLAUDE.md").write_text("".join(parts), encoding="utf-8")
    return 1


SCENARIOS = (
    Scenario("many-files", "3,000 source files, 30 CLAUDE.md, 2 other agent files", _many_files, 5),
    Scenario(
        "many-files-all",
        "the same repository with --all-files (every text file checked for hidden Unicode)",
        _many_files,
        10,
        all_files=True,
    ),
    Scenario(
        "thirty-claude-md", "30 CLAUDE.md of 400 lines in an import chain", _thirty_claude_md, 15
    ),
    Scenario("large-repo", "20,000 files in nested directories, one CLAUDE.md", _large_repo, 15),
    Scenario("big-file", "one 1 MiB CLAUDE.md of ordinary prose", _big_instruction_file, 20),
)


def measure(scenario: Scenario, *, quick: bool, repeat: int) -> tuple[int, float, int]:
    """(files written, median seconds, findings) for ``scenario``."""
    with tempfile.TemporaryDirectory(prefix="ghostrules-perf-") as tmp:
        root = Path(tmp)
        files = scenario.build(root, quick)
        times, findings = [], 0
        for _ in range(repeat):
            started = time.perf_counter()
            result = scan_paths([root], Config(), all_files=scenario.all_files)
            times.append(time.perf_counter() - started)
            findings = len(result.findings)
            if result.errors:
                raise SystemExit(f"{scenario.name}: scan reported errors: {result.errors[0]}")
    return files, statistics.median(times), findings


def run(*, quick: bool, repeat: int) -> list[tuple[Scenario, int, float, int]]:
    return [(s, *measure(s, quick=quick, repeat=repeat)) for s in SCENARIOS]


def table(rows: list[tuple[Scenario, int, float, int]]) -> str:
    out = ["| Scenario | Files | Median (s) | Budget (s) | Findings |", "|---|---:|---:|---:|---:|"]
    for s, files, seconds, findings in rows:
        out.append(
            f"| `{s.name}`: {s.description} | {files:,} | {seconds:.2f} | {s.budget} | {findings} |"
        )
    return "\n".join(out)


def over_budget(rows: list[tuple[Scenario, int, float, int]]) -> list[str]:
    return [
        f"{s.name}: {seconds:.2f}s > budget {s.budget}s"
        for s, _, seconds, _ in rows
        if seconds > s.budget
    ]


def document(rows: list[tuple[Scenario, int, float, int]], repeat: int) -> str:
    when = datetime.now(timezone.utc).date().isoformat()
    machine = f"{platform.system()} {platform.machine()}, Python {platform.python_version()}"
    return f"""# Performance

Generated by `python bench/perf.py --write`; do not edit by hand. Measured on {when} with
ghostrules {__version__} on {machine} (median of {repeat} runs). The repositories are synthetic and
built from a fixed seed, so a run scans the same bytes every time.

{table(rows)}

What is timed is `scan_paths` in one process: Python start-up and import are not included, and the
report is not rendered. The files are warm in the page cache. A different machine will give
different seconds; compare scenarios with each other, not with this table.

## Budget

`python bench/perf.py --check` runs in CI (job `perf`) and fails when a scenario takes longer than
its budget. The budgets are 6 to 10 times the measurement above, deliberately loose: a shared
runner is two or three times slower than a workstation, and the budget exists to catch a change that
turns a rule quadratic (the audit that preceded phase 4 measured minutes on hostile input), not to
track small regressions. Hostile single-file inputs have their own time budget in
`tests/test_robustness_perf.py` (`pytest -m slow`).

A file over `max_file_size` (1 MiB by default) is skipped with a warning rather than scanned, so the
`big-file` scenario is the largest a default scan reads.
"""


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawTextHelpFormatter
    )
    parser.add_argument("--check", action="store_true", help="exit 1 if a scenario is over budget")
    parser.add_argument("--write", action="store_true", help="regenerate docs/PERFORMANCE.md")
    parser.add_argument("--quick", action="store_true", help="tiny sizes (for the tests)")
    parser.add_argument("--repeat", type=int, default=3, help="runs per scenario (default 3)")
    args = parser.parse_args(argv)
    rows = run(quick=args.quick, repeat=max(1, args.repeat))
    print(table(rows))
    if args.write:
        DOC.write_text(document(rows, args.repeat), encoding="utf-8")
        print(f"wrote {DOC.relative_to(ROOT)}")
    problems = over_budget(rows)
    for problem in problems:
        print(f"over budget: {problem}", file=sys.stderr)
    return 1 if (args.check and problems) else 0


if __name__ == "__main__":
    sys.exit(main())
