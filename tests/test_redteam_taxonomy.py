"""The attack taxonomy covers every bench case, cites real agent sections, baseline is current."""

import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "bench"))
sys.path.insert(0, str(ROOT / "bench" / "redteam"))

import baseline  # noqa: E402
from lib import load_cases  # noqa: E402

TAXONOMY = baseline.load_taxonomy()


def test_every_technique_of_every_case_has_a_class() -> None:
    missing = {
        c.technique for c in load_cases() if baseline.class_of(c.technique, TAXONOMY) is None
    }
    assert not missing, f"add these techniques to bench/redteam/taxonomy.toml: {sorted(missing)}"


def test_every_listed_technique_belongs_to_a_known_class_and_is_used() -> None:
    used = {c.technique for c in load_cases()}
    for name, entry in TAXONOMY["technique"].items():
        assert entry["class"] in TAXONOMY["class"], name
        assert entry["files"] and entry["agents"], name
        assert name in used or name == "mcp-server-content", f"{name} has no case"


def test_the_five_classes_exist() -> None:
    assert sorted(TAXONOMY["class"]) == ["C1", "C2", "C3", "C4", "C5"]


def test_cited_agents_are_sections_of_agent_models() -> None:
    headings = [
        line[3:].split(" ")[0]
        for line in (ROOT / "docs" / "AGENT_MODELS.md").read_text(encoding="utf-8").splitlines()
        if line.startswith("## ")
    ]
    for name, entry in TAXONOMY["technique"].items():
        for agent in entry["agents"]:
            assert agent in headings, f"{name} cites {agent}, not a section of AGENT_MODELS.md"


def test_baseline_md_is_what_the_script_prints() -> None:
    printed = subprocess.run(
        [sys.executable, str(ROOT / "bench" / "redteam" / "baseline.py")],
        capture_output=True,
        text=True,
        check=True,
    ).stdout.strip()
    assert printed in (ROOT / "bench" / "redteam" / "BASELINE.md").read_text(encoding="utf-8")
