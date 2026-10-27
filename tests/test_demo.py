"""The demo repositories: what the README GIF shows, and what the docs promise about them."""

from pathlib import Path
from types import ModuleType

from ghostrules.config import Config
from ghostrules.models import Severity
from ghostrules.scanner import scan_paths

ROOT = Path(__file__).resolve().parent.parent


def scan(root: Path):
    result = scan_paths([root], Config())
    assert result.errors == []
    return result


def test_poisoned_repo_hidden_instruction_comes_first(
    demo_root: Path, make_demo: ModuleType
) -> None:
    result = scan(demo_root / "poisoned-repo")
    first = result.findings[0]
    assert (first.rule_id, first.severity, first.path) == ("GR001", Severity.CRITICAL, "AGENTS.md")
    assert first.decoded == make_demo.HIDDEN_INSTRUCTION


def test_poisoned_repo_triggers_a_broad_set_of_rules(demo_root: Path) -> None:
    ids = {f.rule_id for f in scan(demo_root / "poisoned-repo").findings}
    expected = {
        "GR001", "GR005", "GR010", "GR011", "GR012", "GR013", "GR014",
        "GR101", "GR102", "GR103", "GR106", "GR107", "GR108",
    }  # fmt: skip
    assert expected <= ids


def test_poisoned_repo_shows_only_masked_secrets(demo_root: Path, make_demo: ModuleType) -> None:
    result = scan(demo_root / "poisoned-repo")
    assert not any(make_demo.FAKE_GITHUB_TOKEN in f.snippet + f.message for f in result.findings)
    assert any("ghp_****…PLE0" in f.message for f in result.findings)


def test_clean_repo_has_no_findings(demo_root: Path) -> None:
    result = scan(demo_root / "clean-repo")
    assert result.findings == []
    assert result.scanned_files == 4


def test_demo_fake_token_matches_the_real_token_shape(make_demo: ModuleType) -> None:
    token = make_demo.FAKE_GITHUB_TOKEN
    assert token.startswith("ghp_")
    assert len(token) == len("ghp_") + 36


def test_checked_in_examples_are_up_to_date(demo_root: Path) -> None:
    """examples/ must be exactly what scripts/make_demo.py generates."""
    for name in ("poisoned-repo", "clean-repo"):
        fresh = {
            p.relative_to(demo_root / name): p.read_bytes()
            for p in (demo_root / name).rglob("*")
            if p.is_file()
        }
        checked_in = {
            p.relative_to(ROOT / "examples" / name): p.read_bytes()
            for p in (ROOT / "examples" / name).rglob("*")
            if p.is_file()
        }
        assert checked_in == fresh, f"run: python scripts/make_demo.py ({name} is stale)"


def test_demo_files_contain_no_literal_invisible_characters_in_the_generator(
    make_demo: ModuleType,
) -> None:
    source = (ROOT / "scripts" / "make_demo.py").read_text(encoding="utf-8")
    assert not any(
        0xE0000 <= ord(c) <= 0xE007F or ord(c) in (0x200B, 0x200C, 0x200D, 0xFEFF) for c in source
    )
