"""The governance documents exist, link to files that exist, and say what the code does."""

import re
from pathlib import Path

import pytest

from ghostrules import cli

ROOT = Path(__file__).resolve().parent.parent
DOCS = ("docs/THREAT_MODEL.md", "docs/VERSIONING.md", "GOVERNANCE.md", "CODE_OF_CONDUCT.md")


@pytest.mark.parametrize("name", DOCS)
def test_relative_links_point_to_existing_files(name: str) -> None:
    path = ROOT / name
    for target in re.findall(r"\]\(([^)\s]+)\)", path.read_text(encoding="utf-8")):
        if target.startswith(("https://", "http://", "#", "mailto:")):
            continue
        assert (path.parent / target.split("#")[0]).exists(), f"{name}: {target}"


def test_versioning_lists_the_exit_codes_the_cli_uses() -> None:
    text = (ROOT / "docs/VERSIONING.md").read_text(encoding="utf-8")
    codes = (cli.EXIT_OK, cli.EXIT_FINDINGS, cli.EXIT_ERROR, cli.EXIT_INTERNAL)
    assert codes == (0, 1, 2, 3)
    assert "0 clean, 1 findings" in text and "3 internal failure" in text


def test_threat_model_names_its_non_goals_and_rules_that_exist() -> None:
    from ghostrules.rules import all_rules

    text = (ROOT / "docs/THREAT_MODEL.md").read_text(encoding="utf-8")
    assert "## Non-goals" in text and "## Attacks on the scanner itself" in text
    known = {rule.id for rule in all_rules()}
    assert set(re.findall(r"\bGR\d{3}\b", text)) <= known


def test_the_pull_request_template_asks_for_a_false_positive_test() -> None:
    text = (ROOT / ".github/pull_request_template.md").read_text(encoding="utf-8")
    assert "false-positive" in text and "positive" in text


def test_every_changelog_version_has_a_comparison_link() -> None:
    text = (ROOT / "CHANGELOG.md").read_text(encoding="utf-8")
    versions = re.findall(r"^## \[([^\]]+)\]", text, re.M)
    for version in versions:
        assert re.search(rf"^\[{re.escape(version)}\]: https://", text, re.M), version
