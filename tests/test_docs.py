"""The documentation promises: README in sync with the code, complete, and with no dead links."""

import re

import pytest
import yaml
from conftest import ROOT, load_script
from typer.main import get_command

from ghostrules.cli import app
from ghostrules.rules import all_rules
from ghostrules.targets import CONFIG_GLOBS, INSTRUCTION_GLOBS

README = (ROOT / "README.md").read_text(encoding="utf-8")
HOME_FILES = [
    "~/.claude.json",
    "~/.claude/settings.json",
    "~/.claude/CLAUDE.md",
    "~/.cursor/mcp.json",
    "~/.codeium/windsurf/mcp_config.json",
    "~/.gemini/settings.json",
    "~/.codex/config.toml",
]


def section_titles(markdown: str) -> list[str]:
    return re.findall(r"^## (.+)$", markdown, re.MULTILINE)


# --- README ----------------------------------------------------------------------------------


def test_rules_table_is_in_sync_with_the_registry() -> None:
    gen = load_script("gen_rules_table")
    assert gen.replace_block(README, gen.rules_table()) == README, (
        "run: python scripts/gen_rules_table.py --write"
    )


def test_rules_table_lists_every_rule_once_with_an_anchor() -> None:
    for rule in all_rules():
        assert README.count(f'<a id="{rule.id.lower()}"></a>`{rule.id}`') == 1


def test_rules_table_survives_markdown_pipes() -> None:
    gen = load_script("gen_rules_table")
    for line in gen.rules_table().splitlines():
        assert len(re.split(r"(?<!\\)\|", line)) == 6  # five cells, pipes in text are escaped


def test_every_rule_in_the_code_is_documented_in_rules_md_and_vice_versa() -> None:
    documented = set(
        re.findall(r"^### (GR\d{3})\b", (ROOT / "docs/RULES.md").read_text("utf-8"), re.M)
    )
    assert documented == {rule.id for rule in all_rules()}


def test_readme_section_order_follows_the_plan() -> None:
    titles = section_titles(README)
    expected = [
        "Why",
        "Install",
        "Quick start",
        "GitHub Action",
        "pre-commit",
        "Rules",
        "Supported agents and files",
        "Configuration and suppressions",
        "Limits",
        "Roadmap",
        "Contributing, security, license",
    ]
    assert [t for t in titles if t in expected] == expected


def test_readme_opens_with_name_tagline_badges_and_the_gif() -> None:
    lines = README.splitlines()
    assert lines[0] == "# ghostrules"
    assert lines[2] == "*Find the instructions your AI agent sees but you don't.*"
    head = README.split("## Why")[0]
    assert head.count("](https://") >= 4  # CI, PyPI, Python versions, license
    for badge in (
        "actions/workflows/ci.yml",
        "pypi/v/ghostrules",
        "pypi/pyversions",
        "license-MIT",
    ):
        assert badge in head
    assert head.index("badge") < head.index("demo/demo.gif")


def test_readme_documents_every_scan_option() -> None:
    scan = get_command(app).commands["scan"]  # type: ignore[attr-defined]
    for param in scan.params:
        for opt in getattr(param, "opts", []):
            if opt.startswith("--"):
                assert f"`{opt}" in README or f"`-o, {opt}" in README, f"{opt} is not in the README"


def test_readme_lists_every_scanned_file_pattern() -> None:
    for glob in (*INSTRUCTION_GLOBS, *CONFIG_GLOBS):
        assert glob.removeprefix("**/") in README, f"{glob} is not in the README table"
    for path in HOME_FILES:
        assert path in README


def test_readme_explains_why_ghost_findings_cannot_be_suppressed() -> None:
    assert "GR001 and GR002 can never be suppressed" in README
    assert "ghostrules-ignore" in README and ".ghostrules.toml" in README


def test_why_section_links_primary_sources() -> None:
    why = README.split("## Why")[1].split("## Install")[0]
    for host in (
        "embracethered.com",
        "paulbutler.org",
        "trojansource.codes",
        "pillar.security",
        "invariantlabs.ai",
    ):
        assert host in why


# --- links -----------------------------------------------------------------------------------


@pytest.mark.parametrize("name", ["README.md", "CONTRIBUTING.md", "SECURITY.md"])
def test_links_to_repository_files_point_at_files_that_exist(name: str) -> None:
    text = (ROOT / name).read_text(encoding="utf-8")
    for target in re.findall(r"\]\(https://github\.com/OWNER/ghostrules/blob/main/([^)#]+)", text):
        assert (ROOT / target).exists(), f"{name} links to missing {target}"
    for target in re.findall(r"\]\((?!https?:|#|mailto:)([^)#]+)", text):
        assert (ROOT / target).exists(), f"{name} links to missing {target}"


def test_demo_gif_is_referenced_where_the_tape_writes_it() -> None:
    assert "demo/demo.gif" in README
    assert "Output demo/demo.gif" in (ROOT / "demo/demo.tape").read_text(encoding="utf-8")


# --- contributing, security, templates ---------------------------------------------------------


def test_contributing_explains_the_three_steps_and_the_safety_rules() -> None:
    text = (ROOT / "CONTRIBUTING.md").read_text(encoding="utf-8")
    assert "Add a rule in three steps" in text
    for step in ("1. **Write the rule.**", "2. **Test it.**", "3. **Document it.**"):
        assert step in text
    for command in ("pytest -q", "ruff check .", "gen_rules_table.py --write", "make_demo.py"):
        assert command in text
    assert "defanged" in text.lower()
    for script in re.findall(r"scripts/(\w+\.py)", text):
        assert (ROOT / "scripts" / script).exists()


def test_security_policy_says_how_to_report_privately() -> None:
    text = (ROOT / "SECURITY.md").read_text(encoding="utf-8")
    assert "security/advisories/new" in text
    assert "do not open a public issue" in text.lower()
    assert "Supported versions" in text


TEMPLATES = ROOT / ".github" / "ISSUE_TEMPLATE"


def test_issue_templates_are_valid_forms() -> None:
    forms = {p.name: yaml.safe_load(p.read_text("utf-8")) for p in TEMPLATES.glob("*.yml")}
    assert set(forms) == {"config.yml", "false-positive.yml", "new-rule.yml"}
    assert forms["config.yml"]["blank_issues_enabled"] is False
    assert "security/advisories/new" in forms["config.yml"]["contact_links"][0]["url"]
    for name in ("false-positive.yml", "new-rule.yml"):
        form = forms[name]
        assert form["name"] and form["description"] and form["title"]
        ids = [item["id"] for item in form["body"] if "id" in item]
        assert len(ids) == len(set(ids))
        required = [i for i in form["body"] if i.get("validations", {}).get("required")]
        assert required, f"{name} has no required field"
        assert form["body"][0]["type"] == "markdown"  # starts with the "defanged only" warning
    assert "defang" in forms["new-rule.yml"]["body"][0]["attributes"]["value"].lower()
    assert "secrets" in forms["false-positive.yml"]["body"][0]["attributes"]["value"].lower()


def test_license_and_author() -> None:
    assert "MIT License" in (ROOT / "LICENSE").read_text(encoding="utf-8")
    assert "Pablo Seoane Temprano" in README
