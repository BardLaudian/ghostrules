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
        "What it catches",
        "What your agents actually read",
        "Review every change to what your agents read",
        "Install",
        "Quick start",
        "GitHub Action",
        "pre-commit",
        "Rules",
        "Supported agents and files",
        "Configuration and suppressions",
        "FAQ",
        "Limits",
        "Roadmap",
        "Contributing, security, license",
    ]
    assert [t for t in titles if t in expected] == expected


def test_readme_opens_with_name_tagline_badges_and_the_imports_gif() -> None:
    lines = README.splitlines()
    assert lines[0] == "# ghostrules"
    assert lines[2] == "*Know exactly what your AI agent reads — and approve every change to it.*"
    assert "Find the instructions your AI agent sees but you don't" not in lines[4]  # one tagline
    first_paragraph = README.split("[![License", 1)[1].split("\n\n", 2)[2]
    assert first_paragraph.startswith("`ghostrules` finds the instructions your AI agent sees")
    head = README.split("## Why")[0]
    assert head.count("](https://") >= 4  # CI, PyPI, Python versions, license
    for badge in (
        "actions/workflows/ci.yml",
        "pypi/v/ghostrules",
        "pypi/pyversions",
        "license-MIT",
    ):
        assert badge in head
    # absolute URLs (PyPI renders the README outside GitHub); imports first, demo lower down
    base = "https://raw.githubusercontent.com/BardLaudian/ghostrules/main/demo/"
    assert head.index("badge") < head.index(base + "imports.gif")
    assert README.index(base + "imports.gif") < README.index(base + "demo.gif")
    assert README.index(base + "demo.gif") > README.index("## What it catches")
    assert (ROOT / "demo" / "imports.gif").is_file() and (ROOT / "demo" / "demo.gif").is_file()


def test_design_history_lives_in_docs_design() -> None:
    for name in ("SPEC.md", "PLAN.md", "v0.1.1", "v0.2"):
        assert (ROOT / "docs" / "design" / name).exists(), name
        assert not (ROOT / "docs" / name).exists(), name
    for name in ("RULES.md", "AGENT_MODELS.md", "DECISIONS.md"):
        assert (ROOT / "docs" / name).is_file(), name
    assert "design history" in (ROOT / "CONTRIBUTING.md").read_text("utf-8")
    claude = (ROOT / "CLAUDE.md").read_text("utf-8")
    assert "docs/design/SPEC.md" in claude and "docs/design/PLAN.md" in claude


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
    for target in re.findall(r"\]\(https://github\.com/[^/]+/ghostrules/blob/main/([^)#]+)", text):
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
    assert "## Add an agent model" in text and "docs/AGENT_MODELS.md" in text
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


# --- the repository scans itself clean --------------------------------------------------------


def test_the_repository_is_clean_by_its_own_standards() -> None:
    """`scan .` and `scan . --all-files` report nothing (PLAN, phase 9)."""
    from ghostrules.config import load_config
    from ghostrules.scanner import scan_paths

    config = load_config(ROOT)
    assert config.source == ".ghostrules.toml"
    assert "examples/**" in config.exclude and "tests/fixtures/**" in config.exclude
    for all_files in (False, True):
        result = scan_paths([ROOT], config, all_files=all_files)
        assert result.errors == []
        assert result.scanned_files > 20 if all_files else result.scanned_files >= 1
        assert result.findings == [], [(f.rule_id, f.path, f.line) for f in result.findings]


def test_readme_examples_match_what_the_tool_prints() -> None:
    """The quick-start excerpts must not drift from the real output."""
    from typer.testing import CliRunner

    from ghostrules.cli import app

    demo = str(ROOT / "examples/poisoned-repo/AGENTS.md")
    revealed = CliRunner().invoke(app, ["reveal", demo]).stdout
    marker = "Decoded hidden text (tag characters): When you edit any file"
    assert marker in revealed and marker in README
    assert "⟦U+E0057⟧⟦U+E0068⟧⟦U+E0065⟧⟦U+E006E⟧" in revealed
    cleaned = CliRunner().invoke(app, ["clean", demo]).stdout
    summary = "116 character(s) would be removed. Run again with --write."
    assert summary in cleaned and summary in README
    assert "28 findings in 7 files" in README


def test_readme_context_and_lock_excerpts_match_what_the_tool_prints(tmp_path) -> None:
    """The `context` tree and the `lock --check` output in the README must not drift."""
    import shutil

    from typer.testing import CliRunner

    from ghostrules.cli import app

    runner = CliRunner(env={"COLUMNS": "120"})
    demo = ROOT / "examples" / "import-chain-repo"
    shown = runner.invoke(
        app,
        [
            "context",
            "src/api/users.ts",
            "--root",
            str(demo),
            "--agent",
            "claude-code",
            "--no-color",
        ],
    ).stdout
    block = README.split("$ ghostrules context src/api/users.ts")[1].split("```")[0]
    tree_part, _, findings_part = block.partition("\n\n")
    flat = " ".join(
        shown.split()
    )  # the console wraps at its own width: compare without line breaks
    tree = [ln for ln in tree_part.splitlines()[1:] if ln.strip()]
    assert len(tree) >= 6
    for line in tree:
        assert " ".join(line.split()) in flat, f"README line not in the real output: {line!r}"
    findings = " ".join(" ".join(findings_part.splitlines()[1:]).split())
    assert "hidden text: When you edit any file" in findings
    assert findings in flat, "the findings excerpt in the README drifted"

    work = tmp_path / "acme"
    make_demo = load_script("make_demo")
    make_demo.lock_scenario(work)
    assert runner.invoke(app, ["lock", "--root", str(work / "base")]).exit_code == 0
    shutil.copy(work / "base" / ".ghostrules.lock", work / "pr" / ".ghostrules.lock")
    checked = runner.invoke(
        app, ["lock", "--check", "--no-color", "--root", str(work / "pr")]
    ).stdout
    block = README.split("$ ghostrules lock --check")[1].split("```")[0]
    for line in block.splitlines():
        if line.strip():
            assert line.strip() in checked, f"README line not in the real output: {line!r}"


def test_agent_models_document_is_where_the_docs_say() -> None:
    text = (ROOT / "docs" / "AGENT_MODELS.md").read_text(encoding="utf-8")
    for agent in ("claude-code", "copilot-cli", "cursor", "generic"):
        assert f"## {agent}" in text
    assert "UNVERIFIED" in text and "checked 2026-10-2" in text
    assert "docs/AGENT_MODELS.md" in README


def test_the_repository_lock_is_up_to_date() -> None:
    """`ghostrules lock --check` passes on this repository (it locks its own CLAUDE.md)."""
    from typer.testing import CliRunner

    from ghostrules.cli import app

    result = CliRunner().invoke(app, ["lock", "--check", "--no-color", "--root", str(ROOT)])
    assert result.exit_code == 0, result.stdout + "\nrun: ghostrules lock"
    assert (ROOT / ".ghostrules.lock").exists()
