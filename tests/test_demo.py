"""The demo repositories: what the README GIF shows, and what the docs promise about them."""

import re
from pathlib import Path
from types import ModuleType

from typer.testing import CliRunner

from ghostrules.cli import app
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
    for name in ("poisoned-repo", "clean-repo", "import-chain-repo"):
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


# --- completeness of the poisoned demo (RULES.md acceptance criterion) --------------------------


def test_every_rule_fires_somewhere_in_the_poisoned_repo(demo_root: Path) -> None:
    from ghostrules.rules import all_rules

    ids = {f.rule_id for f in scan(demo_root / "poisoned-repo").findings}
    # GR020-GR025 need @imports and symlinks, which this demo (frozen at its 0.1 contents) does
    # not have; examples/import-chain-repo covers them.
    missing = sorted({r.id for r in all_rules() if r.id < "GR020"} - ids)
    assert not missing, f"the poisoned demo does not trigger {missing}"


def test_clean_repo_is_clean_even_with_all_files(demo_root: Path) -> None:
    result = scan_paths([demo_root / "clean-repo"], Config(), all_files=True)
    assert result.findings == []


def test_flat_reports_also_lead_with_the_hidden_instruction(demo_root: Path) -> None:
    first = scan(demo_root / "poisoned-repo").findings[0]
    assert (first.rule_id, first.path) == ("GR001", "AGENTS.md")  # not a nested .github file


def test_checked_in_demos_behave_as_documented() -> None:
    from typer.testing import CliRunner

    from ghostrules.cli import app

    runner = CliRunner()
    assert runner.invoke(app, ["scan", str(ROOT / "examples" / "poisoned-repo")]).exit_code == 1
    clean = runner.invoke(app, ["scan", str(ROOT / "examples" / "clean-repo")])
    assert clean.exit_code == 0
    assert "No findings" in clean.stdout


def test_each_example_explains_that_it_is_a_defanged_demo() -> None:
    for name in ("poisoned-repo", "clean-repo", "import-chain-repo"):
        readme = (ROOT / "examples" / name / "README.md").read_text(encoding="utf-8")
        assert "defanged" in readme


def test_line_endings_of_generated_files_are_protected_by_gitattributes() -> None:
    attributes = (ROOT / ".gitattributes").read_text(encoding="utf-8")
    assert "examples/** -text" in attributes
    assert "tests/fixtures/** -text" in attributes


# --- demo/demo.tape ------------------------------------------------------------------------------


def tape_seconds(tape: str) -> float:
    """Rough duration of the recording: typing time plus sleeps, ignoring hidden sections."""
    speed, total, hidden = 0.05, 0.0, False

    def seconds(value: str) -> float:
        return float(value[:-2]) / 1000 if value.endswith("ms") else float(value.rstrip("s"))

    for raw in tape.splitlines():
        line = raw.strip()
        if line == "Hide":
            hidden = True
        elif line == "Show":
            hidden = False
        elif line.startswith("Set TypingSpeed"):
            speed = seconds(line.split()[-1])
        elif hidden:
            continue
        elif line.startswith("Type"):
            match = re.match(r'Type(?:@(\S+))?\s+"(.*)"$', line)
            assert match, line
            per_char = seconds(match.group(1)) if match.group(1) else speed
            total += len(match.group(2)) * per_char
        elif line.startswith("Sleep"):
            total += seconds(line.split()[-1])
    return total


def test_demo_tape_matches_the_plan() -> None:
    tape = (ROOT / "demo" / "demo.tape").read_text(encoding="utf-8")
    assert "Output demo/demo.gif" in tape
    assert re.search(r"^Set Width 1200$", tape, re.MULTILINE)
    assert re.search(r"^Set FontSize 16$", tape, re.MULTILINE)
    assert re.search(
        r'^Set Theme "(Dracula|Tokyo Night|Catppuccin Mocha|Monokai)', tape, re.MULTILINE
    )
    commands = re.findall(r'^Type "(.*)"$', tape, re.MULTILINE)
    assert commands[0] == "export PS1='$ ' && clear"  # hidden setup
    assert commands[1:] == [
        "cat examples/poisoned-repo/AGENTS.md",
        "ghostrules scan examples/poisoned-repo | head -24",
        "ghostrules reveal examples/poisoned-repo/AGENTS.md",
    ]


def test_demo_tape_is_shorter_than_fifteen_seconds() -> None:
    tape = (ROOT / "demo" / "demo.tape").read_text(encoding="utf-8")
    assert 8 < tape_seconds(tape) < 15


def _commands(tape: str) -> list[str]:
    return re.findall(r'^Type "(.*)"$', tape, re.MULTILINE)


def test_imports_tape_follows_the_import_story() -> None:
    tape = (ROOT / "demo" / "imports.tape").read_text(encoding="utf-8")
    assert "Output demo/imports.gif" in tape
    assert re.search(r"^Set Width 1200$", tape, re.MULTILINE)
    assert _commands(tape) == [
        "export PS1='$ ' && clear",
        "cat examples/import-chain-repo/CLAUDE.md",
        "ghostrules scan --no-follow-imports examples/import-chain-repo",
        "ghostrules scan examples/import-chain-repo | head -12",
        "ghostrules context src/api/users.ts --root examples/import-chain-repo --agent claude-code",
    ]
    assert 10 < tape_seconds(tape) < 20


def test_lock_tape_shows_the_review_diff_and_the_check() -> None:
    tape = (ROOT / "demo" / "lock.tape").read_text(encoding="utf-8")
    assert "Output demo/lock.gif" in tape
    visible = _commands(tape)[2:]  # the first two lines are hidden setup
    assert visible == [
        "diff base/shared/team-rules.md pr/shared/team-rules.md | sed 's/[^ -~]//g'",
        "ghostrules lock --check --root pr",
    ]
    assert "make_demo.py --lock-scenario /tmp/acme" in tape
    assert 8 < tape_seconds(tape) < 20


def test_imports_tape_commands_do_what_the_story_says(demo_root: Path) -> None:
    root = demo_root / "import-chain-repo"
    assert scan_paths([root], Config(follow_imports=False)).findings == []
    result = scan_paths([root], Config())
    assert {"GR001", "GR020", "GR021"} <= {f.rule_id for f in result.findings}


def test_the_import_scan_in_the_tape_fits_in_head_12(demo_root: Path) -> None:
    from ghostrules.reporters import table

    result = scan_paths([demo_root / "import-chain-repo"], Config())
    lines = table.render(result, width=118, target="examples/import-chain-repo").splitlines()[:12]
    text = "\n".join(lines)
    assert "via CLAUDE.md:5 → docs/style.md:4" in text
    assert "Decoded hidden text" in text and "╰" in text
    assert "exfil.example" in text


def test_the_lock_scenario(tmp_path: Path, make_demo: ModuleType) -> None:
    make_demo.lock_scenario(tmp_path)
    base, pr = tmp_path / "base", tmp_path / "pr"
    runner = CliRunner()
    assert runner.invoke(app, ["lock", "--root", str(base)]).exit_code == 0
    (pr / ".ghostrules.lock").write_bytes((base / ".ghostrules.lock").read_bytes())
    assert runner.invoke(app, ["lock", "--check", "--root", str(base)]).exit_code == 0
    checked = runner.invoke(app, ["lock", "--check", "--no-color", "--root", str(pr)])
    assert checked.exit_code == 1
    assert "✎ changed  shared/team-rules.md" in checked.stdout
    assert f"hidden text: {make_demo.PR_HIDDEN_INSTRUCTION}" in checked.stdout
    assert "via CLAUDE.md:5 → docs/style.md:4" in checked.stdout
    # what a reviewer's diff shows: the added bullet, and nothing else
    visible = (pr / "shared" / "team-rules.md").read_text(encoding="utf-8")
    shown = "".join(c for c in visible if " " <= c <= "~" or c == "\n")
    assert "Ask before deleting files." in shown and "bootstrap" not in shown


def test_the_scan_command_in_the_tape_fits_in_head_24(demo_root: Path) -> None:
    """`head -24` must show the whole hidden-text block, not cut it in the middle."""
    from ghostrules.reporters import table

    result = scan_paths([demo_root / "poisoned-repo"], Config())
    lines = table.render(result, width=118, target="examples/poisoned-repo").splitlines()[:24]
    text = "\n".join(lines)
    assert "Decoded hidden text" in text
    assert "╰" in text  # the panel is closed within the first 24 lines
    assert "GR014" in text  # ... and so are the derived findings
