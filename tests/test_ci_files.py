"""The GitHub Action, pre-commit hook and workflows: structure, hygiene and behaviour."""

import json
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path

import pytest
import yaml
from conftest import ROOT, load_script

WORKFLOWS = sorted((ROOT / ".github" / "workflows").glob("*.yml"))
ACTION = yaml.safe_load((ROOT / "action.yml").read_text(encoding="utf-8"))
needs_bash = pytest.mark.skipif(
    os.name == "nt" or shutil.which("bash") is None, reason="action scripts are bash scripts"
)


def load(path: Path) -> dict:
    return yaml.safe_load(path.read_text(encoding="utf-8"))


def steps_of(workflow: dict):
    for job in workflow["jobs"].values():
        yield from job.get("steps", [])


# --- action.yml ------------------------------------------------------------------------------


def test_action_inputs_follow_the_spec() -> None:
    inputs = ACTION["inputs"]
    assert {k: str(v["default"]) for k, v in inputs.items()} == {
        "path": ".",
        "fail-on": "high",
        "all-files": "false",
        "upload-sarif": "true",
        "follow-imports": "true",
        "lock-check": "false",
    }
    assert all(v["description"] for v in inputs.values())
    assert ACTION["name"] == "ghostrules"


def test_action_is_a_composite_with_the_specified_steps_in_order() -> None:
    assert ACTION["runs"]["using"] == "composite"
    steps = ACTION["runs"]["steps"]
    uses = [s.get("uses", "") for s in steps]
    assert uses[0].startswith("actions/setup-python@v")
    assert any(u == "github/codeql-action/upload-sarif@v3" for u in uses)
    names = [s["name"] for s in steps]
    order = [
        "Set up Python",
        "Install",
        "Scan",
        "Upload SARIF",
        "Write job summary",
        "Check the lock",
        "Fail",
    ]
    positions = [next(i for i, n in enumerate(names) if n.startswith(o)) for o in order]
    assert positions == sorted(positions)


def test_action_installs_its_own_source_and_scans_to_sarif_without_failing_yet() -> None:
    steps = {s["name"]: s for s in ACTION["runs"]["steps"]}
    assert "GITHUB_ACTION_PATH" in steps["Install ghostrules"]["run"]
    scan = steps["Scan"]["run"]
    assert "--format sarif --output ghostrules.sarif" in scan
    assert "set +e" in scan and "exit-code=" in scan  # the exit code is kept for the last step
    summary = steps["Write job summary"]["run"]
    assert "--format markdown" in summary and "GITHUB_STEP_SUMMARY" in summary
    upload = steps["Upload SARIF to code scanning"]
    assert "inputs.upload-sarif == 'true'" in upload["if"]
    assert upload["with"]["sarif_file"] == "ghostrules.sarif"


def test_action_run_steps_use_bash() -> None:
    for step in ACTION["runs"]["steps"]:
        if "run" in step:
            assert step["shell"] == "bash", step["name"]


@pytest.mark.parametrize("path", [ROOT / "action.yml", *WORKFLOWS], ids=lambda p: p.name)
def test_no_expression_is_interpolated_into_a_shell_script(path: Path) -> None:
    """Inputs reach scripts through env vars only, never by text substitution (injection)."""
    data = load(path)
    steps = data["runs"]["steps"] if "runs" in data else list(steps_of(data))
    for step in steps:
        assert "${{" not in step.get("run", ""), (path.name, step.get("name"))


@pytest.mark.parametrize("path", [ROOT / "action.yml", *WORKFLOWS], ids=lambda p: p.name)
def test_every_third_party_action_is_pinned_to_a_version(path: Path) -> None:
    data = load(path)
    steps = data["runs"]["steps"] if "runs" in data else list(steps_of(data))
    for step in steps:
        ref = step.get("uses")
        if ref and not ref.startswith("./"):
            assert "@" in ref, ref
            assert ref.split("@")[1] not in ("main", "master"), ref


# --- running the action's scripts for real ----------------------------------------------------


def run_step(name: str, tmp_path: Path, **env: str) -> subprocess.CompletedProcess[str]:
    steps = {s["name"]: s for s in ACTION["runs"]["steps"]}
    output, summary = tmp_path / "github_output", tmp_path / "step_summary"
    output.touch()
    summary.touch()
    environment = {
        **os.environ,
        "PATH": f"{Path(sys.executable).parent}{os.pathsep}{os.environ['PATH']}",
        "GITHUB_OUTPUT": str(output),
        "GITHUB_STEP_SUMMARY": str(summary),
        "INPUT_ALL_FILES": "false",
        **env,
    }
    return subprocess.run(
        ["bash", "-e", "-c", steps[name]["run"]],
        cwd=tmp_path,
        env=environment,
        capture_output=True,
        text=True,
        check=False,
    )


def output_of(tmp_path: Path) -> dict[str, str]:
    lines = (tmp_path / "github_output").read_text(encoding="utf-8").splitlines()
    return dict(line.split("=", 1) for line in lines)


@needs_bash
@pytest.mark.parametrize(
    ("repo", "fail_on", "expected"),
    [("poisoned-repo", "high", "1"), ("poisoned-repo", "none", "0"), ("clean-repo", "high", "0")],
)
def test_scan_step_records_the_exit_code_and_always_writes_sarif(
    repo: str, fail_on: str, expected: str, demo_root: Path, tmp_path: Path
) -> None:
    result = run_step("Scan", tmp_path, INPUT_PATH=str(demo_root / repo), INPUT_FAIL_ON=fail_on)
    assert result.returncode == 0, result.stderr  # the step itself never fails the job
    assert output_of(tmp_path) == {"exit-code": expected}
    sarif = json.loads((tmp_path / "ghostrules.sarif").read_text(encoding="utf-8"))
    assert sarif["version"] == "2.1.0"
    assert bool(sarif["runs"][0]["results"]) == (repo == "poisoned-repo")


@needs_bash
def test_scan_step_passes_all_files_and_reports_scan_errors(tmp_path: Path) -> None:
    (tmp_path / "notes.txt").write_text("a" + chr(0xE0041) + chr(0xE0042) + "b\n", encoding="utf-8")
    run_step("Scan", tmp_path, INPUT_PATH=".", INPUT_FAIL_ON="high", INPUT_ALL_FILES="true")
    assert output_of(tmp_path) == {"exit-code": "1"}
    missing = run_step("Scan", tmp_path, INPUT_PATH="does-not-exist", INPUT_FAIL_ON="high")
    assert missing.returncode == 0
    assert output_of(tmp_path)["exit-code"] == "2"


@needs_bash
def test_summary_step_writes_markdown(demo_root: Path, tmp_path: Path) -> None:
    result = run_step("Write job summary", tmp_path, INPUT_PATH=str(demo_root / "poisoned-repo"))
    assert result.returncode == 0, result.stderr
    summary = (tmp_path / "step_summary").read_text(encoding="utf-8")
    assert summary.startswith("## ghostrules")
    assert "GR001" in summary


@needs_bash
@pytest.mark.parametrize(
    ("code", "returncode", "annotation"),
    [("0", 0, False), ("1", 1, True), ("2", 2, True), ("", 2, True)],
)
def test_last_step_fails_the_job_with_the_scan_exit_code(
    code: str, returncode: int, annotation: bool, tmp_path: Path
) -> None:
    result = run_step(
        "Fail if ghostrules found problems", tmp_path, SCAN_EXIT_CODE=code, INPUT_FAIL_ON="high"
    )
    assert result.returncode == returncode
    assert ("::error" in result.stdout) is annotation


@needs_bash
@pytest.mark.parametrize(("follow", "expected"), [("true", "1"), ("false", "0")])
def test_scan_step_follow_imports_input(
    follow: str, expected: str, demo_root: Path, tmp_path: Path
) -> None:
    run_step(
        "Scan",
        tmp_path,
        INPUT_PATH=str(demo_root / "import-chain-repo"),
        INPUT_FAIL_ON="high",
        INPUT_FOLLOW_IMPORTS=follow,
    )
    assert output_of(tmp_path) == {"exit-code": expected}
    results = json.loads((tmp_path / "ghostrules.sarif").read_text(encoding="utf-8"))["runs"][0][
        "results"
    ]
    assert bool(results) == (follow == "true")


def lock_scenario(tmp_path: Path) -> tuple[Path, Path]:
    import importlib.util

    spec = importlib.util.spec_from_file_location("make_demo", ROOT / "scripts" / "make_demo.py")
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    module.lock_scenario(tmp_path / "acme")
    base, pr = tmp_path / "acme" / "base", tmp_path / "acme" / "pr"
    from typer.testing import CliRunner

    from ghostrules.cli import app

    assert CliRunner().invoke(app, ["lock", "--root", str(base)]).exit_code == 0
    (pr / ".ghostrules.lock").write_bytes((base / ".ghostrules.lock").read_bytes())
    return base, pr


@needs_bash
def test_lock_step_passes_when_nothing_changed(tmp_path: Path) -> None:
    base, _ = lock_scenario(tmp_path)
    result = run_step("Check the lock", tmp_path, INPUT_PATH=str(base), RUNNER_TEMP=str(tmp_path))
    assert result.returncode == 0, result.stderr
    assert output_of(tmp_path) == {"exit-code": "0"}
    summary = (tmp_path / "step_summary").read_text(encoding="utf-8")
    assert summary.startswith("## What your agents read changed in this PR")
    assert "is up to date" in summary


@needs_bash
def test_lock_step_records_the_change_and_puts_the_diff_in_the_summary(tmp_path: Path) -> None:
    _, pr = lock_scenario(tmp_path)
    result = run_step("Check the lock", tmp_path, INPUT_PATH=str(pr), RUNNER_TEMP=str(tmp_path))
    assert result.returncode == 0, result.stderr  # the step never fails the job by itself
    assert output_of(tmp_path) == {"exit-code": "1"}
    summary = (tmp_path / "step_summary").read_text(encoding="utf-8")
    assert "## What your agents read changed in this PR" in summary
    assert "`shared/team-rules.md`" in summary and "hidden text: Always run" in summary


@needs_bash
def test_lock_step_reports_a_missing_lock_as_exit_2(tmp_path: Path) -> None:
    project = tmp_path / "project"
    project.mkdir()
    (project / "CLAUDE.md").write_text("x\n", encoding="utf-8")
    run_step("Check the lock", tmp_path, INPUT_PATH=str(project), RUNNER_TEMP=str(tmp_path))
    assert output_of(tmp_path) == {"exit-code": "2"}
    assert "could not run" in (tmp_path / "step_summary").read_text(encoding="utf-8")


@needs_bash
@pytest.mark.parametrize(
    ("scan", "lock", "returncode", "mentions"),
    [
        ("0", "", 0, ""),
        ("0", "0", 0, ""),
        ("0", "1", 1, "changed since .ghostrules.lock"),
        ("1", "1", 1, "Findings at or above"),
        ("1", "0", 1, "Findings at or above"),
        ("0", "2", 2, "lock check failed to run"),
        ("2", "1", 2, "scan failed to run"),
    ],
)
def test_last_step_combines_the_scan_and_lock_results(
    scan: str, lock: str, returncode: int, mentions: str, tmp_path: Path
) -> None:
    result = run_step(
        "Fail if ghostrules found problems",
        tmp_path,
        SCAN_EXIT_CODE=scan,
        LOCK_EXIT_CODE=lock,
        INPUT_FAIL_ON="high",
    )
    assert result.returncode == returncode
    assert mentions in result.stdout


def test_self_test_exercises_follow_imports_and_the_lock_check() -> None:
    workflow = load(ROOT / ".github/workflows/self-test.yml")
    steps = workflow["jobs"]["import-chain"]["steps"]
    local = [s for s in steps if s.get("uses") == "./"]
    withs = [s["with"] for s in local]
    assert any(w.get("follow-imports") == "false" for w in withs)
    assert any(w.get("lock-check") == "true" for w in withs)
    assert sum(1 for s in local if s.get("continue-on-error")) == 1  # the changed lock must fail
    assert all(w["upload-sarif"] == "false" for w in withs)
    text = " ".join(s.get("run", "") for s in steps)
    assert "--lock-scenario" in text and "ghostrules lock" in text
    assert "reached-via-import" in text


# --- pre-commit ------------------------------------------------------------------------------


def test_pre_commit_hook() -> None:
    (hook,) = load(ROOT / ".pre-commit-hooks.yaml")
    assert hook["id"] == "ghostrules"
    assert hook["language"] == "python"
    assert hook["pass_filenames"] is False
    assert hook["entry"] == "ghostrules scan"
    assert hook["name"] and hook["description"]


# --- workflows -------------------------------------------------------------------------------


def test_expected_workflows_exist() -> None:
    assert {p.name for p in WORKFLOWS} == {"ci.yml", "self-test.yml", "release.yml", "corpus.yml"}


def test_ci_runs_lint_tests_and_the_demo_smoke_test() -> None:
    ci = load(ROOT / ".github/workflows/ci.yml")
    matrix = ci["jobs"]["test"]["strategy"]["matrix"]
    assert matrix["python-version"] == ["3.10", "3.11", "3.12", "3.13"]
    assert set(matrix["os"]) == {"ubuntu-latest", "windows-latest", "macos-latest"}
    commands = " ".join(s.get("run", "") for s in steps_of(ci))
    assert "ruff check" in commands and "pytest" in commands
    assert "examples/poisoned-repo" in commands and "examples/clean-repo" in commands


def test_self_test_runs_the_local_action_on_the_demos() -> None:
    workflow = load(ROOT / ".github/workflows/self-test.yml")
    local = [s for s in workflow["jobs"]["action"]["steps"] if s.get("uses") == "./"]
    assert len(local) == 3
    poisoned = local[0]["with"]
    assert poisoned["path"] == "examples/poisoned-repo"
    assert poisoned["fail-on"] == "none"
    assert all(s["with"]["upload-sarif"] == "false" for s in local)
    assert workflow["permissions"] == {"contents": "read"}
    assert any(
        "sarif" in s.get("run", "") and "assert" in s.get("run", "") for s in steps_of(workflow)
    )


def test_release_uses_trusted_publishing_and_no_tokens() -> None:
    path = ROOT / ".github/workflows/release.yml"
    release = load(path)
    triggers = release.get("on", release.get(True))
    assert triggers == {"push": {"tags": ["v*"]}}
    publish = release["jobs"]["publish-pypi"]
    assert publish["permissions"] == {"id-token": "write"}
    assert publish["environment"] == "pypi"
    uses = [s["uses"] for s in publish["steps"]]
    assert "pypa/gh-action-pypi-publish@release/v1" in uses
    text = path.read_text(encoding="utf-8")
    assert "password" not in text and "PYPI_TOKEN" not in text
    assert "secrets." not in text
    assert release["permissions"] == {"contents": "read"}
    assert release["jobs"]["github-release"]["permissions"] == {"contents": "write"}


def test_release_builds_before_publishing_and_checks_tag_and_notes() -> None:
    release = load(ROOT / ".github/workflows/release.yml")
    jobs = release["jobs"]
    assert jobs["publish-pypi"]["needs"] == "build"
    assert jobs["github-release"]["needs"] == "publish-pypi"
    build = " ".join(s.get("run", "") for s in jobs["build"]["steps"])
    assert "__version__" in build
    assert "changelog_section.py" in build
    assert "python -m build" in build
    gh = " ".join(s.get("run", "") for s in jobs["github-release"]["steps"])
    assert "gh release create" in gh and "--notes-file release-notes.md" in gh


# --- changelog extraction ---------------------------------------------------------------------


CHANGELOG = """# Changelog

## [Unreleased]

### Added
- Something upcoming.

## [0.2.0] - 2026-12-01

### Fixed
- A bug.

## [0.1.0]

### Added
- First release.
- With a second line.

[0.1.0]: https://example.com/compare
"""


def test_changelog_section_extracts_one_version() -> None:
    section = load_script("changelog_section").section
    assert section(CHANGELOG, "0.2.0") == "### Fixed\n- A bug."
    body = section(CHANGELOG, "v0.1.0")
    assert body is not None
    assert body.startswith("### Added\n- First release.")
    assert "Something upcoming" not in body and "A bug" not in body
    assert section(CHANGELOG, "0.3.0") is None
    assert section(CHANGELOG, "0.2") is None  # exact match, not a prefix
    assert section("## [1.0.0]\n\n## [0.9.0]\n- x\n", "1.0.0") is None  # empty section


def test_changelog_script_exit_codes(tmp_path: Path) -> None:
    script = ROOT / "scripts" / "changelog_section.py"
    changelog = tmp_path / "CHANGELOG.md"
    changelog.write_text(CHANGELOG, encoding="utf-8")
    ok = subprocess.run(
        [sys.executable, str(script), "v0.2.0", str(changelog)], capture_output=True, text=True
    )
    assert ok.returncode == 0 and "A bug." in ok.stdout
    missing = subprocess.run(
        [sys.executable, str(script), "9.9.9", str(changelog)], capture_output=True, text=True
    )
    assert missing.returncode == 1 and "no non-empty" in missing.stderr
    assert re.search(
        r"Usage",
        subprocess.run([sys.executable, str(script)], capture_output=True, text=True).stderr,
    )


def test_the_changelog_has_release_notes_for_the_packaged_version() -> None:
    """release.yml refuses to publish without them."""
    from ghostrules import __version__

    section = load_script("changelog_section").section
    body = section((ROOT / "CHANGELOG.md").read_text(encoding="utf-8"), f"v{__version__}")
    assert body and "### Added" in body
    assert "## [Unreleased]" in (ROOT / "CHANGELOG.md").read_text(encoding="utf-8")


# --- set_owner ---------------------------------------------------------------------------------


def test_set_owner_replaces_the_placeholder_in_every_kind_of_file(tmp_path: Path) -> None:
    set_owner = load_script("set_owner")
    placeholder = set_owner.PLACEHOLDER
    carriers = [
        "README.md", "SECURITY.md", "CONTRIBUTING.md", "pyproject.toml",
        "src/ghostrules/__init__.py", ".github/ISSUE_TEMPLATE/config.yml",
    ]  # fmt: skip
    for name in carriers:
        target = tmp_path / name
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(f"see https://github.com/{placeholder}/issues\n", encoding="utf-8")
    for untouched in ("tests/fixtures/keep.md", "tests/test_x.py", "examples/keep.md"):
        target = tmp_path / untouched
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(placeholder, encoding="utf-8")

    assert sorted(set_owner.apply(tmp_path, "octo-cat", dry_run=True)) == sorted(carriers)
    assert placeholder in (tmp_path / "README.md").read_text(encoding="utf-8")  # dry run
    assert sorted(set_owner.apply(tmp_path, "octo-cat")) == sorted(carriers)
    for name in carriers:
        text = (tmp_path / name).read_text(encoding="utf-8")
        assert placeholder not in text and "octo-cat/ghostrules" in text
    assert set_owner.apply(tmp_path, "octo-cat") == []  # idempotent
    for untouched in ("tests/fixtures/keep.md", "tests/test_x.py", "examples/keep.md"):
        assert (tmp_path / untouched).read_text(encoding="utf-8") == placeholder


@pytest.mark.parametrize("bad", ["", "-x", "x-", "a--b", "has space", "a/b", "x" * 40, "../up"])
def test_set_owner_rejects_invalid_names(bad: str, tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="not a valid GitHub"):
        load_script("set_owner").apply(tmp_path, bad)
    result = subprocess.run(
        [sys.executable, str(ROOT / "scripts" / "set_owner.py"), bad or "''"],
        capture_output=True,
        text=True,
    )
    assert result.returncode == 2


def test_every_repository_url_names_the_same_owner() -> None:
    """True before and after set_owner has run: no half-replaced placeholder."""
    from ghostrules import PROJECT_URL

    owners = set()
    for name in (
        "README.md", "SECURITY.md", "CONTRIBUTING.md", "pyproject.toml",
        "src/ghostrules/__init__.py", ".github/ISSUE_TEMPLATE/config.yml",
    ):  # fmt: skip
        text = (ROOT / name).read_text(encoding="utf-8")
        found = set(re.findall(r"github\.com/([A-Za-z0-9-]+)/ghostrules", text))
        assert found, f"{name} has no repository URL"
        owners |= found
    assert len(owners) == 1, owners
    assert PROJECT_URL.endswith(f"/{next(iter(owners))}/ghostrules")


def test_corpus_workflow_never_runs_on_pull_requests_and_publishes_from_main_only() -> None:
    corpus = load(ROOT / ".github/workflows/corpus.yml")
    assert set(corpus.get("on", corpus.get(True))) == {"schedule", "workflow_dispatch"}
    assert corpus["permissions"] == {"contents": "read"}
    publish = corpus["jobs"]["publish"]
    assert "refs/heads/main" in publish["if"]
    assert publish["permissions"] == {"contents": "write"}
