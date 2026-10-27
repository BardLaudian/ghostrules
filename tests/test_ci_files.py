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
    order = ["Set up Python", "Install", "Scan", "Upload SARIF", "Write job summary", "Fail"]
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
    assert {p.name for p in WORKFLOWS} == {"ci.yml", "self-test.yml", "release.yml"}


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
    local = [s for s in steps_of(workflow) if s.get("uses") == "./"]
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
