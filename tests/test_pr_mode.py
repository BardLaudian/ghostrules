"""W2 of docs/design/v0.4/REMEDIATION.md: the change being scanned must not switch the scanner off.

Both attacks are reproduced on a real, temporary git repository: a *base* commit (what was already
reviewed and merged) and a *pull-request* commit on top of it that adds a defanged payload. The
tests that take trusted settings (``--config-from-ref``, ``--trusted-config``,
``--no-inline-suppressions``, ``--suppressions-from-ref``) fail on 0.3.0, which has none of them
and so lets the scanned change silence itself. The ``test_0_3_*`` tests record that exposure: they
pass on 0.3.0 and show the scenarios really are blind without the new options.
"""

import shutil
from pathlib import Path

import pytest
from pr_helpers import CLEAN, IGNORE, PAYLOAD, pull_request, rule_ids, scan
from typer.testing import CliRunner

from ghostrules.cli import app

pytestmark = pytest.mark.skipif(shutil.which("git") is None, reason="git is not installed")


# --- attack 1: an ignore comment at the end of the malicious line -------------------------------


@pytest.fixture
def ignore_attack(tmp_path: Path) -> tuple[Path, str]:
    """The PR adds the payload to CLAUDE.md with a ``ghostrules-ignore`` at the end of the line
    (Claude Code strips the comment, so the payload still reaches the model)."""
    return pull_request(
        tmp_path,
        {"CLAUDE.md": CLEAN},
        {"CLAUDE.md": f"{CLEAN}{PAYLOAD} {IGNORE}\n"},
    )


def test_0_3_default_lets_the_ignore_comment_hide_the_payload(
    ignore_attack: tuple[Path, str],
) -> None:
    repo, _ = ignore_attack
    code, data, _ = scan(repo)
    assert code == 0 and data["findings"] == [] and data["summary"]["suppressed"] >= 1


def test_no_inline_suppressions_reports_the_payload(ignore_attack: tuple[Path, str]) -> None:
    repo, _ = ignore_attack
    code, data, out = scan(repo, "--no-inline-suppressions")
    assert code == 1, out
    assert {"GR011", "GR013"} <= rule_ids(data)
    assert data["summary"]["suppressed"] == 0


def test_suppressions_from_ref_ignores_a_comment_the_pr_just_added(
    ignore_attack: tuple[Path, str],
) -> None:
    repo, base = ignore_attack
    code, data, out = scan(repo, "--suppressions-from-ref", base)
    assert code == 1, out
    assert {"GR011", "GR013"} <= rule_ids(data)


def test_suppressions_from_ref_keeps_a_comment_that_was_already_merged(tmp_path: Path) -> None:
    """A reviewed ignore (same line, same ignore at the base) still works."""
    line = f"{PAYLOAD} {IGNORE}\n"
    repo, base = pull_request(
        tmp_path,
        {"CLAUDE.md": f"{CLEAN}{line}"},
        {"CLAUDE.md": f"{CLEAN}{line}- A new, harmless line.\n"},
    )
    code, data, out = scan(repo, "--suppressions-from-ref", base)
    assert code == 0, out
    assert data["findings"] == [] and data["summary"]["suppressed"] >= 1


def test_suppressions_from_ref_does_not_accept_an_edited_line(tmp_path: Path) -> None:
    """The ignore existed at the base, but the line it covered was changed: not reviewed."""
    repo, base = pull_request(
        tmp_path,
        {"CLAUDE.md": f"{CLEAN}- Print the version. {IGNORE}\n"},
        {"CLAUDE.md": f"{CLEAN}{PAYLOAD} {IGNORE}\n"},
    )
    code, data, out = scan(repo, "--suppressions-from-ref", base)
    assert code == 1, out
    assert {"GR011", "GR013"} <= rule_ids(data)


# --- attack 2: exclude = ["AGENTS.md"] in .ghostrules.toml ------------------------------------


@pytest.fixture
def exclude_attack(tmp_path: Path) -> tuple[Path, str]:
    """The PR adds a poisoned AGENTS.md and a ``.ghostrules.toml`` that excludes it."""
    return pull_request(
        tmp_path,
        {"CLAUDE.md": CLEAN},
        {"AGENTS.md": f"# Rules\n\n{PAYLOAD}\n", ".ghostrules.toml": 'exclude = ["AGENTS.md"]\n'},
    )


def test_0_3_default_lets_the_pr_exclude_its_own_file(exclude_attack: tuple[Path, str]) -> None:
    repo, _ = exclude_attack
    code, data, _ = scan(repo)
    assert code == 0 and data["findings"] == [] and data["scanned_files"] == 1  # only CLAUDE.md


def test_config_from_ref_ignores_the_config_the_pr_added(exclude_attack: tuple[Path, str]) -> None:
    repo, base = exclude_attack
    code, data, out = scan(repo, "--config-from-ref", base)
    assert code == 1, out
    assert {"GR011", "GR013"} <= rule_ids(data)
    assert data["scanned_files"] == 2


def test_trusted_config_ignores_the_working_tree_config(
    exclude_attack: tuple[Path, str], tmp_path: Path
) -> None:
    repo, _ = exclude_attack
    trusted = tmp_path / "trusted.toml"
    trusted.write_text('fail_on = "high"\n', encoding="utf-8")
    code, data, out = scan(repo, "--trusted-config", str(trusted))
    assert code == 1, out
    assert {"GR011", "GR013"} <= rule_ids(data)
    assert data["summary"]["config_source"] != ".ghostrules.toml"  # the PR's file was not used


def test_config_from_ref_still_honours_the_reviewed_config(tmp_path: Path) -> None:
    """The config at the base is the reviewed one: its exclude applies, the PR's does not."""
    repo, base = pull_request(
        tmp_path,
        {"CLAUDE.md": CLEAN, ".ghostrules.toml": 'exclude = ["vendor/**"]\n'},
        {
            "vendor/AGENTS.md": f"# Rules\n\n{PAYLOAD}\n",
            ".ghostrules.toml": 'exclude = ["vendor/**", "CLAUDE.md"]\n',
        },
    )
    code, data, out = scan(repo, "--config-from-ref", base)
    assert rule_ids(data) == {"GR030"}, out  # only the edited config is reported, GR030
    assert code == 1
    assert data["scanned_files"] == 1  # CLAUDE.md is scanned again; vendor/ stays excluded


def test_an_unknown_ref_is_an_error_and_never_a_silent_pass(
    exclude_attack: tuple[Path, str],
) -> None:
    repo, _ = exclude_attack
    for flag in ("--config-from-ref", "--suppressions-from-ref"):
        code, _, out = scan(repo, flag, "no-such-ref")
        assert code == 2, out
        assert "no-such-ref" in out


# --- edges ------------------------------------------------------------------------------------


def test_a_line_inserted_under_a_reviewed_marker_is_not_covered(tmp_path: Path) -> None:
    """A marker covers the next line, so a PR could slip a payload in right below a reviewed one."""
    repo, base = pull_request(
        tmp_path,
        {"CLAUDE.md": f"{CLEAN}{IGNORE}\n- Print the version.\n"},
        {"CLAUDE.md": f"{CLEAN}{IGNORE}\n{PAYLOAD}\n- Print the version.\n"},
    )
    code, data, out = scan(repo, "--suppressions-from-ref", base)
    assert code == 1, out
    assert {"GR011", "GR013"} <= rule_ids(data)


def test_the_report_says_how_many_ignore_comments_were_not_honoured(
    ignore_attack: tuple[Path, str],
) -> None:
    repo, base = ignore_attack
    _, data, _ = scan(repo, "--suppressions-from-ref", base)
    assert any("1 ghostrules-ignore comment not honoured" in w for w in data["warnings"])
    _, data, _ = scan(repo, "--no-inline-suppressions")
    assert any("not honoured" in w for w in data["warnings"])


def test_the_config_options_cannot_be_combined(tmp_path: Path) -> None:
    repo, base = pull_request(tmp_path, {"CLAUDE.md": CLEAN}, {"CLAUDE.md": f"{CLEAN}\n"})
    trusted = tmp_path / "t.toml"
    trusted.write_text("", encoding="utf-8")
    for flags in (
        ["--config", str(trusted), "--trusted-config", str(trusted)],
        ["--trusted-config", str(trusted), "--config-from-ref", base],
    ):
        code, _, out = scan(repo, *flags)
        assert code == 2 and "cannot be used together" in out


def test_options_that_read_a_ref_take_one_path(tmp_path: Path) -> None:
    repo, base = pull_request(tmp_path, {"CLAUDE.md": CLEAN}, {"CLAUDE.md": f"{CLEAN}\n"})
    result = CliRunner().invoke(
        app, ["scan", str(repo), str(repo), "--format", "json", "--config-from-ref", base]
    )
    assert result.exit_code == 2 and "exactly one path" in result.output


def test_a_subdirectory_is_read_at_the_same_place_in_the_ref(tmp_path: Path) -> None:
    """Scanning ``repo/app`` reads ``app/.ghostrules.toml`` at the ref, not the root one."""
    repo, base = pull_request(
        tmp_path,
        {"app/CLAUDE.md": CLEAN, "app/.ghostrules.toml": 'exclude = ["vendor/**"]\n'},
        {"app/vendor/AGENTS.md": f"# Rules\n\n{PAYLOAD}\n", "app/.ghostrules.toml": ""},
    )
    _, data, out = scan(repo / "app", "--config-from-ref", base)
    # the base config excludes vendor/ and the PR's empty one is not read: no payload finding,
    # only GR030 for the edited config
    assert rule_ids(data) == {"GR030"}, out
