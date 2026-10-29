"""GR030, scanner configuration changed (W2.3 of docs/design/v0.4/REMEDIATION.md).

The change under review adds or edits ``.ghostrules.toml``, ``[tool.ghostrules]``, the lockfile or a
``ghostrules-ignore`` comment: a reviewer must always see it, even when it is legitimate. It needs a
base to compare with, so it exists only with ``--config-from-ref`` or ``--suppressions-from-ref``.
"""

from pathlib import Path

from pr_helpers import CLEAN, IGNORE, PAYLOAD, pull_request, scan

from ghostrules.rules import get_rule

TOML = 'exclude = ["vendor/**"]\n'


def gr030(data: dict) -> list[dict]:
    return [f for f in data.get("findings", []) if f["rule_id"] == "GR030"]


def base_scan(repo: Path, base: str, *flags: str) -> tuple[int, list[dict], dict]:
    code, data, _ = scan(repo, "--config-from-ref", base, *flags)
    return code, gr030(data), data


def test_the_rule_is_registered_as_high_and_documented() -> None:
    rule = get_rule("GR030")
    assert rule is not None and rule.severity.label == "high"
    assert "### GR030" in (Path(__file__).resolve().parent.parent / "docs/RULES.md").read_text(
        encoding="utf-8"
    )


# --- .ghostrules.toml ---------------------------------------------------------------------------


def test_an_added_config_file_is_reported(tmp_path: Path) -> None:
    repo, base = pull_request(tmp_path, {"CLAUDE.md": CLEAN}, {".ghostrules.toml": TOML})
    code, found, _ = base_scan(repo, base)
    assert code == 1  # high: a reviewer has to look, so the check fails at the default fail-on
    (finding,) = found
    assert finding["path"] == ".ghostrules.toml" and finding["severity"] == "high"
    assert "added" in finding["message"]


def test_an_edited_config_file_names_the_keys_that_changed(tmp_path: Path) -> None:
    repo, base = pull_request(
        tmp_path,
        {"CLAUDE.md": CLEAN, ".ghostrules.toml": TOML + 'fail_on = "high"\n'},
        {".ghostrules.toml": 'exclude = ["vendor/**", "docs/**"]\nfail_on = "high"\n'},
    )
    _, found, _ = base_scan(repo, base)
    (finding,) = found
    assert finding["path"] == ".ghostrules.toml" and "edited" in finding["message"]
    assert "exclude" in finding["message"] and "fail_on" not in finding["message"]
    assert finding["line"] == 1


def test_an_unchanged_config_file_is_not_reported(tmp_path: Path) -> None:
    repo, base = pull_request(
        tmp_path,
        {"CLAUDE.md": CLEAN, ".ghostrules.toml": TOML},
        {"CLAUDE.md": f"{CLEAN}- A new, harmless line.\n"},
    )
    code, found, _ = base_scan(repo, base)
    assert found == [] and code == 0


def test_a_legitimate_change_is_still_reported(tmp_path: Path) -> None:
    """The rule does not judge the change: it makes sure someone sees it."""
    repo, base = pull_request(
        tmp_path, {"CLAUDE.md": CLEAN}, {".ghostrules.toml": 'min_severity = "medium"\n'}
    )
    assert len(base_scan(repo, base)[1]) == 1


# --- [tool.ghostrules] in pyproject.toml --------------------------------------------------------


def test_a_changed_tool_table_in_pyproject_is_reported(tmp_path: Path) -> None:
    repo, base = pull_request(
        tmp_path,
        {"CLAUDE.md": CLEAN, "pyproject.toml": '[project]\nname = "x"\n'},
        {"pyproject.toml": '[project]\nname = "x"\n\n[tool.ghostrules]\ndisable = ["GR011"]\n'},
    )
    (finding,) = base_scan(repo, base)[1]
    assert finding["path"] == "pyproject.toml" and "disable" in finding["message"]


def test_other_changes_to_pyproject_are_not_reported(tmp_path: Path) -> None:
    repo, base = pull_request(
        tmp_path,
        {"CLAUDE.md": CLEAN, "pyproject.toml": '[project]\nname = "x"\n'},
        {"pyproject.toml": '[project]\nname = "x"\nversion = "2"\n'},
    )
    assert base_scan(repo, base)[1] == []


# --- the lockfile -------------------------------------------------------------------------------


def test_an_edited_lockfile_is_reported_and_an_unchanged_one_is_not(tmp_path: Path) -> None:
    repo, base = pull_request(
        tmp_path,
        {"CLAUDE.md": CLEAN, ".ghostrules.lock": "version = 1\n"},
        {".ghostrules.lock": "version = 2\n"},
    )
    (finding,) = base_scan(repo, base)[1]
    assert finding["path"] == ".ghostrules.lock" and "edited" in finding["message"]
    quiet, base2 = pull_request(
        tmp_path / "q",
        {"CLAUDE.md": CLEAN, ".ghostrules.lock": "version = 1\n"},
        {"CLAUDE.md": f"{CLEAN}- Print the version.\n"},
    )
    assert base_scan(quiet, base2)[1] == []


# --- ignore comments ----------------------------------------------------------------------------


def test_an_added_ignore_comment_is_reported_at_its_line(tmp_path: Path) -> None:
    repo, base = pull_request(
        tmp_path,
        {"CLAUDE.md": CLEAN},
        {"CLAUDE.md": f"{CLEAN}- Print the version. {IGNORE}\n"},
    )
    (finding,) = base_scan(repo, base)[1]
    assert finding["path"] == "CLAUDE.md" and finding["line"] == 4
    assert "ghostrules-ignore" in finding["message"]


def test_an_ignore_comment_that_was_already_there_is_not_reported(tmp_path: Path) -> None:
    line = f"- Print the version. {IGNORE}\n"
    repo, base = pull_request(
        tmp_path,
        {"CLAUDE.md": f"{CLEAN}{line}"},
        {"CLAUDE.md": f"{CLEAN}{line}- A new, harmless line.\n"},
    )
    assert base_scan(repo, base)[1] == []


def test_an_edited_ignore_line_is_reported(tmp_path: Path) -> None:
    repo, base = pull_request(
        tmp_path,
        {"CLAUDE.md": f"{CLEAN}- Print the version. {IGNORE}\n"},
        {"CLAUDE.md": f"{CLEAN}- Print the version and the date. {IGNORE}\n"},
    )
    assert len(base_scan(repo, base)[1]) == 1


def test_ignore_comments_in_a_new_file_are_reported(tmp_path: Path) -> None:
    repo, base = pull_request(
        tmp_path,
        {"CLAUDE.md": CLEAN},
        {"AGENTS.md": f"# Rules\n\n- Print the version. {IGNORE}\n"},
    )
    (finding,) = base_scan(repo, base)[1]
    assert finding["path"] == "AGENTS.md"


# --- it cannot be switched off from inside the change --------------------------------------------


def test_without_a_base_there_is_nothing_to_compare_with(tmp_path: Path) -> None:
    repo, _ = pull_request(
        tmp_path,
        {"CLAUDE.md": CLEAN},
        {".ghostrules.toml": TOML, "CLAUDE.md": f"{CLEAN}{IGNORE}\n"},
    )
    _, data, _ = scan(repo)
    assert gr030(data) == []


def test_the_change_cannot_disable_the_rule_with_its_own_config(tmp_path: Path) -> None:
    repo, base = pull_request(
        tmp_path, {"CLAUDE.md": CLEAN}, {".ghostrules.toml": 'disable = ["GR030"]\n'}
    )
    assert len(base_scan(repo, base)[1]) == 1  # the base config is the one that applies


def test_an_ignore_comment_naming_gr030_does_not_hide_it(tmp_path: Path) -> None:
    repo, base = pull_request(
        tmp_path,
        {"CLAUDE.md": CLEAN},
        {"CLAUDE.md": f"{CLEAN}- Print the version. <!-- ghostrules-ignore: GR030 -->\n"},
    )
    assert len(base_scan(repo, base)[1]) == 1
    _, found, _ = base_scan(repo, base, "--suppressions-from-ref", base)
    assert len(found) == 1


def test_the_caller_can_still_disable_it_explicitly(tmp_path: Path) -> None:
    repo, base = pull_request(tmp_path, {"CLAUDE.md": CLEAN}, {".ghostrules.toml": TOML})
    assert base_scan(repo, base, "--disable", "GR030")[1] == []


def test_it_works_with_only_the_suppressions_ref(tmp_path: Path) -> None:
    repo, base = pull_request(
        tmp_path,
        {"CLAUDE.md": CLEAN},
        {".ghostrules.toml": TOML, "CLAUDE.md": f"{CLEAN}{PAYLOAD} {IGNORE}\n"},
    )
    _, data, _ = scan(repo, "--suppressions-from-ref", base)
    paths = {f["path"] for f in gr030(data)}
    assert paths == {".ghostrules.toml", "CLAUDE.md"}  # the one ref serves config and ignores
