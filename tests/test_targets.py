import os
from pathlib import Path

import pytest

from ghostrules.targets import (
    MAX_OTHER_FILE_BYTES,
    classify_path,
    discover,
    glob_to_regex,
    home_targets,
)


def touch(root: Path, rel: str, content: str | bytes = "x") -> Path:
    path = root / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    if isinstance(content, bytes):
        path.write_bytes(content)
    else:
        path.write_text(content, encoding="utf-8")
    return path


def rels(root: Path, **kwargs) -> dict[str, str]:
    return {c.rel: c.kind for c in discover(root, **kwargs)}


@pytest.mark.parametrize(
    ("pattern", "path", "expected"),
    [
        ("AGENTS.md", "AGENTS.md", True),
        ("AGENTS.md", "sub/AGENTS.md", False),
        ("**/AGENTS.md", "AGENTS.md", True),
        ("**/AGENTS.md", "a/b/agents.md", True),
        (".clinerules/**", ".clinerules/x/y.md", True),
        (".clinerules/**", ".clinerules", False),
        (".roo/rules*/**", ".roo/rules-code/a.md", True),
        (".cursor/rules/**/*.mdc", ".cursor/rules/a.mdc", True),
        (".cursor/rules/**/*.mdc", ".cursor/rules/deep/a.mdc", True),
        (".cursor/rules/**/*.mdc", ".cursor/rules/a.md", False),
        ("*.md", "dir/a.md", False),
    ],
)
def test_glob_to_regex(pattern: str, path: str, expected: bool) -> None:
    assert bool(glob_to_regex(pattern).fullmatch(path)) is expected


def test_classify_path() -> None:
    assert classify_path("CLAUDE.md") == "instructions"
    assert classify_path("pkg/CLAUDE.md") == "instructions"
    assert classify_path(".claude/skills/x/SKILL.md") == "instructions"
    assert classify_path(".github/copilot-instructions.md") == "instructions"
    assert classify_path(".mcp.json") == "config"
    assert classify_path(".claude/settings.local.json") == "config"
    assert classify_path("README.md") is None
    assert classify_path("docs/ai/rules.md", extra_targets=["docs/ai/*.md"]) == "instructions"


def test_discover_finds_targets_with_kinds(tmp_path: Path) -> None:
    touch(tmp_path, "AGENTS.md")
    touch(tmp_path, ".cursorrules")
    touch(tmp_path, ".mcp.json", "{}")
    touch(tmp_path, "src/app.py")
    touch(tmp_path, "README.md")
    assert rels(tmp_path) == {
        "AGENTS.md": "instructions",
        ".cursorrules": "instructions",
        ".mcp.json": "config",
    }


def test_discover_skips_vendored_dirs(tmp_path: Path) -> None:
    touch(tmp_path, "node_modules/pkg/AGENTS.md")
    touch(tmp_path, ".venv/lib/CLAUDE.md")
    touch(tmp_path, ".git/CLAUDE.md")
    touch(tmp_path, "CLAUDE.md")
    assert list(rels(tmp_path)) == ["CLAUDE.md"]


def test_discover_honours_exclude_and_extra_targets(tmp_path: Path) -> None:
    touch(tmp_path, "vendor/AGENTS.md")
    touch(tmp_path, "AGENTS.md")
    touch(tmp_path, "docs/ai/style.md")
    found = rels(tmp_path, exclude=["vendor/**"], extra_targets=["docs/ai/*.md"])
    assert found == {"AGENTS.md": "instructions", "docs/ai/style.md": "instructions"}


def test_discover_all_files_adds_text_files_as_other(tmp_path: Path) -> None:
    touch(tmp_path, "AGENTS.md")
    touch(tmp_path, "src/app.py", "print('hi')")
    touch(tmp_path, "logo.png", b"\x89PNG\x00\x00binary")
    touch(tmp_path, "big.txt", "a" * (MAX_OTHER_FILE_BYTES + 1))
    assert rels(tmp_path, all_files=True) == {"AGENTS.md": "instructions", "src/app.py": "other"}


def test_discover_never_skips_large_or_binary_known_targets(tmp_path: Path) -> None:
    touch(tmp_path, "AGENTS.md", "a" * (MAX_OTHER_FILE_BYTES + 1))
    touch(tmp_path, "CLAUDE.md", b"text\x00more")
    assert rels(tmp_path) == {"AGENTS.md": "instructions", "CLAUDE.md": "instructions"}


@pytest.mark.skipif(os.name == "nt", reason="symlinks need privileges on Windows")
def test_discover_does_not_follow_symlinks(tmp_path: Path) -> None:
    outside = tmp_path / "outside"
    touch(outside, "AGENTS.md")
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "linked").symlink_to(outside, target_is_directory=True)
    (repo / "CLAUDE.md").symlink_to(outside / "AGENTS.md")
    assert rels(repo) == {}


def test_discover_single_file(tmp_path: Path) -> None:
    path = touch(tmp_path, "notes.txt")
    assert [(c.rel, c.kind) for c in discover(path)] == [("notes.txt", "other")]
    agents = touch(tmp_path, "AGENTS.md")
    assert [(c.rel, c.kind) for c in discover(agents)] == [("AGENTS.md", "instructions")]


def test_discover_is_sorted_and_deterministic(tmp_path: Path) -> None:
    for name in ("b/AGENTS.md", "a/AGENTS.md", "AGENTS.md"):
        touch(tmp_path, name)
    assert [c.rel for c in discover(tmp_path)] == ["AGENTS.md", "a/AGENTS.md", "b/AGENTS.md"]


def test_home_targets_linux(tmp_path: Path) -> None:
    touch(tmp_path, ".claude.json", "{}")
    touch(tmp_path, ".claude/CLAUDE.md")
    touch(tmp_path, ".config/Claude/claude_desktop_config.json", "{}")
    found = {c.rel: c.kind for c in home_targets(tmp_path, platform="linux", env={})}
    assert found == {
        "~/.claude.json": "config",
        "~/.claude/CLAUDE.md": "instructions",
        "~/.config/Claude/claude_desktop_config.json": "config",
    }


def test_home_targets_macos_and_windows_desktop_paths(tmp_path: Path) -> None:
    touch(tmp_path, "Library/Application Support/Claude/claude_desktop_config.json", "{}")
    mac = home_targets(tmp_path, platform="darwin", env={})
    assert [c.rel for c in mac] == [
        "~/Library/Application Support/Claude/claude_desktop_config.json"
    ]

    appdata = tmp_path / "AppData"
    touch(appdata, "Claude/claude_desktop_config.json", "{}")
    win = home_targets(tmp_path, platform="win32", env={"APPDATA": str(appdata)})
    assert [c.abs_path for c in win] == [appdata / "Claude/claude_desktop_config.json"]


def test_home_targets_missing_files_are_skipped(tmp_path: Path) -> None:
    assert home_targets(tmp_path, platform="linux", env={}) == []


def test_windows_style_separators_are_understood() -> None:
    backslash = chr(92)
    assert (
        classify_path(f".claude{backslash}skills{backslash}x{backslash}SKILL.md") == "instructions"
    )
    assert classify_path(f".github{backslash}copilot-instructions.md") == "instructions"
    assert (
        classify_path(f"docs{backslash}ai{backslash}a.md", [f"docs{backslash}ai{backslash}*.md"])
        == "instructions"
    )
    assert glob_to_regex(f"vendor{backslash}**").fullmatch("vendor/deep/file.md")


def test_exclude_patterns_with_windows_separators(tmp_path: Path) -> None:
    touch(tmp_path, "vendor/AGENTS.md")
    touch(tmp_path, "AGENTS.md")
    backslash = chr(92)
    assert list(rels(tmp_path, exclude=[f"vendor{backslash}**"])) == ["AGENTS.md"]


def test_home_target_outside_the_home_directory_keeps_its_full_path(tmp_path: Path) -> None:
    home = tmp_path / "home"
    home.mkdir()
    appdata = tmp_path / "elsewhere" / "AppData"
    touch(appdata, "Claude/claude_desktop_config.json", "{}")
    (found,) = home_targets(home, platform="win32", env={"APPDATA": str(appdata)})
    assert found.rel == (appdata / "Claude/claude_desktop_config.json").as_posix()
    assert not found.rel.startswith("~/")
