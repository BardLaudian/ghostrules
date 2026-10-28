import os

import pytest

from ghostrules.agents.repo import Repo


def write(root, rel, text="x"):
    path = root / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def test_listing_is_sorted_posix_and_skips_vcs_and_dependency_dirs(tmp_path) -> None:
    for rel in ("b.md", "a/z.md", "a/y.md", ".git/config", "node_modules/p/x.md", ".venv/l.md"):
        write(tmp_path, rel)
    assert Repo(tmp_path).files == ("a/y.md", "a/z.md", "b.md")


def test_kind(tmp_path) -> None:
    write(tmp_path, "a/b.md")
    repo = Repo(tmp_path)
    assert repo.kind("a/b.md") == "file"
    assert repo.kind("a") == "dir"
    assert repo.kind("nope.md") is None
    assert repo.kind("a/b.md/c") is None
    assert repo.kind("../x") is None
    assert repo.kind("/etc/passwd") is None
    assert repo.kind("") is None


def test_symlinks_are_resolved_by_hand_inside_the_tree(tmp_path) -> None:
    write(tmp_path, "real/a.md", "secret")
    try:
        os.symlink("real", tmp_path / "linkdir", target_is_directory=True)
        os.symlink("real/a.md", tmp_path / "linkfile.md")
    except (OSError, NotImplementedError):
        pytest.skip("symlinks are not available here")
    repo = Repo(tmp_path)
    assert repo.kind("linkfile.md") == "symlink"
    assert repo.kind("linkdir/a.md") == "symlink"
    assert repo.read("linkfile.md") == b"secret" and repo.read("linkdir/a.md") == b"secret"
    assert repo.symlink_target("linkfile.md") == "real/a.md"
    assert "linkdir" in repo.linked_dirs  # never walked into: its files are listed as aliases
    assert "linkdir/a.md" in repo.files


def test_a_symlink_out_of_the_tree_is_never_read(tmp_path) -> None:
    outside = tmp_path / "outside.md"
    outside.write_text("secret", encoding="utf-8")
    inner = tmp_path / "repo"
    inner.mkdir()
    try:
        os.symlink(outside, inner / "link.md")
    except (OSError, NotImplementedError):
        pytest.skip("symlinks are not available here")
    repo = Repo(inner)
    assert repo.kind("link.md") == "symlink" and repo.read("link.md") is None
    assert repo.resolve("link.md").status == "outside"


def test_label_uses_the_prefix(tmp_path) -> None:
    assert Repo(tmp_path, "~/").label(".claude/CLAUDE.md") == "~/.claude/CLAUDE.md"


def test_a_dangling_symlinked_directory_is_still_a_symlink(tmp_path) -> None:
    """Listed as a file by os.walk (it cannot be entered), but reported as a symlink."""
    try:
        os.symlink("nowhere", tmp_path / "rules", target_is_directory=True)
    except (OSError, NotImplementedError):
        pytest.skip("symlinks are not available here")
    assert Repo(tmp_path).kind("rules") == "symlink"
