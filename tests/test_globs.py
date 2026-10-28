import pytest

from ghostrules.globs import (
    BRACE_BUDGET,
    expand_braces,
    matches_any,
    matches_glob,
    normalize_path,
    split_patterns,
)


@pytest.mark.parametrize(
    ("pattern", "path", "expected"),
    [
        ("*.md", "README.md", True),
        ("*.md", "docs/README.md", False),  # * stays in one segment: root only
        ("**/*.ts", "a.ts", True),
        ("**/*.ts", "src/a/b.ts", True),
        ("**/*.ts", "src/a/b.tsx", False),
        ("src/**", "src/a/b.ts", True),
        ("src/**", "src/a.ts", True),
        ("src/**", "lib/a.ts", False),
        ("src/api/**/*.ts", "src/api/users.ts", True),
        ("src/api/**/*.ts", "src/api/v1/users.ts", True),
        ("src/api/**/*.ts", "src/web/users.ts", False),
        ("src/*.{ts,tsx}", "src/a.tsx", True),
        ("src/*.{ts,tsx}", "src/a.js", False),
        ("{a,b}/{c,d}/*.md", "b/c/x.md", True),
        ("{a,b}/{c,d}/*.md", "b/e/x.md", False),
        ("a?c.md", "abc.md", True),
        ("a?c.md", "a/c.md", False),
        ("[ab].md", "a.md", True),
        ("[!ab].md", "c.md", True),
        ("[!ab].md", "a.md", False),
        ("a[0-9].md", "a5.md", True),
        ("photos \\[2024/**", "photos [2024/x.jpg", True),
        ("docs/", "docs/", True),
        ("exact.txt", "exact.txt", True),
        ("exact.txt", "other.txt", False),
        ("**", "anything/at/all", True),
        ("src/a**b", "src/axxb", True),
        ("src/a**b", "src/a/b", False),
    ],
)
def test_matching(pattern: str, path: str, expected: bool) -> None:
    assert matches_glob(pattern, path) is expected


def test_windows_paths_match_like_posix_ones() -> None:
    assert matches_glob("src/**/*.ts", "src\\api\\users.ts")
    assert matches_glob("*.md", ".\\README.md")
    assert matches_glob("{a,b}/*.md", "b\\x.md")
    assert normalize_path(".\\.\\a\\b") == "a/b"


def test_case_sensitivity_is_opt_in() -> None:
    assert not matches_glob("*.MD", "a.md")
    assert matches_glob("*.MD", "a.md", ignore_case=True)


def test_invalid_class_matches_nothing_but_other_patterns_still_work() -> None:
    assert not matches_glob("photos [2024/**", "photos [2024/x.jpg")
    assert matches_any(["photos [2024/**", "*.md"], "a.md")


def test_dotfiles_are_matched() -> None:
    assert matches_glob("*", ".env")
    assert matches_glob("**/*.json", ".claude/settings.json")


def test_expand_braces() -> None:
    assert expand_braces("a.{ts,tsx}") == ["a.ts", "a.tsx"]
    assert expand_braces("{a,b}/{c,d}") == ["a/c", "a/d", "b/c", "b/d"]
    assert expand_braces("x/{a,{b,c}}") == ["x/a", "x/b", "x/c"]
    assert expand_braces("{,x}y") == ["y", "xy"]
    assert expand_braces("{single}") == ["{single}"]
    assert expand_braces("{unbalanced,a") == ["{unbalanced,a"]
    assert expand_braces("a\\{b,c\\}") == ["a\\{b,c\\}"]


def test_brace_expansion_over_budget_stays_literal() -> None:
    pattern = "{a,b}" * 11  # 2**11 = 2048 > budget
    assert BRACE_BUDGET < 2048
    assert expand_braces(pattern) == [pattern]
    assert not matches_glob(pattern, "a" * 11)


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("src/**, lib/**", ["src/**", "lib/**"]),
        ("src/*.{ts,tsx},docs/**", ["src/*.{ts,tsx}", "docs/**"]),
        (["a/**", " b/** "], ["a/**", "b/**"]),
        ("", []),
        ("  ,a, ,", ["a"]),
        ("**/*.{js,ts}", ["**/*.{js,ts}"]),
    ],
)
def test_split_patterns(value: str | list[str], expected: list[str]) -> None:
    assert split_patterns(value) == expected
