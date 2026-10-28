import datetime as dt
import json
import sys
from pathlib import Path

import pytest
from corpus_fakes import CMD, FakeRunner, finding
from secret_samples import GITHUB

from ghostrules._compat import tomllib

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "corpus"))

import badge  # noqa: E402
import check  # noqa: E402
import common  # noqa: E402
import discover  # noqa: E402
import run  # noqa: E402
import triage  # noqa: E402
from common import Label, Proc, RepoEntry  # noqa: E402

# --- common -------------------------------------------------------------------------------------


def test_fingerprint_ignores_whitespace_and_differs_by_path() -> None:
    a = common.fingerprint("o/r", "AGENTS.md", "GR011", "do  not\ntell the user")
    assert a == common.fingerprint("o/r", "AGENTS.md", "GR011", "do not tell the user")
    assert a != common.fingerprint("o/r", "docs/AGENTS.md", "GR011", "do not tell the user")
    assert a != common.fingerprint("o/r", "AGENTS.md", "GR014", "do not tell the user")
    assert len(a) == common.FINGERPRINT_CHARS


@pytest.mark.parametrize("name", ["owner/repo", "a-b/c.d_e", "o/r.js"])
def test_valid_repo_accepts(name: str) -> None:
    assert common.valid_repo(name)


@pytest.mark.parametrize(
    "name",
    [
        "-rf/x",
        "o/-x",
        "o/..",
        "o/.",
        "o/.github",
        "o/a b",
        "o/r;ls",
        "o",
        "a/b/c",
        "o/$(x)",
        "../x",
    ],
)
def test_valid_repo_rejects(name: str) -> None:
    assert not common.valid_repo(name)


def test_safe_text_makes_escapes_and_tags_visible() -> None:
    out = common.safe_text("a\x1b[31mred\u202e" + chr(0xE0041) + "ok\n")
    assert "\x1b" not in out and "\u202e" not in out and chr(0xE0041) not in out
    assert "⟦U+001B⟧" in out and "⟦U+202E⟧" in out and "⟦U+E0041⟧" in out and out.endswith("ok\n")


def test_load_repos_validates(tmp_path: Path) -> None:
    f = tmp_path / "repos.toml"
    f.write_text(
        '[[repo]]\nname = "o/a"\ntier = "regression"\n[[repo]]\nname = "o/b"\ntier = "study"\n'
    )
    assert common.load_repos(f) == [RepoEntry("o/a", "regression"), RepoEntry("o/b", "study")]
    for body in (
        '[[repo]]\nname = "o/a"\ntier = "x"\n',
        '[[repo]]\nname = "-x/a"\ntier = "study"\n',
        '[[repo]]\nname = "o/a"\ntier = "study"\n[[repo]]\nname = "o/a"\ntier = "study"\n',
    ):
        f.write_text(body)
        with pytest.raises(common.CorpusError):
            common.load_repos(f)


def test_labels_roundtrip_and_reported_never_names_repo(tmp_path: Path) -> None:
    f = tmp_path / "labels.toml"
    blocks = [
        common.format_label(
            Label("0123456789abcdef", "fp", "GR011", "high", "o/a", 'why "x"', "t")
        ),
        common.format_label(Label("fedcba9876543210", "reported", rule="GR101")),
    ]
    f.write_text("\n".join(blocks))
    labels = common.load_labels(f)
    assert labels["0123456789abcdef"].reason == 'why "x"'
    assert labels["fedcba9876543210"].repo == ""
    f.write_text('[[label]]\nfingerprint = "fedcba9876543210"\nlabel = "reported"\nrepo = "o/a"\n')
    with pytest.raises(common.CorpusError):
        common.load_labels(f)


def test_test_exists() -> None:
    assert common.test_exists("tests/test_corpus_tools.py::test_test_exists")
    assert not common.test_exists("tests/test_corpus_tools.py::test_nope")
    assert not common.test_exists("tests/missing.py::test_x")
    assert not common.test_exists("../etc/passwd::x")
    assert not common.test_exists("tests/test_corpus_tools.py")


# --- discover -----------------------------------------------------------------------------------


def reply(status: int, body: object, **headers: str) -> Proc:
    head = "".join(f"{k.replace('_', '-')}: {v}\r\n" for k, v in headers.items())
    return Proc(0 if status < 400 else 1, f"HTTP/2.0 {status} X\r\n{head}\r\n{json.dumps(body)}")


def test_gh_client_caches(tmp_path: Path) -> None:
    runner = FakeRunner()
    runner.gh = [reply(200, {"a": 1}, X_RateLimit_Remaining="50")]
    client = discover.GhClient(runner, tmp_path)
    assert client.get("repos/o/r") == (200, {"a": 1})
    assert client.get("repos/o/r") == (200, {"a": 1})  # cached: no second gh call
    assert len(runner.calls) == 1
    assert client.remaining == 50


def test_gh_client_waits_for_rate_limit(tmp_path: Path) -> None:
    runner, slept = FakeRunner(), []
    runner.gh = [
        reply(403, {"message": "rate"}, X_RateLimit_Remaining="0", X_RateLimit_Reset="1100"),
        reply(200, [], X_RateLimit_Remaining="9"),
    ]
    client = discover.GhClient(runner, tmp_path, sleep=slept.append, now=lambda: 1000.0)
    assert client.get("x")[0] == 200
    assert slept == [101.0]


def test_gh_client_missing_gh(tmp_path: Path) -> None:
    class NoGh(FakeRunner):
        def __call__(self, args, **kw):  # type: ignore[no-untyped-def]
            return Proc(127, "", "not found")

    with pytest.raises(common.CorpusError, match="gh CLI"):
        discover.GhClient(NoGh(), tmp_path).get("x")


def tree(*paths: str, truncated: bool = False) -> Proc:
    nodes = [{"path": p, "type": "blob"} for p in paths] + [{"path": "src", "type": "tree"}]
    return reply(200, {"tree": nodes, "truncated": truncated})


def test_agent_files_classification_and_truncation(tmp_path: Path) -> None:
    runner = FakeRunner()
    runner.gh = [
        tree("AGENTS.md", "src/a.py", ".claude/rules/x/style.md", ".mcp.json", "README.md"),
        tree("AGENTS.md", truncated=True),
        reply(404, {"message": "Not Found"}),
    ]
    client = discover.GhClient(runner, tmp_path)
    assert discover.agent_files(client, "o/a", "main") == [
        ".claude/rules/x/style.md",
        ".mcp.json",
        "AGENTS.md",
    ]
    assert discover.agent_files(client, "o/b", "main") is None  # truncated: unknown, not guessed
    assert discover.agent_files(client, "o/c", "main") is None


def test_search_query() -> None:
    q = discover.search_query(2000, "python", 6, dt.date(2026, 10, 28))
    assert q == "stars:>=2000 archived:false fork:false pushed:>2026-05-01 language:python"


def test_discover_and_propose(tmp_path: Path) -> None:
    items = [
        {
            "full_name": "o/py1",
            "stargazers_count": 900,
            "language": "Python",
            "default_branch": "main",
        },
        {
            "full_name": "o/py2",
            "stargazers_count": 800,
            "language": "Python",
            "default_branch": "main",
        },
        {
            "full_name": "o/ts1",
            "stargazers_count": 700,
            "language": "TypeScript",
            "default_branch": "main",
        },
        {
            "full_name": "o/none",
            "stargazers_count": 600,
            "language": "Go",
            "default_branch": "main",
        },
        {"full_name": "-bad/x", "stargazers_count": 5, "language": "Go", "default_branch": "main"},
    ]
    runner = FakeRunner()
    runner.gh = [
        reply(200, {"items": items}),
        tree("AGENTS.md"),
        tree("CLAUDE.md"),
        tree("GEMINI.md"),
        tree("README.md"),
    ]
    found = discover.discover(discover.GhClient(runner, tmp_path), ["q"])
    assert [c["name"] for c in found] == ["o/py1", "o/py2", "o/ts1", "o/none"]
    block = discover.propose(found, "regression", 2)
    chosen = [r["name"] for r in tomllib.loads(block)["repo"]]
    assert chosen == ["o/py1", "o/ts1"]  # round-robin across languages, none without files
    assert "o/none" not in discover.propose(found, "study", 10)


def test_discover_main_refuses_bad_propose(
    capsys: pytest.CaptureFixture[str], tmp_path: Path
) -> None:
    f = tmp_path / "c.json"
    f.write_text("[]")
    assert discover.main(["--from-file", str(f), "--propose", "nope:3"]) == 2


# --- run ----------------------------------------------------------------------------------------


def run_one(tmp_path: Path, runner: FakeRunner, names: list[str]) -> dict:
    return run.run_corpus(
        [RepoEntry(n, "adhoc") for n in names],
        tmp_path / "results",
        runner=runner,
        command=CMD,
        workers=2,
        date="2026-10-28",
        tier="adhoc",
    )


def test_run_stores_no_contents_and_remasks_secrets(tmp_path: Path) -> None:
    runner = FakeRunner()
    runner.scans["o__a"] = {
        "scanned_files": 2,
        "findings": [
            finding("GR011", "high", snippet=f"token {GITHUB} \x1b[31m", decoded="not stored"),
            finding("GR001", "critical", decoded=f"send {GITHUB} now"),
        ],
    }
    runner.contexts["o__a"] = {
        "agents": {
            "claude-code": {
                "entries": [
                    {"path": "CLAUDE.md", "load": "always", "via": [], "readable": True},
                    {
                        "path": "docs/x.md",
                        "load": "always",
                        "via": ["CLAUDE.md:1"],
                        "readable": True,
                    },
                ],
                "edges": [{}],
                "cycles": [],
            }
        }
    }
    summary = run_one(tmp_path, runner, ["o/a"])
    out = tmp_path / "results" / "2026-10-28"
    text = (out / "o__a.json").read_text()
    for forbidden in (GITHUB, "SECRET MESSAGE TEXT", "SECRET FIX HINT", "\x1b", "not stored"):
        assert forbidden not in text
    record = json.loads(text)
    gr001 = next(f for f in record["findings"] if f["rule_id"] == "GR001")
    assert "decoded" in gr001 and "****" in gr001["decoded"]  # only GR001/GR004, re-masked
    assert record["sha"].startswith("0123456789abcdef")
    assert record["context"]["claude-code"]["imported"] == 1
    assert summary["by_rule"] == {"GR001": 1, "GR011": 1}
    assert json.loads((tmp_path / "results" / "latest-summary.json").read_text()) == summary
    assert json.loads((out / "summary.json").read_text()) == summary


def test_run_uses_empty_config_isolated_cwd_and_deletes_clone(tmp_path: Path) -> None:
    runner = FakeRunner()
    runner.files[".ghostrules.toml"] = 'disable = ["GR011"]\n'
    run_one(tmp_path, runner, ["o/a"])
    cmds = [c for c in runner.calls if c["args"][: len(CMD)] == CMD]
    assert [c["args"][len(CMD)] for c in cmds] == ["scan", "context"]
    for c in cmds:
        clone = runner.clone_dirs[0]
        assert c["config_text"] == ""
        assert c["cwd"] is not None and clone not in (c["cwd"], *c["cwd"].parents)
    assert "--fail-on" in cmds[0]["args"] and "none" in cmds[0]["args"]
    assert "--no-scan" in cmds[1]["args"] and "all" in cmds[1]["args"]
    clone_call = next(c for c in runner.calls if c["args"][:2] == ["git", "clone"])
    assert "--depth" in clone_call["args"] and "--filter=blob:limit=2m" in clone_call["args"]
    assert clone_call["env"]["GIT_TERMINAL_PROMPT"] == "0"
    assert not runner.clone_dirs[0].exists() and not runner.clone_dirs[0].parent.exists()


def test_run_records_failures_and_continues(tmp_path: Path) -> None:
    runner = FakeRunner()
    runner.clone_fail["o__gone"] = 128
    runner.clone_fail["o__slow"] = 124
    runner.scan_exit["o__bad"] = 2
    summary = run_one(tmp_path, runner, ["o/gone", "o/slow", "o/bad", "o/fine"])
    assert summary["status"] == {"clone_failed": 1, "timeout": 1, "scan_failed": 1, "ok": 1}
    assert {f["repo"] for f in summary["failures"]} == {"o/gone", "o/slow", "o/bad"}


def test_run_main_rejects_bad_names(capsys: pytest.CaptureFixture[str]) -> None:
    assert run.main(["--repos", "o/a,-evil/x"]) == 2
    assert "invalid repository name" in capsys.readouterr().err
    assert run.main([]) == 2


# --- check --------------------------------------------------------------------------------------


def write_run(tmp_path: Path, findings: list[dict], status: str = "ok") -> Path:
    results = tmp_path / "results"
    out = results / "2026-10-28"
    out.mkdir(parents=True)
    rec = {"repo": "o/a", "status": status, "findings": findings}
    (out / "o__a.json").write_text(json.dumps(rec))
    (out / "summary.json").write_text(
        json.dumps(
            {"date": "d", "tier": "t", "repos": 1, "findings": len(findings), "by_severity": {}}
        )
    )
    return results


def stored(fp: str, severity: str, rule: str = "GR011") -> dict:
    return {
        "fingerprint": fp,
        "rule_id": rule,
        "severity": severity,
        "path": "A.md",
        "snippet": "s",
    }


def write_labels(path: Path, *labels: Label) -> Path:
    path.write_text("\n".join(common.format_label(x) for x in labels))
    return path


FP = "0123456789abcdef"
GOOD_TEST = "tests/test_corpus_tools.py::test_test_exists"


def gate(tmp_path: Path, findings: list[dict], *labels: Label, status: str = "ok") -> int:
    results = write_run(tmp_path, findings, status)
    lab = write_labels(tmp_path / "labels.toml", *labels)
    return check.main(["--results", str(results), "--labels", str(lab)])


def test_check_passes_when_clean_or_only_low(tmp_path: Path) -> None:
    assert gate(tmp_path, [stored(FP, "medium"), stored("1" * 16, "low")]) == 0


def test_check_fails_on_unlabelled_high_and_critical(tmp_path: Path) -> None:
    assert gate(tmp_path, [stored(FP, "high")]) == 1


def test_check_labelled_high_passes(tmp_path: Path) -> None:
    assert gate(tmp_path, [stored(FP, "critical")], Label(FP, "tp", "GR011", "critical")) == 0


def test_check_fp_at_old_severity_fails_but_lowered_passes(tmp_path: Path) -> None:
    label = Label(FP, "fp", "GR011", "high", "o/a", "r", GOOD_TEST)
    assert gate(tmp_path, [stored(FP, "high")], label) == 1
    assert gate(tmp_path / "b", [stored(FP, "critical")], label) == 1
    assert gate(tmp_path / "c", [stored(FP, "medium")], label) == 0


def test_check_fp_needs_an_existing_test(tmp_path: Path) -> None:
    no_test = Label(FP, "fp", "GR011", "high", "o/a", "r", "")
    bad_test = Label(FP, "fp", "GR011", "high", "o/a", "r", "tests/test_corpus_tools.py::test_nope")
    assert gate(tmp_path, [], no_test) == 1
    assert gate(tmp_path / "b", [], bad_test) == 1


@pytest.mark.parametrize("status", ["scan_failed", "context_failed", "timeout"])
def test_check_crashed_scan_is_exit_2(tmp_path: Path, status: str) -> None:
    assert gate(tmp_path, [], status=status) == 2


def test_check_clone_failure_is_not_a_gate(tmp_path: Path) -> None:
    assert gate(tmp_path, [], status="clone_failed") == 0


def test_check_without_a_run_is_exit_2(tmp_path: Path) -> None:
    assert check.main(["--results", str(tmp_path / "none")]) == 2


def test_check_prints_table_and_writes_step_summary(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    step = tmp_path / "step.md"
    monkeypatch.setenv("GITHUB_STEP_SUMMARY", str(step))
    gate(tmp_path, [stored(FP, "high")])
    out = capsys.readouterr().out
    assert (
        "| Severity | Findings |" in out and "**FAIL**" in out and f"{FP}: unlabelled high" in out
    )
    assert "o/a" not in out  # a violation names the fingerprint, not the repository
    assert step.read_text() == out


# --- triage -------------------------------------------------------------------------------------


def scripted(answers: list[str]):  # type: ignore[no-untyped-def]
    it = iter(answers)
    return lambda prompt: next(it)


def test_pending_findings_filters_and_sorts(tmp_path: Path) -> None:
    results = write_run(
        tmp_path,
        [
            stored("a" * 16, "medium"),
            stored("b" * 16, "critical"),
            stored("c" * 16, "low"),
            stored("d" * 16, "high"),
        ],
    )
    labels = {"d" * 16: Label("d" * 16, "tp")}
    found = triage.pending_findings(results / "2026-10-28", labels, "medium")
    assert [f["fingerprint"] for f in found] == ["b" * 16, "a" * 16]
    assert found[0]["repo"] == "o/a"


def run_triage(tmp_path: Path, answers: list[str], findings: list[dict]) -> tuple[int, Path]:
    labels = tmp_path / "labels.toml"
    labels.write_text("")
    items = [{**f, "repo": "o/a", "sha": ""} for f in findings]
    written = triage.triage(items, labels, scripted(answers), echo=lambda s: None, repo_root=ROOT)
    return written, labels


def test_triage_writes_labels(tmp_path: Path) -> None:
    fs = [
        stored("a" * 16, "high"),
        stored("b" * 16, "high"),
        stored("c" * 16, "high"),
        stored("d" * 16, "high"),
        stored("e" * 16, "high"),
    ]
    written, path = run_triage(
        tmp_path,
        ["tp", "real", "fp", "doc text", GOOD_TEST, "reported", "wontfix", "known", "s", "q"],
        fs,
    )
    assert written == 4
    labels = common.load_labels(path)
    assert labels["a" * 16].label == "tp" and labels["a" * 16].repo == ""
    assert labels["b" * 16].test == GOOD_TEST and labels["b" * 16].repo == "o/a"
    assert labels["c" * 16].label == "reported" and not labels["c" * 16].reason
    assert (
        "o/a" not in path.read_text().split('fingerprint = "' + "c" * 16)[1].split("[[label]]")[0]
    )
    assert labels["d" * 16].label == "wontfix"
    assert "e" * 16 not in labels  # skipped, then quit


def test_triage_fp_requires_an_existing_test(tmp_path: Path) -> None:
    written, path = run_triage(
        tmp_path, ["fp", "why", "tests/test_corpus_tools.py::test_nope"], [stored("a" * 16, "high")]
    )
    assert written == 0 and path.read_text() == ""


def test_gh_fetch_sanitises_and_validates(tmp_path: Path) -> None:
    import base64

    runner = FakeRunner()
    body = base64.b64encode(b"one\ntwo \x1b[31m\nthree\n").decode()
    runner.gh = [Proc(0, json.dumps({"content": body}))]
    out = triage.gh_fetch(runner)("o/a", "abc123", "AGENTS.md", 2)
    assert "\x1b" not in out and "⟦U+001B⟧" in out and "two" in out
    assert triage.gh_fetch(runner)("-bad/x", "abc123", "A.md", 1) == ""
    assert triage.gh_fetch(runner)("o/a", "abc;rm", "A.md", 1) == ""
    assert len(runner.calls) == 1


# --- badge ---------------------------------------------------------------------------------------


def _summary(critical: int = 0) -> dict:
    return {
        "date": "2026-10-28",
        "tier": "regression",
        "ghostrules_version": "0.3.0",
        "repos": 300,
        "findings": 5,
        "by_rule": {"GR010": 5},
        "by_severity": {"critical": critical, "low": 5},
        "failures": [{"repo": "o/secret-name", "status": "clone_failed"}],
        "seconds": {"o/secret-name": 1.0},
    }


def test_badge_states_what_is_measured() -> None:
    shield = badge.badge(_summary(), passed=True)
    assert shield == {
        "schemaVersion": 1,
        "label": "corpus",
        "message": "300 repos · 0 critical",
        "color": "brightgreen",
    }
    assert badge.badge(_summary(2), passed=True)["color"] == "yellow"
    failing = badge.badge(_summary(), passed=False)
    assert failing["message"] == "gate failing" and failing["color"] == "red"


def test_public_summary_has_counts_only() -> None:
    pub = badge.public_summary(_summary(), {"unlabelled_blocking": 0}, passed=True)
    assert "failures" not in pub and "seconds" not in pub
    assert "o/secret-name" not in json.dumps(pub)
    assert pub["gate"] == "pass" and pub["unlabelled_critical_high"] == 0


def test_badge_main_writes_files_and_fails_without_run(tmp_path: Path) -> None:
    out = tmp_path / "out"
    assert badge.main(["--out", str(out), "--results", str(tmp_path / "none")]) == 2
    day = tmp_path / "results" / "2026-10-28"
    day.mkdir(parents=True)
    (day / "summary.json").write_text(json.dumps(_summary()), encoding="utf-8")
    (day / "o__r.json").write_text(
        json.dumps({"repo": "o/r", "status": "ok", "findings": []}), encoding="utf-8"
    )
    labels = tmp_path / "labels.toml"
    labels.write_text("", encoding="utf-8")
    args = ["--out", str(out), "--results", str(tmp_path / "results"), "--labels", str(labels)]
    assert badge.main(args) == 0
    assert json.loads((out / "badge.json").read_text())["color"] == "brightgreen"
    assert "secret-name" not in (out / "summary.json").read_text()
    (day / "o__r.json").write_text(
        json.dumps(
            {
                "repo": "o/r",
                "status": "ok",
                "findings": [{"fingerprint": "f" * 16, "severity": "high", "rule_id": "GR010"}],
            }
        ),
        encoding="utf-8",
    )
    assert badge.main(args) == 0
    assert json.loads((out / "badge.json").read_text())["message"] == "gate failing"
