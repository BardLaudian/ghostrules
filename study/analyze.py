"""Aggregate the study: ``python study/analyze.py RESULTS_DIR [RESULTS_DIR ...] [--out DIR]``.

Reads the dated run directories written by ``corpus/run.py`` (one per tier), writes aggregate CSVs
(no repository names, no paths) and prints the ten headline numbers. Every number in the report
comes from these CSVs.
"""

from __future__ import annotations

import argparse
import csv
import json
import sys
from collections import Counter
from collections.abc import Sequence
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "corpus"))
from features import RISK_RULES, repo_features  # noqa: E402


def load_records(dirs: Sequence[Path]) -> list[dict[str, Any]]:
    """Every record of the latest dated run in each results directory."""
    out: list[dict[str, Any]] = []
    for root in dirs:
        runs = sorted(p for p in root.iterdir() if p.is_dir())
        if not runs:
            raise SystemExit(f"no run in {root}")
        for path in sorted(runs[-1].glob("*.json")):
            if path.name != "summary.json":
                out.append(json.loads(path.read_text(encoding="utf-8")))
    return out


def pct(part: int, whole: int) -> float:
    """Percentage rounded to one decimal (0 when ``whole`` is 0)."""
    return round(100 * part / whole, 1) if whole else 0.0


def write_csv(path: Path, header: list[str], rows: list[list[Any]]) -> None:
    """Write one CSV (aggregates only)."""
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.writer(handle, lineterminator="\n")
        writer.writerow(header)
        writer.writerows(rows)


def analyze(
    records: list[dict[str, Any]], out: Path, labels: dict[str, Any] | None = None
) -> dict[str, Any]:
    """Write the CSVs and return the headline numbers. ``labels`` (fingerprint -> Label) adds
    ``precision_by_rule.csv``."""
    ok = [r for r in records if r["status"] == "ok"]
    feats = [repo_features(r) for r in ok]
    n = len(feats)
    with_files = [f for f in feats if f["agent_files"]]

    fam_repos: Counter[str] = Counter()
    fam_files: Counter[str] = Counter()
    for f in feats:
        fam_repos.update(f["families"])
        fam_files.update(f["family_files"])
    write_csv(
        out / "adoption_families.csv",
        ["family", "repos", "pct_of_repos", "files"],
        [[k, v, pct(v, n), fam_files[k]] for k, v in fam_repos.most_common()],
    )
    tools_per_repo = Counter(len(f["tools"]) for f in feats)
    write_csv(
        out / "tools_per_repo.csv",
        ["tools_targeted", "repos", "pct_of_repos"],
        [[k, v, pct(v, n)] for k, v in sorted(tools_per_repo.items())],
    )
    relation = Counter(f["relation"] for f in feats if f["relation"] != "n/a")
    both = sum(relation.values())
    write_csv(
        out / "claude_agents_relation.csv",
        ["relation", "repos", "pct_of_repos_with_both"],
        [[k, v, pct(v, both)] for k, v in relation.most_common()],
    )
    lines = [x for f in feats for x in f["instruction_lines"]]
    bins = [(0, 50), (51, 100), (101, 200), (201, 400), (401, 10**9)]
    write_csv(
        out / "instruction_file_lines.csv",
        ["lines", "files", "pct_of_files"],
        [
            [f"{lo}-{hi}" if hi < 10**9 else f"{lo}+", c, pct(c, len(lines))]
            for lo, hi in bins
            for c in [sum(lo <= x <= hi for x in lines)]
        ],
    )
    claude_repos = [f for f in feats if f["claude_lines"]]
    importers = [f for f in feats if f["imports"]]
    depth = Counter(f["max_import_depth"] for f in importers)
    write_csv(
        out / "imports.csv",
        ["metric", "repos", "pct_of_repos"],
        [
            ["uses_at_imports", len(importers), pct(len(importers), n)],
            [
                "imports_a_non_agent_file",
                sum(1 for f in feats if f["imported_non_agent_files"]),
                pct(sum(1 for f in feats if f["imported_non_agent_files"]), n),
            ],
            *[[f"max_depth_{d}", c, pct(c, len(importers))] for d, c in sorted(depth.items())],
        ],
    )
    entries = sum(f["entries"] for f in feats)
    cond = sum(f["conditional_entries"] for f in feats)
    cond_repos = sum(1 for f in feats if f["conditional_entries"])
    write_csv(
        out / "conditional_rules.csv",
        ["metric", "value"],
        [
            ["repos_with_conditional_entries", cond_repos],
            ["pct_of_repos", pct(cond_repos, n)],
            ["conditional_entries", cond],
            ["pct_of_entries", pct(cond, entries)],
        ],
    )
    rule_repos: Counter[str] = Counter()
    rule_findings: Counter[tuple[str, str]] = Counter()
    for r in ok:
        for rule in {f["rule_id"] for f in r.get("findings", [])}:
            rule_repos[rule] += 1
        for f in r.get("findings", []):
            rule_findings[(f["rule_id"], f["severity"])] += 1
    write_csv(
        out / "findings_by_rule.csv",
        ["rule", "severity", "findings", "repos_with_rule", "pct_of_repos"],
        [
            [rule, sev, c, rule_repos[rule], pct(rule_repos[rule], n)]
            for (rule, sev), c in sorted(rule_findings.items())
        ],
    )
    if labels is not None:
        counts: dict[str, Counter[str]] = {}
        for r in ok:
            for f in r.get("findings", []):
                if f["severity"] not in ("critical", "high", "medium"):
                    continue
                label = labels.get(f["fingerprint"])
                counts.setdefault(f["rule_id"], Counter())[
                    label.label if label else "unlabelled"
                ] += 1
        write_csv(
            out / "precision_by_rule.csv",
            ["rule", "findings_medium_plus", "tp", "benign_context", "fp", "unlabelled"],
            [
                [rule, sum(c.values()), c["tp"], c["benign-context"], c["fp"], c["unlabelled"]]
                for rule, c in sorted(counts.items())
            ],
        )
    risk = {k: sum(1 for f in feats if f["risk"][k]) for k in RISK_RULES}
    write_csv(
        out / "risk_indicators.csv",
        ["indicator", "repos", "pct_of_repos"],
        [[k, v, pct(v, n)] for k, v in risk.items()],
    )
    strata = Counter(f["tier"] for f in feats)
    write_csv(out / "sample.csv", ["tier", "repos"], sorted(strata.items()))

    # A repository has an MCP config when it has an mcp file or a rule about one fired.
    skill_counts = sorted((f["family_files"].get("skills", 0) for f in feats), reverse=True)
    skill_total = sum(skill_counts)
    skill_repos = [c for c in skill_counts if c]
    write_csv(
        out / "skills_concentration.csv",
        ["metric", "value"],
        [
            ["repos_with_skills", len(skill_repos)],
            ["skill_files", skill_total],
            [
                "median_skill_files_per_repo",
                sorted(skill_repos)[len(skill_repos) // 2] if skill_repos else 0,
            ],
            ["top1_repo_pct_of_files", pct(sum(skill_counts[:1]), skill_total)],
            ["top3_repos_pct_of_files", pct(sum(skill_counts[:3]), skill_total)],
            ["top10_repos_pct_of_files", pct(sum(skill_counts[:10]), skill_total)],
        ],
    )
    mcp = sum(1 for f in feats if "mcp" in f["families"] or f["risk"]["mcp"])
    unpinned = sum(1 for f in feats if "GR102" in f["rules"])
    multi = sum(f["multi_tool"] for f in feats)
    over = sum(f["claude_over_limit"] for f in claude_repos)
    html = sum(f["claude_html_comments"] for f in claude_repos)
    non_agent = sum(1 for f in feats if f["imported_non_agent_files"])
    silent = sum("GR022" in f["rules"] for f in feats)
    numbers = [
        ("multi_tool", "repos targeting two or more tools", multi, n),
        (
            "claude_md_over_200",
            "repos whose root CLAUDE.md has more than 200 lines",
            over,
            len(claude_repos),
        ),
        ("at_imports", "repos using @ imports", len(importers), n),
        ("non_agent_import", "repos importing a file that is not an agent file", non_agent, n),
        ("conditional_rules", "repos with conditional rules (paths/globs)", cond_repos, n),
        (
            "claude_html_comments",
            "repos whose CLAUDE.md has HTML comments Claude strips",
            html,
            len(claude_repos),
        ),
        ("unloaded_import", "repos with an import that silently does not load (GR022)", silent, n),
        (
            "mcp_unpinned",
            "repos with an MCP config that runs an unpinned package (GR102)",
            unpinned,
            mcp,
        ),
        (
            "risky_settings",
            "repos with over-permissive agent settings (GR107/GR108)",
            risk["settings"],
            n,
        ),
        ("hidden_unicode", "repos with hidden Unicode (GR001-GR004)", risk["hidden_unicode"], n),
        ("secrets", "repos with a hardcoded-secret finding (GR101)", risk["secrets"], n),
    ]
    write_csv(
        out / "numbers.csv",
        ["id", "metric", "repos", "of", "pct"],
        [[i, m, a, b, pct(a, b)] for i, m, a, b in numbers],
    )
    return {
        "repos_scanned": n,
        "repos_failed": len(records) - n,
        "repos_with_agent_files": len(with_files),
        "pct_multi_tool": pct(sum(f["multi_tool"] for f in feats), n),
        "claude_agents_both": both,
        "claude_agents_symlink_or_import_pct": pct(relation["symlink"] + relation["import"], both),
        "claude_md_over_200_pct": pct(
            sum(f["claude_over_limit"] for f in claude_repos), len(claude_repos)
        ),
        "repos_with_at_imports_pct": pct(len(importers), n),
        "repos_importing_non_agent_file_pct": pct(
            sum(1 for f in feats if f["imported_non_agent_files"]), n
        ),
        "repos_with_conditional_rules_pct": pct(cond_repos, n),
        "repos_with_unloaded_import_pct": pct(sum("GR022" in f["rules"] for f in feats), n),
        "repos_claude_html_comment_pct": pct(
            sum(f["claude_html_comments"] for f in claude_repos), len(claude_repos)
        ),
        "mcp_repos_with_unpinned_pct": pct(unpinned, mcp),
        "repos_with_risky_settings_pct": pct(risk["settings"], n),
        "repos_with_hidden_unicode": risk["hidden_unicode"],
        "repos_with_secret_findings": risk["secrets"],
    }


def main(argv: Sequence[str] | None = None) -> int:
    p = argparse.ArgumentParser(description="Aggregate the study results into CSVs.")
    p.add_argument("results", nargs="+", type=Path)
    p.add_argument("--out", type=Path, default=Path(__file__).resolve().parent / "data")
    p.add_argument("--labels", nargs="*", type=Path, default=[], help="labels.toml files")
    args = p.parse_args(argv)
    labels: dict[str, Any] = {}
    if args.labels:
        from common import load_labels

        for path in args.labels:
            labels.update(load_labels(path))
    headline = analyze(load_records(args.results), args.out, labels if args.labels else None)
    (args.out / "headline.json").write_text(
        json.dumps(headline, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    for key, value in headline.items():
        print(f"{key}: {value}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
