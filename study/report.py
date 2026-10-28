"""Write ``study/report.md`` from the committed CSVs, so every number in it is a CSV number.

python study/report.py [--data study/data] [--out study/report.md]
"""

from __future__ import annotations

import argparse
import csv
import sys
from collections.abc import Sequence
from pathlib import Path
from typing import Any

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
from features import FAMILY_NAMES  # noqa: E402


def table(path: Path) -> list[dict[str, str]]:
    """A CSV as a list of dicts."""
    with path.open(encoding="utf-8", newline="") as handle:
        return list(csv.DictReader(handle))


def md_table(header: list[str], rows: list[list[Any]]) -> str:
    """A Markdown table."""
    lines = ["| " + " | ".join(header) + " |", "|" + "|".join("---" for _ in header) + "|"]
    lines += ["| " + " | ".join(str(c) for c in row) + " |" for row in rows]
    return "\n".join(lines)


def picture(name: str, alt: str) -> str:
    """A chart that follows the reader's colour scheme."""
    return (
        "<picture>\n"
        f'  <source media="(prefers-color-scheme: dark)" srcset="charts/{name}-dark.svg">\n'
        f'  <img alt="{alt}" src="charts/{name}-light.svg">\n'
        "</picture>"
    )


def render(data: Path) -> str:
    """The report text."""
    fam = {r["family"]: r for r in table(data / "adoption_families.csv")}
    tools = table(data / "tools_per_repo.csv")
    rel = {r["relation"]: r for r in table(data / "claude_agents_relation.csv")}
    lines = table(data / "instruction_file_lines.csv")
    nums = {r["id"]: r for r in table(data / "numbers.csv")}
    sample = {r["tier"]: int(r["repos"]) for r in table(data / "sample.csv")}
    skills = {r["metric"]: r["value"] for r in table(data / "skills_concentration.csv")}
    prec = table(data / "precision_by_rule.csv")
    runs = table(data / "precision_runs.csv")
    cond = {r["metric"]: r["value"] for r in table(data / "conditional_rules.csv")}
    depth = {r["metric"]: r for r in table(data / "imports.csv")}
    total = sum(sample.values())
    multi = sum(float(r["pct_of_repos"]) for r in tools if int(r["tools_targeted"]) >= 2)
    both = sum(int(r["repos"]) for r in rel.values())
    over200 = sum(int(r["files"]) for r in lines if r["lines"] in ("201-400", "401+"))
    all_lines = sum(int(r["files"]) for r in lines)
    tp, wf, fp, un = (sum(int(r[k]) for r in prec) for k in ("tp", "wontfix", "fp", "unlabelled"))

    def n(key: str) -> str:
        r = nums[key]
        return f"{r['pct']}% ({int(r['repos']):,} of {int(r['of']):,})"

    return f"""# What {total:,} popular repos tell their AI agents

*The state of AI agent instruction files, October 2026.*

We scanned the agent files of {total:,} popular public repositories with
[ghostrules](https://github.com/BardLaudian/ghostrules): `AGENTS.md`, `CLAUDE.md`, Cursor and Copilot
rules, skills, MCP configs and agent settings. Aggregates only: no repository is named next to a
finding, and every number below comes from the CSVs in [`data/`](data/).

## In short

- **`AGENTS.md` is the shared language.** It is in {fam["agents_md"]["pct_of_repos"]}% of repos,
  ahead of skills ({fam["skills"]["pct_of_repos"]}%) and `CLAUDE.md` ({fam["claude"]["pct_of_repos"]}%).
- **{multi:.1f}% write instructions for more than one tool**, and the repos that keep `CLAUDE.md` and
  `AGENTS.md` together mostly link them ({rel["import"]["pct_of_repos_with_both"]}% import one from
  the other, {rel["symlink"]["pct_of_repos_with_both"]}% use a symlink) instead of copying.
- **What an agent reads is not just what its path says.** {n("at_imports")} use `@` imports,
  {n("conditional_rules")} have rules that apply only to some paths, and {n("non_agent_import")}
  import a file that is not an agent file at all.
- **{n("mcp_unpinned")}** of the repos that configure an MCP server start at least one with an
  unpinned `npx` or `uvx` package.
- **No real secret and no real malicious instruction.** Hidden Unicode: {n("hidden_unicode")}, all
  characters that really are in the text. Hardcoded secrets: {n("secrets")}. Private disclosures
  sent: 0.

## 1. Who writes instructions for agents

{picture("01-adoption", "Bar chart: share of repositories containing each kind of agent file; AGENTS.md leads at 70.7 percent")}

{md_table(["File", "Repos", "% of repos", "Files"], [[FAMILY_NAMES.get(r["family"], r["family"]), f"{int(r['repos']):,}", r["pct_of_repos"], f"{int(r['files']):,}"] for r in fam.values()])}

Skills dominate by file count ({int(skills["skill_files"]):,} `SKILL.md` files) because a few repositories
are skill collections: the largest one holds {skills["top1_repo_pct_of_files"]}% of them, the top three
{skills["top3_repos_pct_of_files"]}% and the top ten {skills["top10_repos_pct_of_files"]}%. The median
repository with skills has {skills["median_skill_files_per_repo"]}. We therefore count repositories,
not files.

{picture("02-tools-per-repo", "Bar chart: share of repositories by number of tools their instruction files target; two tools is the most common multi-tool case")}

{multi:.1f}% of repos target two or more tools. Instruction files are short: {lines[0]["pct_of_files"]}% have
at most 50 lines, and {over200 / all_lines * 100:.1f}% of the {all_lines:,} instruction files are over 200
lines. For the root `CLAUDE.md` specifically, {n("claude_md_over_200")} go beyond the 200 lines Claude
Code recommends.

## 2. Two files, one truth

{picture("03-claude-agents", "Bar chart: how repositories with both CLAUDE.md and AGENTS.md keep them in step; importing is the most common")}

{both} repos have both a root `CLAUDE.md` and an `AGENTS.md`. They keep them in step by
importing ({rel["import"]["pct_of_repos_with_both"]}%), a symlink ({rel["symlink"]["pct_of_repos_with_both"]}%),
two separate files ({rel["separate"]["pct_of_repos_with_both"]}%) or a copy
({rel["duplicate"]["pct_of_repos_with_both"]}%). With two separate files nothing keeps them equal, and each agent
reads a different one.

## 3. What the agent really reads

{picture("04-what-agents-read", "Bar chart: share of repositories with conditional rules, at-imports, stripped HTML comments, imports of non-agent files and imports that do not load")}

- **Imports.** {n("at_imports")} use `@` imports; {float(depth["max_depth_1"]["pct_of_repos"])}% of
  those go one level deep. {n("non_agent_import")} import a file that is not an agent file:
  the text reaches the model, but a scanner that looks at agent paths
  never sees it.
- **Conditional rules.** {n("conditional_rules")} have rules that load only for some paths
  (`paths`, `globs`, `applyTo`), {cond["pct_of_entries"]}% of all loaded entries.
- **Comments the agent does not see.** {n("claude_html_comments")} of the repos with a `CLAUDE.md`
  have HTML comments in it. Claude Code strips block comments before the model reads them, so notes
  written there are invisible to the agent.
- **Imports that silently do not load.** {n("unloaded_import")} have an import that points nowhere
  or that the agent does not follow, with no error.

## 4. Risk indicators

{picture("05-risk", "Bar chart: share of repositories with unpinned MCP packages, over-permissive settings, hidden Unicode and hardcoded secrets")}

- **MCP.** {n("mcp_unpinned")} of the repos with an MCP config start a server with an unpinned
  package: whatever is published next runs on the developer's machine.
- **Agent settings.** {n("risky_settings")} have over-permissive settings (broad allow lists or
  auto-enabled project MCP servers).
- **Hidden Unicode.** {n("hidden_unicode")}. Each was read by hand: they are zero-width or joiner
  characters that really sit in the text (a word joiner before a URL, a demonstration inside a
  security skill), none carries a payload.
- **Secrets.** {n("secrets")}.
- **Instruction-like content.** Phrases that look like injections show up in documentation that
  teaches or forbids them (security skills quoting "ignore previous instructions", `curl | sh`
  installers). Among the findings of medium severity or above we found no instruction written to deceive an
  agent or its user, and nothing to disclose.

## 5. How reliable the scanner is

{picture("06-precision", "Stacked bar chart per rule: true positives and correct matches in benign context among findings of medium severity or above")}

Every finding of medium severity or above in both tiers was triaged by class (each class was checked on its examples and approved by a maintainer): {tp} true positives, {wf}
correct matches in a benign context (an installer one-liner, an attack described in a security
skill), {fp} false positives and {un} unreviewed. The zero is because we fixed the rules instead of
labelling their false positives: the first runs produced many, and each became a test and a rule
change.

{md_table(["Tier", "Run", "Repos", "Findings", "Critical", "High", "Medium"], [[r["tier"], r["run"], r["repos"], r["findings"], r["critical"], r["high"], r["medium"] or "n/a"] for r in runs])}

Whether a `wontfix` is a false positive is a judgement. For GR016, for example, most are a permission-bypass flag named in a CLI guide: the text does contain the flag, so we count it as a correct match in a benign context, but a stricter reader could call them false alarms. The remaining `wontfix` matches are real: a `curl | sh` installer in a README is the pattern the rule
describes. ghostrules reports it so a human can judge, and says so in the severity.

## Limitations

- **Popular open source only.** {total:,} public repositories with at least one agent file, chosen by
  stars and language. Private code, small projects and other ecosystems are not represented, and
  every repo has an agent file by construction, so "has one" is not a result.
- **Uneven strata.** PHP and Ruby are absent from the 10,000-star stratum: popular projects in those
  languages rarely have agent files.
- **Snapshot.** One day, 2026-10-28; default branch, shallow clone.
- **Patterns, not intent.** A rule match says what the text contains, not why.
- **MCP denominator.** "Repos with an MCP config" means a repo with an MCP file or an MCP rule that
  fired ({nums["mcp_unpinned"]["of"]} repos).
- **Known evasions.** The scanner is a heuristic. Splitting an exfiltration instruction across two
  sentences, or phrasing a concealment right after a prohibition, avoids some rules.

## Method

- **Sample.** {sample.get("study", 0):,} repos in a `study` tier and {sample.get("regression", 0):,} in a
  `regression` tier, 10 languages (Rust, JavaScript, C++, Java, Ruby, Go, C#, Python, TypeScript, PHP)
  by 3 star ranges (500-1,999, 2,000-9,999, 10,000+). Candidates came from the GitHub search API
  (public, non-fork, non-archived, pushed in the last six months), keeping the repos with an agent file
  found in the Git tree. See `corpus/discover.py`.
- **Scan.** `corpus/run.py` clones shallowly, runs `ghostrules scan` and `ghostrules context` with an
  empty configuration, stores findings and per-file numbers (never file contents), and deletes the
  clone. Nothing a scanned file says is executed.
- **Review.** Every finding of medium or above is labelled in `corpus/labels.toml` and
  `study/labels.toml` by fingerprint; labels name no repository.
- **Reproduce.** `python study/analyze.py <results> --labels study/labels.toml corpus/labels.toml`
  writes the CSVs, `python study/charts.py` the charts and `python study/report.py` this file.
"""


def main(argv: Sequence[str] | None = None) -> int:
    p = argparse.ArgumentParser(description="Write the study report from the CSVs.")
    p.add_argument("--data", type=Path, default=HERE / "data")
    p.add_argument("--out", type=Path, default=HERE / "report.md")
    args = p.parse_args(argv)
    args.out.write_text(render(args.data), encoding="utf-8")
    print(args.out)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
