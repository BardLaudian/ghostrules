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
    both = sum(int(r["repos"]) for r in rel.values())
    over200 = sum(int(r["files"]) for r in lines if r["lines"] in ("201-400", "401+"))
    all_lines = sum(int(r["files"]) for r in lines)
    tp, wf, fp, un = (
        sum(int(r[k]) for r in prec) for k in ("tp", "benign_context", "fp", "unlabelled")
    )

    def n(key: str) -> str:
        r = nums[key]
        return f"{r['pct']}% ({int(r['repos']):,} of {int(r['of']):,})"

    def share(count: str | int, of: int, pct: str) -> str:
        """``70.7% (1,119 of 1,583)``: a percentage always carries its numerator and denominator."""
        return f"{pct}% ({int(count):,} of {of:,})"

    def rel_n(key: str) -> str:
        return share(rel[key]["repos"], both, rel[key]["pct_of_repos_with_both"])

    def precision(tp_: int, benign: int, fp_: int) -> str:
        total_ = tp_ + benign + fp_
        return f"{tp_ / total_ * 100:.0f}% ({tp_} of {total_})" if total_ else "n/a"

    return f"""# A snapshot (2026-10-28) of what {total:,} popular repos tell their AI agents

*One day, one scan, popular open-source repositories that have agent files. Not a trend and not a
sample of all software.*

We scanned the agent files of {total:,} popular public repositories with
[ghostrules](https://github.com/BardLaudian/ghostrules): `AGENTS.md`, `CLAUDE.md`, Cursor and Copilot
rules, skills, MCP configs and agent settings. Aggregates only: no repository is named next to a
finding, and every number below comes from the CSVs in [`data/`](data/).

## In short

**Security indicators** (what a reviewer cannot easily see, or what executes things)

- **{n("mcp_unpinned")}** of the repos that configure an MCP server start at least one with an
  unpinned `npx` or `uvx` package. The denominator is a lower bound (see "MCP denominator" under
  Limitations), so this share is an upper bound.
- **Hidden Unicode: {n("hidden_unicode")}.** All characters that really are in the text; none carries
  a payload.
- **Over-permissive agent settings: {n("risky_settings")}.**
- **Hardcoded secrets: {n("secrets")}.** Private disclosures sent: 0. No real malicious instruction
  was found among the findings of medium severity or above that one maintainer reviewed.
- **Reliability:** of the {tp + wf + fp} findings of medium severity or above, {precision(tp, wf, fp)} were
  true positives; the rest matched something harmless in context and are noise for a user (section 5).

**How people write agent files** (hygiene, not security)

- **`AGENTS.md` is the shared language.** It is in {share(fam["agents_md"]["repos"], total, fam["agents_md"]["pct_of_repos"])} of repos,
  ahead of skills ({share(fam["skills"]["repos"], total, fam["skills"]["pct_of_repos"])}) and `CLAUDE.md`
  ({share(fam["claude"]["repos"], total, fam["claude"]["pct_of_repos"])}).
- **{n("multi_tool")} write instructions for more than one tool**, and the repos that keep `CLAUDE.md`
  and `AGENTS.md` together mostly link them ({rel_n("import")} import one from the other,
  {rel_n("symlink")} use a symlink) instead of copying.
- **What an agent reads is not just what its path says.** {n("at_imports")} use `@` imports,
  {n("conditional_rules")} have rules that apply only to some paths, and {n("non_agent_import")}
  import a file that is not an agent file at all.

## 1. Who writes instructions for agents

{picture("01-adoption", "Bar chart: share of repositories containing each kind of agent file; AGENTS.md leads at 70.7 percent")}

{md_table(["File", "Repos", "% of repos", "Files"], [[FAMILY_NAMES.get(r["family"], r["family"]), f"{int(r['repos']):,}", r["pct_of_repos"], f"{int(r['files']):,}"] for r in fam.values()])}

Skills dominate by file count ({int(skills["skill_files"]):,} `SKILL.md` files) because a few repositories
are skill collections: the largest one holds {skills["top1_repo_pct_of_files"]}% of them, the top three
{skills["top3_repos_pct_of_files"]}% and the top ten {skills["top10_repos_pct_of_files"]}%. The median
repository with skills has {skills["median_skill_files_per_repo"]}. We therefore count repositories,
not files.

{picture("02-tools-per-repo", "Bar chart: share of repositories by number of tools their instruction files target; two tools is the most common multi-tool case")}

{n("multi_tool")} target two or more tools. Instruction files are short: {share(lines[0]["files"], all_lines, lines[0]["pct_of_files"])} have
at most 50 lines, and {over200 / all_lines * 100:.1f}% ({over200:,} of {all_lines:,}) are over 200
lines. For the root `CLAUDE.md` specifically, {n("claude_md_over_200")} go beyond the 200 lines Claude
Code recommends.

## 2. Two files, one truth

{picture("03-claude-agents", "Bar chart: how repositories with both CLAUDE.md and AGENTS.md keep them in step; importing is the most common")}

{both} repos have both a root `CLAUDE.md` and an `AGENTS.md`. They keep them in step by
importing ({rel_n("import")}), a symlink ({rel_n("symlink")}),
two separate files ({rel_n("separate")}) or a copy
({rel_n("duplicate")}). With two separate files nothing keeps them equal, and each agent
reads a different one.

## 3. What the agent really reads

{picture("04-what-agents-read", "Bar chart: share of repositories with conditional rules, at-imports, stripped HTML comments, imports of non-agent files and imports that do not load")}

- **Imports.** {n("at_imports")} use `@` imports; {share(depth["max_depth_1"]["repos"], int(depth["uses_at_imports"]["repos"]), depth["max_depth_1"]["pct_of_repos"])} of
  those go one level deep. {n("non_agent_import")} import a file that is not an agent file:
  the text reaches the model, but a scanner that looks at agent paths
  never sees it.
- **Conditional rules.** {n("conditional_rules")} have rules that load only for some paths
  (`paths`, `globs`, `applyTo`), {cond["pct_of_entries"]}% ({int(cond["conditional_entries"]):,} entries) of all loaded entries.
- **Comments the agent does not see.** {n("claude_html_comments")} of the repos with a `CLAUDE.md`
  have HTML comments in it. Claude Code strips block comments before the model reads them, so notes
  written there are invisible to the agent.
- **Imports that silently do not load.** {n("unloaded_import")} have an import that points nowhere
  or that the agent does not follow, with no error.

## 4. Risk indicators

{picture("05-risk", "Bar chart: share of repositories with unpinned MCP packages, over-permissive settings, hidden Unicode and hardcoded secrets")}

- **MCP.** {n("mcp_unpinned")} of the repos with an MCP config start a server with an unpinned
  package: whatever is published next runs on the developer's machine. The denominator is built
  from what a scan can see (see "MCP denominator" under Limitations), so treat the share as an
  upper bound.
- **Agent settings.** {n("risky_settings")} have over-permissive settings (broad allow lists or
  auto-enabled project MCP servers).
- **Hidden Unicode.** {n("hidden_unicode")}. Each was read by hand: they are zero-width or joiner
  characters that really sit in the text (a word joiner before a URL, a demonstration inside a
  security skill), none carries a payload.
- **Secrets.** {n("secrets")}.
- **Instruction-like content.** Phrases that look like injections show up in documentation that
  teaches or forbids them (security skills quoting "ignore previous instructions", `curl | sh`
  installers). Among the findings of medium severity or above, one maintainer found no instruction
  written to deceive an agent or its user, and nothing to disclose. That is one reviewer's reading,
  not a proof that there are none.

## 5. How reliable the scanner is

{picture("06-precision", "Stacked bar chart per rule: true positives and correct matches in benign context among findings of medium severity or above")}

We reviewed every finding of medium severity or above in both tiers, by class (each class was
checked on its examples and approved by one maintainer): {tp} true positives, {wf} matches in a
benign context (an installer one-liner, an attack described in a security skill), {fp} labelled false
positives and {un} unreviewed. **For a user, a benign-context match is noise**: it is the right
pattern in a harmless place, and someone still has to read it. Precision for a user is therefore
true positives / (true positives + benign-context + false positives): **{precision(tp, wf, fp)}**.

The count of labelled false positives is not a precision figure. Every false positive found while
reviewing was fixed in the rules (each became a test), so none is left by construction; the rules
were then measured on the same repositories they were tuned on, which flatters them.

{md_table(["Rule", "Findings (medium+)", "True positive", "Benign context", "False positive", "Precision for a user"], [[r["rule"], r["findings_medium_plus"], r["tp"], r["benign_context"], r["fp"], precision(int(r["tp"]), int(r["benign_context"]), int(r["fp"]))] for r in prec] + [["**All**", tp + wf + fp + un, tp, wf, fp, precision(tp, wf, fp)]])}

{md_table(["Tier", "Run", "Repos", "Findings", "Critical", "High", "Medium"], [[r["tier"], r["run"], r["repos"], r["findings"], r["critical"], r["high"], r["medium"] or "n/a"] for r in runs])}

Whether a benign-context match is a false positive is a judgement. For GR016, for example, most are
a permission-bypass flag named in a CLI guide: the text does contain the flag, so we count it as a
correct match in a benign context, but a stricter reader would call them false alarms. GR010, GR012
and GR013 have no true positive at all in this data: every finding was a benign-context match. A
`curl | sh` installer in a README is the pattern the rule describes; ghostrules reports it so a
human can judge, and says so in the severity.

## Limitations

- **Popular open source only.** {total:,} public repositories with at least one agent file, chosen by
  stars and language. Private code, small projects and other ecosystems are not represented, and
  every repo has an agent file by construction, so "has one" is not a result.
- **Uneven strata.** PHP and Ruby are absent from the 10,000-star stratum: popular projects in those
  languages rarely have agent files.
- **Snapshot.** One day, 2026-10-28; default branch, shallow clone. Nothing here says how these
  numbers change over time.
- **Patterns, not intent.** A rule match says what the text contains, not why.
- **MCP denominator.** "Repos with an MCP config" means a repo with an MCP file, or one where an MCP
  rule (GR102 to GR106) fired: {nums["mcp_unpinned"]["of"]} repos. Both parts count repositories, but
  a repo that declares a clean MCP server inside an agent settings file and triggers no MCP rule is
  not in the denominator, because the scan stores counts and never file contents. The denominator is
  therefore a lower bound and the unpinned share ({n("mcp_unpinned")}) an upper bound. Fixing it
  needs a new scan that records whether a server is configured.
- **Known evasions.** The scanner is a heuristic. Splitting an exfiltration instruction across two
  sentences, or phrasing a concealment right after a prohibition, avoids some rules.

## Threats to validity

- **One snapshot.** A single day and a single scan.
- **Popularity bias.** Repositories were chosen by stars and language, so they are not typical of
  all code, and small or private projects are missing.
- **Rules tuned on the same data.** Rules were adjusted after the first runs on these repositories
  and then measured on them, so the precision above is optimistic. A held-out set of 100
  repositories (`bench/heldout.toml`, frozen on 2026-10-29, never used for tuning) is meant to give
  an honest figure.
- **One reviewer, labelling by class.** Findings were labelled by class on examples and approved by
  one maintainer; there was no independent second reviewer.
- **Recall is not measured here.** The study counts what the scanner found. It says nothing about
  what it misses: paraphrases, other languages and split instructions are not caught.

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
