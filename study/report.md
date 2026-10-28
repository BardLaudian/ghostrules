# What 1,583 popular repos tell their AI agents

*The state of AI agent instruction files, October 2026.*

We scanned the agent files of 1,583 popular public repositories with
[ghostrules](https://github.com/BardLaudian/ghostrules): `AGENTS.md`, `CLAUDE.md`, Cursor and Copilot
rules, skills, MCP configs and agent settings. Aggregates only: no repository is named next to a
finding, and every number below comes from the CSVs in [`data/`](data/).

## In short

- **`AGENTS.md` is the shared language.** It is in 70.7% of repos,
  ahead of skills (50.2%) and `CLAUDE.md` (49.3%).
- **44.4% write instructions for more than one tool**, and the repos that keep `CLAUDE.md` and
  `AGENTS.md` together mostly link them (38.5% import one from
  the other, 28.9% use a symlink) instead of copying.
- **What an agent reads is not just what its path says.** 16.9% (268 of 1,583) use `@` imports,
  30.2% (478 of 1,583) have rules that apply only to some paths, and 4.7% (74 of 1,583)
  import a file that is not an agent file at all.
- **33.3% (27 of 81)** of the repos that configure an MCP server start at least one with an
  unpinned `npx` or `uvx` package.
- **No real secret and no real malicious instruction.** Hidden Unicode: 0.4% (6 of 1,583), all
  characters that really are in the text. Hardcoded secrets: 0.0% (0 of 1,583). Private disclosures
  sent: 0.

## 1. Who writes instructions for agents

<picture>
  <source media="(prefers-color-scheme: dark)" srcset="charts/01-adoption-dark.svg">
  <img alt="Bar chart: share of repositories containing each kind of agent file; AGENTS.md leads at 70.7 percent" src="charts/01-adoption-light.svg">
</picture>

| File | Repos | % of repos | Files |
|---|---|---|---|
| AGENTS.md | 1,119 | 70.7 | 3,351 |
| Skills (SKILL.md) | 794 | 50.2 | 20,359 |
| CLAUDE.md | 781 | 49.3 | 1,824 |
| GitHub Copilot | 301 | 19.0 | 565 |
| .claude/ (commands, agents, rules) | 170 | 10.7 | 2,620 |
| .claude/settings*.json | 143 | 9.0 | 147 |
| MCP config | 78 | 4.9 | 99 |
| Cursor rules | 66 | 4.2 | 261 |
| Other agent files | 65 | 4.1 | 227 |
| GEMINI.md | 51 | 3.2 | 51 |
| Windsurf | 10 | 0.6 | 10 |
| Cline / Roo | 6 | 0.4 | 24 |

Skills dominate by file count (20,359 `SKILL.md` files) because a few repositories
are skill collections: the largest one holds 9.8% of them, the top three
29.3% and the top ten 51.3%. The median
repository with skills has 4. We therefore count repositories,
not files.

<picture>
  <source media="(prefers-color-scheme: dark)" srcset="charts/02-tools-per-repo-dark.svg">
  <img alt="Bar chart: share of repositories by number of tools their instruction files target; two tools is the most common multi-tool case" src="charts/02-tools-per-repo-light.svg">
</picture>

44.4% of repos target two or more tools. Instruction files are short: 49.4% have
at most 50 lines, and 14.7% of the 5,748 instruction files are over 200
lines. For the root `CLAUDE.md` specifically, 16.3% (93 of 570) go beyond the 200 lines Claude
Code recommends.

## 2. Two files, one truth

<picture>
  <source media="(prefers-color-scheme: dark)" srcset="charts/03-claude-agents-dark.svg">
  <img alt="Bar chart: how repositories with both CLAUDE.md and AGENTS.md keep them in step; importing is the most common" src="charts/03-claude-agents-light.svg">
</picture>

491 repos have both a root `CLAUDE.md` and an `AGENTS.md`. They keep them in step by
importing (38.5%), a symlink (28.9%),
two separate files (31.4%) or a copy
(1.2%). With two separate files nothing keeps them equal, and each agent
reads a different one.

## 3. What the agent really reads

<picture>
  <source media="(prefers-color-scheme: dark)" srcset="charts/04-what-agents-read-dark.svg">
  <img alt="Bar chart: share of repositories with conditional rules, at-imports, stripped HTML comments, imports of non-agent files and imports that do not load" src="charts/04-what-agents-read-light.svg">
</picture>

- **Imports.** 16.9% (268 of 1,583) use `@` imports; 97.4% of
  those go one level deep. 4.7% (74 of 1,583) import a file that is not an agent file:
  the text reaches the model, but a scanner that looks at agent paths
  never sees it.
- **Conditional rules.** 30.2% (478 of 1,583) have rules that load only for some paths
  (`paths`, `globs`, `applyTo`), 62.8% of all loaded entries.
- **Comments the agent does not see.** 7.7% (44 of 570) of the repos with a `CLAUDE.md`
  have HTML comments in it. Claude Code strips block comments before the model reads them, so notes
  written there are invisible to the agent.
- **Imports that silently do not load.** 1.3% (21 of 1,583) have an import that points nowhere
  or that the agent does not follow, with no error.

## 4. Risk indicators

<picture>
  <source media="(prefers-color-scheme: dark)" srcset="charts/05-risk-dark.svg">
  <img alt="Bar chart: share of repositories with unpinned MCP packages, over-permissive settings, hidden Unicode and hardcoded secrets" src="charts/05-risk-light.svg">
</picture>

- **MCP.** 33.3% (27 of 81) of the repos with an MCP config start a server with an unpinned
  package: whatever is published next runs on the developer's machine.
- **Agent settings.** 0.8% (12 of 1,583) have over-permissive settings (broad allow lists or
  auto-enabled project MCP servers).
- **Hidden Unicode.** 0.4% (6 of 1,583). Each was read by hand: they are zero-width or joiner
  characters that really sit in the text (a word joiner before a URL, a demonstration inside a
  security skill), none carries a payload.
- **Secrets.** 0.0% (0 of 1,583).
- **Instruction-like content.** Phrases that look like injections show up in documentation that
  teaches or forbids them (security skills quoting "ignore previous instructions", `curl | sh`
  installers). Among the findings of medium severity or above we found no instruction written to deceive an
  agent or its user, and nothing to disclose.

## 5. How reliable the scanner is

<picture>
  <source media="(prefers-color-scheme: dark)" srcset="charts/06-precision-dark.svg">
  <img alt="Stacked bar chart per rule: true positives and correct matches in benign context among findings of medium severity or above" src="charts/06-precision-light.svg">
</picture>

Every finding of medium severity or above in both tiers was triaged by class (each class was checked on its examples and approved by a maintainer): 158 true positives, 317
correct matches in a benign context (an installer one-liner, an attack described in a security
skill), 0 false positives and 0 unreviewed. The zero is because we fixed the rules instead of
labelling their false positives: the first runs produced many, and each became a test and a rule
change.

| Tier | Run | Repos | Findings | Critical | High | Medium |
|---|---|---|---|---|---|---|
| regression | first run | 300 | 323 | 84 | 156 | n/a |
| regression | after precision fixes | 300 | 212 | 0 | 53 | 37 |
| study | first run | 1283 | 1072 | 13 | 296 | 194 |
| study | after precision fixes | 1283 | 945 | 12 | 252 | 119 |

Whether a `wontfix` is a false positive is a judgement. For GR016, for example, most are a permission-bypass flag named in a CLI guide: the text does contain the flag, so we count it as a correct match in a benign context, but a stricter reader could call them false alarms. The remaining `wontfix` matches are real: a `curl | sh` installer in a README is the pattern the rule
describes. ghostrules reports it so a human can judge, and says so in the severity.

## Limitations

- **Popular open source only.** 1,583 public repositories with at least one agent file, chosen by
  stars and language. Private code, small projects and other ecosystems are not represented, and
  every repo has an agent file by construction, so "has one" is not a result.
- **Uneven strata.** PHP and Ruby are absent from the 10,000-star stratum: popular projects in those
  languages rarely have agent files.
- **Snapshot.** One day, 2026-10-28; default branch, shallow clone.
- **Patterns, not intent.** A rule match says what the text contains, not why.
- **MCP denominator.** "Repos with an MCP config" means a repo with an MCP file or an MCP rule that
  fired (81 repos).
- **Known evasions.** The scanner is a heuristic. Splitting an exfiltration instruction across two
  sentences, or phrasing a concealment right after a prohibition, avoids some rules.

## Method

- **Sample.** 1,283 repos in a `study` tier and 300 in a
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
