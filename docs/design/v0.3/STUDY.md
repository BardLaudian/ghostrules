# v0.3 — Study: "The state of AI agent instruction files (2026)"

## Goal
A data-driven article (blog + `study/report.md` in the repo) answering: **what do popular
repositories actually tell their AI agents, and how risky is it?** Tools get a glance; data gets
shared. ghostrules is presented as the instrument, not the headline.

## Sample
- From `corpus/discover.py`: public, non-fork, non-archived repos with recent pushes, stratified by
  stars (e.g. 500–2k, 2k–10k, 10k+) and by language, ~1,000–2,000 repos with at least one agent file.
- Record the snapshot date and the exact selection query. State the sampling bias plainly
  (popular open-source ≠ all code; private repos unknown).

## Questions → metrics (extracted by `study/features.py` from `corpus/run.py` outputs)
Adoption
1. Which agent files appear, and how often (AGENTS.md, CLAUDE.md, Cursor rules, Copilot
   instructions, GEMINI.md, skills, .mcp.json…)? How many repos target several agents?
2. How many use `CLAUDE.md -> AGENTS.md` symlinks vs `@AGENTS.md` imports vs duplicated files?
3. Size: lines/bytes per instruction file; how many exceed Claude Code's recommended 200 lines?

What agents actually read (only ghostrules can measure this)
4. How many repos use `@` imports; depth distribution; how often an imported file is **not** an
   agent file (i.e. invisible to path-based scanners).
5. Conditional rules: share of rules with `paths`/`globs`/`applyTo`.
6. Imports that silently do not load (GR022) and imports escaping the repo (GR020).
7. HTML comments in CLAUDE.md that Claude Code strips (content authors think the agent reads but it
   doesn't).

Risk indicators (aggregate counts only)
8. MCP configs: unpinned `npx`/`uvx` (GR102), `http://` remotes (GR103), docker flags (GR106),
   broad filesystem scope (GR104).
9. Agent settings: `bypassPermissions`, broad `Bash(*)` allows, auto-enabled MCP servers.
10. Skills: remote-execution patterns, sensitive file access, safety-bypass instructions.
11. Hidden Unicode (GR001–GR004) anywhere in agent files — expected ≈0; any hit is triaged by hand
    first (most will be emoji/RTL edge cases → fix ghostrules; anything real → private disclosure).
12. Hardcoded secrets in agent configs: **only a count**, after private disclosure, never examples.

Precision section
13. Findings per rule before/after triage, false positive rate per rule, what was fixed because of the
    study (links to commits). This makes the article credible and shows engineering rigour.

## Output
- `study/analyze.py` → `study/data/*.csv` (aggregates only) + charts as SVG with matplotlib
  (consistent palette, labelled axes, one message per chart, readable in light and dark).
- `study/report.md`: findings first, method last; every number reproducible from the CSVs; a
  "Limitations" section.
- Blog version (Hugo, ES + EN) and a 5-chart LinkedIn carousel / thread.
- Headline candidates (pick the one the data supports):
  - "X% of repos import files into their AI agent's context that no path-based scanner checks"
  - "1 in N MCP configs runs an unpinned package on every start"
  - "What 1,500 popular repos tell their AI agents"

## Rules
- Never publish a repo name together with a risk finding unless it's clearly benign and illustrative.
- Disclose first, publish later. Note in the report how many private reports were sent.
- Numbers in the article must match the committed CSVs exactly.
