# Real-world scan v2

A read-only scan of 40 public repositories that the rules were **not** tuned on. It reports; no rule
was adjusted from what it found (the findings below are listed so that they can be fixed deliberately,
with a benign case in the corpus, in a later round).

## How the repositories were chosen (2026-11-27)

1. **Candidate pool.** `gh search code --filename F --language L --limit 40` for four file names
   (`AGENTS.md`, `CLAUDE.md`, `.cursorrules`, `SKILL.md`) and eight languages (python, typescript, go,
   rust, java, ruby, php, javascript): 32 queries, 123 distinct repositories. Several criteria on
   purpose, so the pool is not only what a popularity ranking returns.
2. **Exclusions.** Every repository used for the earlier tuning scans (none of the 123 overlapped), forks,
   private repositories, and anything over 40 MB.
3. **Stratified draw** by stars with a fixed seed (20261128): all 4 repositories with 1000+ stars, all 7
   with 100–999, 12 of 20 with 10–99, 17 of 48 with 0–9, and every repository found through
   `.cursorrules` (3). Result: 40 repositories, found through `AGENTS.md` 21, `SKILL.md` 17, `CLAUDE.md` 5,
   `.cursorrules` 3 (a repository can be found by more than one).
4. **Cloned** with `git clone --depth 1`, hooks disabled, nothing executed. `repos.json` lists each one
   with the commit that was scanned.

## Scan

`python scripts/realworld_scan.py CLONES_DIR tests/realworld/v2` scans every repository twice with the
default configuration, `--visibility default` and `--visibility root-medium` (see USAGE.md), and writes
`results-default.json` and `results-root-medium.json`: 40 repositories, 1899 agent files, 40 findings of
any severity in each variant (the same 40; only some severities differ).

## Findings at medium or above, with a verdict (`verdicts.json`)

19 findings reach `medium` or above in at least one variant. **All 19 are false positives; there are 0
true positives**, which is what a sample of ordinary repositories should give. It is not a recall
measurement (nothing in it is an attack).

| rule | findings | default | root-medium | what they are |
|---|---|---|---|---|
| GR110 | 7 | high | high | an authenticated call to the API the token belongs to (Apify, an MCP gateway) |
| GR031 | 5 | low | **medium** | a "no-review / skip approval" option the user can ask for in a drafting workflow |
| GR013 | 2 | low | **medium** | an API-token variable documented in a heading and a table |
| GR011 | 2 | medium | medium | "do not include it in the output" (a data field), "checkers silently leak" (a failure mode) |
| GR003 | 1 | medium | medium | ZWJ and a variation selector inside an emoji regular expression in JavaScript |
| GR015 | 1 | medium | medium | the public IC root key written in hex, in documentation |
| GR035 | 1 | medium | medium | a description of when a network dialler announces a connection |

By variant: 12 false positives at medium or above with `default`, 19 with `root-medium` (the 7 extra are
GR031 and GR013). Per agent file: 0.63 % and 1.0 %.

Which of them come from rules changed in the detection round of this branch: GR031 (5), GR011 (2), GR035
(1) and probably GR013 (2). GR110, GR003 and GR015 are older rules.

## Performance note

One of the repositories (`criptogus/agent-evolve-network`: 62 MB, 610 agent files) takes about 135 s to scan,
against about 77 s with the code of `main` (both measured while other work ran on the machine). The
rules gained roughly 90 patterns in this round and every pattern runs on three views of the text.
Reusing matches between rules and a faster Unicode check recovered part of it; a keyword prefilter would
recover more.
