# v0.3 — Real-world corpus (precision you can prove)

## Goal
Run ghostrules every week against a fixed corpus of popular public repositories that contain agent
files, so that:
1. every false positive becomes a regression test before users see it;
2. the README can state a measured claim, e.g. *"Tested weekly against 300 popular repositories:
   0 critical false positives"* (only ever publish numbers the latest run supports);
3. the same data feeds the study (STUDY.md).

The corpus tooling lives in `corpus/`, is **not** part of the published package (exclude it from the
wheel/sdist) and is the only part of the project that uses the network (cloning). ghostrules itself
stays offline.

## Layout
```
corpus/
├── README.md            what this is, how to run it, ethics (see bottom)
├── repos.toml           the pinned corpus: [[repo]] name = "owner/repo", tier = "regression" | "study"
├── discover.py          build/refresh candidate list with the GitHub API (gh CLI auth)
├── run.py               clone shallow, scan, write results
├── triage.py            interactive labelling of findings (tp / fp / wontfix + reason)
├── labels.toml          triaged findings, keyed by stable fingerprint
├── check.py             regression gate: compares a run with labels.toml
└── results/             gitignored except the latest summary JSON
```

## discover.py
- Uses `gh api` (user's token; never commit tokens). Search repositories by stars
  (e.g. `stars:>2000`, several languages, `pushed:>` last 6 months, not archived, not forks).
- For each candidate, one call to the Git trees API (`/repos/{o}/{r}/git/trees/{default}?recursive=1`)
  to check whether it contains any file the 0.2 target list or agent models know (AGENTS.md,
  CLAUDE.md, .cursor/rules, .github/copilot-instructions.md, .mcp.json, SKILL.md, …). Truncated trees:
  mark as "unknown", don't guess.
- Respect rate limits (read `X-RateLimit-Remaining`, sleep), cache responses in
  `corpus/.cache/` (gitignored), resumable.
- Output: candidates with stars, language, which agent files exist. The human picks the tiers:
  `regression` (~300, stable list) and `study` (larger, stratified by stars; see STUDY.md).

## run.py
- For each repo in the chosen tier: `git clone --depth 1 --filter=blob:limit=2m` into a temp dir,
  record the commit SHA, run `ghostrules scan --format json --fail-on none` **and**
  `ghostrules context --format json --agent all --no-scan`, delete the clone.
- Parallel (configurable workers), per-repo timeout, robust to clone failures (record and continue).
- Writes `results/<date>/<owner>__<repo>.json` + `results/<date>/summary.json`
  (counts per rule/severity, per repo time, failures, ghostrules version).
- **Never store file contents.** Findings already contain masked snippets; drop `decoded` text from
  stored results except for GR001/GR004 (needed for triage), and mask anything secret-shaped again.

## Fingerprints and triage
- Finding fingerprint: `sha256(repo, path, rule_id, normalized snippet)` (no line numbers, so it
  survives unrelated edits).
- `triage.py` walks unlabelled findings ≥ medium, shows the snippet with context (re-fetch the single
  file via the API for display only, not stored), and records `tp` / `fp` / `wontfix` + a one-line
  reason in `labels.toml`.
- Rule for contributors: every `fp` must link to a test in `tests/` that reproduces it synthetically
  (`test = "tests/test_rules_injection.py::test_gr011_tell_user_to"`). `check.py` verifies the test
  exists.

## check.py (the gate)
Fails if, in the latest run:
- any **unlabelled** finding is `critical` or `high`;
- any finding labelled `fp` still appears at its old severity;
- the scan crashed on any repo (exit 2).
Prints a markdown table for the job summary.

## CI
`.github/workflows/corpus.yml`: `schedule` weekly + `workflow_dispatch`; never on PRs.
Steps: install ghostrules from the checked-out source → `run.py --tier regression` → `check.py` →
upload results as an artifact → on `main` only, publish `summary.json` to the orphan `badges` branch
(path `corpus/summary.json`) so the README badge can read it via a shields.io endpoint badge
(`https://img.shields.io/endpoint?url=…`). Badge text e.g. `corpus · 300 repos · 0 critical FP`.
Use `GITHUB_TOKEN` (read-only) for the API; no other secrets.

## Ethics (put this in corpus/README.md)
- Only public repositories, shallow clones, deleted after scanning; no file contents stored.
- If a run finds a **real secret** (GR101/GR021 on a live-looking token) or anything that looks
  genuinely **malicious** (GR001/GR004 decoded text with a real instruction, not documentation):
  do not publish it, do not name the repo anywhere public, report it privately to the maintainer
  (security policy / private vulnerability reporting) and record only "reported" in labels.toml.
- Results and reports use aggregates; named examples only for benign, illustrative patterns and only
  after checking the maintainers would not mind (prefer anonymised examples).
