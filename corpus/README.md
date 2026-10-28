# corpus — ghostrules against real repositories

Tooling that runs ghostrules against popular public repositories that contain AI agent files, so
every false positive becomes a regression test and any precision claim is measured.
**This directory is not part of the published package** (the wheel only packages `src/ghostrules`;
the sdist excludes `corpus/`) and is the only part of the project that uses the network: `git clone`
and the `gh` CLI. ghostrules itself stays offline.

```bash
pip install -e ".[dev]"
python corpus/discover.py --min-stars 2000 --language python,typescript --propose regression:300
python corpus/discover.py --strata 500-1999,2000-9999,10000- --language Go,Rust --propose study:1500
python corpus/run.py --repos owner/a,owner/b      # or --tier regression
python corpus/check.py                            # the gate; exit 0 pass, 1 violation, 2 crash
python corpus/triage.py                           # label unlabelled findings >= medium
```

| File | What it does |
|---|---|
| `discover.py` | `gh api` search + one Git trees call per candidate; cached in `.cache/`, resumable, waits for the rate limit. Prints a TOML proposal; never writes `repos.toml`. |
| `run.py` | Shallow clone (`--depth 1 --filter=blob:limit=2m`), `scan` + `context --no-scan`, with an empty `--config` so a repo's own `.ghostrules.toml` cannot change the measurement. Deletes the clone. |
| `check.py` | The gate: fails on an unlabelled critical/high finding, an `fp` still at its old severity, an `fp` without an existing test, or a crashed scan. |
| `filestats.py` | Per-file numbers for the study (size, lines, symlink target, HTML-comment count, content hash); never a file's text, never follows links. |
| `badge.py` | Writes the shields.io endpoint badge and an aggregate summary (counts only, no repository names). |
| `triage.py` | Walks unlabelled findings, shows snippet and context (fetched for display, never stored). |
| `repos.toml`, `labels.toml` | The pinned corpus and the triaged findings (keyed by fingerprint). |
| `results/` | Gitignored, except `latest-summary.json`. |

A fingerprint is `sha256(repo, path, rule_id, normalised snippet)`, with no line numbers, so it
survives unrelated edits. Every `fp` must name a synthetic test in `tests/` that reproduces it.

## Ethics

- Only public repositories, shallow clones, deleted after scanning; no file contents are stored.
- If a run finds a **real secret** (GR101/GR021 on a live-looking token) or anything that looks
  genuinely **malicious** (GR001/GR004 decoded text with a real instruction, not documentation): do
  not publish it, do not name the repo anywhere public, report it privately to the maintainer
  (security policy / private vulnerability reporting) and record only `reported` in `labels.toml`.
- Results and reports use aggregates; named examples only for benign, illustrative patterns and only
  after checking the maintainers would not mind (prefer anonymised examples).
