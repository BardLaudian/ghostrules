# ghostrules v0.3 — Build plan

Read first: `CLAUDE.md`, `docs/RULES.md`, `docs/AGENT_MODELS.md`, and `docs/design/v0.3/CORPUS.md`,
`STUDY.md`, `PLAYGROUND.md`. One phase at a time; after each: tests + ruff + mypy, commit, stop and
report. Branch `v0.3`.

## Phase 1 — Corpus tooling (2 h)
`corpus/` per CORPUS.md: `discover.py`, `run.py`, fingerprints, `labels.toml`, `triage.py`,
`check.py`; excluded from the package (check the built wheel/sdist contents in a test).
Unit tests with a fake `gh`/git layer (no network in tests).
**Done when:** `python corpus/run.py --repos owner/a,owner/b` works locally on two real repos and
`check.py` prints the summary.

## Phase 2 — First real run + triage (with the user, 1–2 h)
- `discover.py` → propose a `regression` tier of ~300 repos; the user approves it.
- Run it. Triage every finding ≥ medium together with the user (`triage.py`). For each `fp`: write
  the synthetic test, fix the rule, re-run. Continue until `check.py` passes.
- Anything that looks like a real secret or real malicious content: stop and tell the user; follow
  the disclosure rules. Do not paste such findings into commits, issues or logs.
**Done when:** `check.py` passes on the full regression tier.

## Phase 3 — Corpus CI + badge (45 min)
`.github/workflows/corpus.yml`, `badges` branch summary, endpoint badge in README with an honest label.

## Phase 4 — Playground (3–4 h)
Per PLAYGROUND.md: feasibility test first (core imports without typer/rich), then features 1 → 2 → 3,
Pages workflow, Playwright smoke test. Show the user screenshots of each feature (light and dark).

## Phase 5 — Study (with the user, 1 weekend)
- `study` tier (~1,000–2,000 repos) — the user approves the selection query first.
- `study/features.py`, `study/analyze.py`, CSVs, SVG charts, `study/report.md` per STUDY.md.
- Before writing conclusions: list the top 10 numbers to the user and wait for approval; handle any
  private disclosures first.

## Phase 6 — Release 0.3.0 (45 min)
- README: playground link at the top ("Try it in your browser"), corpus badge, link to the study,
  short "How we test precision" section.
- CHANGELOG `[0.3.0]` (precision fixes found by the corpus, playground, corpus tooling).
  `__version__ = "0.3.0"`; snippets → v0.3.0.
- Open the PR with the before/after corpus numbers.
