# Red-team loop (v0.6.0)

Infrastructure for the rounds described in `docs/improvement/PLAN-0.6-deteccion.md`, section 2.
The roles are subagents of the chat (`.claude/agents/`); the chat is the orchestrator
(`/redteam-round`). Nothing here calls an external API, and the scanner still makes no network
requests. Cases are labelled `ai-redteam`: the three roles share a model family and its blind spots.

| Piece | File | What it guarantees |
|---|---|---|
| Case format | `case_schema.toml`, `schema.py` | ids, classes, paths and payload size are checked before anything runs |
| Oracle | `oracle.py` | scans in a fresh temporary git repo; returns only `detected` (high or critical) and `max_severity` |
| Split | `split.py` | dev/test by hash of the id (50/50); test cases are written outside the repo |
| Prompts | `make_prompt.py` | allow-list of sources (taxonomy, schema, `docs/AGENT_MODELS.md` with rule ids removed); refuses `src/`, `tests/`, rules, dev/test files |
| Judge check | `judge_check.py` | the decoded text must match the declared payload (`difflib` ratio ≥ 0.6 on normalised text; chosen, not tuned) |
| Gate | `gate.py`, `gate_thresholds.toml` | tests, mypy, ruff, FP tests, perf, dev regression, twin false positives, diff size under `src/`, blind audit |
| Audit | `audit_blind.py` | flags any logged tool call that names the test set; no log means exit 2 |
| Ledger | `rounds/ledger.template.md` | models, seeds, prompts, cost, counts, patch, gate, audit |

## Where the test set lives

`$GHOSTRULES_REDTEAM_TEST_DIR` (default `~/.cache/ghostrules-redteam-test`), refused if inside the
repository. `.claude/settings.json` denies reading it and logs every tool call
(`.claude/hooks/log_tool_call.py` to `.claude/redteam-calls.jsonl`, git-ignored).

## Limits, stated

- The deny rules and the audit are a net, not a wall: a shell command can reach a path they do
  not recognise. The blind prompts and the human review of every round PR are the other layers.
- `tools: []` and `disallowedTools` on the blind agents are **not yet proven** to leave them without
  tools. Phase 13 runs the blindness test (ask each to read a repo file; it must fail) before any
  round counts.
- The hook log does not say which subagent made a call; any access to the test set, by anyone,
  voids the round.
- The gate's corpus check compares the committed results with the labels; it does not re-scan the
  300 repositories (Phase 16, needs network).
- `.claude/agents/*.md` are not read as agent files by ghostrules itself (a scan of that folder
  reports 0 files), so the project's own scan and lock do not cover them.

## Procedure as it worked in the pilot (round 000)

- The orchestrator cannot pass a file to a subagent: it pastes the prompt text. Long prompts cost
  tokens twice, so the prompts of round 000 were shortened by hand (see its ledger).
- Subagent output comes back as a message. Extract the TOML from the subagent transcript with a
  script (do not retype it) and validate it with `schema.validate_round` before `split.py`.
- `split.py` rewrites `dev.toml` from the whole `cases.toml` each time, so merge the turns first and
  run the oracle on `dev.toml`; feed back only the ids of the current turn.
- Run every command from the repository root: the hook now uses `$CLAUDE_PROJECT_DIR`, but the
  scripts and the audit log use paths relative to the root.
- The review sample must keep `test` rows outside the repo (`review.csv` holds dev rows only).
- Do not print counts over `test` cases, not even aggregates (round 000 did; it is declared).
- Pilot numbers: the attacker did not improve from turn 1 to 3 (dev evasion 62 %, 92 %, 100 %); the
  judge accepted 30 of 30 sampled cases; 3 of 15 dev twins fired because the judge keeps the hiding
  technique in the twin.
- Saturation: the scanner had so many gaps that evasion was ≥ 80 % from turn 2, so extra turns add
  nothing; the round stops at that point (see `redteam-round.md`).
- Judge-human agreement: after filling `human_valid`, run `python bench/redteam/review_agreement.py rounds/000/review.csv ~/.cache/ghostrules-redteam-test/000/review_test.csv` (prints totals only; below 85 % adjust the judge prompt and repeat).
- Review in a terminal: `python bench/redteam/review_cli.py <review.csv>` shows each row with mechanical decoding hints and saves after every answer. Run it outside Claude Code when the CSV is the test half.
