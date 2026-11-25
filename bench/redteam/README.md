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
