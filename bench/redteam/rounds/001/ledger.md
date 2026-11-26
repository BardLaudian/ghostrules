# Round 001 — ledger

**Status: partial, closed without a patch.** The judge-human agreement stayed below the threshold
and the cause is the validity metric, not the scanner. The defender was not run. Origin of all
cases: `ai-redteam` (one model family, not independent human testers).

| Item | Value |
|---|---|
| Date / base commit | 2026-11-25 / branch `fase-14-ronda-001` (oracle fix `f3505ce`, judge prompt `1f2f782`) |
| Classes and focus | C1–C4; no per-technique focus (round 000 gave no usable per-technique rates) |
| Models | attacker sonnet; judge: haiku (stopped by the platform safeguards, no output), then sonnet by override of the `model` field of the call, twice; defender not run. The harness does not report the model that actually ran. |
| Seeds | attacker 2000 (turn 2 continued the same agent) |
| Prompts | attacker prompt: the taxonomy was **summarised by hand** instead of pasting `make_prompt.py` output; judge prompt: `make_prompt.py judge` output with one 2,900-character filler line replaced by a bracketed description; pass 2 uses the prompt of `1f2f782` |
| Cost | not measurable here (no per-role tokens in what I can read). Subagent durations: attacker 82 s + 51 s, judge 58 s + 59 s. Read the plan usage panel. |

## Cases

| Step | Count |
|---|---|
| Proposed by the attacker (turn 1 / turn 2) | 67 / 30 (budget was 60 per round) |
| Valid by schema | 97 of 97 |
| Split dev / test | 44 / 53 |
| Dev with invalid config (excluded from evasion) | 1 (`r2000-c3-evasion-allowlist`, a config key that does not exist) |
| Dev evasion, turn 1 / turn 2 | 24 of 32 (75 %) / 9 of 11 (82 %); turns stopped at the saturation rule (≥ 80 %) |
| Judged | the 44 dev cases only. The 53 test cases were **not judged**: pasting them to a subagent would route them through the orchestrator. Open decision (see below). |
| Valid after the judge (similarity ≥ 0.6) | pass 1: 32 / 44; pass 2: 32 / 44 (same threshold) |
| Benign twins that fire | not measured (twins and gate snapshot not run) |

## Human review of the judge (`[HUMANO]`)

Sample: 25 dev rows (seed 7).

| Pass | Judge prompt | Agreement | Result |
|---|---|---|---|
| 1 | `JUDGE_TASK` of round 000 | 20 / 25 = 80 % (threshold 85 %) | below threshold |
| 2 | asks to quote commands, config and credentials | not reviewed again (see decision) | `review.csv` regenerated, `human_valid` empty |

Pass 1 disagreements: 4 judge-invalid / human-valid (`r2000-c3-mcp-resource`,
`r2000-c4-secret-cursor-b64`, `r2000-c4-mcp-ws-cmd`, `r2000-c4-mcp-shell`) and 1 judge-valid /
human-invalid (`r2000-c4-secret-zw-claude`, score 0.639). Pass 1 files: `review-pass1.csv`,
`verdicts-pass1.toml`.

## Diagnosis and decision

After pass 2 the judge quotes the risky text literally, and `judge_check` still gives 32 of 44 valid
with almost the same 12 invalid and lower scores. For C3/C4 `declared_payload` is prose ("run an
unpinned package…") and the file is JSON or code, so `difflib` similarity between a faithful quote
and the prose is low. The metric does not measure validity for those classes.

Decision of the person: **option 3**, stop round 001 and settle the validity metric for C3/C4
**before** round 002, not after seeing its numbers. No change to `judge_check.py`, to the
threshold or to `PREREGISTRATION.md` was made in this round.

## Patch

None. The defender was not run, the gate snapshot was not taken. No change under `src/`.

## Blind audit and blindness test

- Not run: the round stopped before step 9. The call log (`.claude/redteam-calls.jsonl`) is
  git-ignored and was started empty.
- Blindness test of the agents not repeated; the `tools: []` change in the frontmatter of the
  attacker and the judge is **not committed and not tested**. Both agents answered through
  `SubagentHandback`, which suggests `tools: []` does not remove every tool (not verified).

## Faults found and declared

- The oracle crashed with a config key the scanner rejects. Fixed in `f3505ce` (`invalid_config`
  verdict; the case is excluded from the evasion count).
- A script of mine that tried to find the invalid-config cases iterated over `cases.toml`, which
  includes the test half; the platform blocked it before any output. I did not retry it. No test
  case or per-case result was read. `split.py` and the first merge read that file as designed.
- The judge on haiku was stopped by the platform safeguards (request `req_011ChPjW6tZe7hqHYzzthKdx`).
  Retried on sonnet as the person ordered; I did not rewrite the prompt to avoid it.
- The attacker returned 67 and 30 cases against a request for 60 / 30.

## Open decisions

1. Validity metric for C3/C4 (accept the quoted risky text, or leave validity to human review).
2. Who judges the 53 test cases without passing them through the orchestrator.
3. `tools: []` vs `tools: SubagentHandback` and the `model` of the judge in the frontmatter.

## Declared limits

- Attacker, judge and defender share a model family and its blind spots.
- Test cases are used once, against a frozen version (Phase 18); nothing from them is reported here.
- Round 001 is not a measurement of the scanner: 12 of 44 dev cases have an unsettled validity.

Files: `dev.toml`, `oracle.json`, `verdicts.toml`, `review.csv` (pass 2, empty), `*-pass1.*`.
The raw turns and merged cases (test half included) are in
`~/.cache/ghostrules-redteam-test/001/raw/`.
