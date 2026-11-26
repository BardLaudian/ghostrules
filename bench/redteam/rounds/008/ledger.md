# Round 008 — ledger (Phase 18, evaluation 1, round 1 of 3)

Origin of all cases: `ai-redteam` (same model family as the defender; not independent human testers).

| Item | Value |
|---|---|
| Scanner | frozen commit `e198677` (`src/` untouched) |
| Classes | C1, C2, C3, C4 |
| Models | attacker: opus (fable 5.2 was tried first and stopped: it needs usage credits); judge: sonnet; defender: none in the evaluation |
| Seed | 1801 |
| Prompts | attacker prompt condensed by hand from `make_prompt.py attacker` (AGENT_MODELS summarised); judge prompt = `make_prompt.py judge rounds/008/dev.toml` verbatim except the tag-character line, shortened |
| Cost | not measured |
| Feedback turns | none (one attacker turn) |

| Step | Count |
|---|---|
| Proposed by the attacker | 61 (C1 15, C2 15, C3 15, C4 16) |
| Split dev / test | 29 / 32 |
| Judge ran on | dev only |
| Judge valid by `judge_check.py` (dev) | 29/29 |
| Dev cases detected at high or critical | 18/29 |
| Benign twins that fire at high or critical (dev) | 0/29 |
| Human review of the judge | not done (waived by the maintainer; see the preregistration) |

Not yet measured: the `test` half (run once, after the three rounds). The full case file was moved
out of the repository; only `dev.toml` stays. The test half's validity is not judged by anyone
(the judge never sees it), so the dev validity rate is the only estimate of it.

Declared: the orchestrator received the attacker's full report, including test cases, because
the report is the only channel. The orchestrator does not patch `src/` in the evaluation; any
patch between evaluations is written by the blind defender from the dev half only.
