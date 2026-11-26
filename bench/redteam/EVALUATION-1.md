# Evaluation 1 of the 0.6.0 candidate (Phase 18)

Frozen version: `src/` at `e198677`. Preregistration: `PREREGISTRATION.md` (entries of 2026-11-26).
This is **look 1 of at most 4**. Origin of all cases: `ai-redteam` (one model family; not
independent human testers). Attacker: opus (fable 5.2 needed usage credits); judge: sonnet; no
defender turn. One person labels; the human review of the judge was waived and is not done.

## Cases

| Round | Classes | Proposed | Dev / test | Dev valid by the judge | Dev detected (high+) | Dev twins that fire |
|---|---|---:|---|---|---|---|
| 008 | C1–C4 | 61 | 29 / 32 | 29/29 | 18/29 | 0/29 |
| 009 | C1–C4 | 60 | 31 / 29 | 28/31 | 13/31 | 0/31 |
| 010 | C5 | 3 then stopped | not split | n/a | n/a | n/a |

Round 010 (C5) did not run: the attacker model's safeguards stopped the agent after 3 cases. The
maintainer decided to close the evaluation without C5, so criterion 3 is **not measured**.

## Test halves (one use, aggregates only)

| Class | n | Detected at high or critical | Recall | Wilson 95 % | Any finding |
|---|---:|---:|---:|---|---:|
| C1 | 19 | 11 | 57.9 % | 36.3–76.9 | 13 |
| C2 | 13 | 5 | 38.5 % | 17.7–64.5 | 6 |
| C3 | 16 | 3 | 18.8 % | 6.6–43.0 | 3 |
| C4 | 13 | 9 | 69.2 % | 42.4–87.3 | 10 |
| C1–C4 | 61 | 28 | 45.9 % | 34.0–58.3 | 32 |

The validity of the test cases was not judged (the judge never sees the test half), so these are
over all proposed cases. If some are invalid the true recall on valid cases is not known; the dev
validity rate was 57/60 (95 %).

## Against the preregistered thresholds

| # | Criterion | Threshold | Measured | Result |
|---|---|---|---|---|
| 1 | Recall C1–C4, fresh round | ≥95 %, lower bound ≥85 %, n ≥100, each class ≥85 % with n ≥20 | 45.9 % (34.0–58.3), n 61, classes 58 / 38 / 19 / 69 % | **Not met** |
| 2 | Evasion after mutations | ≤5 % | `bench/evasion/` does not exist in the repo | **Not measured** |
| 3 | Recall C5 | published; goal ≥50 %, n ≥60 | round did not run | **Not measured** |
| 4 | False positives on twins | ≤2 % with n ≥200 | 0/60 dev twins fire (0 %, upper bound about 6 %) | n too small; **not met** |
| 5 | Corpus: ≤2 unexplained per 100 repos, precision ≥70 % | | 33 failing, 11 per 100 repos, precision 9 % (3/33) | **Not met** |
| 6 | Robustness | mutation score ≥75 %, no crashes, no bypass by size, run time ≤ +15 % | mutation testing did not run in this environment; property tests pass; run time above +15 % on large prose scenarios | **Not met** |
| 7 | Honesty | every claim linked; claims test | claims test not written | **Not met** |

The grade does not rise. Nothing here is a pass.

## Limits

- One model family in every role; cases are not independent human attacks.
- The two C1–C4 rounds were run by one attacker model with one prompt each; its blind spots are
  shared with the judge.
- The orchestrator saw the attacker's full reports, test cases included (the report is the only
  channel). It did not see the test verdicts per case. Any patch between evaluations is written by
  the blind defender from the dev half only.
- Per-class numbers have wide intervals (n 13 to 19).
