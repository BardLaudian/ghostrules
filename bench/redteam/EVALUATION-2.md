# Evaluation 2 of the 0.6.0 candidate (Phase 18)

Frozen version: `src/` at `4aaa674` (the blind defender's patch from the dev halves of rounds 008 and
009). **Look 2 of at most 4.** Rounds 011 and 012 (C1–C4, seeds 1811 and 1812, 60 cases each, new test
halves). Attacker: opus; no judge, no twins and no human review in this evaluation (cost); no
defender turn. Origin of all cases: `ai-redteam`.

## Test halves (one use, aggregates only)

| Class | n | Detected at high or critical | Recall | Wilson 95 % | Any finding |
|---|---:|---:|---:|---|---:|
| C1 | 11 | 7 | 63.6 % | 35.4–84.8 | 8 |
| C2 | 13 | 5 | 38.5 % | 17.7–64.5 | 7 |
| C3 | 17 | 1 | 5.9 % | 1.0–27.0 | 2 |
| C4 | 17 | 6 | 35.3 % | 17.3–58.7 | 8 |
| C1–C4 | 58 | 19 | 32.8 % | 22.1–45.6 | 25 |

Dev halves (for reference, not a measure): 011 detected 11/31, 012 detected 13/31.

## Against the preregistered thresholds

Criterion 1 (recall ≥95 %, lower bound ≥85 %, n ≥100, each class ≥85 %): **not met** (32.8 %,
n 58). Criteria 2, 3, 4: not measured or not met as in `EVALUATION-1.md` (no mutation harness, no C5
round, twins n below 200). Criteria 5, 6, 7: unchanged from evaluation 1, **not met**. The grade does
not rise.

## Reading, with its limits

- Evaluation 1 gave 45.9 % (28/61) on the version before the patch; evaluation 2 gives 32.8 %
  (19/58) on the patched version. The case sets differ (new attacker run, new seeds), so this is
  **not** a measure of the patch's effect and is not read as a regression either. What it shows is
  that closing the dev cases of two rounds did not raise recall on fresh cases: the next attacker
  finds other routes. C3 (reach through imports, references, hook and skill scripts, MCP files)
  stays near zero.
- The patch is not credited with any generalisation on this evidence. Per-class intervals are wide.
- Validity of the test cases was not judged; recall is over all proposed cases.
- One model family in every role; one person labels; the human review of the judge was waived.
