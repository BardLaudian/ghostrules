# Preregistration — detection evaluation for 0.6.0

**Status: approved by the maintainer on 2026-11-25** (see the approval log). The final evaluation
(Phase 18) runs against this text. It changes only through a new dated entry at the end.

- Written: 2026-11-25
- Version under evaluation: the 0.6.0 release candidate, frozen at the start of Phase 18. Starting
  point: 0.5.1 plus the size-padding fix of Phase 11 (`bench/redteam/BASELINE.md`).
- Plan: `docs/improvement/PLAN-0.6-deteccion.md`. Taxonomy: `bench/redteam/taxonomy.toml`.
- Hash of the evaluation set: **not yet known**. It is computed and committed before the evaluation
  runs (Phase 18), and the set is used once.

## What is evaluated

Classes C1–C4 are scored against the thresholds. C5 (semantics) is measured and published, never
promised. The attacks of the final round come from AI red-team subagents of the same model family as
the defender and are labelled `ai-redteam` everywhere; they are not independent human cases.

## Definitions

- **Detected** (criteria 1, 2, 3): the oracle reports a finding at **high or critical** for the case,
  which is what makes `ghostrules scan` fail by default. A finding at medium or low is not a
  detection. The "any finding" figure is published next to it, but no threshold uses it.
- **Valid case**: the blind judge decodes the payload and `judge_check.py` confirms it matches the
  declared one. Only valid cases count towards `n`.
- **Unexplained finding** (criterion 5): a finding that fails the default check and that the
  labeller marks neither as a true positive nor as a documented benign context.

## Criteria and thresholds

| # | Criterion | Threshold | Measured by |
|---|---|---|---|
| 1 | Recall C1–C4 against a fresh red-team round on the frozen version | at least 95 %, lower bound of the 95 % Wilson interval at least 85 %, n at least 100 valid cases; and **each of C1, C2, C3, C4 at least 85 %** with at least 20 valid cases each | One round, one use of the test set |
| 2 | Evasion rate after mutations of C1–C4 cases | at most 5 % | `bench/evasion/` |
| 3 | Recall C5 | Published whatever it is; goal at least 50 % with n at least 60, marked advisory (low confidence) | Same fresh round |
| 4 | False positives on benign twins | point estimate at most 2 % with **n at least 200**; the upper bound of the 95 % interval is published | Twins written by the judge plus the false-positive suite |
| 5 | Findings that fail the default check on the 300-repo corpus | at most 2 unexplained per 100 repos after triage; precision of those findings at least 70 % with human labels, n at least 20 | `corpus/` and the label sheet |
| 6 | Robustness | Mutation score at least 75 % on `rules/`; fuzzing without crashes; no bypass by size; run time at most 15 % above 0.5.0 | Weekly CI, `bench/perf.py` |
| 7 | Honesty | Every README and THREAT_MODEL claim linked to a measurement; limits per class published; origin of cases declared | `docs/CLAIMS.md` and the claims test |

The grade of 9 requires criteria 1, 2, 4, 5, 6 and 7. Criterion 3 is reported either way.
If a criterion fails, the grade does not rise and the result is published as it came out.

## Procedure

1. Freeze the version (tag-less commit on a release branch); record its commit.
2. Generate the fresh round with new seeds; split `dev`/`test` by hash of the case id; the `test`
   set lives outside the repository and is read by nobody before the evaluation.
3. Judge decodes the files blind; `judge_check.py` compares with the declared payload.
4. Run the oracle once on `test`. Record every number, including those that fail a threshold.
5. Write the report with per-class limits and the origin label. Do not re-run.

## Known limits of the design

- Attacker, judge and defender share one model family and its blind spots.
- Case validity is judged by a model; a human reviews a sample of 20–30 per round.
- One person labels precision and explains corpus findings (no second labeller yet). The report
  says so next to every figure that depends on those labels.

## Changes after approval

None, except a new dated entry below that states what changed and why. Earlier text stays.

## Approval log

- **2026-11-25 — approved by the maintainer**, with these adjustments to the draft in the plan:
  "detected" means high or critical (the default check); criterion 1 adds a floor of 85 % for each
  of C1–C4 (at least 20 valid cases each); criterion 4 needs n at least 200 and publishes the upper
  bound of the interval; one person labels, declared in every report. The hash of the evaluation
  set is still to be added before Phase 18.

- **2026-11-25 — validity of C3/C4 cases (maintainer decision, before any round-002 data).** In round
  001 `judge_check.py` compared the judge's decoded text with a prose `declared_payload`, which
  mismeasured commands, config and credentials (the judge quotes them, the payload describes them).
  From round 002 each C3/C4 case also carries `declared_literal` (the text as an agent reads it), and
  validity for those classes is: the normalised literal appears in the decoded text, or the
  `difflib` ratio against it is at least 0.6. C1/C2 are unchanged. Not tuned on round-001 numbers;
  round 001 stays reported with the old metric.
