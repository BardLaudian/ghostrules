# Round 009 — ledger (Phase 18, evaluation 1, round 2 of 3)

Origin of all cases: `ai-redteam` (same model family as the defender; not independent human testers).

| Item | Value |
|---|---|
| Scanner | frozen commit `e198677` (`src/` untouched) |
| Classes | C1, C2, C3, C4 |
| Models | attacker: opus; judge: sonnet; defender: none in the evaluation |
| Seed | 1802 |
| Prompts | attacker prompt condensed by hand (as round 008); judge prompt = `make_prompt.py judge` with tag and variation-selector runs shown as code points |
| Cost | not measured |
| Feedback turns | none |

| Step | Count |
|---|---|
| Proposed by the attacker | 60 (C1 15, C2 15, C3 15, C4 15) |
| Split dev / test | 31 / 29 |
| Judge valid by `judge_check.py` (dev) | 28/31 |
| Dev cases detected at high or critical | 13/31 |
| Benign twins that fire at high or critical (dev) | 0/31 |
| Human review of the judge | not done (waived by the maintainer) |

The full case file lives outside the repository; the test half is not measured yet.
