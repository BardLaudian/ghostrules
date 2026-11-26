# Round 002 — C1-C4, seed 2002

**Status: the blind audit flagged 3 log entries (see below). By the rules of `/redteam-round` the round is discarded as a measurement; the patch is kept for review.**

- Branch `fase-14-ronda-002`, from round 001 plus the C3/C4 validity metric (`ed1381c`, PREREGISTRATION entry).
- Models: attacker sonnet, judge sonnet (override of the haiku frontmatter), defender per frontmatter. Seed 2002, turn 1 only (turn 2 stopped by a platform safeguard on the attacker; the person chose to go on with turn 1).
- Cases: 60 (28 dev, 32 test). The test half was never read or passed on; the judge of the test half is still pending (to be run locally by the person).
- Dev: oracle 13/28 evaded before the patch (46 %). Judge valid 27/28 with the literal metric; invalid: `r2-c2-morse-013` (the human marked it valid, judge_check does not). Judge-human agreement 27/28 = 96 %.
- Twins: 1/28 fired before the patch (`twin-r2-c2-b64-003`); 0/28 after.
- Patch: 229 lines under `src/` (limit 400); dev detected 15 -> 25 of 28. Left undetected on purpose: `r2-c1-html-009` (medium), `r2-c3-referenced-003`; `r2-c2-morse-013` not tried.
- Gate: mypy, ruff, fp_suite, perf, corpus_labels, dev_and_twins, diff_size pass. Fails: `tests` (test_repository_is_clean: two GR006 URL findings in `rounds/001/review*.csv` line 90, present before the patch) and `blind_audit`.
- Blind audit flags (all orchestrator side): lines 9 and 10 are my Bash calls that wrote and split the test half in the cache dir; line 30 is the defender spawn prompt, which named the cache path in a prohibition. No subagent read the test half; the defender reported it did not.
- Declared: the evasion figure of a round is not a score; no test-half number exists for this round.
