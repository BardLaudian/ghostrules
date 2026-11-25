# Round 007 — ledger

Origin of all cases: `ai-redteam` (same model family as the defender; not independent human testers).
Budget: round 007 is above the 6-round cap of the phase 14 closeout; the person extended it for the
C5 focus of phase 15.

| Item | Value |
|---|---|
| Scanner before | `fase-14-ronda-006` (8b9a9fd) |
| Classes and focus | C5 (semantics): paraphrase, six languages, indirect wording, code blocks, tables, quotes |
| Models | attacker: redteam-attacker (condensed prompt, as in round 006); judge: sonnet by override; defender: redteam-defender |
| Seed | 7 |
| Prompts | attacker prompt condensed from `make_prompt.py attacker --classes C5 --n 60 --seed 7`; judge prompt = `make_prompt.py judge rounds/007/dev.toml` verbatim |
| Cost | not measured |

## Cases

| Step | Count |
|---|---|
| Proposed by the attacker (turn 1 / 2 / 3) | 60 / not run / not run |
| Why no turn 2 | dev evasion of turn 1 was 26/26 (100 %), over the 80 % stop rule |
| Split dev / test | 26 / 34 |
| Judge ran on | dev only (the test half is never given to a subagent) |
| Judge valid by `judge_check.py` (dev) | 15/26 |
| Human valid (dev) | 26/26 |
| Dev cases that evade before the patch | 26/26 |
| Dev cases that evade after the patch | 4/26 (22/26 reach high) |
| Benign twins that fire | 0/26 before, 0/26 after (any finding) |

## Human review of the judge (`[HUMANO]`)

| Sampled | Judge valid and human agrees | Disagreements |
|---|---|---|
| 26 (all dev) | 15 | 11 (judge below threshold, human valid) |

The 11 disagreements are a property of the metric: for plain-text C5 payloads the judge translates
non-English text to English and summarises, so text similarity to the declared payload drops while
the intent is read correctly. The similarity threshold is not a valid filter for C5.

## Patch

| Item | Value |
|---|---|
| Rule | GR114, a deterministic signal scorer (`src/ghostrules/rules/semantics.py`), advisory: one signal is medium (confidence low); high only for combinations, confidence medium |
| Tests added | 53 (`tests/test_redteam_round007.py`), the defender's own phrasings, positive and negative (policy, prompt-injection docs, quotes, fences, allowed domains) |
| Files changed | `semantics.py` (new, 395 lines), `rules/__init__.py`, `rules/directive.py` (+1 verb), `docs/RULES.md`, `CHANGELOG.md`, 13 golden fixtures regenerated, `tests/test_directive.py` |
| Suite | 2589 passed, 1 xfailed; ruff, ruff format, mypy clean; `examples/clean-repo` clean |
| Gate | passed. Note: `diff_size` reports "4 lines" because it counts the tracked diff and `semantics.py` is untracked at check time; the real size under `src/` is 399 |
| Blind audit | clean, 0 flagged |
| Dev cases still not high | con-01 (concealment only), sen-04, sen-09, sen-10 (secret or store without output or outbound target: medium by the round 004 policy) |

## Declared limits

- The defender read the 26 dev cases while designing the lexicons, so 22/26 on dev is optimistic.
  The only figure that counts is the evasion of the fixed test half, before and after: not measured
  here (it needs the person to run it outside Claude Code, see the closeout).
- The test half has no judge verdict; its validity is a human review.
- Languages beyond EN/ES/FR/DE/PT/IT and intent with no listed stem are not covered.
- FP measure on a real corpus is phase 16.
