# Phase 14 closeout — rounds C1–C4 (rounds 001–006)

Status on 2026-11-25. Source: `bench/redteam/rounds/NNN/ledger.md`. Origin of all cases: `ai-redteam`
(one model family, not independent human testers).

**Stop reason:** the 6-round cap was reached. The preregistered stop rule (dev evasion under the
threshold two rounds in a row) could not be applied: the threshold is still undefined.

## 1. Rounds

Dev evasion is measured on the dev cases the defender saw. It is **not a score**. No round has a
test-half number: the test halves of rounds 001–006 are unjudged.

| Round | PR | Cases (dev/test) | Judge valid (dev) | Human agreement | Dev evasion before → after | Twins fired | Patch lines (limit 400) | Blind audit |
|---|---|---|---|---|---|---|---|---|
| 001 | #33 | 97 (44/53), 2 turns | 32/44 | 20/25 = 80 % (pass 1, below 85 %) | 24/32 (75 %), 9/11 (82 %) | not run | none (no defender) | n/a |
| 002 | #34 | 60 (28/32) | 27/28 | 27/28 = 96 % | 13/28 (46 %) → 3/28 | 1 → 0 | 229 | **3 flags: discarded as a measurement** |
| 003 | #35 | 60 (34/26) | 33/34 | 34/34 = 100 % | 18/33 (55 %) → 5/33 | 1 → 0 | 274 | clean |
| 004 | #37 | 60 (27/33) | 25/27 | 25/27 = 93 % | 16/25 (64 %) → 6/25 (24 %) | 0 → 0 | 257 | clean |
| 005 | #38 | 60 (31/29) | 58/60 | 31/31 = 100 % | 19/31 (61 %) → 11/31 (35 %) | 0 → 0 | 307 | clean script, **one process incident** |
| 006 | #36 | 59 (28/31); judge on dev only | 24/28 | 24/24 = 100 % | 14/24 (58 %) → 10/24 (42 %) | 0 → 0 | 72 | clean |

Round 001 closed without a patch: the validity metric, not the scanner, caused the low agreement;
the C3/C4 "payload literal" metric was preregistered in round 002.

Patch line counts are measured against the previous round's branch (stacked), not `main`.

## 2. Limits declared per class (dev cases still undetected)

- **C1/C2 (hidden and encoded text):** acrostics are not decoded; a plain sentence without any
  escape is not an escape case; a dependency suggestion matches no lexicon; nested base64 in a
  comment decodes but, with no agent address, is medium by policy.
- **C3 (structure and reach):** the reach works (imports, referenced files, conditional rules,
  nested skills), but when the payload is plain English or a plain GET that no rule grades, nothing
  fires. Local script runs are not graded. An in-repo symlink alias gives no finding by design.
  Scanner-evasion through the scanner's own config (`exclude`, `disable`, `allow_domains`) is honest
  limit: the config is a pinned contract that the scanner reads.
- **C4 (configuration):** unpinned `npx` is the norm (GR102 medium by documentation); GR108 is
  medium by documentation; EXAMPLE placeholders are ignored by policy (a real value in the same
  position is critical); a fake token shorter than the real format is not reported; `gemini-cli` is
  not a default agent, so `GEMINI.md` imports are not followed by default.
- **Not testable here:** C5 (semantic) was out of scope for this phase.

## 3. False-positive surface

0 twins fired after every patch, but the twins are written by the same judge that validated the
cases. Treat that as weak evidence. Published severity changes and lexicon widening are listed in
the ledgers of rounds 003–006 and in `docs/RULES.md` (GR005, GR011, GR013–GR017, GR101, GR104,
GR109, GR110). A hidden comment such as "Skip the telemetry prompt on CI" now goes high (GR016).

## 4. Process incidents and deviations

- Round 002: the blind audit flagged 3 entries, all orchestrator side (writing the test half,
  and one prompt that named the cache path in a prohibition). Round discarded as a measurement.
- Round 005: the raw attacker file with the test half was left in the round folder while the defender
  ran; one test-half case text was exposed through a quoted test failure. Removed before commit.
- Round 006: the judge was refused by a platform classifier on all 59 cases; by decision of the
  person it ran on the dev half only. The attacker received a condensed prompt, not the literal
  `make_prompt.py` output.
- Attacker turn 2 was stopped by a platform safeguard in rounds 002–003 and not used afterwards.
- Cases above 60 were cut to the first 15 per class in file order (declared).

## 5. Decisions for the person

| # | Decision | Recommendation |
|---|---|---|
| 1 | Define the dev-evasion threshold (today undefined, so the two-in-a-row counter is 0) | Do not use dev evasion as a stop criterion; use the fixed test-half evasion once judged, and the fresh round of phase 18 for criterion 1 |
| 2 | Judge the test halves of rounds 001–006 locally (see `bench/redteam/README.md`) | Yes, before phase 15; report totals only |
| 3 | Does round 005 count as a measurement after its incident? | Exclude it from any test-half before/after figure; keep its patch |
| 4 | Agent files: `tools: []` vs `tools: SubagentHandback`, and the judge's model in the frontmatter (haiku was refused; sonnet by override) | Set the judge to sonnet in the frontmatter; keep the `tools` change only after the blindness test passes |
| 5 | Make `gemini-cli` a default agent | Yes if `GEMINI.md` is in the supported targets of SPEC; it is a SPEC change |
| 6 | Accept the published severity changes and the wider lexicon | Accept with FP measurement in phase 16 (corpus and human labels) before 0.6.0 |
| 7 | `.ghostrules.toml` excludes for `verdicts.toml` and `review*.csv` | Accept (the decoded text quotes lookalike hosts on purpose) |
| 8 | The skill text says `--base main`; practice was stacked bases | Change the skill text to say the previous round's branch |
| 9 | Merge order | #33 → #34 → #35 → #37 → #38 → #36 |

## 6. Next

Phase 15 (semantic layer, C5) starts after decisions 1–3 are made.
