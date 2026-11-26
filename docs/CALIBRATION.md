# Calibration

Status: labels in, decisions written and implemented (commit `0b03adb`); the re-measurement on
the corpus is in the section "After the decisions". Source:
`bench/labels-0.6.csv` (162 findings that fail the default check, high or critical), ghostrules 0.5.1
on the 300-repo regression corpus, 2026-11-26.

## How the labels were made (read this before the numbers)

- **One person labelled** (the maintainer). Most labels were given by group, after seeing examples,
  not row by row. The group note is in the `label_note` column. In GR015, GR017 and GR006 the grouping
  was proposed by the assistant from a rescan of the lines and confirmed by the person.
- Labels: `tp` (the finding is a real risk or a real hostile instruction), `fp` (it is not),
  `dubious` (cannot tell from the text, for example a secret sent to a URL taken from the
  environment).
- **The sheet is the whole population of findings that fail the check**, except GR114, which is capped
  at medium and is not in it. There is no sampling for the rules below, so there is no scaling.
- **The rows are not independent.** The same line is copied across languages and directories of the
  same repository (24 GR017 rows come from 3 repositories). Read the repository count next to `n`.
- For 22 rows (13 of GR015, 3 of GR006, and the 6 of GR012, whose snippet does not show the match) the
  exact span that fired was not visible; the first 16 did not reproduce when the file was rescanned
  alone. The label rests on the context. It is in the notes.
- Precision here is `tp / n` with `dubious` counted as not true. The interval is Wilson, 95 %.

## Precision per rule

| Rule | n | Repos | tp | fp | dubious | Precision (95 % CI) | Enough n? | Decision |
|---|---:|---:|---:|---:|---:|---|---|---|
| GR015 | 88 | 33 | 0 | 88 | 0 | 0 % (0–4.2) | yes | Narrow the path that fires (see below) |
| GR017 | 24 | 3 | 0 | 24 | 0 | 0 % (0–13.8) | yes, but 3 repos | Narrow the connection-URL case |
| GR006 | 21 | 10 | 0 | 21 | 0 | 0 % (0–15.5) | yes | Narrow the leet-folding path |
| GR110 | 13 | 9 | 0 | 9 | 4 | 0 % (0–22.8), 31 % if dubious are tp | no | None; collect more |
| GR012 | 6 | 6 | 0 | 6 | 0 | 0 % (0–39) | no | None; collect more |
| GR107 | 4 | 2 | 3 | 0 | 1 | 75 % (30–95) | no | None; keep high |
| GR011 | 3 | 2 | 0 | 3 | 0 | 0 % (0–56) | no | None; collect more |
| GR014 | 3 | 3 | 0 | 3 | 0 | 0 % (0–56) | no | None; collect more |
| All | 162 | | 3 | 149 | 5 | 1.9 % (0.6–5.3) | | |

The plan's rule: precision under 20 % **with enough n** lowers severity, requires extra signals or
turns the rule off by default, with reasoning. "Enough n" is taken here as n ≥ 20 and an upper bound
of the interval under 20 %. GR110 (upper bound 22.8 %) and the rest fail that test, so they are only
documented.

## Decisions

All three are implemented. Each was written test-first with synthetic cases (a true positive and a
false positive) in `tests/test_calibration_decisions.py`, not derived from the rows of the sheet. The
plan forbids retouching patterns by reading the labelled cases: the mechanisms were found from the
rule code (a file-wide cue, a local host, digits folded to letters), not from the lines.
Deviations from the text below are marked "As implemented".

### GR015, encoded payload (0 of 88, 33 repositories)

73 of the 88 findings come from the path that reads a line as an instruction "hidden in reversed,
escaped or character-referenced text"; 2 come from "instruction split into fragments that the file
asks to join and run"; 13 did not reproduce on rescan. The lines are ordinary documentation, and many
of them end in "on". The cause, found in the rule code: the reversed-line path turns on when the
*file* contains the word "backward", "backwards" or "reversed" anywhere (for example "backward
compatibility"), and from then on every line of the file is reversed and tested as an instruction.
A reversed "…on" starts with "no", which the instruction test reads as a verb-led clause.

Decision: the reversed and fragments paths stop failing the default check (medium) and need an
extra signal to be high.

As implemented: a reversed line is high if its reversed reading is addressed to the agent (the same
test as a decoded directive) or one of the two lines before it asks to read it reversed and obey it.
Fragments are high if the joined text reads as a directive to the agent, matches an injection pattern
or contains an external URL. Otherwise both are medium. The base64 and hex path is not part of this decision: no
row of the sheet came from it.

### GR017, secret in an instruction file (0 of 24, 3 repositories)

All 24 are database connection URLs in documentation, with a local or placeholder host (`localhost`,
`db`, `HOST:PORT`) and an example user. The password is masked in the sheet, so the reviewer could not
see whether it was a realistic value.

Decision: a connection URL whose host is local or a placeholder is not critical. It stays reported
as medium, confidence medium. "Local or placeholder" is implemented as: `localhost`, `127.x`, `::1`,
`0.0.0.0`, a host with no dot (a compose or cluster service name such as `db`), `*.local`,
`*.internal`, `*.lan`, and names such as `HOST` or `your-host…`. A URL with a public host and a realistic password stays critical. Tokens of a known
vendor format (ghp_, sk-ant-, AKIA…) are not part of this decision: no row came from them.

### GR006, mixed-script homoglyph word (0 of 21, 10 repositories)

All 21 findings are ASCII lines, numbers or emoji, flagged because folding digits to letters (1→l,
0→o, 5→s) makes the line "read as an instruction". No look-alike character from another alphabet
was present in the rows that reproduced.

Decision: the digit-only (leet) folding must not reach high by itself. It needs a non-ASCII look-alike
in the same word, or it is reported low.

As implemented, with one deviation from that text: a word counts as leet only if it has a letter of
its own (so numbers never do); leet-only lines are low; and a leet-only line is still high if its
plain reading matches a known injection pattern (`1gn0r3 4ll pr3v10us…`). Without that exception the
leet form of a known injection would have lost its high severity. The test of round 002 that asserted
a `5k1p wr1t1ng t35t5…` line was high now asserts it is not.

### Not changed

GR110, GR012, GR011, GR014 and GR107 have too few rows to decide. They stay as they are. Four of the
13 GR110 rows are `dubious` (a secret sent to a destination from an environment variable or built at
run time): the rule cannot tell a legitimate API from a hostile one there, and that is documented as a
limit of the rule. GR107 had 3 true positives out of 4: broad shell permissions (`Bash`, `rm:*`,
`curl:*`) committed in `.claude/settings.local.json`.

## After the decisions (measured)

Same corpus, same 300 repositories, run on 2026-11-26 with the commit that implements the three
decisions (`0b03adb`).

| | Findings failing the check | Repos | Per 100 repos |
|---|---:|---:|---:|
| Before GR114 cap | 1743 | 172 | 581 |
| After GR114 cap | 162 | 53 | 54 |
| After the three decisions (measured) | 33 | 24 | 11 |

The projection in the earlier version of this file said 29. It was 33: four GR006 findings still fail
the check. They are labelled `fp` and have causes other than the leet folding that was fixed (the
decision covered the digit-only path; these four reproduce on other characters, and were not
examined further so as not to tune against the sheet).

Every one of the 33 is a row of the labelled sheet (no new, unlabelled finding at high or critical):

| Rule | Failing now | tp | fp | dubious |
|---|---:|---:|---:|---:|
| GR110 | 13 | 0 | 9 | 4 |
| GR012 | 6 | 0 | 6 | 0 |
| GR107 | 4 | 3 | 0 | 1 |
| GR006 | 4 | 0 | 4 | 0 |
| GR011 | 3 | 0 | 3 | 0 |
| GR014 | 3 | 0 | 3 | 0 |
| GR015, GR017 | 0 | | | |
| All | 33 | 3 | 25 | 5 |

Precision of what still fails the check: 3 of 33 = 9 % (95 % CI 3–24 %). **Criterion 5 is still not
met** (≥70 % precision, ≤2 unexplained per 100 repos; today 11 per 100 repos). The measurement is
circular in one way: the same labels motivated the changes and measure them. The gain from the three
decisions is real in count (162 → 33) but proves nothing about precision on unseen repositories. The
plain check that would: relabel a fresh corpus run.

Side effect, measured: findings at medium rose to 4798 (from 4683), because findings that fail the
check no longer do. They are not labelled.

## What this does to the plan's criterion 5

Criterion 5: at most 2 unexplained findings per 100 repos that fail the default check after triage,
and precision of those findings at least 70 % with n ≥ 20 labelled.

| | Findings failing the check | Per 100 repos | Precision |
|---|---:|---:|---|
| Before GR114 cap (measured) | 1743 | 581 | not labelled |
| After GR114 cap (measured) | 162 | 54 | 1.9 % (3 of 162) |
| After the three decisions (measured, see above) | 33 | 11 | 9 % (3 of 33) |

**Criterion 5 is not met.** The 33 remaining rows include the 3 true positives and the 5 dubious
ones.

## Confidence

Each finding has a `confidence` and an `effective_severity` (see `docs/USAGE.md`). Today:

| Confidence | Meaning | Where it is set |
|---|---|---|
| `high` | A fact about the text: invisible tag characters, bidi controls, a token of a known format | GR001, GR002, GR017 |
| `medium` | Not measured. The default | every other rule, GR114 with a combination of signals |
| `low` | A lone weak signal | GR114 with one signal |

GR017 is marked `high` because a token of a known format is a fact about the text. Its
connection-URL case with a local or placeholder host now has confidence `medium`. GR006's leet-only
case has confidence `low`.

## Limits

- One labeller, and labels by group. A second reviewer on a sample of 30 rows would give an agreement
  figure; it was not done.
- The corpus is public repositories with agent files that were popular on 2026-10-28. It is not a
  sample of private code.
- No GR114 precision exists. Its 4658 medium findings are not labelled.
- The benign twins (`tests/benign_twins.py`, 118) were written by a model and did not fire any rule
  at high. Ten raise GR114 at medium.
