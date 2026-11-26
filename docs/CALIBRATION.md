# Calibration

Status: labels in, decisions written, **none of the decisions is implemented yet**. Source:
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

All three are **proposals recorded, not applied**. Each needs new synthetic cases (a true positive
and a false positive) written first, not derived from the rows of the sheet. The plan forbids
retouching patterns by reading the labelled cases.

### GR015, encoded payload (0 of 88, 33 repositories)

73 of the 88 findings come from the path that reads a line as an instruction "hidden in reversed,
escaped or character-referenced text"; 2 come from "instruction split into fragments that the file
asks to join and run"; 13 did not reproduce on rescan. The lines are ordinary documentation, and many
of them end in "on". The assistant's hypothesis, not verified: reversed, "on" becomes "no", which
matches a negation, so a plain English line looks like a reversed instruction.

Decision: the reversed and fragments paths stop failing the default check (medium) and need an
extra signal to be high: the reversed text must read as an addressed instruction with an action and
an object, not only contain a common word. The base64 and hex path is not part of this decision: no
row of the sheet came from it.

### GR017, secret in an instruction file (0 of 24, 3 repositories)

All 24 are database connection URLs in documentation, with a local or placeholder host (`localhost`,
`db`, `HOST:PORT`) and an example user. The password is masked in the sheet, so the reviewer could not
see whether it was a realistic value.

Decision: a connection URL whose host is local or a placeholder is not critical. It stays reported
as medium. A URL with a public host and a realistic password stays critical. Tokens of a known
vendor format (ghp_, sk-ant-, AKIA…) are not part of this decision: no row came from them.

### GR006, mixed-script homoglyph word (0 of 21, 10 repositories)

All 21 findings are ASCII lines, numbers or emoji, flagged because folding digits to letters (1→l,
0→o, 5→s) makes the line "read as an instruction". No look-alike character from another alphabet
was present in the rows that reproduced.

Decision: the digit-only (leet) folding must not reach high by itself. It needs a non-ASCII look-alike
in the same word, or it is reported low.

### Not changed

GR110, GR012, GR011, GR014 and GR107 have too few rows to decide. They stay as they are. Four of the
13 GR110 rows are `dubious` (a secret sent to a destination from an environment variable or built at
run time): the rule cannot tell a legitimate API from a hostile one there, and that is documented as a
limit of the rule. GR107 had 3 true positives out of 4: broad shell permissions (`Bash`, `rm:*`,
`curl:*`) committed in `.claude/settings.local.json`.

## What this does to the plan's criterion 5

Criterion 5: at most 2 unexplained findings per 100 repos that fail the default check after triage,
and precision of those findings at least 70 % with n ≥ 20 labelled.

| | Findings failing the check | Per 100 repos | Precision |
|---|---:|---:|---|
| Before GR114 cap (measured) | 1743 | 581 | not labelled |
| After GR114 cap (measured) | 162 | 54 | 1.9 % (3 of 162) |
| If the three decisions were applied (projection) | 29 | about 10 | not measured |

**Criterion 5 is not met.** The projection is arithmetic on the same labels (162 − 88 − 24 − 21 = 29
rows would no longer fail). It is not a measurement: it has to be re-run on the corpus after the
fixes, and its precision measured on a fresh labelling. The 29 remaining rows include the 3 true
positives and the 5 dubious ones.

## Confidence

Each finding has a `confidence` and an `effective_severity` (see `docs/USAGE.md`). Today:

| Confidence | Meaning | Where it is set |
|---|---|---|
| `high` | A fact about the text: invisible tag characters, bidi controls, a token of a known format | GR001, GR002, GR017 |
| `medium` | Not measured. The default | every other rule, GR114 with a combination of signals |
| `low` | A lone weak signal | GR114 with one signal |

GR017 is marked `high` because a token of a known format is a fact about the text. The sheet shows
that its connection-URL case is not that, so the decision above should also set the confidence of that
case to `medium`.

## Limits

- One labeller, and labels by group. A second reviewer on a sample of 30 rows would give an agreement
  figure; it was not done.
- The corpus is public repositories with agent files that were popular on 2026-10-28. It is not a
  sample of private code.
- No GR114 precision exists. Its 4658 medium findings are not labelled.
- The benign twins (`tests/benign_twins.py`, 118) were written by a model and did not fire any rule
  at high. Ten raise GR114 at medium.
