# Calibration

Status: **pending human labels.** The per-rule precision table needs `bench/labels-0.6.csv` filled in
by a person (`human_label`: `tp`, `fp` or `dubious`). Nothing below is a measured precision.

## What the sheet holds

The findings that fail the default check (high or critical) on the 300-repo regression corpus, with
ghostrules 0.5.1 on 2026-11-26: 162 findings in 53 repositories (24 critical, 138 high). GR114 is not
in the sheet because it is capped at medium (see the ADR "GR114 capped at medium"). Before that cap,
the same run gave 1743 findings in 172 repositories, 1581 of them GR114.

| Rule | Findings that fail the check |
|---|---:|
| GR015 | 88 |
| GR017 | 24 |
| GR006 | 21 |
| GR110 | 13 |
| GR012 | 6 |
| GR107 | 4 |
| GR014 | 3 |
| GR011 | 3 |

## Confidence

Each finding has a `confidence` and an `effective_severity` (see `docs/USAGE.md`). Today:

| Confidence | Meaning | Where it is set |
|---|---|---|
| `high` | A fact about the text: invisible tag characters, bidi controls, a token of a known format | GR001, GR002, GR017 |
| `medium` | Not measured yet. The default | every other rule, GR114 with a combination of signals |
| `low` | A lone weak signal | GR114 with one signal |

## Per-rule table

Pending. For each rule: precision, n, decision. A rule with precision under 20 % and enough
labelled cases gets a lower severity, extra signals or is off by default, with the reasoning here.
The decision is taken from the labels, not by reading individual cases to retouch patterns.
