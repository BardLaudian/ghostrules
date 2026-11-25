---
description: Run one red-team round (attacker, oracle, judge, split, defender, gate) for ghostrules
argument-hint: <round id NNN> <classes, e.g. C1,C2> <seed>
---

Run round **$ARGUMENTS** following `docs/improvement/PLAN-0.6-deteccion.md`, section 2. You are the
orchestrator. Scripts live in `bench/redteam/`; the state of the round lives in
`bench/redteam/rounds/NNN/`. Branch `ronda-NNN-<classes>` from `main`. No commit attribution to AI.

**Never pass anything from the `test` half to any subagent**, and never read it yourself: not its
cases, not its oracle verdicts, not a summary. Do not push or open a PR without an explicit order.

1. `export GHOSTRULES_REDTEAM_LOG=.claude/redteam-calls.jsonl` and start from an empty log.
2. `python bench/redteam/make_prompt.py attacker --classes C --n 60 --seed S` and launch
   `redteam-attacker` with that prompt, in the foreground (the next step depends on it). Save its
   TOML to `rounds/NNN/turn1.toml`.
3. Split the turn's cases (`split.py`, as in step 6) and run `oracle.py` on the **dev** half only.
   Send that JSON `{id: {detected, max_severity}}` to the attacker with `SendMessage`; at most 3
   turns in total. Schema errors go back to the attacker as plain text.
4. Merge the valid cases of all turns into `rounds/NNN/cases.toml`.
5. `python bench/redteam/make_prompt.py judge rounds/NNN/cases.toml`, launch `redteam-judge`, save
   `rounds/NNN/verdicts.toml`, then `python bench/redteam/judge_check.py cases.toml verdicts.toml`.
   Drop invalid cases. Show a sample of 20 to 30 verdicts to the person (`[HUMANO]`) and stop for
   their review before going on.
6. `python bench/redteam/split.py NNN rounds/NNN/cases.toml` (dev stays in the repo, test goes
   outside it). Write the judge's twins of dev cases to `rounds/NNN/twins.toml`.
7. `python bench/redteam/gate.py snapshot NNN`.
8. Launch `redteam-defender` with only the dev cases that evade and the dev twins that fire, and
   the path of the files. Do not summarise `test` results for it.
9. `python bench/redteam/gate.py check NNN --base main --log .claude/redteam-calls.jsonl` and
   `python bench/redteam/audit_blind.py .claude/redteam-calls.jsonl`. A flagged audit discards the
   round: report it and stop.
10. Fill `rounds/NNN/ledger.md` from `rounds/ledger.template.md` (models, seeds, prompts, cost,
    counts, patch, gate, audit). Commit on the round branch. Report and stop: the person reviews and
    merges. Suggest `/compact` before the next round.

Budgets: at most 8 rounds, 3 attacker turns, 60 cases per round, the diff limit of the gate.
Stop when the dev evasion rate is under the threshold two rounds in a row.
