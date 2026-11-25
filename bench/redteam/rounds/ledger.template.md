# Round NNN — ledger

Copy to `bench/redteam/rounds/NNN/ledger.md` and fill it in at the end of the round. Origin of all
cases: `ai-redteam` (same model family as the defender; not independent human testers).

| Item | Value |
|---|---|
| Date / commit of the scanner | |
| Classes and focus | |
| Attacker model / Judge model / Defender model | |
| Seeds | |
| Prompts (file or hash) | |
| Cost (tokens or plan usage), per role | |

## Cases

| Step | Count |
|---|---|
| Proposed by the attacker (turns 1 / 2 / 3) | |
| Valid after the judge (similarity ≥ threshold) | |
| Of those, split dev / test | |
| Dev cases that evade (detected = false) | |
| Benign twins that fire (false positives) | |

## Human review of the judge (`[HUMANO]`, 20–30 cases)

| Sampled | Judge valid and human agrees | Disagreements |
|---|---|---|
| | | |

## Patch

| Item | Value |
|---|---|
| Tests added | |
| Files changed under `src/` / lines | |
| Generalisation argument (summary) | |
| Gate result (JSON attached) | |
| Blind audit (`audit_blind.py`) | clean / flagged → round discarded |

## Declared limits

- Attacker, judge and defender share a model family and its blind spots.
- Test cases are used once, against a frozen version (Phase 18); nothing from them is reported here.
