# AI assistance and commit attribution — decision pending

**Status: decided 2026-11-23 — option A + B (history kept; use declared in general; no trailer on new commits).** The text is in `CONTRIBUTING.md` and the README. Option C was rejected.

## Facts (measured, `git log` on `main`, 2026-11-23)

- 104 commits; 80 carry a `Co-Authored-By: Claude …` trailer.
- `CLAUDE.md` (project memory for Claude Code) is committed.
- The labels of the held-out precision set were given by an assistant, not by a person
  ([bench/README.md](../bench/README.md)); see [bench/labels-review.csv](../bench/labels-review.csv).
- 7 release tags exist; rewriting history would change the commit that each one points to.

## Options

| | Option | Effect | Cost and risk |
|---|---|---|---|
| A | **Keep the history, declare the AI use** (recommended to evaluate first) | A short "How this project is built" note in `CONTRIBUTING.md` and the README: assistant used for code, tests and docs; a person decides what merges; labels and numbers that no human has reviewed are marked as such. | None to history. Honest and cheap. Visible trailers stay. |
| B | Keep the history, add a policy for new commits | A written rule in `CONTRIBUTING.md` (trailer or not, and who is responsible). | None to history. Needs enforcing in review. |
| C | Rewrite history to remove the trailers | `git filter-repo` / rebase of 80 commits. | **Destructive.** Needs a force-push; every commit hash changes; the 7 tags and the releases and PyPI attestations that cite the old commits stop matching; forks and open clones diverge; it also hides provenance, which cuts against what this project asks of others. Not recommended. |

## What the agent will not do

It does not rewrite history, force-push or move tags. If option C is chosen, take a full backup
(`git clone --mirror`) first and do it by hand.

## Resolution

Recorded in `docs/DECISIONS.md`; the wording is in `CONTRIBUTING.md` (section "How this project is built") and in the README's last section.
