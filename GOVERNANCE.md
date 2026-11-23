# Governance

`ghostrules` is a small project with one maintainer. This file says how decisions are made so that
they are predictable, and what changes if more people join.

## Who decides

The **maintainer** (currently Pablo Seoane Temprano) merges, releases and has the final word. Every
change goes through a pull request and the required checks (`ci-ok`); nothing is pushed directly to
`main`. An AI coding assistant is used for code, tests and documentation, and the maintainer
reviews and merges everything ([CONTRIBUTING.md](CONTRIBUTING.md#how-this-project-is-built-ai-assistance)).
Contributors can propose, review and comment; reviews from anyone are welcome and recorded in the
pull request.

Decisions that need judgement (a rule's severity, a trade-off between recall and noise) are written
in [docs/DECISIONS.md](docs/DECISIONS.md) with the reason, so they can be questioned later.

## Adding a rule

A new rule is accepted when **all** hold:

1. It is described in [docs/RULES.md](docs/RULES.md): ID, severity, logic, true and false positive
   examples.
2. It has at least one **positive and one negative (false positive) test**, and the defanged
   fixtures follow [CONTRIBUTING.md](CONTRIBUTING.md).
3. It names a real technique with a public reference or a reproducible case, not a hunch.
4. It has been run on `corpus/` and the 100-repository precision set, and the new findings are
   listed in the pull request. A rule that adds noise on clean repositories starts at a lower
   severity.
5. It does not make the existing bench or golden outputs worse without an explanation. The bench
   cases are not tuned on their own misses: a fix for a miss adds new, varied cases first.

A rule ships in a minor version and is listed under **Added**.

## Changing or retiring a rule

- **Severity or pattern change:** a **Changed** entry; see [docs/VERSIONING.md](docs/VERSIONING.md).
- **Too many false positives.** Any issue that uses the "False positive" template counts. A rule is
  reviewed when it has reached either of these:
  - 3 independent reports of false positives on real repositories, or
  - a measured precision under 50 % on the labelled set with at least 10 findings.

  The review ends in one of: narrow the pattern, lower the default severity, make it opt-in, or
  **retire** it. The maintainer decides within a release cycle and writes the reason in DECISIONS.md.
- **Retiring** a rule: it is deprecated for two minor releases, then removed; its ID stays reserved
  and marked retired in the index.
- An urgent false positive that blocks users may be fixed in a patch release by lowering severity.

## Security reports

Privately, through [SECURITY.md](SECURITY.md). Fixes are released as soon as ready, and reporters are
credited unless they prefer not to be.

## Releases

Tagged `vX.Y.Z` from `main` by the maintainer, published to PyPI with Trusted Publishing. A tag is
never moved after a release, except the moving `v0` major tag documented in the README.

## Becoming a maintainer

Someone who has contributed several accepted changes and reviews can be invited. Merge rights come
with the branch protection settings in [docs/GITHUB_SETTINGS.md](docs/GITHUB_SETTINGS.md).
If the maintainer is unreachable for 6 months, an active contributor may ask for a fork to be
linked from the README.

## Conduct

[CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md) applies in issues, pull requests and discussions.
