# GitHub settings the repository cannot enforce by itself

These are configured in the GitHub UI (or with `gh api`) by someone with admin rights. They are
not applied by this repository and are **pending** until a maintainer does them.

Status as of 2026-11-23, checked with read-only `gh api` calls where the API allows it.

| Setting | Where | Status |
|---|---|---|
| Ruleset `protect-main`: pull request required, checks `test`, `typecheck`, `audit` and `self-scan` required, branch up to date, no force push, no deletion, no bypass | Settings → Rules | **Done** |
| Required approving review | same | **Not applicable**: a single maintainer cannot approve their own pull request (0 approvals required) |
| Signed commits | same | **Skipped on purpose** (optional): needs a signing key set up first |
| Two-factor authentication on GitHub and PyPI | Account settings | **Done** (reported by the maintainer; not verifiable from the repository) |
| Environment `pypi` with a required reviewer | Settings → Environments | **Done** |
| Ruleset `protect-release-tags`: `v*` tags cannot be moved, deleted or created except by an admin; `v0` is excluded so the release workflow can move it | Settings → Rules | **Done** |
| Dependabot alerts and security updates | Settings → Code security | **Done** |
| Code scanning | Settings → Code security | **Done** (CodeQL alerts open; see the Security tab) |
| Workflow permissions default to read-only | Settings → Actions → General | **Done** |
| Scorecard badge in the README | README | **Done** (first result 6.2/10 on 2026-11-23; the badge shows the live score) |

`test` is a matrix, so no check is named plain `test`. `ci.yml` has a `ci-ok` job that fails unless
`test`, `typecheck`, `audit` and `self-scan` all succeeded: the `protect-main` ruleset should require
`ci-ok` (plus the individual jobs if wanted), not `test`.
