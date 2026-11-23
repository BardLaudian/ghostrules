# GitHub settings the repository cannot enforce by itself

These are configured in the GitHub UI (or with `gh api`) by someone with admin rights. They are
not applied by this repository and are **pending** until a maintainer does them.

| Setting | Where | Why |
|---|---|---|
| Branch protection on `main`: require a pull request, require the `CI` checks (test, typecheck, audit, self-scan) to pass, block force pushes and deletion | Settings → Branches | Nothing reaches `main` without CI |
| Require at least one approving review (and code-owner review if a `CODEOWNERS` file is added) | same | A second pair of eyes on every change |
| Require signed commits (optional) | same | Verifiable authorship |
| Two-factor authentication on every maintainer account, and on PyPI | GitHub and PyPI account settings | Account takeover is the main route to a poisoned release |
| Environment `pypi` with required reviewers | Settings → Environments | A release cannot publish without an explicit approval |
| Restrict who can push `v*` tags (tag ruleset) | Settings → Rules | The release workflow runs on a tag |
| Dependabot alerts and security updates; code scanning (receives the Scorecard SARIF) | Settings → Code security | Alerts for dependencies and findings |
| Workflow permissions default to read-only | Settings → Actions → General | Matches the per-workflow `permissions:` blocks |
| Add the Scorecard badge to the README | README | Only after the first Scorecard run has published a result |
