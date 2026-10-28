# ghostrules v0.2 — New and changed rules

Add these to `docs/RULES.md` (keep the existing catalogue) and to the registry. Same conventions
as 0.1: pure functions, ≥1 positive and ≥1 negative test each, defanged fixtures only.
Rules in the `GR02x` range need the import graph, so they receive a `ContextGraph` (or the
`via`/`agents` data) in addition to the `ScanTarget`.

---

## GR020 — External import (high)
An `@path` import that resolves outside the repository root (absolute path, `~/…`, or `../` climbing
above the root).
- Message names the agents affected: Claude Code asks once for approval (and an earlier approval
  silently applies to new ones); Copilot CLI does not load it.
- Severity: high. Info if the importing file is user-level (`~/.claude/CLAUDE.md`) — users import
  their own files legitimately.
- Never resolve or read the external target in repo mode; report the path as written.

## GR021 — Sensitive file imported into context (critical)
An import whose target is a secrets or credentials file: `.env`, `.env.*` (except `.env.example`,
`.env.sample`, `.env.template`), `~/.ssh/*`, `id_rsa*`, `id_ed25519*`, `.aws/credentials`, `.npmrc`,
`.pypirc`, `.netrc`, `kubeconfig`, `*.pem`, `*.key`, `credentials.json`, `secrets.*`.
Importing it puts the secret into every prompt sent to the model provider. Reuse the GR014 sensitive
path list. Never read the target's content.

## GR022 — Import that silently does not load (low)
`@path` that the agent will not load: target missing, deeper than the documented maximum depth,
quoted path, path cut at an unescaped space, or `blocked` for that agent. Low, because it is mostly
a reliability problem, but report it: the author believes the agent reads something it doesn't.
Message explains which agent ignores it and why.

## GR023 — Import cycle (info)
A → B → A. Report once with the cycle. Agents stop at the depth limit; nothing breaks, but it's noise.

## GR024 — Payload reached only through an import (severity: of the inner finding, +0)
Not a separate detector: when any GR001–GR016 finding is in a file that is **not** itself an agent
target and is reached only through imports, add the tag `reached-via-import` and set `via`. The
table/markdown/SARIF output must make the chain prominent ("this file is not an agent file, but
CLAUDE.md:12 imports it"). This is the headline feature of v0.2; it needs a dedicated test and the
demo repo.

## GR025 — Symlinked instruction source (medium)
An instruction file or rules directory that is a symlink (ghostrules never follows it). High if the
link target is outside the repository. Claude Code treats links outside the working directory as
external imports needing approval.

---

## Changed: GR005 — Hidden HTML comment (agent-aware)
0.1 reports long HTML comments in Markdown instruction files. In 0.2, compute which agents actually
**see** the comment:
- In `CLAUDE.md` / `CLAUDE.local.md` / `.claude/CLAUDE.md` (and their imports) Claude Code strips
  block-level comments → Claude Code does **not** see it. Copilot CLI also reads CLAUDE.md and has no
  documented stripping → it **does** see it (unverified).
- Severity is computed on the agents that see it. If no modelled agent sees it → `info`, message
  "stripped by claude-code before reaching the model".
- Message lists `seen by:` / `not seen by:` agents.
This is a precision improvement other scanners don't make; mention it in the README FAQ.

## Changed: all findings
- New optional fields `via: list[str]` and `agents: list[str]`.
- `ghostrules-ignore` in an importing file does **not** suppress findings in the imported file
  (an attacker controlling the importer could otherwise silence the payload). Document it next to
  the GR001/GR002 rule.

---

## Acceptance (demo repos)
- `examples/clean-repo`: still 0 findings (add a legitimate `@docs/conventions.md` import to it so
  the clean path is exercised).
- `examples/poisoned-repo`: unchanged expectations except where GR005 becomes agent-aware.
- `examples/import-chain-repo`: `--no-follow-imports` → 0 findings; default → GR001 + re-scan
  findings in `shared/team-rules.md` with `via CLAUDE.md:… → docs/style.md:…`, plus one GR021
  (an `@.env` import, defanged `.env` with fake values that is **never read**) and one GR020.
