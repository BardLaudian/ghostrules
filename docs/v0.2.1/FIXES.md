# v0.2.1 — Real-world precision fixes

Source of these cases: a scan of 12 popular public repositories on 2026-10-28 (openai/codex,
astral-sh/uv, pydantic/pydantic-ai, langchain-ai/langchain, cline/cline, n8n-io/n8n, vercel/ai,
PostHog/posthog-js, getsentry/sentry-python, microsoft/vscode-python,
modelcontextprotocol/servers, anthropics/claude-agent-sdk-python).
Result: 0 critical (good), but every `high` was a false positive, and `context` was **wrong** for
the most common real setup. Each item below becomes a regression test. Use **minimal synthetic
reproductions** in `tests/` (one or two lines, same shape), not copies of third-party files; cite
the source repo in a comment.

Workflow: one item at a time, test first (it must fail on 0.2.0), then fix. Run the full suite,
ruff and mypy after each item.

---

## F1 — `CLAUDE.md` symlinked to `AGENTS.md` (correctness bug, highest priority)
Real repos (pydantic-ai: 16 times, sentry-python, posthog-js) use `CLAUDE.md -> AGENTS.md`. The
Claude Code docs describe exactly this setup and say Claude reads `CLAUDE.md` through the link.
0.2.0 marks both files `skipped` in `context` (so it claims Claude reads nothing) and emits one
GR025 `medium` per link.

Fix — symlink resolution policy (document in AGENT_MODELS.md and DECISIONS.md):
- A symlink whose **final target is a regular file inside the repository root** is an **alias**:
  the agent reads the target's content under the link's name. Resolve chains hop by hop, max 8
  hops, every hop must stay inside the root, no cycles. Never `open()` anything before checking the
  resolved path is inside the root.
- `context` shows it as loaded: `● always  CLAUDE.md → AGENTS.md (symlink)`. The CLAUDE-vs-AGENTS
  precedence applies to the link name (a `CLAUDE.md` exists, so Claude reads `CLAUDE.md`, whose
  content is `AGENTS.md`; the separate `AGENTS.md` entry stays "skipped: already read through
  CLAUDE.md symlink" — no double counting).
- `scan` scans the content **once** (dedupe by resolved path) and findings list the link as an
  alias in `agents`/`via` (e.g. `via CLAUDE.md (symlink)`).
- `lock` records the link and its target; changing the target content changes the lock.
- In-repo **directory** symlinks (e.g. `.claude/rules/shared -> ../shared-rules`): same alias rule
  for files under them.
- GR025 now fires only when the link (or any hop) points **outside** the root, is broken, or is a
  cycle. Severity: high outside the root, low broken/cycle. In-repo aliases: no finding.
- Windows with `core.symlinks=false` checks out a link as a tiny text file whose content is the
  target path (e.g. a 9-byte `CLAUDE.md` containing `AGENTS.md`). If an agent file's whole content
  is a single relative path to an existing file in the same directory, emit an `info` note
  ("probably a symlink checked out as text; the agent will read only this path string").
Tests: alias file, chain of two links, link to dir, link escaping root, broken link, cycle, the
Windows text-checkout case, and a context tree snapshot for the pydantic-ai shape (root + nested
`CLAUDE.md -> AGENTS.md`).

## F2 — GR022 on npm-scoped names and @mentions
Noise (8 findings): headings and prose like `# @n8n/design-system`, `Development guidance for the
@cline/llms package.`, `## Owners` / `@n8n/design`. Claude Code would try those as relative paths,
find nothing and silently ignore them: harmless, and the author never meant an import.
Fix: report GR022 only when the token **looks like an intended file reference**: it has a file
extension (`.md`, `.txt`, `.json`, …), or starts with `./`, `../`, `~/`, `/`, or its first path
segment exists in the repo relative to the importing file. Skip tokens matching an npm scope
pattern `@[a-z0-9-~][a-z0-9-._~]*/[a-z0-9-._~]+` with no extension, and bare `@word` mentions.
Tests: the three shapes above → no finding; `@docs/missing.md` → GR022; `@./notes` (missing) → GR022.

## F3 — Directive vs descriptive text (shared helper for GR011, GR014, GR016)
Most high false positives are **descriptions** or **instructions about what to say**, not
instructions telling the agent to misbehave. Add one tested helper,
`rules/directive.py::classify(target, span) -> "directive" | "descriptive" | "example"`, and use it
in GR011, GR014 and GR016:
- `example`: inside a fenced block, an inline code span, quotes, or a sentence introduced by
  "e.g.", "for example", "such as", "a skill that…", "instructs the agent to…" (meta-description).
- `directive`: imperative sentence (starts with a verb, or "you must/should/always/never", or
  "always/never" + verb), or text in decoded hidden content (always directive).
- `descriptive`: everything else (third-person subject: "the scripts read…", "Claude then uses…",
  "with `~/.npmrc` moved aside it exits 1").
Severity: directive → rule's normal severity; descriptive → medium; example → low.
Hidden text keeps its existing +1 bump (critical) regardless.

Specific fixes on top of the helper:
- **GR011** “Do not tell the user **to** open a setup…” / “Do not tell the user to …”: an
  instruction about what to say, not concealment. Negative lookahead: `tell (the )?user to\b`,
  `tell the user which|what|how|that` → no finding. Keep `do not tell the user` followed by end of
  sentence, `about`, `this`, `that you` → finding.
- **GR014** “copy `.env.ai-surfaces.example` to it”: template files (`.env.example`,
  `.env.sample`, `.env.template`, `*.example`) are not secrets → never fire (reuse the GR021
  exclusion list). Also the verb list matched `output` in “exits 0 with no guard output; with
  `~/.npmrc`…”: require the verb to govern the path (same clause, path is its object, ≤ 6 words
  apart, no sentence/clause break `;` `.` between them).
- **GR016** a prose paragraph documenting that a test harness runs Claude with
  `--permission-mode bypassPermissions` → descriptive → medium (not high). Directive “run with
  --dangerously-skip-permissions” stays high.
Tests (synthetic, mirroring): n8n agent-builder line 468 and workflow-builder line 1043 (GR011
→ none); n8n testmax lines 50–55 (GR014 → none/medium per helper); cline publish-cli line 184
(GR014 → none); sentry skill-scanner line 88 “A skill described as … that instructs the agent to
read ~/.ssh is misaligned” (GR014 → low, example); n8n testmax line 649 (GR016 → medium). Keep all
existing positive tests passing (the poisoned demo must still produce the same critical findings).

## F4 — GR012 on `curl … | python -c` and Claude's installer
- `curl -s "https://open-vsx.org/api/…" | python3 -c "import json,sys; …"`: stdin is **data** for an
  inline script, not code being executed. Pattern change: `| python…` counts as RCE only when the
  interpreter reads the program from stdin (`python`, `python -`, `python3 -`, no `-c`/`-m`/script
  argument). Same idea for `| node -e`, `| jq`, `| sh -c '…'` (data, not program). Tests for each.
- Add `https://claude.ai/install.sh` (host `claude.ai`, path prefix `/install.sh`) to the known
  installers. Test: anthropics/claude-agent-sdk-python verify skill line 14 shape → low.
- While there, add any other installer seen in the corpus run of v0.3 later (keep list sorted,
  each with a source link in a comment).

## F5 — Housekeeping
- README: keep only the new tagline ("Know exactly what your AI agent reads — and approve every
  change to it."); move the old one into the first paragraph.
- Record `demo/imports.tape` → `demo/imports.gif` and make it the **first** GIF in the README (it is
  the differentiator). Keep `demo.gif` lower, in the "hidden Unicode" section. Use absolute
  raw.githubusercontent URLs (PyPI).
- Move internal planning docs (`docs/v0.1.1/`, `docs/v0.2/`, `docs/PLAN.md`, `docs/SPEC.md`) to
  `docs/design/` and say so in CONTRIBUTING ("design history"). Keep `RULES.md`,
  `AGENT_MODELS.md`, `DECISIONS.md` at `docs/`.
- CHANGELOG `[0.2.1]` (Fixed: F1–F4; Changed: README). `__version__ = "0.2.1"`. Snippets → v0.2.1.

## Acceptance
- All previous tests pass (update only expectations these fixes intentionally change).
- New tests for every case above.
- On the 12 repos listed at the top (shallow clones in a temp dir, not committed): **zero `high`
  or `critical`** and **zero GR025** for in-repo aliases. Put the before/after counts in the PR
  description. (The v0.3 corpus will automate this.)
