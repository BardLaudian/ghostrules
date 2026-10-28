# ghostrules v0.2 — Build plan

Read first: `docs/v0.2/SPEC.md`, `docs/AGENT_MODELS.md`, `docs/v0.2/RULES.md`, plus the 0.1
docs and `CLAUDE.md`. Same workflow as 0.1: one phase at a time; after each phase run
`pytest -q && ruff check . && mypy src`, commit with a conventional message, then stop and report.
Work on a branch `v0.2`; open a PR at the end.

Estimated: 2 weekends.

---

## Phase 0 — Verify the agent models (30–45 min, no code)
- Fetch the sources listed in `AGENT_MODELS.md` (Claude Code memory docs, Copilot CLI custom
  instructions, Cursor rules, agents.md). Compare with the file. Update `AGENT_MODELS.md` with any
  difference and today's date; turn UNVERIFIED items into verified ones where the docs are clear.
- Search for existing tools that resolve `@` imports or compute an agent's effective context for
  security scanning. Report what you find in `docs/DECISIONS.md` (name, link, what it does, how we
  differ). If something already does exactly this, stop and tell the user.
**Done when:** the user has read the report.

## Phase 1 — Markdown primitives (45 min)
- `markdown_utils.py`: inline code spans (if not already done in 0.1.1), YAML frontmatter
  parser (tiny, no PyYAML at runtime: only `key: value`, `key: [a, b]`, block lists `- item`,
  quoted strings, booleans; anything else → keep raw and mark unparsed), block-level HTML comment
  stripping that preserves code blocks and line numbers mapping.
- Import parser: find `@path` tokens per the Claude Code rules (not in code spans/blocks, `\ `
  escapes, quoted paths ignored, stop at whitespace). Return `(path_as_written, line, col)`.
  Avoid false imports: e-mail addresses (`user@example.com`), npm scopes in prose (`@types/node`
  — decide: Claude Code would try to import it; treat as an import that resolves to a missing file →
  GR022 only if it looks like a path, i.e. contains `/` or ends with a known extension; document in
  DECISIONS.md), `@mentions`. Lots of unit tests.
**Done when:** parser tests cover every rule in AGENT_MODELS.md "Imports".

## Phase 2 — Context engine (1.5 h)
- `src/ghostrules/agents/base.py`: `ContextEntry`, `AgentModel` protocol, `ContextGraph`
  (nodes = files, edges = imports with line numbers; cycle detection; depth tracking).
- Path resolution: relative to the importing file, `~` and absolute recorded but never read in repo
  mode, symlinks never followed, everything normalised to repo-relative POSIX paths (Windows!).
- Glob matching for `paths` / `globs` / `applyTo` with brace expansion and `**` — one shared helper,
  tested on Windows paths.
- Agent models: `claude_code.py`, `copilot_cli.py`, `generic.py`; `cursor.py` per the verified
  Phase 0 notes.
**Done when:** table-driven tests per agent: given a fake repo tree (built in `tmp_path`), cwd and
target, the ordered entries and load states match expectations. Include the AGENTS.md vs CLAUDE.md
precedence cases and the four-hop limit.

## Phase 3 — Scan integration + new rules (1 h)
- `scan` follows imports by default; imported files become targets of kind `instructions` with `via`.
- Findings: add `via`, `agents`; reporters updated (table shows the chain; JSON fields; SARIF
  `relatedLocations` + `properties.agents`; markdown shows the chain). SARIF must still validate.
- Rules GR020–GR025 and the agent-aware GR005; suppression rule for imported files.
**Done when:** RULES.md v0.2 tests pass; all 0.1 tests still pass (update only where GR005 changes).

## Phase 4 — `ghostrules context` (1 h)
- Command per SPEC §4 with tree/json/markdown output and `--show-text`.
- The tree is part of the new GIF: make it clear and pretty (load-state icons, chain indentation,
  finding counts per node, skipped entries with the reason).
**Done when:** `ghostrules context src/api/users.ts --agent claude-code` on the demo repo shows the
chain and the finding; snapshot tests for the three formats.

## Phase 5 — `ghostrules lock` (1.5 h)
- Lock format per SPEC §4 (deterministic; CRLF-normalised hashes; sorted).
- `lock`, `lock --update`, `lock --check` with the review diff (added/changed/removed, chain,
  seen-text diff with invisible chars revealed, "changed but not visible to <agent>" section).
- Markdown output for PRs.
**Done when:** tests for: unchanged → exit 0; edit to an imported non-agent file → exit 1 and the
diff names the chain; new import added → "added"; change inside a stripped HTML comment → listed as
not visible to claude-code; lock generated on Linux equals lock generated with CRLF files.

## Phase 6 — Action, config, demo (1 h)
- Action inputs `lock-check`, `follow-imports` (SPEC §5); self-test workflow exercises both.
- Config keys (SPEC §6).
- `scripts/make_demo.py`: `examples/import-chain-repo/` and a `lock --check` scenario.
- `demo/demo.tape`: new GIF — `cat CLAUDE.md` (clean) → `ghostrules scan --no-follow-imports`
  (nothing) → `ghostrules scan` (found via import) → `ghostrules context … --agent claude-code`.
  Keep < 20 s. Second tape `demo/lock.tape` for `lock --check`.

## Phase 7 — Docs and release prep (45 min)
- README: new tagline, a "What your agent actually reads" section with the tree, the import-chain
  story, `context` and `lock` docs, honest comparison paragraph (other lock tools exist; our lock
  covers the resolved context), FAQ entry on GR005 agent-awareness, updated Action snippet.
- `docs/AGENT_MODELS.md` linked from README ("how we model each agent — PRs welcome").
- CONTRIBUTING: how to add an agent model.
- CHANGELOG `[0.2.0]`; `__version__ = "0.2.0"`; snippets to `v0.2.0`.
- Full suite + ruff + mypy + self-scan + `lock --check` on the repo itself (commit a
  `.ghostrules.lock` for ghostrules' own CLAUDE.md — dogfooding).
**Done when:** PR from `v0.2` to `main` is open with a summary; the user merges and tags.
