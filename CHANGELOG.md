# Changelog

All notable changes to this project are documented here.
The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

### Added
- `ghostrules lock`: writes `.ghostrules.lock`, a deterministic record (sorted keys, no timestamps,
  CRLF-normalised hashes) of every file in each modelled agent's context, how it is reached, and
  the text the agent actually receives, plus a hash of every MCP and agent settings file.
  `lock --check` recomputes it and shows what changed (added, changed, removed, and changes that
  only touch text an agent strips), with invisible characters revealed; exit 0 up to date, 1
  changed, 2 error. `--format text|markdown|json`, `--update`, `--lockfile`; config key `lockfile`.
- `ghostrules context [TARGET]`: shows what an agent reads when it works on a file (the files it
  loads at session start, the rules its `paths`/`globs` select, the directories that load on
  demand, the imports it follows and the files it skips, with the reason) and scans exactly that.
  Output as a tree, JSON or Markdown; `--agent`, `--cwd`, `--root`, `--show-text`, `--no-scan`,
  `--home`, `--fail-on`.
- `examples/import-chain-repo`: a CLAUDE.md that looks clean and reaches a hidden payload through two
  imports, plus a `.env` import and one outside the repository.
- `scan` follows `@path` imports by default: files an instruction file imports are scanned as
  instructions, and their findings carry the import chain (`via`), the agents that load them and the
  tag `reached-via-import`. `--no-follow-imports` (or `follow_imports = false`) turns it off.
- Rules GR020 (external import), GR021 (sensitive file imported), GR022 (import that silently does
  not load), GR023 (import cycle), GR024 (tag for payloads reached through an import) and GR025
  (symlinked instruction source).
- The files each modelled agent loads (including `.claude/rules/**`) are scanned even when the
  discovery globs do not list them. New config keys `follow_imports` and `agents`.
- JSON findings gain optional `via`, `agents` and `tags`; SARIF results gain `relatedLocations` for
  the chain and `properties.agents`/`tags`; the table and Markdown reports show the chain.

### Changed
- GR005 is agent-aware: it says which agents see a hidden comment. Claude Code strips block-level
  comments from CLAUDE.md files, so the finding is info when no configured agent sees the comment.

## [0.1.1] - 2026-10-27

### Changed
- GR012 (remote code execution pattern) now sets its severity from context instead of reporting
  every `curl ... | sh` as critical. A well-known installer in a code block is low, in prose
  medium; an unknown domain is high in a code block and critical in prose. Plain `http://`, IP
  literals, non-default ports, collector domains, opaque payloads (`base64 -d | sh`,
  `powershell -enc`) and text hidden by invisible characters stay critical. This stops the default
  `--fail-on high` from failing on real repositories that document `uv` or `rustup`.
  GR105 and GR107 (MCP server commands and hooks) are unchanged.

### Added
- Built-in list of well-known installers (uv/ruff, rustup, Bun, Deno, pnpm, Poetry, Homebrew, nvm,
  SDKMAN, Docker, Ollama, Volta), matched on the exact host and optional path prefix, and
  `ghostrules rules --installers` to print it.
- `trust_known_installers` option (default `true`); `false` restores the 0.1.0 behaviour.
- Inline code span awareness for GR012 (`ScanTarget.code_span_at`).

## [0.1.0] - 2026-10-27

First release.

### Added
- Scanner for the files AI coding agents read and obey (`AGENTS.md`, `CLAUDE.md`, `.cursorrules`,
  Copilot instructions, skills, MCP configs, agent settings and more), with `--home` for
  user-level configs and `--all-files` for hidden Unicode anywhere in a tree.
- 21 rules. Hidden content: Unicode tag characters (GR001), bidirectional controls (GR002),
  zero-width characters (GR003), variation-selector steganography (GR004), hidden HTML comments
  (GR005), mixed-script homoglyphs (GR006). Malicious instructions, English and Spanish: instruction
  override (GR010), concealment (GR011), remote code execution (GR012), data exfiltration (GR013),
  sensitive file access (GR014), encoded payloads (GR015), safety bypass (GR016). Configuration:
  hardcoded secrets (GR101), unpinned packages (GR102), insecure transport (GR103), broad
  filesystem scope (GR104), shell wrappers (GR105), dangerous Docker options (GR106),
  over-permissive agent settings (GR107), auto-trusted MCP servers (GR108).
- Hidden text decoded by GR001, GR004 and GR015 is re-scanned by GR010-GR016 and reported with
  one more level of severity.
- CLI: `scan` (the default command), `reveal`, `clean`, `rules`, `version`. Reports as a table
  grouped by file with the decoded hidden text highlighted, JSON, SARIF 2.1.0 (validated against the
  official schema) and Markdown. Exit codes: 0 clean, 1 findings at or above `--fail-on`, 2 error.
- Configuration through `.ghostrules.toml` or `[tool.ghostrules]`, and inline `ghostrules-ignore`
  suppressions (never for GR001, GR002 or text found inside hidden characters).
- GitHub Action (SARIF upload to code scanning, job summary, `fail-on` gate), pre-commit hook, CI
  with a smoke test and a self-scan, and a tag-triggered release workflow using PyPI Trusted
  Publishing.
- Demo repositories `examples/poisoned-repo` (every rule fires) and `examples/clean-repo` (no
  findings), and `demo/demo.tape` to record the README GIF.

### Security
- Read-only: nothing found in a scanned file is executed, imported, downloaded or sent anywhere,
  and the tool makes no network requests. Symbolic links are not followed.
- Secrets are never printed: every finding, warning and error passes through one masking step
  (`ghp_****…a1b2`), and a test fails if a secret appears in any report format.
