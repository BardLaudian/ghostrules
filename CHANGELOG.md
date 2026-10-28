# Changelog

All notable changes to this project are documented here.
The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

## [0.3.0] - 2026-10-28

Measurement release. ghostrules now runs against real repositories every week, a browser playground
runs the real scanner without installing anything, and the first full study of popular repositories
drove a round of precision fixes. On the 300-repository regression tier 0.2.1 reported 323 findings
(84 critical, 156 high); 0.3.0 reports 212 (0 critical, 53 high), every critical and high finding
reviewed. On the 1,283-repository study tier the first run reported 1,072 findings (13 critical, 296
high); after the fixes 945 (12 critical, 252 high), all of medium and above triaged.

### Added
- **Playground** (`web/`, `.github/workflows/pages.yml`): a static page that runs the real scanner in
  the browser with Pyodide. Paste a file, drop a folder (agent files and what they import, up to
  5 MB) or name a public GitHub repo (the only tab that uses the network). Shows what you see versus
  what the agent reads, the context tree per agent and downloadable JSON, Markdown and SARIF reports.
  Playwright smoke test; deployed to GitHub Pages on release tags.
- **Corpus tooling** (`corpus/`, outside the package and the wheel): `discover.py`, `run.py`,
  `check.py`, `triage.py`, `badge.py`, `filestats.py`, a weekly `corpus.yml` workflow and an endpoint
  badge in the README. Findings are labelled by fingerprint in `corpus/labels.toml`; labels never
  name a repository for a reported finding.
- **Study tooling** (`study/`): per-repository features, aggregate CSVs, SVG charts in light and dark,
  the triage classes and `study/report.md`, generated from the CSVs.
- `ghostrules.playground`, `ghostrules.reveal_data` and `ghostrules.reporters.context_data`: the core
  (scanner, rules, context engine, JSON, SARIF and Markdown reporters) now imports without `typer`
  and `rich`; the terminal output is unchanged.
- `action.yml` is named `ghostrules scan` and its description fits the Marketplace limit (125
  characters).

### Fixed
- GR003: a lone U+200B between two letters of Khmer, Thai, Lao or Myanmar text is that script's word
  separator and is ignored.
- GR005: a hidden comment is `medium` when it carries an instruction cue, `low` when it only mentions
  agents, `high` unchanged for injection matches.
- GR010: `override system|safety` needs a following noun, and defensive text that quotes the phrase
  is `low`.
- GR011: `without asking the user` is no longer concealment; a prohibition earlier in the clause, a
  safety claim ("does not silently install"), a description in the third person ("silently runs") and
  a modal before it are not reported.
- GR012: naming the `curl | sh` pattern without a target is `low`; a `curl` in prose no longer joins
  the next code block; `| bash script.sh` is not a data pipe into the shell.
- GR013: needs a verb, a secret and a URL in the same clause; prohibitions, loopback URLs, `POST`
  and `.post(`, "send the user to" and "send X only to the fixed origin" are not exfiltration.
- GR014: the verb must govern the path across no paragraph break, clause connector (`before`,
  `after`, `when`), passive or noun use; `### Output` is a heading; `.env.default` and copying a
  dotenv file are not reads.
- GR015: runs inside URLs, Subresource Integrity digests and low-entropy hex (`AAAA…`) are skipped.
- GR016: a prohibition ("Avoid `--yolo`"), a table row and a list item that documents a flag are not
  an instruction.
- A bare `@/`, `@~/`, `@./` or `@../` is a path prefix, not an import.

### Known limits
- Splitting an exfiltration instruction across two sentences avoids the GR013 prose match, and a
  concealment right after an unrelated prohibition in the same clause is not reported.

## [0.2.1] - 2026-10-28

Precision release. A scan of 12 popular public repositories with 0.2.0 found no critical issue,
but every `high` finding was a false positive, and `context` was wrong for the most common real
setup. On those repositories 0.2.0 reported 9 high, 18 medium and 8 low findings; 0.2.1 reports
2 medium and 2 low, with no high, no critical and no GR025.

### Added
- `ghostrules context --format json` entries carry `alias_of` (and `link_problem`) when a symlink is
  involved; lock entries carry `link` for an alias. Both keys are omitted otherwise.
- `ghostrules.rules.directive.classify`: the helper that tells directive, descriptive and example
  text apart (used by GR011, GR014 and GR016).

### Fixed
- A symbolic link whose final target is a regular file inside the repository is now an **alias**:
  `CLAUDE.md -> AGENTS.md` (the setup Claude Code documents) is loaded under the link's name,
  `context` shows `CLAUDE.md → AGENTS.md (symlink)` and the `AGENTS.md` entry as already read, the
  content is scanned once (findings say `via CLAUDE.md (symlink)`), and `lock` records the link and
  its target. Chains of up to 8 links and in-repository directory links work the same way. Nothing
  is opened before the resolved path is known to be inside the repository.
  GR025 now fires only for links that leave the repository (`high`) or are broken, cyclic or too
  long (`low`), instead of one `medium` per link, and adds an `info` note for a link checked out as
  a text file (Windows with `core.symlinks=false`).
- GR022 no longer reports npm scopes and mentions (`@n8n/design-system`, `@cline/llms`, `@types/node`)
  as imports that do not load. It reports a token only if it has a file extension, starts with `./`,
  `../`, `~/` or `/`, or its first directory exists next to the importing file.
- GR011, GR014 and GR016 tell instructions from descriptions and examples. A match in prose that
  describes something ("The scripts read `~/.npmrc`", "The harness runs Claude with
  `bypassPermissions`") is at most `medium`; in a fenced block, in quotes or after "e.g.", "such
  as", "a skill that ..." it is at most `low`; imperative text and decoded hidden text keep their
  severity. A lowered finding says why.
  - GR011: "do not tell the user to/which/what/how ..." is no longer concealment.
  - GR014: the verb must govern the path (same clause, six words at most) and template files
    (`.env.example`, `*.example`, `.env.ai-surfaces.example`) never fire.
- GR012: `curl ... | python -c`, `| python -m`, `| python script.py`, `| sh -c '...'` use stdin as
  data and are no longer reported; `| python`, `| python -` and `| sh` still are. The Claude Code
  installer (`https://claude.ai/install.sh`) is a known installer. GR105 and GR107 share these
  patterns and follow.

### Changed
- README: the new tagline is the only one (the old one opens the first paragraph), the import-chain
  GIF comes first and the hidden-Unicode GIF sits further down, both by absolute URL.
- The original `SPEC.md`, `PLAN.md` and the per-version design documents moved to `docs/design/`
  (design history, not kept up to date). `RULES.md`, `AGENT_MODELS.md` and `DECISIONS.md` stay in
  `docs/`.

## [0.2.0] - 2026-10-28

Know exactly what your agent reads: `ghostrules` now models how each agent loads its instructions,
scans exactly that, shows it, and pins it.

### Added
- GitHub Action inputs `follow-imports` (default `true`) and `lock-check` (default `false`). With
  `lock-check` the action runs `ghostrules lock --check`, puts the differences in the job summary
  under "What your agents read changed in this PR" and fails the job if there are any; new output
  `lock-exit-code`.
- Config keys `follow_imports`, `agents` and `lockfile`.
- `python scripts/make_demo.py --lock-scenario DEST` and the tapes `demo/imports.tape` and
  `demo/lock.tape` for the 0.2 GIFs.
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

- `docs/AGENT_MODELS.md`: how each agent loads its instructions, with the documentation it is based on
  and what is still unverified; `CONTRIBUTING.md` explains how to add a model.
- `ghostrules` locks its own `CLAUDE.md` (`.ghostrules.lock`), checked in CI.

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
