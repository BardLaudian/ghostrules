# Changelog

All notable changes to this project are documented here.
The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

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
