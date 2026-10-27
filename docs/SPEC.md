# ghostrules — Specification (v0.1)

## 1. Problem
AI coding agents (Claude Code, Cursor, Copilot, Windsurf, Cline, Gemini CLI, Codex…) automatically
load instruction files from a repository and follow them. Anyone who can get a file into a repo
(a PR, a dependency, a template, a copied "awesome rules" file) can plant instructions that:

- are **invisible to humans** (Unicode tag characters, zero-width chars, bidi controls, HTML comments),
- tell the agent to **run remote code**, **exfiltrate secrets** or **hide what it is doing**,
- or configure MCP servers / agent permissions in **dangerous ways** (hardcoded tokens, unpinned
  packages, privileged Docker, permission bypass).

Code review does not catch this because the reviewer literally cannot see it.
`ghostrules` makes it visible, in the terminal, in CI and in GitHub's Security tab.

## 2. Non-goals (v0.1)
- No network access, no execution of scanned content.
- No LLM calls in the core scanner (optional LLM triage is roadmap, see §10).
- Not a general secret scanner — secret detection only inside agent/MCP config files.

## 3. File targets
Default target globs (relative to scan root, case-insensitive on file names). Keep the list in one
place (`src/ghostrules/targets.py`) so it is easy to extend:

**Instruction files (kind = `instructions`)**
- `AGENTS.md`, `**/AGENTS.md`, `AGENT.md`
- `CLAUDE.md`, `CLAUDE.local.md`, `**/CLAUDE.md`
- `.claude/commands/**/*.md`, `.claude/agents/**/*.md`, `.claude/skills/**/*.md`, `**/SKILL.md`
- `.cursorrules`, `.cursor/rules/**/*.mdc`, `.cursor/rules/**/*.md`
- `.github/copilot-instructions.md`, `.github/instructions/**/*.instructions.md`,
  `.github/prompts/**/*.prompt.md`, `.github/chatmodes/**/*.md`
- `.windsurfrules`, `.windsurf/rules/**`
- `.clinerules` (file) and `.clinerules/**` (dir), `.roo/rules*/**`, `.roorules`
- `GEMINI.md`, `.gemini/**/*.md`
- `.junie/guidelines.md`, `.kiro/steering/**/*.md`, `.continue/rules/**`
- `CONVENTIONS.md` (aider)

**Config files (kind = `config`)**
- MCP: `.mcp.json`, `mcp.json`, `.cursor/mcp.json`, `.vscode/mcp.json`, `.gemini/settings.json`,
  `claude_desktop_config.json`, `.roo/mcp.json`
- Agent settings: `.claude/settings.json`, `.claude/settings.local.json`
- Other: `.aider.conf.yml` (unicode rules only in v0.1)

Flags:
- `--all-files`: additionally apply the Unicode rules (GR001–GR006) to **every** text file in the
  tree (skip binaries, `.git/`, `node_modules/`, `.venv/`, files > 2 MB).
- `--home`: additionally scan user-level configs on this machine (read-only):
  `~/.claude.json`, `~/.claude/settings.json`, `~/.claude/CLAUDE.md`, `~/.cursor/mcp.json`,
  `~/.codeium/windsurf/mcp_config.json`, `~/.gemini/settings.json`, `~/.codex/config.toml`,
  and the Claude Desktop config (`~/Library/Application Support/Claude/claude_desktop_config.json`
  on macOS, `%APPDATA%\Claude\claude_desktop_config.json` on Windows,
  `~/.config/Claude/claude_desktop_config.json` on Linux). Missing files are silently skipped.

## 4. CLI
```
ghostrules scan [PATH ...] [options]     # default command; PATH defaults to "."
ghostrules reveal FILE                   # print file with invisible chars made visible + decoded
ghostrules clean FILE [--write]          # strip invisible/bidi chars; dry-run diff unless --write
ghostrules rules                         # list all rules (id, severity, title)
ghostrules version
```

`scan` options:
| Option | Default | Meaning |
|---|---|---|
| `--format` | `table` | `table`, `json`, `sarif`, `markdown` |
| `--output, -o FILE` | stdout | write report to file |
| `--fail-on` | `high` | exit 1 if any finding ≥ this severity (`none` to never fail) |
| `--min-severity` | `low` | hide findings below this |
| `--all-files` | off | see §3 |
| `--home` | off | see §3 |
| `--disable GR010,GR012` | — | disable rules |
| `--config FILE` | auto | explicit config path |
| `--no-color` | off | plain output |

Exit codes: `0` ok, `1` findings at/above `--fail-on`, `2` usage/runtime error.

### Table output (default)
Rich output grouped by file. For each finding: severity badge, rule ID, title, `path:line:col`,
snippet with invisible chars rendered as `⟦U+E0049⟧` (dim/red), and, when present, a
**"Decoded hidden text:"** line. End with a summary line: `3 critical · 2 high · 1 medium in 4 files (scanned 17)`.

This decoded line is the money shot of the demo — make it look great.

### JSON
`{"version": "...", "scanned_files": N, "findings": [Finding...], "summary": {...}}`

### SARIF 2.1.0
One `run`, `tool.driver.name = "ghostrules"`, `rules` populated from the registry
(id, shortDescription, fullDescription, helpUri → README anchor, defaultConfiguration.level).
Severity → level: critical/high → `error`, medium → `warning`, low/info → `note`.
Also set `properties.security-severity` (critical 9.5, high 8.0, medium 5.5, low 3.0, info 1.0)
so GitHub shows severities. Locations use repo-relative URIs and 1-based line/column.
Must validate against the SARIF 2.1.0 schema (add a test using a vendored schema or structural checks).

### Markdown
Compact table suitable for a PR comment / `$GITHUB_STEP_SUMMARY`.

## 5. `reveal` and `clean`
- `reveal FILE`: prints the file with line numbers; every invisible / bidi / tag char replaced by a
  highlighted `⟦U+XXXX NAME⟧` token; after each line containing tag characters, prints the decoded
  ASCII (tag char − 0xE0000). Also shows HTML comments highlighted.
- `clean FILE`: removes chars matched by GR001–GR004 (keeps a leading BOM only if `--keep-bom`).
  Without `--write` prints a unified diff of what would change. With `--write` writes in place and
  saves `FILE.ghostrules.bak`.

## 6. Configuration
Looked up in order: `--config`, `.ghostrules.toml`, `[tool.ghostrules]` in `pyproject.toml`.
```toml
disable = ["GR014"]
fail_on = "high"
min_severity = "low"
exclude = ["vendor/**", "tests/fixtures/**"]
extra_targets = ["docs/ai/*.md"]          # treated as kind=instructions
allow_domains = ["mycompany.com"]          # never flagged by URL/exfil rules
```
Inline suppression: a line containing `ghostrules-ignore` suppresses findings on that line and the
next; `ghostrules-ignore: GR010` suppresses only that rule.
A suppression comment can never suppress GR001/GR002 (invisible chars) — document why in README.

## 7. GitHub Action (`action.yml`, composite)
Inputs: `path` (default `.`), `fail-on` (default `high`), `all-files` (default `false`),
`upload-sarif` (default `true`).
Steps: setup-python → `pip install` the action's own source (`${{ github.action_path }}`) →
run scan with `--format sarif -o ghostrules.sarif` (don't fail yet) → upload via
`github/codeql-action/upload-sarif@v3` if enabled → also write markdown summary to
`$GITHUB_STEP_SUMMARY` → finally exit with scan exit code.
Provide a ready-to-copy workflow in README.

## 8. pre-commit
`.pre-commit-hooks.yaml` with hook id `ghostrules`, `language: python`, `pass_filenames: false`,
`entry: ghostrules scan`.

## 9. Repository layout
```
ghostrules/
├── src/ghostrules/
│   ├── __init__.py  cli.py  scanner.py  targets.py  models.py  config.py  unicode_utils.py
│   ├── rules/  __init__.py (registry)  unicode.py  injection.py  mcp.py  agent_settings.py
│   └── reporters/  table.py  json_.py  sarif.py  markdown.py
├── tests/  (pytest; fixtures generated into tests/fixtures/ by scripts/make_fixtures.py)
├── scripts/make_fixtures.py
├── examples/poisoned-repo/   (defanged demo — the README GIF is recorded here)
├── examples/clean-repo/      (realistic, zero findings)
├── demo/demo.tape            (charmbracelet/vhs script to record the GIF)
├── action.yml  .pre-commit-hooks.yaml
├── .github/workflows/ci.yml  release.yml
├── docs/  SPEC.md RULES.md PLAN.md DECISIONS.md
├── README.md  LICENSE (MIT)  SECURITY.md  CONTRIBUTING.md  CHANGELOG.md
└── pyproject.toml
```

## 10. Roadmap (put in README, do NOT build in v0.1)
- `--llm` optional second opinion on suspicious natural-language instructions (Ollama local or API),
  off by default, never sends files without explicit flag.
- Baseline file to ignore known findings.
- VS Code extension that highlights invisible chars in agent files.
- Scan MCP server tool descriptions (tool poisoning) by reading a server's manifest.
