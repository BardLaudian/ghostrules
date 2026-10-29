# How agents load instructions — the source of truth for `context` and `lock`

**Rule for implementers:** model only what is written here. Each section lists its source and the
date it was checked. Phase 0 of the plan re-checks every source; if the official docs differ, update
this file first (with the new date), then the code. Anything marked **UNVERIFIED** must be modelled
conservatively and shown in output as `(unverified)`.

**Phase 0 status (2026-10-28):** all four sources were fetched and compared with the 2026-10-27
draft. Changes are marked **[0-28]**. Method caveat: pages were read through a fetch tool that
summarises, so the exact quotes below are the ones the tool returned; re-read the source page before
relying on a detail that decides a rule's severity.

---

## claude-code
Source: Claude Code docs, "How Claude remembers your project" —
https://code.claude.com/docs/en/memory (re-checked 2026-10-28; all of this section is verified
unless marked otherwise).

**Session-start sources, in context order** (concatenated, not overriding):
1. Managed policy `CLAUDE.md` (macOS `/Library/Application Support/ClaudeCode/CLAUDE.md`, Linux/WSL
   `/etc/claude-code/CLAUDE.md`, Windows `C:\Program Files\ClaudeCode\CLAUDE.md`) — only with
   `--home`. **[0-28]** Managed settings can also carry the text inline (`claudeMd` key in
   `managed-settings.json`); not modelled (not a file in the repo or home).
2. User `~/.claude/CLAUDE.md` and `~/.claude/rules/` — only with `--home`.
3. For every directory from the filesystem root **down to** the working directory: `CLAUDE.md`,
   `.claude/CLAUDE.md`, then `CLAUDE.local.md` (local is appended after CLAUDE.md at the same level).
   Closer directories come later in the context. Docs: "Across the directory tree, content is
   ordered from the filesystem root down to your working directory." In repo mode, walk from repo
   root to `--cwd`; directories above the repo root are out of scope (say so in `context` output).
4. Project rules: `.claude/rules/**/*.md` (recursive). Rules **without** `paths` frontmatter load
   at launch "with the same priority as `.claude/CLAUDE.md`".

**Conditional**: rules with YAML frontmatter `paths:` (a YAML list **or a comma-separated string**)
load when the agent uses Read, Write or Edit on a matching file, or views one with a Bash command
that counts as a read (`cat`, `head` on a single file). Globs are relative to "the directory that
contains the rule's `.claude` folder" (user-level rules: the session's primary working directory).
Brace expansion is supported; a rule's whole `paths` list shares a budget of 1,000 expanded patterns
and 4 MiB, and a pattern over budget is used unexpanded (its braces then match nothing). **[0-28]**
A `[` that cannot be read as a bracket expression makes that one pattern invalid (matches nothing;
other patterns keep working); `\[` matches a literal bracket.
`paths` is the only frontmatter field read; others are ignored without error; the frontmatter is
**removed** before loading. **[0-28]** If the YAML between the `---` markers does not parse, Claude
Code ignores the frontmatter and loads the rule **as if it had no `paths`** → model as `always`
with `note: frontmatter did not parse`.

**On demand**: `CLAUDE.md` / `CLAUDE.local.md` in subdirectories **below** the working directory load
once the agent reads, writes or edits a file in that subdirectory (same read-by-Bash rule as above).
Same for a subdirectory's `.claude/rules/`. Files they `@`-import are on-demand too.

**AGENTS.md** (setting "Project instructions", default `claude-md-or-agents-md`): at session start
every `AGENTS.md` and `.claude/AGENTS.md` in the working directory and above are read **only if**
there is no `CLAUDE.md`, `.claude/CLAUDE.md` or `CLAUDE.local.md` in the working directory or any
directory above (user/managed CLAUDE.md and `.claude/rules/` do not count). A subdirectory's
`AGENTS.md` loads on demand (on Read of a file there) if that subdirectory has none of the three
CLAUDE files. Other values: `claude-md-and-agents-md` (each directory's CLAUDE.md files first, its
AGENTS.md after them; an AGENTS.md already loaded through an import or symlink is skipped),
`claude-md` (CLAUDE.md only), `managed-only`. Support `--claude-instructions-mode` with the
default above. `@` imports are expanded inside AGENTS.md; `claudeMdExcludes` applies to it.
**[0-28]** Reading AGENTS.md directly needs Claude Code **v2.1.277+**; older versions and some
sessions ("can't read AGENTS.md") only see it via an `@AGENTS.md` import in a CLAUDE.md. Not read at
all: `AGENTS.local.md`, `AGENTS.override.md`, anything under `.agents/`. For an AGENTS.md read via
the setting, an `@` import outside the working directory loads **only if external imports were
already approved** (no prompt).

**Imports** (`@path`):
- "Relative paths resolve relative to the file containing the import, not the working directory."
  Absolute paths and `~` are allowed.
- Recursive, "maximum depth of four hops". The docs do not say whether a direct import is hop 0 or
  hop 1. Counting a direct import as hop 1: hops 1-4 load under both readings, hop 5 loads only if
  the count starts at 0, hop 6 and beyond never load. Model: hops 1-4 loaded; hop 5 loaded and
  marked `(unverified)`; hop 6+ not loaded (`depth`). (A security scan would rather read one file
  too many than miss one.) Third-party guides quoting "5 levels" disagree with the official page.
- Not parsed inside Markdown **code spans or fenced code blocks** ("wrap it in backticks to keep the
  text literal").
- A path ends at the first space; `\ ` escapes a space ("Without the backslashes, the path ends at
  the first space, even when the import is on a line of its own"). A path wrapped in quotes is **not**
  imported "with or without the backslashes".
- An import is **external when its path resolves outside the working directory** (**[0-28]** the
  *working directory*, not the repository root). First encounter in a project shows an approval
  dialog listing the files; if declined, the imports stay disabled and the dialog does not reappear.
  User-scope files (`~/.claude/CLAUDE.md`, `~/.claude/rules/`) load their imports without the
  dialog (except in Cowork sessions, which skip user-scope imports outside the working directory).
  Model as `load: always` + `note: external import requires approval` and report GR020. With the
  default `--cwd` = repo root, "outside the working directory" = "outside the repository";
  with a deeper `--cwd`, `../x.md` inside the repo is already external — report GR020 against the
  working directory and say so.
- Imported files load together with the importing file (same `load` state as the importer).

**Transforms**: block-level HTML comments (`<!-- … -->`) in CLAUDE.md files are **stripped** before
injection; "comments inside code blocks are preserved"; opening the file with the Read tool shows
them. Rule frontmatter is stripped. **[0-28] UNVERIFIED:** the docs say "in CLAUDE.md files" only;
whether stripping also applies to AGENTS.md read via the setting, to `.claude/rules/*.md` and to
imported files is not stated. Model stripping for CLAUDE.md / CLAUDE.local.md /
.claude/CLAUDE.md only, and treat the others as "seen" (`(unverified)`), so GR005 is never
downgraded on a guess. Inline (non block-level) comments: not documented → seen.
Files over **4 MiB** are skipped entirely at launch (`load: blocked`, note).
**[0-28]** On-demand files (subdirectory CLAUDE.md / CLAUDE.local.md and the files they import,
subdirectory rules, path-scoped rules) are truncated to the start with a note, over a per-file
limit that depends on the session's context window: **40,000 characters** (200K window);
**200,000** (1M window, Opus 4.6 / Sonnet 4.6) or **150,000** (1M window, later models). Applied
since v2.1.309. Do not model truncation; add a `note` on on-demand entries over 40,000 characters.

**Symlinks**: `.claude/rules/` supports symlinks (circular ones are handled). A symlink whose target
is outside the working directory is treated like an external import: it does not load until
external imports are approved, and afterwards only rules **without** `paths` load. UNC/network paths
(`\\server\share`, `/net`, `/Network`) are never followed. **[0-28]** `CLAUDE.md -> AGENTS.md`
symlinks are a documented pattern (Claude reads `CLAUDE.md` through the link).

**ghostrules symlink policy (v0.2.1, all agent models).** Links are resolved by hand, hop by hop,
and only inside the repository root; nothing is opened before the resolved path is known to be
inside it.
- A link whose **final target is a regular file inside the root** is an **alias**: the agent reads
  the target's content under the link's name (`CLAUDE.md → AGENTS.md (symlink)`). Chains are
  followed up to 8 hops, every hop inside the root, no cycles. The precedence rules apply to the
  link's name (a `CLAUDE.md` exists, so `AGENTS.md` is skipped), and the separate `AGENTS.md`
  entry is shown as skipped, "already read through CLAUDE.md (symlink)", so it is not counted
  twice. Imports in the target are resolved relative to the link's directory.
- Files under a **directory** link that stays inside the root (`.claude/rules/shared ->
  ../shared-rules`) are aliases by the same rule.
- A link that points **outside** the root (absolute or through `..`), is **broken**, loops or
  crosses more than 8 links is not read (GR025: `high` outside, `low` otherwise).
- Windows with `core.symlinks=false` checks a link out as a small text file holding the target's
  path; if an agent file's whole content is one relative path to an existing file, GR025 `info`
  notes that the agent reads only that path string.

**Out of scope, document as limitation [0-28]:** `claudeMdExcludes` (settings in user, project,
local or managed layers; absolute-path globs) can remove files from the context — ghostrules does
not read it, so `context` may list a file the agent skips. Also `--add-dir` with
`CLAUDE_CODE_ADDITIONAL_DIRECTORIES_CLAUDE_MD`, `--setting-sources`, and auto memory (`MEMORY.md`,
first 200 lines / 25 KB).

---

## copilot-cli
Source: GitHub Docs, "Adding custom instructions for GitHub Copilot CLI" —
https://docs.github.com/en/copilot/how-tos/copilot-cli/customize-copilot/add-custom-instructions
(re-checked 2026-10-28; no change to the 2026-10-27 draft except where marked).

**Repository and agent files**, in "standard locations" = repository root, current working directory,
intermediate directories between them, and directories nested in the path of a file Copilot is
working on:
- `.github/copilot-instructions.md` (repository-wide)
- `.github/instructions/**/*.instructions.md` (path-specific; standard locations "but not
  intermediate directories")
- `AGENTS.md`, `CLAUDE.md` (also `.claude/CLAUDE.md`), `GEMINI.md`

**User-level** (`--home`): `$HOME/.copilot/copilot-instructions.md`,
`$HOME/.copilot/instructions/**/*.instructions.md` (`COPILOT_HOME` replaces `$HOME/.copilot`).
`COPILOT_CUSTOM_INSTRUCTIONS_DIRS` (comma-separated directories; extra `AGENTS.md` and
`*.instructions.md`): ignore in v0.2 (env-dependent); mention in docs.

**Conditional**: `*.instructions.md` frontmatter `applyTo` (glob; several separated by commas) —
loaded only when it matches a file the CLI works with. `excludeAgent` (`"code-review"` or
`"cloud-agent"`; if omitted both use the file) — the page does **not** say how it affects the CLI;
record it in `note`, CLI still loads. Files can also be disabled by the user through `/instructions`
(not visible to a static scan; note as limitation).

**Imports**: `@` followed by a relative path works in `.github/copilot-instructions.md`, `AGENTS.md`
and `CLAUDE.md`; **not expanded** in `GEMINI.md` or `*.instructions.md`. "Copilot reads the file
immediately and supports references inside referenced files." Referenced files must stay inside the
repository (or inside the custom instructions directory for local instructions); **absolute and
`~/` paths are not loaded** (`load: blocked`). Relative-path base: **UNVERIFIED** (page does not say)
— assume relative to the importing file, mark unverified. Max depth: **UNVERIFIED** (page states no
limit) — use 4 and mark unverified. Code-span/code-block handling: **UNVERIFIED** — apply the same
rule as claude-code, mark unverified.

**Precedence**: none defined ("avoid conflicting instructions"); identical copies of user-level,
repository-wide and agent instructions are de-duplicated. Model as union.

**Transforms**: none documented ("only that whitespace between instructions is ignored") → assume
raw text (HTML comments are **seen**). Mark unverified.

---

## cursor
Source: Cursor docs, "Rules" — https://cursor.com/docs/context/rules (**[0-28]** fetched and read
for the first time; the 2026-10-27 draft was a guess). The `.cursorrules` and `.md` points below
come from a summarising fetch tool; re-read the page before shipping the `cursor` model.

**Rule types and frontmatter** (verified table: `alwaysApply` / `description` / `globs`):

| `alwaysApply` | `description` | `globs` | Behaviour | `load` |
|---|---|---|---|---|
| `true` | any | any | "Always included; globs and description ignored" | `always` |
| `false` | any | set | auto-attached "when a matching file is in context" | `conditional` |
| `false` | set | omitted | "Agent pulls the rule in when relevant" | `agent_decides` |
| `false` | omitted | omitted | only when @-mentioned in chat | `manual` |

**Locations**: project rules live in `.cursor/rules` as `.mdc`; subfolders are allowed ("Organize
rules in folders"). **Changed:** the page says "Project rules must use the `.mdc` extension" and that
a plain `.md` file there "is ignored by the rules system" (no frontmatter). So `.cursor/rules/*.md`
is **not** a rule: `context` lists it as `blocked` with `note: Cursor ignores .md files in
.cursor/rules`, but `scan` keeps scanning it (0.1 behaviour). `AGENTS.md`: "Cursor supports
AGENTS.md in the project root and subdirectories"; nested files combine with parent instructions,
"more specific instructions taking precedence" → `always` for root, `conditional`
(`reason: nested AGENTS.md, applies to files under <dir>`) for nested.

**Legacy `.cursorrules`**: the Rules page does not mention it → status **UNVERIFIED**; model as
`always` with `(unverified)` (conservative: scan it).

**Imports: none.** `@file` references in rules are **not expanded**: "The file's contents are not
inlined into the prompt"; the agent reads the file with its tools when needed. Do **not** model
them as imports for Cursor (no edges, no GR020–GR022 from Cursor). A file only referenced from a
rule is therefore not in Cursor's context.

**Transforms**: none documented; frontmatter is metadata → text seen = body. HTML comments:
UNVERIFIED → seen.

**Out of the repo, not modelled:** User Rules (Customize → Rules) and Team Rules (dashboard;
precedence Team → Project → User; "Enforce this rule" makes a rule required). Mention as a limitation
in `context` output: Team Rules may add instructions ghostrules cannot see. Size guidance: "Keep
rules under 500 lines" (no truncation documented).

---

## generic (AGENTS.md convention)
Source: https://agents.md (re-checked 2026-10-28).

**Documented:** the file goes at the repository root; large monorepos can add an AGENTS.md in each
package; "Agents automatically read the nearest file in the directory tree"; "The closest AGENTS.md
to the edited file wins; explicit user chat prompts override everything". It is plain Markdown with
no required fields. **No imports/includes mechanism and no transforms are described.**

**Not documented:** whether files higher in the tree are also read. So the model is:
- the nearest `AGENTS.md` to the target (or to `--cwd` when there is no target): `always`, verified;
- every other `AGENTS.md` between repo root and the target: `always` with `(unverified)` — modelled
  because a security scan must not miss them;
- `AGENTS.md` in directories off the path: `on_demand`.
No imports, no transforms (HTML comments are **seen**).

---

## codex
Sources, read 2026-10-29: https://developers.openai.com/codex/guides/agents-md (now served from
https://learn.chatgpt.com/docs/agent-configuration/agents-md) and the config reference.

**Documented:** Codex reads, per directory, **at most one file**: `AGENTS.override.md`, then
`AGENTS.md`, then each name in `project_doc_fallback_filenames` (a setting of `~/.codex/config.toml`);
"Codex uses only the first non-empty file". It starts at the project root (typically the Git root)
and walks down to the working directory, and "stops searching once it reaches your current
directory"; files closer to the working directory come later in the combined prompt. The global
scope is `~/.codex` (or `CODEX_HOME`): `AGENTS.override.md` first, then `AGENTS.md`, first non-empty
only. Empty files are skipped, and Codex "stops adding files once the combined size reaches" the
limit, `project_doc_max_bytes`, **32 KiB by default**. The chain is built once per run. **No imports
and no transforms are described.** Project-scoped `.codex/` layers (config, hooks, rules) load only
for a trusted project (`projects.<path>.trust_level`).

Model (`src/ghostrules/agents/codex.py`):
- global: the first non-empty of `~/.codex/AGENTS.override.md`, `~/.codex/AGENTS.md`; the other is
  `blocked` ("ignored");
- each directory from the root to `--cwd`: the first non-empty of override, `AGENTS.md`, the
  fallback names; the rest in that directory are `blocked` (ignored, or empty);
- nothing below `--cwd` and nothing in other branches is in the context;
- the combined size counts toward the limit (global files do not: the docs name only project
  instructions); a file that crosses it is `always` with a note and `(unverified)` ("may be
  truncated"), later ones are `blocked`;
- no imports; HTML comments are not documented either way, so they count as seen.
**UNVERIFIED:** whether the global files count toward the limit; whether `project_doc_fallback_filenames`
set in a project `.codex/config.toml` is honoured (the docs name the user-level file only, so only
that one is read); how a file that crosses the limit is cut.

## gemini-cli
Sources, read 2026-10-29: https://geminicli.com/docs/cli/gemini-md/ and
https://geminicli.com/docs/reference/configuration/.

**Documented:** the CLI "concatenates the contents of all found files" from `~/.gemini/GEMINI.md`
(global), the workspace directories and their parents, and, "just in time", the directories a tool
touches and their ancestors "up to a trusted root". `@file.md` lines import files ("supports both
relative and absolute paths"). `context.fileName` in `settings.json` (a name or a list) changes the
file names; `.gemini/settings.json` in the project overrides the user's. **Not documented:** import
depth, cycles, whether imports are processed inside code blocks, what a "trusted root" is.

Model (`src/ghostrules/agents/gemini_cli.py`): global files, then each directory from the root to
`--cwd` for every configured name (`always`), then the same names in other directories (`on_demand`,
`condition` = the directory). Imports are followed to 4 hops and **all are `(unverified)`**; a path
outside the tree is recorded and never read. No transforms are described.

**Security settings (rules, not context).** Gemini's reference has no `yolo` key (YOLO is a command
line flag, `security.disableYoloMode` can forbid it); the settings that skip confirmation are
`tools.allowed` entries such as a bare `run_shell_command`, `security.enablePermanentToolApproval`
and `mcpServers.<name>.trust`. GR107 and GR108 cover them. The older `yolo` check stays.

The two models are **opt-in** (`agents = ["claude-code", "codex"]` or `context --agent codex`): adding
an agent to the default would change every existing lockfile.

## Prior art for import-aware scanning (searched 2026-10-28, corrected 2026-10-29)
The 2026-10-28 search concluded that no tool resolved `@` imports. **That was wrong**: cfgaudit has
scanned the files that Claude Code instruction files import with `@path` since commit `5099798`
(2026-10-24, "scan files that Claude Code instruction files import with @path, add CFG116"). Others
also overlap with parts of ghostrules: agnix parses `@` imports and import cycles, Claude Code's own
`/context` shows the memory files actually loaded, and cairnlock locks agent files and checks the
lock against a git ref (`cairnlock verify --base origin/main`). rulesentry and promptwarden also
scan for hidden Unicode, and AgentShield, Cisco's skill-scanner and Snyk's agent-scan cover agent
configuration, MCP servers and skills. Verified on 2026-10-29 from their repositories' descriptions
and, for cfgaudit and cairnlock, one commit and one README; the others were not read in depth.

What ghostrules adds on top of these is narrower than "nobody does this": a context model for
several agents (conditional rules, precedence, on-demand loading, what each agent strips, symlink
aliases) that runs offline, in CI, before an agent runs, and a lock of the resolved text each agent
receives. Details and the original table are in `docs/DECISIONS.md` ("v0.2 Phase 0").

---

## Out of scope for v0.2 (document as roadmap)
Windsurf, Cline/Roo, Junie, Kiro, Continue, Aider (Codex CLI and Gemini CLI have models since 0.4).
Their files are still scanned by `scan` exactly as in 0.1; they just have no `context` model yet.
Adding one = one module + one section here + tests (put this in CONTRIBUTING.md).
