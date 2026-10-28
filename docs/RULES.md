# ghostrules — Rule catalog (v0.1)

Conventions: `GR0xx` = content of instruction files (and any file with `--all-files` for GR001–GR006).
`GR1xx` = MCP / agent configuration files. Every rule: ≥1 positive and ≥1 negative test.
Patterns are case-insensitive unless noted. Keep false positives low: a noisy scanner gets no stars.

---

## Hidden / invisible content

### GR001 — Unicode tag characters (critical)
Chars in U+E0000–U+E007F. Used to smuggle ASCII text that models read but humans can't see
("ASCII smuggling"). **Decode** runs of tag chars (`chr(cp - 0xE0000)`) and put the result in
`Finding.decoded`. One finding per contiguous run. Exception: valid emoji flag tag sequences
(U+1F3F4 followed by tags and U+E007F) → ignore.

### GR002 — Bidirectional control characters (high)
U+202A–U+202E, U+2066–U+2069, U+200E, U+200F, U+061C ("Trojan Source"). Medium instead of high
if the file contains substantial RTL script (Arabic/Hebrew) — legitimate use.

### GR003 — Zero-width / invisible formatting characters (medium → high)
U+200B, U+200C, U+200D, U+2060, U+2061–U+2064, U+180E, U+FEFF (not at file start), U+00AD.
Severity high if ≥ 5 in one line or ≥ 20 in the file (likely binary-encoded payload), else medium.
Ignore U+200D between emoji code points (emoji ZWJ sequences) and U+200C/U+200D next to
Indic/Persian letters.

### GR004 — Variation-selector steganography (high)
Runs of ≥ 3 chars in U+FE00–U+FE0F or U+E0100–U+E01EF not directly following an emoji / CJK base.
(Known technique to hide bytes after a single visible char.) Try to decode as bytes
(FE00–FE0F → 0–15, E0100–E01EF → 16–255) and show printable result in `decoded`.

### GR005 — Hidden HTML comments with instructions (medium / high)
`<!-- ... -->` blocks in markdown instruction files are invisible when rendered on GitHub.
Report **only** if the comment body is ≥ 40 chars and either matches any GR010–GR016 pattern
(→ high, include which) or contains imperative agent-directed language
(`you must`, `always`, `never`, `assistant`, `AI`, `agent`, `model`) (→ medium).
Plain short comments (TODOs, lint directives) are ignored.

Agent-aware (since 0.2): the finding lists which modelled agents see the comment. Claude Code strips
block-level comments from `CLAUDE.md`, `CLAUDE.local.md` and `.claude/CLAUDE.md` before the model
sees them, so a comment there is *not seen by* claude-code; Copilot CLI and the others are assumed
to see it. If no configured agent sees it the finding is info ("stripped by claude-code before
reaching the model"); otherwise the severity is unchanged. Where stripping is not documented
(AGENTS.md, rules, imported files) the comment counts as seen. Set `agents = ["claude-code"]` to
model a team that only uses Claude Code.

### GR006 — Mixed-script homoglyph words (low)
A single word mixing Latin with Cyrillic/Greek lookalikes (e.g. `pаypal` with Cyrillic а) inside
instruction files or URLs. Low severity, but upgrade to high if inside a URL/domain.

---

## Malicious instructions (natural language, English + Spanish)

Implementation: a table of regexes per rule in `rules/injection.py`. Match per line, but also run
over a whitespace-normalized version of the whole file so phrases broken across lines still match.
Text revealed by GR001/GR004 decoding must ALSO be scanned by GR010–GR016 (report with
`decoded` context and +1 severity bump, capped at critical).

### GR010 — Instruction override (high)
`ignore (all )?(previous|prior|above|earlier) (instructions|rules|prompts)`,
`disregard (the |all )?(previous|above|system)`, `forget (everything|your instructions)`,
`new (system )?instructions:`, `you are now (in )?(developer|dan|jailbreak)`,
`override (the )?(system|safety)`, ES: `ignora (todas )?las instrucciones (anteriores|previas)`,
`olvida (tus|las) instrucciones`.
Negative: documentation *about* prompt injection inside fenced code blocks marked as examples is
still reported but at `low` with message "appears inside a code block".

### Directive, descriptive and example text (GR011, GR014, GR016; v0.2.1)
These three rules match phrases that are just as common in prose that *describes* something. Each
match is classified by the sentence around it (`src/ghostrules/rules/directive.py`):

| Kind | What it is | Severity |
|---|---|---|
| directive | An imperative sentence or clause ("Read …", "Always send …", "Silently run …"), "you must/should …", anything that does not start like a description, and **all decoded hidden text** | the rule's normal severity |
| descriptive | A third-person description ("The scripts read …", "Claude then uses …", "With `~/.npmrc` moved aside it exits 1") | at most medium |
| example | Inside a fenced block or in quotes, or a sentence introduced by "e.g.", "for example", "such as", "a skill that …", "… instructs the agent to …" | at most low |

Text decoded from hidden characters is always a directive and keeps the +1 bump (critical).
Inline code does not make a match an example: `` Run `claude --yolo` `` is read as "Run …". A lowered
finding says so in its message. GR010 and GR012 have their own context rules and do not use this.

### GR011 — Concealment from the user (high)
`do not (tell|inform|mention|show|reveal)( this)? (to )?the user`, `without (telling|asking|notifying) the user`,
`(silently|secretly|quietly) (run|execute|add|send|install|modify)`, `don't mention (this|these)`,
`hide (this|the) (from|output)`, ES: `no (se lo )?(digas|menciones|muestres) al usuario`, `sin avisar al usuario`.
Not concealment, and not reported: "do not tell the user **to** …", "… **which|what|how|where|when|why**
…" and "… **that** …" unless it is "that you …": these say what to tell the user. "Do not tell the
user about this", "Do not tell the user." and "Do not tell the user that you did it" are.

### GR012 — Remote code execution patterns (context-aware in instructions, high elsewhere)
`curl … | (ba|z)?sh`, `wget … -O- | sh`, `curl … | python`, `iwr|Invoke-WebRequest … | iex`,
`powershell … -e(nc|ncodedcommand) <base64>`, `base64 (-d|--decode) … | (ba)?sh`,
`bash <(curl …)`, `eval "$(curl …)"`. Snippet must show the full command.

Stdin counts as code only when the interpreter reads its **program** from it (v0.2.1). `… | python`,
`… | python3 -` and `… | sh` / `bash -s` are matched; `… | python -c '…'`, `-m module`, `script.py`,
`… | sh -c '…'`, `… | node -e '…'` and `… | jq …` use stdin as data and are not.

Severity in instruction files (since 0.1.1). Decide in this order; first match wins:

| # | Situation | Severity |
|---|---|---|
| 1 | Match is inside decoded hidden text (GR001/GR004/GR015) | critical (the +1 bump) |
| 2 | No URL to judge: `base64 -d … \| sh`, `powershell -enc <b64>`, `eval "$(curl …)"` with a variable/unknown target | critical |
| 3 | Any URL uses `http://`, an IP literal, a non-default port, or a known collector domain (GR013 list) | critical |
| 4 | Every URL is in `allow_domains` | not reported |
| 5 | Every URL is a known installer, visible text, inside a fenced code block or inline code span | low |
| 6 | Every URL is a known installer, visible text, in prose | medium |
| 7 | Unknown domain, visible text, inside a code block or inline code span | high |
| 8 | Unknown domain, visible text, in prose | critical |

A command with no URL that is not case 2 (`curl $URL \| sh`) counts as an unknown domain. With
`trust_known_installers = false`, rows 5-8 collapse to critical, as in 0.1.0.

Why: a visible, well-known installer in a code block is documentation a human reviewer can see and
judge; an unknown domain in prose telling the agent to run it is the attack pattern.

Known installers (`src/ghostrules/rules/known_installers.py`, `ghostrules rules --installers`).
Matching is the exact `https` host plus an optional path prefix, never a suffix, so
`astral.sh.attacker.example` does not match: Astral uv/ruff `astral.sh`, rustup `sh.rustup.rs`,
Bun `bun.sh`, Deno `deno.land`, pnpm `get.pnpm.io`, Poetry `install.python-poetry.org`, Homebrew
`raw.githubusercontent.com/Homebrew/install/`, nvm `raw.githubusercontent.com/nvm-sh/nvm/`, SDKMAN
`get.sdkman.io`, Docker `get.docker.com`, Ollama `ollama.com/install.sh`, Volta `get.volta.sh`,
Claude Code `claude.ai/install.sh`.

GR105 and GR107 reuse the GR012 patterns for MCP server commands and hooks and are not affected:
in configuration files a piped installer stays high/critical.

### GR013 — Data exfiltration (critical)
- Markdown image/link whose URL contains a template or variable in the query:
  `!\[[^\]]*\]\(https?://[^)]*[?&][^=]+=(\{|\$|%7B|<)` → classic markdown-image exfil.
- Instructions to send/post/upload/append secrets: verbs (`send|post|upload|append|include|exfiltrate|forward`)
  within 80 chars of (`env|environment variables|\.env|secret|token|api key|credentials|ssh key|password`)
  and a URL.
- Known collector domains anywhere in instruction files: `webhook.site`, `requestbin`, `pipedream.net`,
  `ngrok(-free)?.(io|app)`, `interact.sh`, `oast.(fun|pro|live|site|online|me)`, `burpcollaborator.net`,
  `beeceptor.com`, `hookbin.com`, `canarytokens`. (high if only domain, critical if combined with above)
Respect `allow_domains` from config.

### GR014 — Sensitive file access (high)
Instruction text referencing `~/.ssh`, `id_rsa`, `id_ed25519`, `.aws/credentials`, `.env`
(as a file to read/send, not "add .env to .gitignore"), `.npmrc`, `.pypirc`, `.netrc`, `kubeconfig`,
`Keychain`, browser cookie stores, `/etc/shadow`, combined with a read/print/cat/send verb that
governs the path: same clause (no `;` or sentence end between them) and at most six words apart
(v0.2.1; it was "within 60 chars"). Negative test: "Never commit .env files" must NOT fire. Template
files (`.env.example`, `.env.sample`, `.env.template`, `.env.ai-surfaces.example`, `*.example`) are not
secrets and never fire (the same list as GR021). Severity by directive / descriptive / example (above).

### GR015 — Encoded payloads (medium → high)
Base64 runs ≥ 60 chars (or hex ≥ 80) in instruction files. Decode; if the result is mostly
printable text → high and put it in `decoded` (and scan it with GR010–GR014). Skip data URIs of
images and things inside fenced code blocks labelled with a language other than shell.

### GR016 — Agent safety bypass (high)
`--dangerously-skip-permissions`, `bypassPermissions`, `--yolo`, `yolo mode`, `auto[- ]?approve (all|every)`,
`always (allow|approve|accept) (all )?(commands|tools|edits)`, `disable (the )?(sandbox|safety|guardrails)`,
`never ask (for )?(permission|confirmation)`, ES: `sin pedir (permiso|confirmación)`.
Severity by directive / descriptive / example (above): "Run with `--dangerously-skip-permissions`" is
high, "The test harness runs Claude with `--permission-mode bypassPermissions`" is medium, a fenced
`claude --dangerously-skip-permissions` is low.

---

## MCP / agent configuration (JSON/TOML parsed; report line numbers by locating the key in text)

### GR101 — Hardcoded secret in agent config (critical)
In MCP server `env`, `args`, `headers`, `url` query, or `.claude/settings*.json` `env`:
known formats — `ghp_|gho_|ghu_|ghs_|ghr_` + 36, `github_pat_\w{22,}`, `sk-ant-[\w-]{20,}`,
`sk-(proj-)?[A-Za-z0-9_-]{20,}`, `AKIA[0-9A-Z]{16}`, `xox[baprs]-[\w-]{10,}`, `AIza[\w-]{35}`,
`glpat-[\w-]{20}`, `hf_[A-Za-z0-9]{30,}`, `npm_[A-Za-z0-9]{36}`, Slack/Discord webhooks,
`Bearer <long token>`; plus generic: key name matches `(?i)(token|secret|key|password|passwd|auth)`
and value has length ≥ 16 and Shannon entropy ≥ 3.5 and is not `${VAR}` / `$VAR` / `<placeholder>`
/ `your-...-here` / all-same-char. **Always mask** (`first 4 + **** + last 4`).

### GR102 — Unpinned package execution (medium)
`command` in (`npx`, `bunx`, `pnpm dlx`, `yarn dlx`, `uvx`, `pipx run`) where the package arg has no
version (`pkg`, `pkg@latest`, `git+https://...` without commit SHA). Pinned `pkg@1.2.3` / `pkg==1.2.3` is OK.
Fix hint: pin an exact version.

### GR103 — Insecure remote MCP transport (high)
`url` / `serverUrl` with `http://` to a non-loopback host (`localhost`, `127.0.0.0/8`, `::1` are OK).

### GR104 — Overly broad filesystem scope (medium)
Filesystem-like servers (name/package contains `filesystem`, `fs`, `files`) whose args include
`/`, `~`, `$HOME`, `%USERPROFILE%`, `C:\\`, `/Users`, `/home` exactly (root of home or disk).

### GR105 — Shell wrapper / remote fetch in server command (high → critical)
`command` is `bash|sh|zsh|cmd|powershell|pwsh` with `-c` / `/c` / `-Command` → high;
critical if the command string also matches GR012.

### GR106 — Dangerous Docker options (high)
`command: docker` with args containing `--privileged`, `-v /:/…`, mounting `/var/run/docker.sock`,
`--network host`, `--pid host`, `--cap-add SYS_ADMIN`.

### GR107 — Over-permissive agent settings (high)
`.claude/settings*.json`: `permissions.defaultMode == "bypassPermissions"`; `permissions.allow`
containing `Bash`, `Bash(*)`, `Bash(curl:*)`, `Bash(sudo:*)`, `Bash(rm:*)`, or `WebFetch` without domain;
`hooks` whose command matches GR012/GR013 (→ critical).
Other agents: equivalent keys if trivial to support (e.g. Gemini `"yolo": true`), otherwise skip.

### GR108 — Auto-enable project MCP servers (medium)
`enableAllProjectMcpServers: true` in settings, or equivalent auto-trust flags. Explains that any
cloned repo's `.mcp.json` would start servers without review.

---

## Import graph (0.2)

Agents build their context by following `@path` imports, so these rules look at every modelled
agent's context (`docs/AGENT_MODELS.md`), not only at a fixed list of files. Findings sit on the
importing line, and nothing an import points at outside the repository is ever read. Files an
import reaches are scanned as instruction files and their findings carry the chain
(`via CLAUDE.md:12 → docs/style.md:3`) and the agents that load them. An `ghostrules-ignore` marker
in the importing file never silences a finding in the imported file: markers only apply to the
file they are written in.

### GR020 — External import (high)
An `@path` import that resolves outside the repository: an absolute path, `~/…`, or `../` climbing
above the root. Claude Code asks for a one-time approval (an earlier approval silently covers new
imports); Copilot CLI does not load it. The message names the agents affected. Info when the
importing file is user-level (`~/.claude/CLAUDE.md`).

### GR021 — Sensitive file imported into context (critical)
An import whose target is a credentials file: `.env`, `.env.*` (not `.example`, `.sample`,
`.template`, `.dist`), anything under `.ssh/`, `id_rsa*`, `id_ed25519*`, `.aws/credentials`,
`.npmrc`, `.pypirc`, `.netrc`, kubeconfig, `*.pem`, `*.key`, `credentials.json`, `secrets.*`.
Importing it sends the secret to the model provider with every prompt. The file is never read. High
when the import itself is uncertain (inside an HTML comment, or after punctuation).

### GR022 — Import that silently does not load (low)
An `@path` the agent ignores: the file does not exist, is a directory, is deeper than the depth
limit, is wrapped in quotes, or is cut at an unescaped space (`@Design Docs/a.md`; the finding says
to write `@Design\ Docs/a.md`). Only tokens that look like an intended file reference are reported
(v0.2.1): a file extension (`@docs/missing.md`), a prefix `./`, `../`, `~/` or `/` (`@./notes`), or
a first path segment that exists next to the importing file (`@docs/missing` with a `docs/`
directory). `@alice` is a mention and `@types/node`, `@n8n/design-system` are npm scopes: none is
reported.

### GR023 — Import cycle (info)
`A → B → A`, reported once on the import that closes the loop. Agents stop at the depth limit.

### GR024 — Payload reached only through an import (tag)
Not a detector. A GR001–GR016 finding in a file that is not itself an agent file and is reached only
through imports gets the tag `reached-via-import` and the import chain in `via`. This is what makes
a payload hidden in an imported file visible. Adding `GR024` to `disable` (or `--no-follow-imports`)
stops ghostrules from scanning imported files.

### GR025 — Symlinked instruction source (high outside the repository, low broken or cyclic, info checked out as text)
An instruction file, imported file or rules directory that is a symlink the agent would follow but
ghostrules cannot (v0.2.1). A symlink whose final target is a regular file inside the repository is
an **alias** (`CLAUDE.md -> AGENTS.md`): the agent reads the target under the link's name, ghostrules
scans it once, and **no finding** is produced.
- `high`: a hop points outside the repository root (absolute, or through `..`). Claude Code treats
  such links like external imports. The target is never read.
- `low`: the link is broken, part of a cycle, or crosses more than 8 links.
- `info`: a file whose whole content is one relative path to an existing file in the repository
  (`CLAUDE.md` containing `AGENTS.md`): probably a symlink checked out as text (Windows with
  `core.symlinks=false`); the agent will read only that path string.

## Severity calibration targets (acceptance)
- `examples/clean-repo` (realistic AGENTS.md, CLAUDE.md, .mcp.json with `${GITHUB_TOKEN}`, pinned
  packages, settings with narrow allow-list): **0 findings**.
- `examples/poisoned-repo`: at least one finding for every rule, and the top of the table shows the
  decoded hidden instruction from GR001.
