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

### GR011 — Concealment from the user (high)
`do not (tell|inform|mention|show|reveal)( this)? (to )?the user`, `without (telling|asking|notifying) the user`,
`(silently|secretly|quietly) (run|execute|add|send|install|modify)`, `don't mention (this|these)`,
`hide (this|the) (from|output)`, ES: `no (se lo )?(digas|menciones|muestres) al usuario`, `sin avisar al usuario`.

### GR012 — Remote code execution patterns (critical in instructions, high elsewhere)
`curl … | (ba|z)?sh`, `wget … -O- | sh`, `curl … | python`, `iwr|Invoke-WebRequest … | iex`,
`powershell … -e(nc|ncodedcommand) <base64>`, `base64 (-d|--decode) … | (ba)?sh`,
`bash <(curl …)`, `eval "$(curl …)"`. Snippet must show the full command.

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
`Keychain`, browser cookie stores, `/etc/shadow`, combined with a read/print/cat/send verb within
60 chars. Negative test: "Never commit .env files" must NOT fire.

### GR015 — Encoded payloads (medium → high)
Base64 runs ≥ 60 chars (or hex ≥ 80) in instruction files. Decode; if the result is mostly
printable text → high and put it in `decoded` (and scan it with GR010–GR014). Skip data URIs of
images and things inside fenced code blocks labelled with a language other than shell.

### GR016 — Agent safety bypass (high)
`--dangerously-skip-permissions`, `bypassPermissions`, `--yolo`, `yolo mode`, `auto[- ]?approve (all|every)`,
`always (allow|approve|accept) (all )?(commands|tools|edits)`, `disable (the )?(sandbox|safety|guardrails)`,
`never ask (for )?(permission|confirmation)`, ES: `sin pedir (permiso|confirmación)`.

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

## Severity calibration targets (acceptance)
- `examples/clean-repo` (realistic AGENTS.md, CLAUDE.md, .mcp.json with `${GITHUB_TOKEN}`, pinned
  packages, settings with narrow allow-list): **0 findings**.
- `examples/poisoned-repo`: at least one finding for every rule, and the top of the table shows the
  decoded hidden instruction from GR001.
