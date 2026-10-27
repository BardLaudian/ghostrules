# ghostrules

*Find the instructions your AI agent sees but you don't.*

`ghostrules` scans a repository (and optionally your machine) for hidden instructions and risky
configuration in the files AI coding agents read and obey: `AGENTS.md`, `CLAUDE.md`,
`.cursorrules`, Copilot instructions, skills, MCP configs and more.

It is a defensive tool: it only reads files and reports findings. It never executes anything it
finds and never makes network requests.

> Work in progress (pre-0.1.0). The full README lands in the final phase.

## Usage

```bash
pip install -e ".[dev]"                    # from a checkout, for now

ghostrules scan .                          # scan the current repo (`scan` is the default command)
ghostrules scan examples/poisoned-repo     # a defanged demo that must find issues
ghostrules scan --home                     # also your user-level agent configs (read-only)
ghostrules reveal AGENTS.md                # show invisible characters and the text they hide
ghostrules clean AGENTS.md                 # dry run: diff of what would be removed
ghostrules clean AGENTS.md --write         # remove it (keeps AGENTS.md.ghostrules.bak)
ghostrules rules                           # list every rule
```

| `scan` option | Default | Meaning |
|---|---|---|
| `PATH ...` | `.` | Files or directories to scan |
| `--format` | `table` | `table`, `json`, `sarif` or `markdown` |
| `-o, --output FILE` | stdout | Write the report to a file |
| `--fail-on` | `high` | Exit 1 if a finding is at least this severe (`none` to never fail) |
| `--min-severity` | `low` | Hide findings below this severity |
| `--all-files` | off | Check every text file for hidden Unicode, not just agent files |
| `--home` | off | Also scan user-level agent configs |
| `--disable GR010,GR012` | | Disable rules |
| `--config FILE` | auto | Config file (default: `.ghostrules.toml` in the scan root) |
| `--no-color` | off | Plain output |

Exit codes: `0` nothing at or above `--fail-on`, `1` findings at or above it, `2` usage or
runtime error (including a rule that crashed or a path that does not exist).

Secrets are never printed: tokens are shown masked, as in `ghp_****…a1b2`, in every format.
