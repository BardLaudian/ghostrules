# Threat model

What `ghostrules` protects, from whom, where it trusts and where it does not, and what it does
**not** detect. The rules are in [RULES.md](RULES.md); the known limits are summarised in
[USAGE.md](USAGE.md#limits). This file is the reasoned version of both.

## What is protected

| Asset | Why it matters |
|---|---|
| The agent's context: instruction files, imports, skills, hook scripts, MCP and agent settings | Whatever the agent reads, it may obey. A change nobody can read is a change nobody reviewed. |
| Secrets and files on the developer's machine and in CI (tokens, `.env`, SSH keys) | The usual goal of a poisoned instruction is to read or send them. |
| The reviewer's attention | A tool that reports too much gets switched off, so false positives are a cost to the asset, not a nuisance. |
| The integrity of the scan itself | A scanner that can be crashed, slowed down or talked out of a finding gives false assurance. |

## Who attacks

| Attacker | Capability | Typical goal |
|---|---|---|
| Contributor to a repository (pull request) | Edits any file in the change, including `.ghostrules.toml`, ignore comments and the lock | Get an instruction into an agent's context that the reviewer cannot see, or switch the scanner off for it |
| Author of a dependency, template, skill or shared rules file | Controls a file that others import or copy | Plant a payload that arrives indirectly (an `@path` import, a skill, a hook script) |
| Author of a hostile file a user scans | Controls the bytes the scanner parses | Crash it, make it slow, escape a report (terminal, Markdown, SARIF), or make it read or run something |
| Someone with a leaked token or a hijacked account | Can push as a maintainer | Out of scope: see non-goals |

## Trust boundaries

1. **Scanned content is untrusted.** Everything under the scan root is data. It is parsed, never
   executed, imported, downloaded or evaluated, and no network request is made
   (`tests/test_no_network.py`).
2. **The scan root is the boundary for reading.** An `@path` import is resolved inside the root and
   never above it. A symbolic link whose target leaves the repository is reported (GR025) and not
   read. A credentials file named by an import (`.env`) is reported (GR021) and stays unread.
3. **The configuration is trusted only when it comes from before the change.** On a pull request
   `.ghostrules.toml`, `[tool.ghostrules]` and `ghostrules-ignore` comments can be taken from the
   base commit (`--config-from-ref`, `--suppressions-from-ref`; the Action does it by default), and
   a change to them is itself a finding (GR030).
4. **The lock is a visibility control.** `lock --check --base REF` compares with the lock at the base,
   so a change cannot re-bless itself. Someone accountable still has to approve the diff.
5. **Git is the only subprocess.** Only `git rev-parse` and `git cat-file` run, with fixed arguments.
6. **Output is untrusted too.** Every string a report prints passes one masking step for secrets and
   one that renders control and invisible characters as visible tokens.

## Attacks on the scanner itself

| Attack | Defence | Evidence |
|---|---|---|
| Huge or pathological file (ReDoS, 3 MB without spaces) | Size limit (`max_file_size`, 1 MiB, with a visible warning when a file is skipped); property and fuzz tests on the parsers | `tests/test_robustness_limits.py`, `tests/test_robustness_*.py`, [PERFORMANCE.md](PERFORMANCE.md) |
| A rule that raises on crafted input | The failure is an error in every report and exit code 2, never a silent skip | `tests/test_robustness_limits.py` |
| Import chains, cycles, very deep imports | Bounded depth, cycle detection (GR023), "too deep" reported | `tests/test_scan_imports.py` |
| Symlink out of the tree, symlink loops | Not followed outside the root; reported (GR025) | `tests/test_symlink_alias.py` |
| Unicode evasion (zero-width inside a word, soft hyphen, fullwidth, homoglyphs) | Text is normalised before matching and the offset map is kept | `tests/test_evasion_regressions.py` |
| Escape sequences or Markdown in a finding | Output sanitising in every reporter | `tests/test_output_contract.py` |
| Secret in a finding | One masking step; a test searches every format | `tests/test_demo.py`, `tests/test_lock.py` |
| Config or ignore comment in the PR that hides its own payload | Trusted config and suppressions from a ref; GR030 | `docs/USAGE.md` "Scanning a pull request" |
| A malformed config | Fails with `file:line`, exit 2, never ignored | `tests/test_config_errors.py` |

## Assumptions

- The reviewer reads what the report shows. `ghostrules` makes hidden text visible; it does not
  replace the review.
- The base branch is protected: only reviewed changes reach it. If an attacker can push to the base,
  the "trusted config" is the attacker's.
- The agent models follow each agent's public documentation. Where the documentation is silent they
  say `(unverified)`.
- Python, `git` and the installed package are not compromised. Releases carry attestations
  (verification is described in `SECURITY.md` once published).

## Non-goals: what it does not detect

These are limits by design, not bugs. Several have a bench case listing the miss
([bench/RESULTS.md](../bench/RESULTS.md)).

| Not detected | Why | Related |
|---|---|---|
| Malicious instructions that share no words with the patterns (a paraphrase of "send the environment to this address") | Detection is lexical, not semantic. No model understands the text | GR010, GR011, GR013, GR014; USAGE "Limits" |
| Languages other than English, Spanish and French | The patterns exist only for those | GR010-GR016 |
| A command split across lines or built from variables and aliases | GR012 does not emulate a shell | GR012, GR112, GR113 |
| A secret without a known format | Secrets are matched by format and context | GR017, GR101 |
| MCP tool descriptions served by a running server | Nothing is started or fetched | `bench` case `mcp-server-content` |
| Files an agent reads that nothing in the repository points to, or that live outside it (Cursor user and team rules, managed policy, `--add-dir`) | The scanner sees only the tree it is given | AGENT_MODELS.md |
| Whether a legitimate-looking instruction is wise ("always run `make deploy`") | Intent is the reviewer's call | |
| Vulnerabilities in the code an agent writes, or in your dependencies | Not a code or dependency scanner; not a general secret scanner | |
| A compromised maintainer, base branch or CI runner | Out of scope for a file scanner | |
| Behaviour at run time: what an agent actually does with a file | Static only | |
| Instructions in files no agent model covers | Unknown agents are scanned by name patterns only | `docs/AGENT_MODELS.md` |

"No findings" is therefore never "safe": it means none of the listed patterns matched in the files
the model says the agent reads.

## Reporting gaps

A miss is a normal issue (the "New rule proposal" template). A way to crash the scanner, make it
read, run or send something, or leak a secret through it, is a vulnerability: see
[SECURITY.md](../SECURITY.md).
