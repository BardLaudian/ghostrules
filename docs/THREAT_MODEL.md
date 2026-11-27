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
| Secret in a finding | One masking step; a test searches every format | `tests/test_lock.py` |
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

These are limits by design, not bugs. Several are listed in the limits of USAGE.md.

| Not detected | Why | Related |
|---|---|---|
| Malicious instructions that share no words with the patterns (a paraphrase of "send the environment to this address") | Detection is lexical, not semantic. No model understands the text | GR010, GR011, GR013, GR014; USAGE "Limits" |
| Languages other than English, Spanish, French, German and Portuguese, and any language for a rule that has not been extended | Patterns exist only for those, and only some rules cover all five | GR010-GR016, GR031-GR035 |
| A command split across lines or built from variables and aliases | GR012 does not emulate a shell | GR012, GR112, GR113 |
| A secret without a known format | Secrets are matched by format and context | GR017, GR101 |
| MCP tool descriptions served by a running server | Nothing is started or fetched | |
| Files an agent reads that nothing in the repository points to, or that live outside it (Cursor user and team rules, managed policy, `--add-dir`) | The scanner sees only the tree it is given | AGENT_MODELS.md |
| Whether a legitimate-looking instruction is wise ("always run `make deploy`") | Intent is the reviewer's call | |
| Vulnerabilities in the code an agent writes, or in your dependencies | Not a code or dependency scanner; not a general secret scanner | |
| A compromised maintainer, base branch or CI runner | Out of scope for a file scanner | |
| Behaviour at run time: what an agent actually does with a file | Static only | |
| Instructions in files no agent model covers | Unknown agents are scanned by name patterns only | `docs/AGENT_MODELS.md` |

"No findings" is therefore never "safe": it means none of the listed patterns matched in the files
the model says the agent reads.

## Known limitations

Open gaps that a determined author can use today. They are not fixed because each fix would flag
ordinary text in the real-world scans (`tests/realworld/v2/README.md`).

- **An evasion left open: an own-service default that the environment can override (GR110).**
  `os.environ.get("APIFY_BASE_URL", "https://api.apify.com")` followed by a send of `APIFY_TOKEN` is
  read as the service's own call, because the file spells out its own domain. Whoever controls that
  variable (a `.env` in the repository, a CI setting) gets the token, and the scanner does not read
  the environment. A host the file spells out that is not the service's own domain is reported:
  `apify.com` and `api.apify.com` pass, `apify.evil.example` does not. A host that is unknown is
  reported too.
- **Languages.** Patterns exist for English, Spanish, French, German and Portuguese, and not every
  rule covers all five. In any other language, or in a paraphrase with none of the listed words, the
  attack is not seen. The detection is lexical.
- **A payload spread over sections.** GR035 weighs one paragraph. An action in one section, a
  remote target in another and "do not mention it" in a third are three harmless paragraphs. The
  same holds for an instruction split between two files.
- **Framing that exempts.** A skipped review is not reported when the user asks for it or a mode
  names it, unless what is skipped is the review of the agent files, the lock or ghostrules (GR031).
  A hidden-text cue in a paragraph that talks about attacks ("for example", "attackers") is not
  reported (GR035). Both can be used to dress an order up as a description of one.
- **The numbers are not recall.** Blind set v1 and the 91 real repositories (51 of the first
  round and 40 of the second) were used to adjust the rules, so they no longer measure anything. v1
  was written without seeing the rules, but it has been read since; the real repositories hold no
  attack at all, so they measure false positives only, and only before the fixes made from them.
  A new, unseen set is needed for a fresh figure.

## Blind measurement

The rules were tuned on a labelled corpus the rule author wrote, so its numbers say nothing about inputs
the author did not think of. To measure that, a set of cases was written by someone who had **not seen the
rules**, and the scanner was run on it without changing anything.

**Method.** 60 cases: 30 attacks and 30 benign twins (`tests/holdout/holdout-v1.jsonl`, SHA-256 recorded
next to it, 11 attack families). Every benign twin shares its topic and vocabulary with an attack: a
security document that quotes an injection phrase, a prohibition, a policy, a legitimate use of the same
characters. Each case is one file at the path its name implies, scanned with the default configuration
(`scripts/holdout_eval.py`). "Visible" means a finding at `medium` or above in the default output, which is
the strict reading (`low` is printed by default but easy to miss). Wilson 95 % intervals; with 30 cases
per label the intervals are wide.

**Result of v1** (code of `62145d6`, before the second detection round):

| | attacks seen at medium+ | 95 % interval |
|---|---|---|
| all 30 attacks | 11 (36.7 %) | 21.9 – 54.5 % |
| seen anywhere in the default output (`low` counts) | 13 (43.3 %) | 27.4 – 60.8 % |
| fails the default `--fail-on high` check | 10 (33.3 %) | 19.2 – 51.2 % |
| benign twins with a finding at medium+ (false positives) | 2 of 30 (6.7 %) | 1.8 – 21.3 % |
| benign twins that fail the default check | 1 of 30 (3.3 %) | 0.6 – 16.7 % |

By family (attacks seen at medium+): **structural** families all detected, unicode 3/3, MCP configuration
3/3, hidden comment 1/1; **semantic** families mostly missed, override 1/5, exfiltration 2/4,
remote execution 1/5, concealment 0/2, sensitive files 0/2, persistence 0/2, tampering 0/1, other 0/2. In
those two groups: 7 of 7 (64.6 – 100 %) against 4 of 23 (7.0 – 37.1 %).

**v1 is burned.** Its misses guided the next detection round (generalised by category, never copied as
patterns), so it can no longer validate anything: a rerun on it measures a set the rules were improved
with, not the scanner. Anything run on v1 from now on must be labelled "tuning set, not a measurement". A
test checks that no text of v1 is in the tuning corpus. Measuring the later releases needs a new blind set
(v2) written by someone who has not seen them.

**Structural and semantic detection.** What the numbers say is a difference of kind, not of effort.

- *Structural* detection looks at properties of the bytes or the structure: invisible, bidirectional and tag
  characters, variation selectors, a hidden HTML comment, the fields of an MCP or settings file (an
  unpinned package, `http://`, a shell wrapper, an auto-approve flag), a secret by its format. It does not
  depend on what the text means, so it is strong and close to deterministic; it can be evaded only by
  changing the structure.
- *Semantic* detection tries to recognise what a sentence asks the agent to do, with lexical patterns
  over words in five languages. It is **best effort**: a paraphrase, a language or a framing the patterns do
  not know is missed, and every pattern added to catch one more wording risks flagging documentation that
  only talks about it. Combining weak signals in a paragraph (GR035) helps at the margin and does not change
  this.

**The lock is the control that does not depend on detection.** `ghostrules lock` records what every agent
reads and `lock --check` makes each change to it visible for a person to approve, whatever the text says.
A paraphrase that evades every pattern still appears as a changed file in a reviewed pull request; GR030
and GR031 exist so that a change cannot switch that review off. It does not judge the first content it
records, and it only works if someone reads the diff. Detection and the lock are complementary: detection
reduces what a reviewer has to read, the lock makes sure they are asked to.

## Reporting gaps

A miss is a normal issue (the "New rule proposal" template). A way to crash the scanner, make it
read, run or send something, or leak a secret through it, is a vulnerability: see
[SECURITY.md](../SECURITY.md).
