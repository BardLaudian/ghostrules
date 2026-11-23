# Security policy

`ghostrules` is a defensive tool that reads untrusted files, so its own security matters.

## Reporting a vulnerability

Please **do not open a public issue** for a vulnerability. Use GitHub's private reporting:
[report a vulnerability](https://github.com/BardLaudian/ghostrules/security/advisories/new)
(repository **Security → Report a vulnerability**).

Include the `ghostrules` version (`ghostrules version`), what you expected, what happened and, if
you can, a minimal file that reproduces it. Please defang anything you attach: no real secrets, no
working malicious payloads.

You can expect an acknowledgement within a few days and a fix or a clear answer as soon as
reasonably possible. Reporters are credited in the changelog unless they prefer not to be.

## What counts as a vulnerability

- **The scanner does something it must never do**: executes, downloads, imports or evaluates
  scanned content, follows a symbolic link out of the scanned tree, or makes a network request.
- **An `@path` import makes the scanner read what it must not**: a file outside the scanned
  tree, a symbolic link's target, or a credentials file such as `.env` (GR021 reports these
  imports and the file must stay unread).
- **A secret is printed unmasked** in any output format (table, JSON, SARIF, Markdown, `reveal`,
  `clean`) or in a warning or error message.
- **Crafted input hurts the scan**: a crash that stops the report, an unbounded loop or memory
  use (for example a regular expression with catastrophic backtracking), or output that injects
  terminal escape sequences, Markdown or HTML into a report.
- **A suppression or configuration trick** that hides invisible-character findings (GR001, GR002)
  or hidden-text findings from a file the scanner reads.

## What is a normal bug instead

A missed detection (false negative) or a wrong detection (false positive) is a bug, not a
vulnerability, unless it falls under the list above. Please open a regular issue with the
**New rule proposal** or **False positive** template. `ghostrules` is a set of heuristics and
cannot prove that a file is safe.

## Supported versions

Only the latest released `0.x` version receives fixes.

## Design guarantees you can rely on

- Read-only on your repository: the only writes are the report you ask for (`--output`),
  `ghostrules lock` (the lock file) and `ghostrules clean --write`, which keeps a backup of the
  original.
- No network access and no execution of scanned content, at runtime or in tests.
- Test fixtures and demos are defanged (`*.example` domains, fake tokens).
- Secrets are masked in a single place that every output passes through, and a dedicated test
  fails if any appears in any report.

## What the tests cover

Backed by tests (`tests/test_robustness_*.py`, hypothesis property tests plus fixed cases), and
only that:

- The Unicode normaliser is idempotent and its offset map is valid and monotonic.
- `@path` resolution never resolves above the scan root; imports through a symlink to a file
  outside the tree, a symlink loop or `..` do not read the outside file and do not loop.
- The located-JSON parser does not raise on arbitrary text or on 50,000 levels of nesting.
- No report format (table, JSON, SARIF, Markdown) prints a known-format secret or an ESC
  character for generated file content; SARIF validates against the 2.1.0 schema.
- A file over `--max-file-size` (default 1 MiB) is skipped with a warning in every format, never
  silently. A rule that raises is reported as an error and the exit code is 2.
- Hostile inputs (3 MB without spaces or on one line, 60,000 repeated sentences, 200,000 brackets
  or quotes) finish within a 60 s budget in `pytest -m slow`. This is a regression guard, not a
  promise about speed, and it runs with the size limit off. A file under the default limit is
  well inside it.

Not covered: fuzzing of the standard-library JSON and TOML parsers, memory limits, and
patterns outside the tested inputs.

