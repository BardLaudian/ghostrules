# Security policy

`ghostrules` is a defensive tool that reads untrusted files, so its own security matters.

## Reporting a vulnerability

Please **do not open a public issue** for a vulnerability. Use GitHub's private reporting:
[report a vulnerability](https://github.com/OWNER/ghostrules/security/advisories/new)
(repository **Security → Report a vulnerability**).

Include the `ghostrules` version (`ghostrules version`), what you expected, what happened and, if
you can, a minimal file that reproduces it. Please defang anything you attach: no real secrets, no
working malicious payloads.

You can expect an acknowledgement within a few days and a fix or a clear answer as soon as
reasonably possible. Reporters are credited in the changelog unless they prefer not to be.

## What counts as a vulnerability

- **The scanner does something it must never do**: executes, downloads, imports or evaluates
  scanned content, follows a symbolic link out of the scanned tree, or makes a network request.
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

- Read-only on your repository: the only writes are the report you ask for (`scan --output`) and
  `ghostrules clean --write`, which keeps a backup of the original.
- No network access and no execution of scanned content, at runtime or in tests.
- Test fixtures and demos are defanged (`*.example` domains, fake tokens).
- Secrets are masked in a single place that every output passes through, and a dedicated test
  fails if any appears in any report.
