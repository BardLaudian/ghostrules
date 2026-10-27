# Decisions

Choices made where `SPEC.md`, `RULES.md` or `PLAN.md` were ambiguous or inconsistent.
Newest at the bottom of each section. "Phase N" says when the decision takes effect.

## Applied (Phases 0-1)

- **Git:** the project directory was not a repository; `git init -b main` was run in Phase 0 so
  per-phase commits are possible.
- **Single version source:** `__version__` in `src/ghostrules/__init__.py`, read by hatch.
- **Rule registry:** `rules/registry.py` holds `Rule` + `@rule`; `rules/__init__.py` re-exports it
  and imports the rule modules. `Rule.scans_decoded` marks GR010-GR016.
- **Hidden-text pass:** text decoded by a rule (`Finding.decoded`) is scanned as a virtual
  `instructions` target by `scans_decoded` rules only (no recursion). Results are attributed to
  the parent's location and get +1 severity (cap critical).
- **Suppression scope:** inline `ghostrules-ignore` never suppresses GR001/GR002 (SPEC §6), and
  also cannot suppress findings derived from decoded hidden text. `ScanResult.suppressed` counts
  suppressed findings so reports can show it.
- **Size/binary limits:** the 2 MB / binary skip only applies to unrecognised files added by
  `--all-files`. Known target files are always scanned, otherwise padding a file would hide it.
- **Symlinks:** never followed during repo discovery (no escaping the root, no loops). `--home`
  accepts symlinked dotfiles.
- **Explicit file argument:** `scan some/file` scans it even if it is not a known target
  (`kind = other`, unless its name matches a target glob).
- **Reported paths:** relative to the scan root; with several roots, prefixed by the root as given;
  home files are labelled `~/...`.
- **Columns:** 1-based, in Unicode code points (not UTF-16). SARIF must declare
  `columnKind: unicodeCodePoints` (Phase 5).
- **Decoding:** files are read as UTF-8 with `surrogateescape`; reporters must sanitise lone
  surrogates before printing (Phase 5).
- **Rule crashes:** recorded in `ScanResult.errors` and treated as a failed scan by the CLI
  (exit 2) rather than silently dropped.
- **Config unknown keys:** an unknown key in `.ghostrules.toml` is an error (catches typos).
- **Config from the scanned repo:** honoured as the spec says, but `ScanResult.config_source` is
  kept so the summary can show that a repo-supplied config (which could disable rules or add
  `allow_domains`) was loaded.
- **JSONC:** comment/trailing-comma stripping is string-aware and preserves offsets and lines.

## Planned for later phases

- **GR101 fixture token:** `ghp_EXAMPLEEXAMPLEEXAMPLEEXAMPLE0000` has 32 chars after the prefix
  and low entropy, so it would not match GR101 (needs 36). Demo/fixture tokens will be 36 chars.
- **Masking format:** `ghp_****…a1b2` (CLAUDE.md) wins over RULES' `first 4 + **** + last 4`.
  Masking is applied centrally when a `Finding` is built, so snippets/messages/decoded text are
  already safe, including GR012's "full command" snippet.
- **Poisoned demo coverage:** PLAN §6 does not trigger GR004, GR006, GR014, GR015, GR016, GR104
  or GR105; the demo will be extended so every rule fires (RULES acceptance criterion).
- **`clean`:** removes only characters the rules actually flag (so emoji ZWJ, flag tag sequences,
  VS16 and legitimate RTL marks survive). A leading BOM is stripped unless `--keep-bom`.
- **`--all-files`:** runs GR001-GR004 on `other` files; GR005 only on markdown-like files and
  GR006 only on URLs, to avoid noise.
- **Code-block downgrade:** only GR010 drops to `low` inside fenced code blocks (RULES).
- **Exit code:** `--fail-on` considers findings left after `--min-severity` filtering and after
  suppressions.
- **Self-scan (Phase 9):** exclude `examples/**` as well as test fixtures.
- **SARIF:** findings from `--home` files are not repo-relative and are left out of SARIF.
- **MCP shapes:** also read `projects.*.mcpServers` in `~/.claude.json`.
