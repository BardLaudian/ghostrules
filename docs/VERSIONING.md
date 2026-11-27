# Versioning and stability

`ghostrules` follows [Semantic Versioning](https://semver.org/) **for the surface listed below**.
Everything else may change in any release and is noted in the [changelog](../CHANGELOG.md).

## Current status

The latest `0.x` receives fixes (see [SECURITY.md](../SECURITY.md)). Before 1.0, a minor version
(`0.N`) may break the stable surface when the changelog says so under **Changed** or **Removed**;
a patch version (`0.N.P`) does not.

## What is stable

| Surface | Promise | Where it is pinned |
|---|---|---|
| **Rule IDs** (`GR001`…) | An ID keeps its meaning. It is never reused for a different check. A retired rule's ID stays reserved | [RULES.md](RULES.md) index |
| **Rule severity** | Part of the contract. Raising or lowering a default severity is a **Changed** entry, and a lowering that stops failing `--fail-on high` is called out | RULES.md; golden tests |
| **JSON report** | `schema_version` is an integer. Within one version fields are only **added**. A field removed, renamed or retyped bumps it | `src/ghostrules/schemas/scan.schema.json`, `tests/test_output_contract.py` |
| **SARIF** | SARIF 2.1.0; rule IDs and `executionSuccessful` as above | validated against the official schema in tests |
| **Exit codes** | 0 clean, 1 findings at or above `--fail-on`, 2 usage, config or rule failure, 3 internal failure | [USAGE.md](USAGE.md#exit-codes), `tests/test_exit_codes.py` |
| **CLI flags and commands** | A documented flag keeps its name and meaning | `tests/test_usage_matches_help.py` |
| **Configuration keys** | `.ghostrules.toml` / `[tool.ghostrules]` keys keep their meaning; unknown keys are errors | `tests/test_config_errors.py` |
| **Action inputs and outputs** | Names and meaning | `action.yml` |
| **Lock file format** | Carries a format version; an older lock is read or rejected with a clear message, never misread | `tests/test_lock.py` |

## What is not stable

- The wording of messages, hints and the table and Markdown layout (the JSON fields are the interface).
- The exact set of findings: a better detection can add findings, and a fix for a false positive can
  remove them. That is why the baseline and `--fail-on` exist. New rules are added in minor versions.
- The Python import path `ghostrules.*` except what [USAGE.md](USAGE.md#use-the-context-engine-as-a-library)
  documents (the context engine and its JSON schema).
- `bench/`, `corpus/`, `study/`, `web/` and `scripts/`.
- Agent models: they follow each agent's documentation, so they change when the agent does.

## Deprecation

1. The change is announced under **Deprecated** in the changelog, and the old form keeps working
   and prints a warning (never on stdout, so reports stay parseable).
2. It stays for at least **two minor releases** (one after 1.0 reaches a major boundary: removal only
   in a major version).
3. Removal is listed under **Removed**. A retired rule keeps its ID in the index, marked retired.

A security fix may skip this when waiting would leave users exposed; the changelog says so.

## Criteria for 1.0

1.0 is declared when **all** of these hold. Each is checked by a person, not by this file.

1. The stable surface above has gone through at least **two minor releases without a breaking
   change** to it.
2. Recall and precision are published with confidence intervals on cases **independent of the rule
   author**, with labels reviewed by a human, and the sample is large enough that the interval is
   useful (the current independent sample is too small).
3. At least **one external validation**: an independent review or use in repositories the author
   does not control, with its findings answered.
4. Releases carry verified provenance attestations and an SBOM, and the verification has been
   done once by someone other than the release author.
5. CI (lint, types, tests on three operating systems, audit, self-scan, performance budget) is
   required on the protected branch.
6. [THREAT_MODEL.md](THREAT_MODEL.md) and the limits in USAGE.md are current, and every README claim
   is backed (see [CLAIMS.md](CLAIMS.md)).
7. No known open vulnerability against the scanner itself.
8. More than one person can review and release (see [GOVERNANCE.md](../GOVERNANCE.md)), or the
   single-maintainer limit is stated on the front page.
