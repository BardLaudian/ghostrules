## What and why

<!-- One or two sentences. Link the issue if there is one. -->

## Checklist

- [ ] `pytest -q`, `ruff check .`, `ruff format --check .` and `mypy src` pass
- [ ] Every new or changed detection has a **positive** test and a **false-positive (negative)** test
- [ ] If a rule's severity or pattern changed: `docs/RULES.md`, `docs/DECISIONS.md` and the `CHANGELOG.md` (Unreleased) say so, and the effect on `bench/` and `corpus/` is in this description
- [ ] The bench cases were not tuned on their own misses (new, varied cases were added first)
- [ ] `examples/poisoned-repo` still triggers every rule and `examples/clean-repo` is still clean
- [ ] Fixtures are defanged (`*.example`, fake tokens), and invisible characters are generated, not typed
- [ ] Nothing executes, downloads or evaluates scanned content, and nothing uses the network
- [ ] If this touches a file an agent reads, `ghostrules lock --update` was run and the lock diff reviewed
- [ ] If the JSON schema, exit codes, flags or rule IDs changed: `docs/VERSIONING.md` was followed
- [ ] I read what the assistant (if any) wrote, and I am responsible for it
