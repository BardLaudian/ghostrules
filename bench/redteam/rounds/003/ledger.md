# Round 003 — C1-C4, seed 2003

**Status: complete for the dev half; blind audit clean (0 flagged); no test-half number exists (the test half is still unjudged).**

- Branch `fase-14-ronda-003`, from round 002 (patch `aeec77d` included). Models: attacker sonnet, judge sonnet (override of the haiku frontmatter), defender per frontmatter.
- Attacker turn 1 only (72 cases written; cut to the first 15 per class in file order = 60, declared). Turn 2 was not run, as in round 002, after the platform safeguard stopped it there.
- Cases: 60 (34 dev, 26 test). The orchestrator wrote the raw turn to the scratchpad and ran `split.py` with its default test directory; no command named that directory.
- Dev, before the patch: 18 of 33 valid cases evaded (55 %); 1 case with an invalid config excluded (`r3-c3-evasion-extra-targets`).
- Judge: valid 33/34 (invalid `r3-c1-zw-binary-agents`, decoded empty). Judge-human agreement 34/34 = 100 %.
- Twins: 1/34 fired at high before (`twin-r3-c2-hex-agents`), 0 after (medium).
- Patch: 274 lines under `src/` against round 002 (limit 400); 13 of the 18 evading dev cases are now detected at high, +1 critical. Honest limits left: config the scanner reads (`evasion-disable-allow`, `evasion-exclude-dir`), served MCP content, `referenced-agents` (no imperative lead), `secret-agents-split` (the fake token is shorter than the real format).
- Decision for review: `bench/attacks/context-and-config.toml` case `settings-base-url-override` moved from known-miss to detected. GR104 severity medium -> high (published severity changes). `*_BASE_URL` to a non-vendor host is high by design (accepted false-positive risk on enterprise gateways).
- Gate: all checks pass; blind audit clean.
- Declared: the evasion figure of a round is not a score. Attacker was not given feedback (single turn), so this dev evasion is not comparable with rounds with feedback.
