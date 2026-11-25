# Baseline per attack class (0.5.1 plus the Phase 11 size fix)

Command: `python bench/redteam/baseline.py`. Cases: `bench/attacks/` (110), class of each technique:
`bench/redteam/taxonomy.toml`. "Reported" means an expected rule fired; "fails the default check" means it
fired at high or critical. These are the project's own cases (author, public, review), not an
independent sample. The C5 cases are direct phrasings; paraphrases are not in the bench yet.

| Class | Cases | Reported | Fails the default check |
|---|---|---|---|
| C1 Hidden text | 20 | 20 of 20 (100 %, 95 % CI 84–100 %) | 17 of 20 (85 %, 95 % CI 64–95 %) |
| C2 Obfuscation and encoding | 6 | 6 of 6 (100 %, 95 % CI 61–100 %) | 6 of 6 (100 %, 95 % CI 61–100 %) |
| C3 Structure and reach | 22 | 18 of 22 (82 %, 95 % CI 61–93 %) | 17 of 22 (77 %, 95 % CI 57–90 %) |
| C4 Configuration | 17 | 17 of 17 (100 %, 95 % CI 82–100 %) | 14 of 17 (82 %, 95 % CI 59–94 %) |
| C5 Semantics | 45 | 41 of 45 (91 %, 95 % CI 79–96 %) | 6 of 45 (13 %, 95 % CI 6–26 %) |
