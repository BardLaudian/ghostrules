# Línea base (Fase 0)

Medido el 2026-11-23 sobre `main` (8d65b35) antes de tocar `src/`.

| Métrica | Valor |
|---|---|
| Versión | 0.4.1 |
| Reglas (`ghostrules rules`) | 33 (GR001–GR113) |
| Tests (antes de la fase) | 2024 passed |
| Cobertura total | 97 % (6212 líneas, 210 sin cubrir) |
| `pytest -q --cov` | 84 s |
| `ruff check .` | sin errores |
| `ruff format --check .` | 168 ficheros ya formateados |
| `mypy src` | 1 error: `scanner.py:390 Unused "type: ignore"` (H7) |
| Escaneo propio (`ghostrules scan .`) | exit 0 |

## `python bench/run.py attacks` (101 casos)

| Origen | Casos | Reportados | Falla el check por defecto |
|---|---:|---:|---:|
| author | 28 | 20 (71 %) | 9 (32 %) |
| review (independiente) | 4 | 1 (25 %) | 1 (25 %) |
| public | 69 | 66 (96 %) | 40 (58 %) |

## Red de seguridad añadida

`tests/test_evasion_regressions.py`: 10 casos H1–H5 en `xfail(strict=True)` (comportamiento
deseado) y 6 casos de falso positivo que ya pasan.

Nota: el entorno usa `.venv/` (`export PATH=$PWD/.venv/bin:$PATH`); `ghostrules`, `pytest`,
`ruff` y `mypy` no están en el PATH global.
