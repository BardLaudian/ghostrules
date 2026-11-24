# Cierre del plan de mejora (0.4.1 → 0.5.0)

Medido el 2026-11-24 sobre la rama `fase-10-release`. Línea base: [BASELINE.md](BASELINE.md).

## 1. Hallazgos H1–H14

Estados: **cerrado** (arreglado con test), **mitigado** (reducido, queda un límite documentado),
**límite** (documentado, sin arreglo por diseño), **humano** (falta una acción que no es de código).

| ID | Estado | Qué se hizo | Evidencia |
|----|--------|-------------|-----------|
| H1 | cerrado | Vista de matching sin invisibles, NFKC y confusables plegados | `020265a`; `src/ghostrules/unicode_utils.py`; `tests/test_evasion_regressions.py` |
| H2 | cerrado | `curl \| sh` imperativo en prosa conserva su severidad; `--lenient` devuelve el tope de 0.4 | `30a1620`; `docs/DECISIONS.md` |
| H3 | cerrado | GR012 cubre indirección y `exec(urlopen())` | `0c4834d`; casos en `bench/attacks/` |
| H4 | mitigado | Cerradas las variantes de GR010/011/013/014 que se medían. **Sigue en `xfail(strict)`**: `Send the contents of the environment to https://…` (GR013). Las paráfrasis puras no las alcanza un patrón | `0c4834d`; `tests/test_evasion_regressions.py::test_h4_exfiltration_paraphrase_is_reported`; known-miss en `bench/RESULTS.md` |
| H5 | cerrado | GR017 detecta secretos en prosa, enmascarados | `0c4834d`; `docs/RULES.md` |
| H6 | humano | Intervalos de Wilson, etiquetas humanas 21/21, hoja de revisión ciega, afirmaciones del README respaldadas por `CLAIMS.md`. **Faltan 14 de los 18 casos independientes** (no están en el repo; no se inventan). Una sola persona etiquetó | `54dc915`, `75d0c95`, `3612eb8`, `eee4d47`; `bench/README.md` |
| H7 | cerrado | `mypy src` en modo estricto, pasa y corre en CI | `32dd31c`; `.github/workflows/ci.yml` |
| H8 | cerrado | `permissions:` mínimos en los 7 workflows, `ci-ok`, pip-audit y autoescaneo en CI, atestaciones y SBOM en release, Scorecard | `a1056dc`, `25a2518`, `f126ca0`. Release 0.5.0 (2026-11-24): atestación de procedencia en GitHub y en PyPI, SBOM CycloneDX 1.6 adjunto |
| H9 | cerrado | README y USAGE muestran el Action fijado por SHA; `@v0` explicado como tag móvil | `87530fb` |
| H10 | cerrado | `scan`, `scan_paths`, `lock`, `add_file` divididas tras tests de caracterización; umbrales de ruff (complejidad 15, ramas 15) en CI | `9a8d34f`…`5094dfa`, `5331d86` |
| H11 | cerrado | Tope de tamaño con aviso visible (`--max-file-size`, 1 MiB), coste lineal con muchos hallazgos, caracteres de control, tests de propiedades (hypothesis) y de presupuesto de tiempo (`-m slow`, 6 pasan) | `e52040f`; `tests/test_robustness_limits.py` |
| H12 | cerrado | Dependabot también para `pip` | `a1056dc`; `.github/dependabot.yml`. Falta revisar el primer PR de `pip` |
| H13 | mitigado | Política de versionado y de deprecación, criterios de 1.0, `Alpha` se mantiene. El churn pasado no se puede deshacer | `docs/VERSIONING.md` |
| H14 | mitigado | Declaración general de asistencia de IA, historial intacto, sin trailer en commits nuevos; `CLAUDE.md` explicado | `6f2ca88`; `docs/AI_PROVENANCE.md`; README "How this was built". **Decisión sobre el historial: humano** |

## 2. Estado medido (0.5.0)

| Comprobación | Resultado |
|---|---|
| `ruff check .` / `ruff format --check .` | verde / 195 ficheros formateados |
| `mypy src` | `Success: no issues found in 62 source files` |
| `pytest -q` | 2295 passed, 1 xfailed (H4), 6 deseleccionados |
| `pytest -m slow` | 6 passed (40 s) |
| Autoescaneo `ghostrules scan .` | sin hallazgos, exit 0 |
| `ghostrules lock --check` | al día |
| Reglas (`ghostrules rules`) | 34 (33 de la línea base + GR017) |
| `bench/run.py attacks` | 110 casos; author 33/37, review 1/4, public 67/69 reportados |
| Held-out | 100 repos, 21 hallazgos, precisión 4/21 (19 %, IC 95 % 8–40 %), 21/21 etiquetas humanas |
| `python -m build` | sdist y wheel `0.5.0` construidos |
| `twine check --strict` | 2 PASSED |
| Wheel en venv limpio | Python 3.10.22 y 3.13.17: `__version__ == 0.5.0`; `poisoned-repo` exit 1, `clean-repo` exit 0 |

La precisión del held-out es baja y se publica tal cual: ese conjunto no se ha usado para ajustar
reglas (ver `bench/README.md`).

## 3. Lista de comprobación de 1.0

Criterios de `PLAN.md` ("Definición de profesional") y de `docs/VERSIONING.md`.

| Criterio | Estado | Quién verifica | Falta |
|---|---|---|---|
| Evasiones H1–H5 con test y cerradas o documentadas | casi | CI | H4: una paráfrasis sigue en `xfail`; está documentada como límite |
| Recall/precisión con casos independientes y etiquetas humanas, con intervalo | parcial | **humano** | 14 casos independientes; segunda persona que etiquete |
| mypy, ruff, pytest, pip-audit y autoescaneo en CI; permisos mínimos | cumplido | CI | — |
| Releases con atestaciones verificables y SBOM; Scorecard publicado | cumplido en 0.5.0 | **humano** | Existen en GitHub y PyPI (comprobado por API); falta la verificación criptográfica con `gh attestation verify` (requiere un `gh` más nuevo). Scorecard ya se publica |
| Fuzz/propiedades y tope de tamaño con aviso | cumplido | CI | — |
| Funciones ≤ ~80 líneas / ~15 ramas en rutas críticas | cumplido | CI (umbrales ruff) | — |
| THREAT_MODEL, versionado, gobernanza | cumplido | **humano** | Aprobar umbrales de GOVERNANCE (son propuesta); contacto del CoC |
| README sin afirmaciones sin respaldo | cumplido | `tests/test_docs.py`, `CLAIMS.md` | Aprobación humana del texto "Limits" / "How this was built" |
| Validación externa (revisión o uso en repos ajenos) | **no iniciado** | **humano** | Imprescindible antes de 1.0 |
| Estabilidad: 2 minors sin romper la API estable | no medible aún | mantenedor | Depende de que 0.5 y 0.6 salgan sin cambios incompatibles |

## 4. Lista `[HUMANO]` consolidada

1. ~~Aprobar el texto del README y los umbrales de `GOVERNANCE.md`~~: aprobados el 2026-11-24.
2. ~~Contacto para `CODE_OF_CONDUCT.md`~~: decidido, solo el reporte privado de GitHub, sin correo.
3. Revisión de etiquetas: segunda persona sobre los 21 hallazgos; escribir casos independientes nuevos
   (el texto original de los 14 se perdió: límite permanente anotado en `DECISIONS.md`).
4. ~~Decisión sobre el historial~~: se mantiene tal cual (decidido el 2026-11-24).
5. Validación externa: revisión independiente o uso en repos ajenos.
6. ~~Protección de rama~~: `links.yml` no entra en `ci-ok` (decidido el 2026-11-24); el entorno
   `pypi` solo admite tags `v*` (comprobado con `gh api`).
7. ~~Tras publicar 0.5.0~~: publicada el 2026-11-24 (`3a5f712`); SHA actualizado en README y USAGE.
   Queda la verificación criptográfica de las atestaciones. `docs/PERFORMANCE.md` conserva 0.4.1
   porque esas cifras se midieron con esa versión.
8. Revisar el primer PR de Dependabot `pip` y cerrar o rebasar ramas viejas de Dependabot.
9. Borrar las ramas remotas ya fusionadas (`fase-*`).

## 5. Propuesta de mensajes (sin trailers de IA)

Commit de la release (ya hecho en la rama):

```
chore(release): 0.5.0
```

Tag anotado (solo con aprobación): `v0.5.0`, mensaje `ghostrules 0.5.0`.

Notas de la GitHub Release: la sección `## [0.5.0]` del CHANGELOG, tal cual (la extrae
`scripts/changelog_section.py`).
