# Handoff para continuar en otro chat (2026-10-28)

Pega esto (o dile a Claude que lea este fichero) al empezar el chat nuevo:

> Lee CLAUDE.md, docs/RULES.md, docs/AGENT_MODELS.md, docs/DECISIONS.md y todo docs/v0.3/
> (incluido HANDOFF.md). Estamos en la Fase 1 de docs/v0.3/PLAN.md, a medias. Continúa desde
> "Estado de la Fase 1" de HANDOFF.md. Tests + ruff + mypy, commit y para.

## Proyecto
`ghostrules`: CLI + GitHub Action en Python 3.10+ ("Find the instructions your AI agent sees but you
don't"). Repo local `/root/ghostrules`, remoto `BardLaudian/ghostrules`. Defensivo: sólo lee, nunca
ejecuta ni usa red (el único código con red será `corpus/`, fuera del paquete). Reglas del proyecto en
`CLAUDE.md` (fixtures "defanged", secretos siempre enmascarados, tests positivo y negativo por regla,
un commit por fase con mensaje convencional, parar al acabar cada fase). Trabajo por fases; el usuario
escribe en español y yo respondo en español.

## Publicado
- v0.2.0 (imports `@path`, `context`, `lock`) y **v0.2.1** (F1 symlinks como alias, F2 GR022,
  F3 helper directive/descriptive/example, F4 GR012, F5 README/docs). v0.2.1 está en PyPI
  (`pip install ghostrules==0.2.1`) y con GitHub Release. Main = `0bbd416`.
- El SPEC/PLAN originales y los docs por versión viven en `docs/design/`. `docs/v0.2.1/` y
  `docs/v0.3/` siguen **sin versionar** a propósito (sólo en el árbol de trabajo).

## Rama y estado actual
- Rama `v0.3` creada desde `main` (0bbd416). **Nada commiteado todavía en esta rama.**
- Sin versionar: `corpus/` (empezado), `docs/v0.2.1/`, `docs/v0.3/`.
- Entorno: `source .venv/bin/activate` (python/pytest/ruff/mypy están ahí; `python` a secas no existe
  fuera del venv). Último estado verde conocido en v0.2.1: 1197 tests, ruff y mypy limpios.
- Comandos de calidad: `pytest -q`, `ruff check . && ruff format --check .`, `mypy src`.
  (`mypy src tests` da 15 errores antiguos en tests; CONTRIBUTING sólo pide `mypy src`.)
- `pip install hatchling` ya hecho en el venv (lo necesita el test del sdist).

## Fase 1 — Corpus tooling (docs/v0.3/PLAN.md y CORPUS.md)
Objetivo: `corpus/` con `discover.py`, `run.py`, fingerprints, `labels.toml`, `triage.py`, `check.py`,
excluido del paquete (test que mire el contenido del wheel/sdist). Tests unitarios con una capa `gh`/git
falsa (sin red). Hecho cuando `python corpus/run.py --repos owner/a,owner/b` funcione en local con dos
repos reales y `check.py` imprima el resumen.

### Hecho
- `corpus/common.py` (escrito, **sin probar ni pasar por ruff**): `Proc`/`Runner`/`subprocess_runner`
  (nada pasa por shell; timeout = 124, falta de programa = 127), `git_env()`, `valid_repo()`,
  `safe_text()` (sustituye control/formato/privados por `⟦U+XXXX⟧`; el contenido de repos ajenos puede
  traer secuencias de escape), `fingerprint(repo, path, rule_id, snippet)` = sha256 truncado a 16 hex,
  sin números de línea y con el snippet normalizado, `toml_string()`, `load_repos()` (valida nombres,
  tiers y duplicados), `latest_results_dir()`, `read_json/write_json`, `Label`/`load_labels()`
  (un `reported` no puede nombrar el repo), `format_label()`, `test_exists("tests/x.py::nombre")`.

### Falta (por orden)
1. `corpus/discover.py`: cliente `gh api -i` (cabeceras para `X-RateLimit-*`, espera hasta el reset,
   caché en `corpus/.cache/`, reanudable), búsqueda por estrellas/lenguaje/`pushed:>`/no archivado/no
   fork, una llamada a Git trees por candidato (`truncated` => "unknown", no adivinar), detectar
   ficheros con `ghostrules.targets.classify_path(rel, (".claude/rules/**/*.md",))`, salida JSON y
   `--propose regression:300` que imprime un bloque TOML (el humano elige los tiers; no escribe
   `repos.toml`).
2. `corpus/run.py`: `git clone --depth 1 --filter=blob:limit=2m --no-tags --single-branch` a un
   tempdir, SHA, `ghostrules scan --format json --fail-on none --min-severity info` y
   `ghostrules context --format json --agent all --no-scan --root DIR`, **siempre con `--config` a un
   TOML vacío** (para que el `.ghostrules.toml` del repo ajeno no altere la medición) y con cwd fuera
   del clon; comando por defecto `[sys.executable, "-I", "-c", "from ghostrules.cli import app; app()"]`
   (no hay `__main__`). Workers configurables, timeout por repo, tolera fallos de clon. Escribe
   `results/<fecha>/<owner>__<repo>.json` y `summary.json` (+ copia `results/latest-summary.json`).
   **No guardar contenido de ficheros**: quitar `message`/`fix_hint`, `decoded` sólo para GR001/GR004,
   re-enmascarar con `ghostrules.secrets.mask_secrets`, contexto sólo como conteos y rutas legibles.
   Estados: ok, clone_failed, scan_failed, context_failed, timeout.
3. `corpus/check.py` (la puerta): falla si hay un hallazgo **sin etiquetar** critical/high, un `fp`
   que sigue a su severidad antigua, un `fp` sin test o con test inexistente, o un scan caído
   (exit 2). Imprime tabla markdown (opcional a `$GITHUB_STEP_SUMMARY`). Exit 0/1/2.
4. `corpus/triage.py`: recorre hallazgos sin etiquetar >= medium, muestra snippet y contexto (re-descarga
   el fichero con `gh api` sólo para mostrar, saneado con `safe_text`, nunca guardado), registra
   tp/fp/wontfix/reported en `labels.toml`. Un `reported` guarda sólo el fingerprint (nunca el repo).
   Modo no interactivo para tests.
5. Ficheros: `corpus/README.md` (qué es, cómo ejecutar y la sección de **ética** de CORPUS.md),
   `corpus/repos.toml` (vacío con cabecera), `corpus/labels.toml` (vacío con cabecera), `.gitignore`
   (`corpus/.cache/`, `corpus/results/*` salvo `!corpus/results/latest-summary.json`).
6. `pyproject.toml`: `[tool.hatch.build.targets.sdist] exclude = ["/corpus"]` (el wheel ya sólo
   empaqueta `src/ghostrules`) y `hatchling` en el extra `dev`.
7. Tests (`tests/test_corpus_*.py`, con `sys.path.insert` a `corpus/`): runner falso para git/gh (el
   falso de `git clone` escribe ficheros en el destino), fingerprint estable, validación de nombres,
   caché/ratelimit de discover, run -> JSON sin contenido, check (todos los casos de fallo), triage,
   y un test que construye wheel+sdist con hatchling y comprueba que no hay `corpus/` (skip si falta
   hatchling).
8. Verificación real: `python corpus/run.py --repos owner/a,owner/b` sobre dos repos reales (p. ej.
   `getsentry/sentry-python`, `anthropics/claude-agent-sdk-python`) + `check.py`. Luego ruff, mypy,
   anotar decisiones en `docs/DECISIONS.md` (sección v0.3 Fase 1) y commit.

## Lecciones de esta sesión (para no repetirlas)
- Antes de etiquetar, comprobar en GitHub que el PR está realmente fusionado (el usuario se adelantó una
  vez). Con una rama y una tag de igual nombre, subir la tag con `git push origin refs/tags/vX.Y.Z`.
- El workflow de release necesita que el usuario apruebe el entorno `pypi`; un 502 de Sigstore/Rekor se
  arregla con `gh run rerun <id> --failed`.
- `vhs` como root necesita `VHS_NO_SANDBOX=true`.
- No volver a publicar ni reutilizar tokens; el usuario ya autenticó `gh`.
- Los clones de los 12 repos de la pasada de precisión siguen en
  `/tmp/claude-0/-root-ghostrules/bf45461a-3dd4-4933-be22-e144e9573a3f/scratchpad/corpus/` (1,8 GB);
  preguntar al usuario si borrarlos.

## Fases siguientes (resumen de PLAN.md)
2 primera ejecución real + triage con el usuario (~300 repos `regression`, aprobados por él; si algo
parece un secreto o contenido malicioso real: parar y avisar, divulgación privada); 3 workflow
`corpus.yml` + badge; 4 playground con Pyodide; 5 estudio; 6 release 0.3.0.
