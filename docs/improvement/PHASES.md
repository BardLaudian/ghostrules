# Fases de desarrollo — ghostrules

Uso: abre sesión nueva (o `/compact`) por fase y ejecuta `/phase N`, o pega el prompt de la fase.
Cada prompt asume que el agente lee primero `docs/improvement/PLAN.md` (reglas de trabajo,
hallazgos H1–H14, informe de fase). Orden recomendado: 0 → 1 → 2 → 3 → 4 → 5 → 6 → 7 → 8 → 9 → 10.
Las fases 1–3 son el mayor impacto; 5 y 6 son baratas y se pueden adelantar.

---

## Fase 0 — Línea base y red de seguridad

```
Lee docs/improvement/PLAN.md y aplica sus reglas de trabajo. Fase 0: línea base.

1. Crea la rama fase-0-baseline desde main.
2. Con un subagente, resume en <300 palabras la estructura (src/, tests/, bench/, corpus/,
   .github/workflows/). No leas ficheros enteros.
3. Ejecuta y guarda en docs/improvement/BASELINE.md (tabla, sin volcar logs): versión, nº de
   reglas (`ghostrules rules`), tests, cobertura total, salida de ruff y mypy, tiempo de
   `pytest -q`, y salida resumida de `python bench/run.py attacks`.
4. Escribe tests/test_evasion_regressions.py con un caso por cada evasión H1–H5 de PLAN.md.
   Cada caso construye el fichero en tmp_path, ejecuta el scanner por API/CLI y afirma el
   comportamiento DESEADO (por ejemplo: la variante con U+200B produce un hallazgo >= high).
   Márcalos `@pytest.mark.xfail(strict=True, reason="Hn, fase M")`. Strict para que fallen
   ruidosamente cuando una fase los arregle y obligue a quitar el xfail.
5. Añade 6 casos de falso positivo legítimos (documento de política que dice "nunca leas
   ~/.ssh", instrucciones de instalación con `curl | sh`, una regla que cita "ignore previous
   instructions" como ejemplo de entrada no confiable, MCP con versión fijada, etc.) como tests
   normales que ya deben pasar. Son la red contra sobre-detección en fases posteriores.
6. Añade una línea a CLAUDE.md que remita a docs/improvement/PLAN.md. Ejecuta
   `ghostrules lock --update` y revisa el diff del lock.

Cierre: criterio 11 de PLAN.md más informe de fase. No toques código de src/ en esta fase.
```

---

## Fase 1 — Normalización Unicode antes del matching (H1)

```
Lee docs/improvement/PLAN.md. Fase 1 (rama fase-1-unicode-normalization). Objetivo: que los
patrones de GR010–GR016 no se evadan con caracteres invisibles, de ancho completo o homoglifos.

1. Con grep localiza dónde se aplican los patrones al texto (src/ghostrules/rules/patterns.py,
   rules/injection.py, markdown_utils.py, unicode_utils.py). Lee solo esos rangos.
2. Diseña una vista normalizada del texto para el matching: NFKC, eliminar U+00AD, U+200B–U+200F,
   U+2060–U+2064, U+FEFF, selectores de variación y caracteres de etiqueta, y plegado de
   confusables latín/cirílico/griego de alta confianza. Debe conservar un mapa de offsets a la
   línea/columna ORIGINAL para que los hallazgos señalen el texto real.
3. Aplica los patrones a la vista normalizada además de la original (sin duplicar hallazgos).
4. Regla de escalado: si un hallazgo de GR010–GR016 solo aparece tras normalizar, súbelo a `high`
   como mínimo y añade al mensaje que el texto estaba ofuscado. Un GR003/GR006 aislado conserva
   su severidad.
5. Quita los xfail de los casos H1 de tests/test_evasion_regressions.py y añade: soft hyphen,
   fullwidth, cirílico, mezcla ZWSP+homoglifo, ZWJ en emoji legítimo y texto árabe/persa/hindi
   legítimo (no deben dar falso positivo; ver docs/USAGE.md sobre ZWJ).
6. Mide el efecto en corpus/ (solo lectura, sin red si no hay caché): informa de hallazgos
   nuevos y cuántos son falsos positivos probables. No ajustes patrones mirando el corpus.
7. Rendimiento: compara el tiempo de scan en un árbol de 3.000 ficheros antes y después; el
   sobrecoste no debe superar un 25 %.

Cierre: criterio 11 + informe de fase con la tabla antes/después de las evasiones de H1.
```

---

## Fase 2 — Política de severidad en prosa (H2)

```
Lee docs/improvement/PLAN.md. Fase 2 (rama fase-2-prose-severity). Objetivo: que el umbral por
defecto no deje pasar ataques obvios en prosa sin disparar falsos positivos de documentación.

1. Localiza con grep la lógica que baja la prosa a `low` y la opción --strict.
2. Propón y documenta (docs/DECISIONS.md) una política con evidencia, comparando 3 opciones:
   (a) mantener, (b) subir por contexto (línea imperativa dirigida al agente, o dentro de bloques
   de código ejecutables), (c) en pull requests evaluar con severidad completa solo las líneas
   AÑADIDAS por el diff. Implementa la que menor tasa de falsos positivos dé en los tests de
   falso positivo de la Fase 0 y en corpus/.
3. Si el cambio altera el exit code por defecto, trátalo como cambio de comportamiento:
   entrada en CHANGELOG (sección "Changed" con migración) y flag/config para el modo anterior.
4. Tests: `curl | bash` imperativo en CLAUDE.md debe fallar el check por defecto en la variante
   elegida; la instrucción de instalación documentada en un README normal no debe fallar.
5. Actualiza README y docs/USAGE.md solo con lo que el código hace.

Cierre: criterio 11 + informe con tasas de falso positivo antes/después sobre los 100 repos del
benchmark de precisión (sin reetiquetar).
```

---

## Fase 3 — Huecos de detección (H3, H4, H5)

```
Lee docs/improvement/PLAN.md y CONTRIBUTING.md (añadir una regla = 3 pasos). Fase 3
(rama fase-3-detection-gaps). Para cada ítem: test que falla primero, arreglo, test de falso
positivo, entrada en docs/RULES.md y en bench/attacks (caso nuevo con origen `author`).

1. GR012: variable intermedia (`c=curl; $c … && sh`), `exec/eval` sobre `urlopen`/`requests.get`
   en `python -c`/`node -e`, `bash <(curl …)` y `| sh -s --`. Límite documentado: no se emula un shell.
2. GR014: verbo `open`, rutas `~/.npmrc`, `~/.pypirc`, `~/.netrc`, `~/.config/gh/hosts.yml`,
   `.git-credentials`, y descripciones con "private key" + "ssh" en la misma frase (heurística
   de baja severidad, documentada como tal).
3. GR013/GR010/GR011: patrones en francés además de inglés/español. Una lista pequeña y
   revisada por idioma, no traducciones automáticas masivas.
4. Secretos en prosa (H5): regla nueva para tokens de formato conocido (ghp_, sk-ant-, AKIA…,
   xox*) en ficheros de instrucciones y `.cursorrules`. Reutiliza el enmascarado único de
   src/ghostrules/secrets.py; el test existente que falla si un secreto aparece sin máscara
   debe cubrir el nuevo caso. Asigna el siguiente ID libre vía el registro.
5. Documenta en docs/USAGE.md#limits lo que sigue sin detectarse (paráfrasis, intención). No
   prometas más de lo que hacen los patrones.

Cierre: criterio 11 + informe con recall del bench por origen ANTES y DESPUÉS y una nota
explícita: los casos nuevos son de `author`, así que la mejora no es evidencia independiente.
```

---

## Fase 4 — Robustez: fuzz y límites (H11)

```
Lee docs/improvement/PLAN.md y SECURITY.md. Fase 4 (rama fase-4-robustness).

1. Añade `hypothesis` al extra `dev`. Escribe tests de propiedades para: el normalizador de la
   Fase 1 (idempotente, el mapa de offsets es monótono y válido), el parser de imports `@path`
   (no escapa de la raíz, no lee symlinks fuera, no entra en bucles), jsonloc (no lanza con
   entrada arbitraria) y los reporters (ningún secreto sin máscara, sin secuencias de escape de
   terminal en la salida, SARIF válido contra el esquema).
2. Límite de tamaño: opción `--max-file-size` (valor por defecto razonable, p. ej. 1 MiB) y
   clave de config equivalente. Un fichero omitido NUNCA se calla: emite un hallazgo `info`
   (o aviso visible en el resumen y en SARIF) con nombre y tamaño. Test que lo verifica.
3. Presupuesto de tiempo: test de rendimiento marcado `slow` con entradas hostiles (líneas de
   3 MB sin espacios, 60.000 repeticiones de una frase, 200.000 corchetes) que falla si
   supera un umbral generoso; no uses timings frágiles en CI normal, usa un job aparte o
   marcador.
4. Revisa cada `except Exception` de src (scanner.py:176, 332, 361): el fallo de una regla debe
   verse en la salida y en el exit code (p. ej. un aviso "regla GRxxx falló" y exit distinto de
   0 en modo estricto), no tragarse en silencio. Test con una regla que lanza.
5. Actualiza SECURITY.md con lo que ahora está respaldado por tests, y solo eso.

Cierre: criterio 11 + informe con tiempos hostiles antes/después.
```

---

## Fase 5 — Calidad de código y tipado (H7, H10)

```
Lee docs/improvement/PLAN.md. Fase 5 (rama fase-5-code-quality). Refactor SIN cambio de
comportamiento.

1. Arregla `mypy src` (scanner.py:390 y lo que salga). Activa `strict` por módulos de forma
   progresiva en pyproject.toml; no desactives comprobaciones para "arreglar" errores. Añade
   mypy al job de CI.
2. Antes de tocar nada, escribe tests de caracterización de las salidas actuales (golden files
   de `scan`, `context`, `lock --check` sobre examples/*) para cli.py:119 `scan`,
   scanner.py:462 `scan_paths`, cli.py:562 `lock` y agents/base.py:334 `add_file`, `_follow`.
3. Divide esas funciones en unidades con una sola responsabilidad (resolución de opciones,
   descubrimiento de ficheros, aplicación de reglas, filtrado por baseline/supresiones,
   reporte). Objetivo: ninguna función >80 líneas ni >15 ramas en esas rutas.
4. Ejecuta los golden tests tras cada paso; el diff de salida debe ser cero. Un commit por función refactorizada.
5. Mide complejidad con `ruff` (reglas C901/PLR09xx con umbrales) o `radon` en dev y añade el
   umbral a CI para que no se degrade.

Cierre: criterio 11 + informe con tabla de funciones antes/después (líneas y ramas).
```

---

## Fase 6 — Cadena de suministro y CI (H8, H9, H12)

```
Lee docs/improvement/PLAN.md. Fase 6 (rama fase-6-supply-chain). Regla estricta: los SHAs de
actions se obtienen con `gh api` o `git ls-remote`; no inventes ni recuerdes SHAs.

1. ci.yml: `permissions: contents: read` a nivel de workflow; `concurrency` para cancelar
   ejecuciones obsoletas; añade jobs de mypy, `pip-audit` sobre las dependencias, y el
   autoescaneo de ghostrules sobre el propio repo.
2. dependabot.yml: añade el ecosistema `pip` (pyproject y action-requirements) además de
   github-actions, con agrupación semanal.
3. README.md y docs/USAGE.md: los ejemplos de `uses:` muestran SHA completo con comentario de
   versión, y explican `@v0` solo como alternativa. Deja una frase sobre por qué.
4. release.yml: atestaciones de procedencia (PyPI attestations de pypa/gh-action-pypi-publish y/o
   actions/attest-build-provenance, ambas fijadas por SHA) y SBOM (CycloneDX) adjunto al release.
   Verifica el resultado con `gh attestation verify` o `pypi-attestations` cuando exista una release.
5. Añade un workflow de OpenSSF Scorecard (fijado por SHA, permisos mínimos) y un badge solo
   cuando haya un resultado publicado.
6. Activa o documenta como pendiente `[HUMANO]` los ajustes de GitHub que no se pueden hacer
   desde el repo: protección de rama en main, revisión obligatoria, "Require signed commits"
   si se quiere, 2FA y entorno `pypi` con revisores requeridos.

Cierre: criterio 11 + informe. Valida los workflows con `actionlint` (instálalo en el entorno).
```

---

## Fase 7 — Honestidad de las métricas (H6, H14)

```
Lee docs/improvement/PLAN.md y bench/README.md. Fase 7 (rama fase-7-metrics).

1. Completa los 14 casos independientes que faltan (el repo cita REMEDIATION.md como origen):
   localízalos con grep en docs/ y bench/; añádelos con origen `review`, sin adaptarlos a las
   reglas actuales. Si faltan fuentes, déjalo como pendiente `[HUMANO]` y para.
2. Reetiquetado de precisión: genera `bench/labels-review.csv` con los 21 hallazgos (repo, regla,
   fichero:línea, contexto de 3 líneas, columna vacía `human_label`) para que los revise
   `[HUMANO]`. NO rellenes `human_label`. Modifica bench/run.py para distinguir etiquetas
   `assistant` de `human` y reportarlas por separado.
3. Añade intervalos de confianza (Wilson) a las cifras de recall y precisión que genera el
   script, y tamaño de muestra siempre junto al porcentaje.
4. Regenera las secciones marcadas del README con `python bench/run.py report --write`; no
   edites esas cifras a mano. Si el recall independiente sigue siendo bajo, el README lo dice.
5. Auditoría de claims: crea docs/CLAIMS.md con una tabla claim del README → evidencia
   (fichero:línea, test o resultado). Todo claim sin evidencia se elimina o se reescribe.
6. `[HUMANO]` Decidir qué hacer con los 80 commits con trailer de coautoría de IA. Opciones a
   documentar, sin ejecutar: dejarlos y declarar el uso de IA en CONTRIBUTING/README, o
   reescribir historial (destructivo, requiere force-push y rompe tags/releases). El agente
   no reescribe historial.

Cierre: criterio 11 + informe con cifras antes/después y lista de tareas `[HUMANO]`.
```

---

## Fase 8 — Producto y experiencia de uso

```
Lee docs/improvement/PLAN.md. Fase 8 (rama fase-8-product).

1. Validación de configuración: `.ghostrules.toml` con claves desconocidas o valores inválidos
   da un error claro con la clave y la línea; test por cada tipo de error.
2. Códigos de salida documentados y estables (0 limpio, 1 hallazgos >= umbral, 2 uso o config,
   3 fallo interno); test que los fija.
3. Baselines y supresiones: `baseline` expone fecha, versión y número de entradas; aviso cuando
   un baseline está obsoleto (entradas que ya no casan). Documenta cómo caducan.
4. Windows/macOS: tests de rutas con separadores, mayúsculas/minúsculas, CRLF, BOM UTF-8 y
   symlinks no disponibles; asegúrate de que corren en la matriz de CI de los tres SO.
5. Salida: SARIF validado contra el esquema oficial en un test; `--format json` con
   `schema_version` y garantía de compatibilidad documentada.
6. Rendimiento: benchmark reproducible en bench/perf.py (3.000 ficheros, 30 CLAUDE.md, repos
   grandes sintéticos) y presupuesto en CI con margen amplio; publica las cifras en docs/.
7. `ghostrules scan --help` y `docs/USAGE.md` coherentes entre sí (test que compara las opciones
   de `--help` con las documentadas).

Cierre: criterio 11 + informe.
```

---

## Fase 9 — Documentación y gobernanza

```
Lee docs/improvement/PLAN.md. Fase 9 (rama fase-9-docs-governance).

1. docs/THREAT_MODEL.md: activos, atacantes, fronteras de confianza, suposiciones y no-objetivos
   (qué NO detecta), vinculado a las reglas GR y a los límites de USAGE.md. Incluye el modelo de
   ataque contra el propio escáner (entradas hostiles, imports, symlinks, config en PR).
2. docs/VERSIONING.md: qué es API estable (IDs de reglas, esquema JSON, exit codes, flags) y
   política de deprecación; criterio explícito para llegar a 1.0.
3. GOVERNANCE.md mínimo (quién decide, cómo se aceptan reglas nuevas, cómo se revoca una regla
   con muchos falsos positivos) y CODE_OF_CONDUCT.md estándar.
4. CHANGELOG limpio: Keep a Changelog, enlaces de comparación entre tags, sin entradas
   internas ("point 4 and 5"). Verifica que cada versión tiene su GitHub Release con notas.
5. README: aplica docs/CLAIMS.md, mueve el detalle del benchmark a bench/ y deja arriba
   problema, instalación, un ejemplo, límites honestos y enlaces. Una sección "Cómo se
   construyó" que declare el uso de asistentes de IA y qué revisa el autor. `[HUMANO]` aprueba el texto.
6. Plantillas de issue y PR actualizadas (incluye casilla de tests de falso positivo).

Cierre: criterio 11 + informe. Comprueba enlaces rotos con una herramienta (lychee u otra) en CI.
```

---

## Fase 10 — Release 0.5.0 y camino a 1.0

```
Lee docs/improvement/PLAN.md. Fase 10 (rama fase-10-release). No hagas push ni tag sin
confirmación explícita.

1. Verifica que todos los hallazgos H1–H14 están cerrados, mitigados o documentados como límite
   con enlace al commit o doc. Tabla en docs/improvement/CLOSEOUT.md.
2. Prepara la release 0.5.0: versión en src/ghostrules/__init__.py, CHANGELOG, `ghostrules lock
   --update`, build local (`python -m build`) y `twine check`. Prueba la instalación del wheel en
   un venv limpio en Python 3.10 y 3.13.
3. Ejecuta la suite completa, el bench, los tests lentos y el autoescaneo; adjunta el resumen.
4. Lista de comprobación de 1.0 con estado: criterios de PLAN.md, quién los verifica y qué falta.
5. Propón mensajes de commit/tag/release (sin trailers de IA) y espera aprobación humana
   antes de crear nada fuera de la rama.

Cierre: informe final con la tabla de hallazgos y la lista `[HUMANO]` consolidada
(revisión de etiquetas, decisión sobre historial, validación externa, protección de rama).
```

---

## Notas de orden y riesgo

- Las fases 1–3 tocan el mismo núcleo de reglas: no las paralelices.
- Cada fase termina con informe y una pausa: revisa el diff antes de empezar la siguiente.
- La mejora de recall de las fases 1 y 3 no cuenta como evidencia independiente hasta que
  la Fase 7 añada casos que no escribió quien arregló las reglas.
