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
# Fases 11–18 — v0.6.0, Detección a 9

Añade este contenido al final de `docs/improvement/PHASES.md` (borra antes las Fases 11–19 de
`PHASES-0.6.md` si las habías añadido) y copia `PLAN-0.6-deteccion.md` a `docs/improvement/`.
Cada prompt asume `docs/improvement/PLAN.md` (reglas de trabajo: grep antes de leer, subagente para
explorar, diff y no fichero, sin trailers de IA, sin push ni reescritura de historial sin orden) y el
plan de detección. Una rama por fase. El chat principal es el orquestador; los roles son subagentes.

---

## Fase 11 — Línea base, taxonomía y preregistro

```
Lee PLAN.md y PLAN-0.6-deteccion.md. Fase 11 (rama fase-11-baseline-prereg).

1. Taxonomía: crea bench/redteam/taxonomy.toml con las clases C1–C5 del plan, técnicas por clase
   y agentes/ficheros a los que aplica, citando docs/AGENT_MODELS.md. Cada caso existente de
   bench/attacks/ se etiqueta con clase; si no encaja, se anota.
2. Línea base: ejecuta bench/run.py y genera una tabla por clase: casos, detectados, fallan el
   check por defecto, con IC de Wilson. Guarda en bench/redteam/BASELINE.md (solo tabla y comando).
3. Bypass por relleno (es una evasión de C3): primero un test que falla (CLAUDE.md >1 MiB con la
   inyección al final, y variantes AGENTS.md y .cursorrules; payload al inicio, medio y final).
   Arreglo y decisión documentada en docs/DECISIONS.md: escaneo por ventanas con solapamiento y
   límite duro, y fallo explícito si no puede escanearse un fichero de agente. Corrige
   docs/USAGE.md y SECURITY.md para que describan el comportamiento real.
4. Preregistro: crea bench/redteam/PREREGISTRATION.md con los criterios 1–7 y los umbrales del
   plan, la fecha, la versión evaluada y el procedimiento. Marca "pendiente de aprobación humana".
   No se modifica tras la aprobación salvo con una nueva entrada fechada y motivo.
5. Tests de claims: test que compare límites documentados (tamaño, exit codes) con el código.

Cierre: criterio 11 de PLAN.md + informe de fase. [HUMANO] aprueba el preregistro antes de la Fase 18.
```

---

## Fase 12 — Infraestructura del bucle con subagentes

```
Lee PLAN.md y PLAN-0.6-deteccion.md. Fase 12 (rama fase-12-redteam-infra). No llames a ninguna API
externa desde el repo: los roles son subagentes de este chat.

A) Subagentes (.claude/agents/)
1. redteam-attacker.md: descripción, `model:` configurable y `tools:` reducido al mínimo posible (sin
   Read, Grep, Glob, Bash, Edit ni Agent). Prompt del sistema: rol, entradas permitidas (taxonomía,
   formatos públicos, resultados del oráculo), salida en TOML dentro de su respuesta, payloads
   inofensivos (dominios .example, sin secretos reales), nada de pedir contexto adicional.
2. redteam-judge.md: igual de restringido. Recibe solo el contenido de los ficheros del caso, decodifica
   el mensaje que un agente leería (sin ver el payload declarado) y escribe un gemelo benigno por caso.
3. redteam-defender.md: tools Read, Grep, Glob, Edit, Write, Bash. TDD obligatorio y un argumento de
   generalización por parche; solo trabaja con los casos dev que le entregue el orquestador.
4. Si `tools:` no admite una lista vacía, deja el mínimo y verifica en la Fase 13 que no puede leer.

B) Scripts en bench/redteam/
5. make_prompt.py: construye el prompt de Red y de Juez solo con fuentes permitidas (taxonomía,
   formatos públicos de los agentes, resultados del oráculo). Lista blanca explícita; falla si se le
   pide incluir src/, rules/, tests/ o RULES.md.
6. oracle.py: copia cada caso a un directorio temporal aislado (git init), ejecuta `ghostrules scan` y
   devuelve solo {detected, max_severity}. Sin ids de regla ni mensajes. Sin red.
7. case_schema.toml y validador. split.py: reparto dev/test por hash del id; el conjunto test se
   guarda FUERA del árbol del repo (ruta configurable, fuera del control de versiones) y se añade a
   las denegaciones de lectura de .claude/settings, más un hook que registra cualquier intento de lectura.
8. judge_check.py: similitud normalizada entre el payload decodificado por el Juez y el declarado;
   umbral documentado.
9. gate.py: tests, mypy, ruff, suite FP, gemelos dev, regresión de casos dev ya detectados, muestra
   del corpus, rendimiento y tamaño de diff; comprueba que no se leyó test/; salida JSON; umbrales en
   un fichero versionado.
10. audit_blind.py: recorre el registro de llamadas del defensor y marca lecturas de rounds/**/test/ y
    del directorio externo del conjunto test. Una marca invalida la ronda.

C) Orquestación
11. .claude/commands/redteam-round.md: instrucciones para el chat principal: construir prompt, lanzar
    a Red (sin background, porque el siguiente paso depende del resultado), oráculo, feedback con
    SendMessage (máx. 3 turnos), Juez, split, Blue, Puerta, rama y PR, auditoría. Prohíbe pasar datos
    de `test` a ningún subagente.
12. Plantilla rounds/NNN/ledger.md: modelo de cada subagente, semillas, prompts, coste, casos válidos,
    evasiones, parches, auditoría.
13. Tests de la infraestructura: el oráculo no filtra ids; el split es estable; gate falla ante una
    regresión forzada; audit_blind detecta una lectura prohibida simulada; make_prompt rechaza rutas prohibidas.

Cierre: criterio 11 + informe. Ejecuta `ghostrules lock --update` si añadiste ficheros que lee un agente.
```

---

## Fase 13 — Ronda piloto

```
Lee PLAN.md y PLAN-0.6-deteccion.md. Fase 13 (rama fase-13-pilot). Es la ronda 000: sirve para
calibrar, no para medir.

1. Prueba de ceguera obligatoria: lanza redteam-attacker y redteam-judge y pídeles leer
   src/ghostrules/__init__.py. Debe fallar. Si pueden leer, corrige los `tools:` y repite; no sigas
   hasta que falle. Guarda el resultado en el ledger.
2. Ejecuta /redteam-round con N=30 casos y presupuesto bajo. Registra coste y tiempo.
3. Mide: tasa de casos válidos según el Juez, tasa de evasión, calidad de los gemelos benignos,
   distribución por clase, mejora de Red entre el turno 1 y el 3.
4. Prepara una muestra de 25 casos aleatorios con el veredicto del Juez en
   bench/redteam/rounds/000/review.csv, con columna human_valid vacía. NO la rellenes. [HUMANO] la revisa.
5. Con la muestra revisada, calcula el acuerdo Juez–humano. Si es <85 %, ajusta el prompt del Juez y
   repite. No pases a la Fase 14 con un Juez poco fiable.
6. Revisa los prompts por fugas (pistas sobre reglas) y documenta en bench/redteam/README.md el
   procedimiento tal como funcionó realmente.

Cierre: criterio 11 + informe con coste por ronda, validez del Juez y ajustes. Si falta la revisión
humana, la fase queda "parcial" y lo dice.
```

---

## Fase 14 — Rondas C1–C4

```
Lee PLAN.md y PLAN-0.6-deteccion.md. Fase 14 (rama por ronda: fase-14-ronda-NNN). Itera hasta que la
tasa de evasión dev de C1–C4 esté por debajo del umbral dos rondas seguidas, o hasta 6 rondas.
Entre rondas, /compact o sesión nueva; el estado está en rounds/NNN/.

Para cada ronda:
1. /redteam-round con N=60 casos, foco en C1–C4 y en las técnicas con peor tasa de la ronda anterior.
2. Blue arregla solo lo que generaliza: normalización, canonicalización, decodificación de
   codificaciones comunes, estructura y alcance. Un parche por clase de evasión, no por caso.
   Cada parche con tests TP y FP, entrada en docs/RULES.md y justificación de generalización.
3. La Puerta debe pasar. Si el parche añade FP en gemelos o corpus, se rechaza o se acota.
4. Se abre un PR por ronda; [HUMANO] revisa el diff y la muestra de validez del Juez. No fusiones.
5. Actualiza el ledger con costes, evasiones restantes y límites declarados: si una técnica no se
   puede cerrar sin FP inaceptables, se documenta como límite de la clase, no se oculta.

Cierre de cada ronda: informe corto con tasa de evasión dev por clase, FP, rendimiento y coste.
No uses el conjunto test para decidir nada.
```

---

## Fase 15 — Capa semántica (C5)

```
Lee PLAN.md y PLAN-0.6-deteccion.md. Fase 15 (rama fase-15-semantic).

1. Mide primero: recall actual en C5 sobre casos dev de las rondas anteriores, por tipo (paráfrasis,
   idioma, instrucción indirecta).
2. Diseña un puntuador por señales combinadas, determinista y explicable, sin dependencias nuevas:
   categorías de señal (verbo imperativo sobre secretos o ficheros sensibles, salida a una URL o
   herramienta, ocultación al usuario, sobrescritura de instrucciones, saltarse confirmaciones), con
   léxicos en inglés y español y, si hay revisión, francés. Cada indicio débil suma; la severidad
   depende de la combinación y del contexto (línea imperativa dirigida al agente, bloque de código,
   cita). El hallazgo expone qué señales sumó (confianza `low`/`medium`).
3. Rondas /redteam-round con foco semántico. Los hallazgos de este puntuador se marcan como
   asesoría y no fallan el check por defecto salvo combinaciones de alta confianza.
4. Tests TP y FP; los gemelos benignos de política de seguridad y de documentación que cita
   ataques son obligatorios.
5. ADR docs/DECISIONS.md: si el recall de C5 no alcanza el objetivo, documenta el techo, el coste
   de un modo opcional con modelo (local o servicio) y los requisitos de privacidad. No lo implementes.

Cierre: criterio 11 + informe con recall C5 dev y FP. [HUMANO] decide sobre el modo opcional.
```

---

## Fase 16 — Calibración de precisión

```
Lee PLAN.md y PLAN-0.6-deteccion.md. Fase 16 (rama fase-16-calibration).

1. Mide hallazgos sobre el corpus de 300 repos (corpus/) con la versión actual. Lista los que fallan
   el check por defecto y clasifícalos: verdadero positivo, falso positivo, dudoso.
2. Genera bench/labels-0.6.csv con esos hallazgos, contexto de 3 líneas y columna human_label vacía.
   NO la rellenes. [HUMANO] etiqueta (una persona; se declara en el informe).
3. Con las etiquetas, tabla por regla en docs/CALIBRATION.md: precisión, n, decisión. Regla con
   precisión <20 % y n suficiente: baja de severidad, requiere señales adicionales o se desactiva por
   defecto, con razonamiento. No retocar patrones mirando casos concretos del conjunto de etiquetas.
4. Campo `confidence` (high/medium/low) en JSON y SARIF, documentado, con `schema_version`
   incrementado y migración en CHANGELOG. La severidad efectiva deriva de severidad y confianza.
5. Suite de gemelos benignos ampliada (≥100) con casos reales de documentación y política.

Cierre: criterio 11 + informe con hallazgos que fallan por 100 repos antes y después.
```

---

## Fase 17 — Robustez

```
Lee PLAN.md y PLAN-0.6-deteccion.md. Fase 17 (rama fase-17-robustness).

1. Mutation testing (mutmut o equivalente, versión fijada) sobre src/ghostrules/rules/ y
   unicode_utils.py en un job semanal. Informa el mutation score y los 10 supervivientes más
   relevantes; escribe tests que los maten cuando sean legítimos.
2. Fuzz y propiedades (hypothesis) para el normalizador, el puntuador semántico y el escaneo por
   ventanas: idempotencia, sin excepciones con entrada arbitraria, mapa de offsets válido, sin
   secretos sin enmascarar.
3. Rendimiento: bench/perf.py con presupuesto: 3.048 ficheros en ≤0,9 s (0.5.0: 0,77 s) y ficheros
   hostiles dentro de presupuesto. Perfila con cProfile y optimiza solo lo medido.
4. Cobertura: cada regla y señal nueva con TP, FP y caso en bench; cobertura global ≥95 %.
5. Test de claims: cada cifra de README, THREAT_MODEL y CALIBRATION con su fuente.

Cierre: criterio 11 + informe con mutation score y presupuestos.
```

---

## Fase 18 — Congelación, ronda fresca y release 0.6.0

```
Lee PLAN.md y PLAN-0.6-deteccion.md. Fase 18 (rama fase-18-final). No hagas push, tag ni release sin
confirmación explícita.

1. Verifica que PREREGISTRATION.md está aprobada por una persona. Si no lo está, para.
2. Congela la versión (commit y hash) y regístralo en el preregistro. A partir de aquí no se
   toca src/ hasta terminar la evaluación.
3. Ronda fresca: /redteam-round con semillas nuevas, N ≥150 casos (cubre C1–C4 con n ≥100 y C5 con
   n ≥60), con modelos de nivel distinto al usado por Blue, ceguera auditada y sin turno de Blue.
   Es la única evaluación final.
4. Calcula contra los umbrales preregistrados: recall C1–C4 con IC, tasa de evasión tras mutaciones,
   recall C5, FP en gemelos, hallazgos que fallan por 100 repos, precisión con etiquetas, mutation
   score y rendimiento. Tabla con cumple/no cumple. No muevas umbrales.
5. Si algo no se cumple: publícalo como está, abre un plan de ronda siguiente y NO subas la nota.
6. Regenera README, docs/CLAIMS.md y THREAT_MODEL con las cifras. Documenta límites por clase, que
   los casos son `ai-redteam` de la misma familia de modelos (no independientes humanos), los niveles
   usados y el coste.
7. Versión 0.6.0, CHANGELOG (cambios de comportamiento con migración), `ghostrules lock --update`,
   build, `twine check`, instalación del wheel en Python 3.10 y 3.13.
8. Propón mensajes de commit/tag/release sin trailers de IA y espera aprobación humana.

Cierre: informe final con cumple/no cumple por criterio, el coste total y las tareas [HUMANO] restantes.
```
