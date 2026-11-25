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
