# Plan v0.6.0 — Detección a 9

Sustituye a `PLAN-0.6.md` y a las Fases 11–19 de `PHASES-0.6.md` (bórralos si no los ejecutaste).
Las fases de este plan son 11–18 (`PHASES-0.6-deteccion.md`). Reglas de trabajo: `PLAN.md`.

La 0.6 hace una sola cosa: **que la detección sea defendible con números**. Producto, adopción y
comparativa con competidores pasan a 0.7.

## 1. Qué significa "9" (se fija antes de medir)

El 9 es una nota que pongo yo según criterios. Los criterios se escriben **antes** de la evaluación
final y no se cambian después (preregistro). Si no se cumplen, la nota no sube y se publica igual.

### Taxonomía de ataques (qué cuenta como "detectar")

| Clase | Qué es | Ejemplos | Límite esperable |
|---|---|---|---|
| C1 Texto oculto | Invisible al humano, legible para el modelo | tags Unicode, ZW, bidi, HTML/Markdown oculto, selectores de variación | Alto: determinista |
| C2 Ofuscación y codificación | Misma instrucción disfrazada | homoglifos, fullwidth, troceado, base64/hex, mayúsculas, espaciado | Alto con normalización |
| C3 Estructura y alcance | El payload llega por un camino que el humano no ve | imports `@`, reglas condicionales, skills, hooks, symlinks, **relleno de tamaño** | Alto: determinista |
| C4 Configuración | Riesgo en config de agente y MCP | paquetes sin fijar, http, secretos, shell, docker | Alto: determinista |
| C5 Semántica | Intención sin patrón fijo | paráfrasis, otros idiomas, instrucciones indirectas | Bajo con patrones; el techo hay que medirlo y declararlo |

### Criterios del 9 (umbrales preregistrados; ajustables por una persona antes de congelar)

| # | Criterio | Umbral | Cómo se mide |
|---|---|---|---|
| 1 | Recall C1–C4 frente a una ronda **nueva** de red team de IA contra la versión congelada | ≥95 %, límite inferior del IC 95 % ≥85 %, n ≥100 | Ronda fresca, un solo uso |
| 2 | Tasa de evasión tras mutaciones C1–C4 | ≤5 % | `bench/evasion/` |
| 3 | Recall C5 (semántica) | Medido y publicado; objetivo ≥50 % con n ≥60, marcado como asesoría (confianza baja) | Ronda fresca |
| 4 | Falsos positivos en gemelos benignos | ≤2 %, n ≥100 | Gemelos del juez + suite FP |
| 5 | Hallazgos que fallan el check por defecto, corpus de 300 repos | ≤2 sin explicar por cada 100 repos tras triage; precisión de esos hallazgos ≥70 % con etiquetas humanas (n ≥20) | corpus/ + hoja de etiquetas |
| 6 | Robustez | Mutation score ≥75 % en `rules/`; fuzz sin caídas; sin bypass por tamaño; rendimiento ≤+15 % sobre 0.5.0 | CI semanal, bench/perf.py |
| 7 | Honestidad | Cada afirmación del README y de THREAT_MODEL enlazada a una medición; límites por clase publicados; origen de los casos declarado | docs/CLAIMS.md y test de claims |

El 9 requiere cumplir **1, 2, 4, 5, 6, 7**. El criterio 3 se publica pase lo que pase: no se promete.

Línea base conocida (0.5.0): recall independiente 1/4 (IC 5–70 %), precisión 4/21 (19 %, n pequeño),
101/110 en el bench propio, bypass por relleno abierto. Estas cifras son el punto de partida.

## 2. El bucle de red team con subagentes del chat

El **chat principal es el orquestador**. Los tres roles son subagentes definidos en
`.claude/agents/`. La Puerta no es un agente: es un script.

| Rol | Subagente | Qué hace | Ceguera |
|---|---|---|---|
| Atacante (Red) | `redteam-attacker` | Genera evasiones válidas por clase y técnica; adapta con el feedback del oráculo (máx. 3 turnos por ronda) | **Por construcción:** sin herramientas de lectura. Solo sabe lo que el orquestador le pasa en el prompt: taxonomía, formatos públicos de los agentes y resultados del oráculo |
| Juez | `redteam-judge` | Decodifica cada fichero **sin ver** el payload declarado y escribe gemelos benignos | Igual: solo recibe el contenido de los ficheros del caso |
| Defensor (Blue) | `redteam-defender` | Parchea con TDD y escribe el argumento de generalización | **Por contrato y auditoría:** necesita leer el repo. Solo recibe casos `dev`; el conjunto `test` vive fuera del árbol, con denegaciones de lectura y registro |
| Puerta | `gate.py` | Decide si el parche pasa al PR | Determinista |
| Orquestador | chat principal | Lanza subagentes, ejecuta oráculo y scripts, abre PR | No pasa información `test` a nadie |

Cada subagente fija su `model:` en el frontmatter. **Elige niveles distintos para Red y Blue**
(p. ej. Red con el modelo más capaz, Blue y Juez con otro nivel). Todos son de la misma familia:
comparten puntos ciegos y eso se declara en cada informe.

### Protocolo de una ronda

1. El orquestador construye el prompt de Red con `make_prompt.py` (solo fuentes permitidas) y lo lanza.
2. Red devuelve N casos (p. ej. 60) en TOML dentro de su respuesta: payload canónico declarado, clase y técnica.
3. El oráculo (`oracle.py`) ejecuta `ghostrules scan` en un directorio temporal aislado y devuelve
   solo `{detectado, severidad máxima}` por caso. No devuelve ids de regla.
4. El orquestador envía a Red ese resultado con `SendMessage`. Red adapta y devuelve nuevos casos
   (hasta 3 turnos). Es el actor adaptándose al crítico.
5. El Juez recibe solo los ficheros, decodifica a ciegas y `judge_check.py` compara con el payload
   declarado (similitud normalizada). Un caso que "evade" borrando la instrucción se descarta.
6. Split determinista por hash del id: `dev` o `test`. `test` se guarda fuera del repo.
7. Blue recibe los `dev` que evaden y los gemelos `dev` que dan FP. Escribe test primero, parche y
   argumento de por qué generaliza (no es un parche por caso).
8. `gate.py` comprueba: tests, mypy y ruff en verde; los casos `dev` detectados antes siguen
   detectados; suite FP y gemelos `dev` sin regresión; muestra del corpus sin hallazgos nuevos sin
   explicar; rendimiento; tamaño de diff; que no se leyó `test/`.
9. Se abre un PR a una rama. **Nada llega a `main` sin una persona.**

### Reglas que evitan engañarnos

- **Un solo uso del conjunto test por versión.** La evidencia final es una ronda nueva de Red contra
  una versión **congelada**, con semillas nuevas. Se registra tal cual salga.
- **Preregistro:** umbrales y hash del conjunto de evaluación se commitean antes de ejecutarlo.
- **Ledger por ronda:** modelo de cada subagente, semillas, prompts, coste, casos válidos,
  evasiones, parches y resultado de la auditoría.
- **Prueba de ceguera en el piloto:** se pide a Red y a Juez que lean un fichero del repo; debe fallar.
  Si no falla, no se arranca la Fase 14.
- **Auditoría de Blue:** se revisa su registro de llamadas; si leyó `test/`, la ronda se descarta.
- **Presupuestos duros:** máximo de rondas (8), de turnos de Red (3), de casos por ronda, de líneas
  de diff y de coste. Los subagentes gastan el uso de tu plan.
- **Parar** cuando la tasa de evasión `dev` esté bajo el umbral dos rondas seguidas, o al agotar presupuesto.
- **Etiqueta de origen:** `ai-redteam`, misma familia de modelos. Nunca "independientes humanos".
- **Contexto:** compactar (`/compact`) o sesión nueva entre rondas; el estado vive en `rounds/NNN/`.

## 3. Capa semántica (C5) sin romper "sin red ni ejecución"

Los patrones no entienden la intención. Antes de prometer nada se prueba, en este orden:

1. **Puntuación por señales combinadas**, determinista y explicable: verbos imperativos sobre objetos
   sensibles, salida a una URL, ocultación, sobrescritura de instrucciones, léxicos multilingües
   revisados. Varios indicios débiles juntos suben la severidad; uno solo no. Sin dependencias nuevas.
2. Medir qué recall alcanza en C5 con precisión aceptable.
3. **ADR:** si no basta, decidir (con la persona) si se explora un modo opcional con modelo local o
   servicio externo. Fuera de 0.6: solo se documenta el techo y el coste.

## 4. Fases (ver `PHASES-0.6-deteccion.md`)

| Fase | Contenido |
|---|---|
| 11 | Línea base por clase, taxonomía, preregistro y bypass por relleno (es un bypass de detección) |
| 12 | Infraestructura: subagentes, oráculo, split, ledger, Puerta, auditoría, generador de prompts, comando de ronda |
| 13 | Ronda piloto: prueba de ceguera, coste, validez del Juez, con revisión humana de una muestra |
| 14 | Rondas C1–C4 hasta el umbral |
| 15 | Capa semántica C5: señales combinadas, multilingüe, rondas con foco |
| 16 | Calibración de precisión: gemelos, corpus de 300 repos, etiquetas, confianza y severidad por regla |
| 17 | Robustez: mutation testing, fuzz, rendimiento, cobertura de las reglas nuevas |
| 18 | Congelar, ronda fresca, evaluación única contra el preregistro, informe y release 0.6.0 |

## 5. Calendario orientativo (1 persona, tiempo parcial, ~6–7 semanas)

| Semana | Fases |
|---|---|
| 1 | 11, arranque de 12 |
| 2 | 12, 13 |
| 3–4 | 14 |
| 4–5 | 15, 16 |
| 6 | 17 |
| 7 | 18 |

## 6. Riesgos

| Riesgo | Mitigación |
|---|---|
| Sobreajuste al propio adversario | Split dev/test, un solo uso del test, ronda fresca contra versión congelada |
| Misma familia de modelos en los tres roles | Niveles distintos, declarado en cada informe, etiqueta `ai-redteam` |
| Red o Juez con herramientas de lectura | Frontmatter mínimo y prueba de ceguera obligatoria en la Fase 13 |
| El orquestador filtra información del test | `make_prompt.py` construye los prompts solo con fuentes permitidas; el orquestador no resume resultados `test` |
| Casos "válidos" que ya no contienen el ataque | Juez ciego + comparación determinista + muestra humana |
| El Defensor degrada la precisión | Gemelos benignos, suite FP, corpus de 300 repos, límite de diff |
| Coste y saturación de contexto | Presupuestos, `/compact` entre rondas, estado en ficheros |
| La semántica tiene techo | Se mide, se marca como asesoría y se publica |
| Deriva de documentación | `docs/CLAIMS.md` y test de claims en CI |

## 7. Tareas humanas `[HUMANO]`

- Aprobar o ajustar los umbrales del preregistro **antes** de la ronda final.
- Revisar una muestra (20–30 casos) por ronda del juicio de validez del Juez.
- Revisar y fusionar cada PR de ronda. Nada se fusiona solo.
- Elegir los modelos de cada subagente y fijar el presupuesto de uso.
- Etiquetar los hallazgos de precisión (una persona; declararlo en el informe).
- Decidir sobre el modo semántico opcional (ADR de la Fase 15).
