# Revisión de producto reproducible

Procedimiento E2; la ejecución y sus resultados se conservan en un expediente privado
fuera del checkout público. Una ejecución local no certifica otros equipos o versiones.

## Preservación y alcance

`python3 scripts/review_product.py --output /ruta/privada/expediente`

El destino debe estar fuera del repositorio. Contiene rutas originales y puede contener
información privada: no se publica. Se inventarían JSONL en los directorios locales de
sesiones de los tres runtimes, detectados durante la investigación. Las rutas codificadas
son adaptadores de este entorno, no descubrimiento universal de instalaciones.

Se calculan hashes de todas las fuentes encontradas. Se copian y analizan todos los diarios
descubiertos mediante `core.telemetry.diarios` y tres transcripts recientes por runtime,
de hasta 20 MiB cada uno. El inventario distingue claramente selección y análisis. La
selección por modificación es una muestra de conveniencia, no representativa. La búsqueda
de diarios tiene profundidad limitada; no se afirma cobertura global del equipo.

Las copias JSONL se verifican mediante SHA-256 y se registra si la fuente cambió durante
la captura. Una fuente activa no equivale a una instantánea transaccional. Para SQLite se
usa conexión `mode=ro`, online backup y `quick_check` sobre la copia. No se compacta ni
escribe la base original. Sólo se inspeccionan bases Codex descubiertas en su directorio;
no se presupone que los otros runtimes usen SQLite.

Los nombres de tabla son identificadores SQL, no valores parametrizables: se delimitan con
comillas dobles y se duplican las comillas internas. La excepción local B608 de Bandit cubre
sólo ese recuento; una regresión crea una tabla cuyo nombre contiene comillas y `DROP TABLE`,
comprueba ambos recuentos sobre la copia y confirma que los bytes originales no cambian.
Las conexiones de origen y copia se cierran explícitamente al terminar: el contexto
transaccional de SQLite por sí solo no libera la conexión. La regresión verifica también
que ambas conexiones quedan cerradas después del backup.

La proyección analítica omite texto libre, comandos, stdout, stderr, contenido y rutas.
Los identificadores de sesión se pseudonimizan con SHA-256. Eso no hace anónimos los
originales ni garantiza que todos los metadatos sean publicables. Un nulo significa
desconocido, omitido o extracción no soportada; **no demuestra ausencia en origen**.

## Contrato analítico

`refuto.review.event/v2` es una proyección forense independiente del contrato del producto.
`FIELDS` en el script enumera sus columnas. No promete completar el ADR-0009.

La versión 2 retira el respaldo de `session_id` desde `run_id`: una ejecución reportada no
es una sesión conversacional. Conserva el valor explícito por separado como
`reported_run_id`, pseudonimizado y sin atribuirle semántica universal de invocación o tarea.
Las sesiones sólo proceden de sus campos explícitos (o del payload nativo session_meta).
Los datasets anteriores se conservan y se reprocesan desde copias con hash verificado
en otro destino; no se parchean silenciosamente las filas históricas.

| Campos | Semántica |
|---|---|
| `event_id`, `evidence_reference` | SHA-256 de la copia y línea; identidad del registro, no de una operación |
| `session_id`, `parent_event_id`, `tool_call_id` | IDs explícitos pseudonimizados; no se enlazan por proximidad |
| `reported_run_id` | `run_id` explícito pseudonimizado; no sustituye sesión, tarea ni invocación |
| `runtime`, `runtime_version`, `raw_type` | Etiqueta de fuente o dato explícito; versión normalmente desconocida |
| `timestamp` | Marca original; no se corrigen relojes ni se inventa causalidad |
| `decision`, `policy_digest`, `input_digest` | Datos del diario del guardián; decisión no equivale a efecto |
| `duration`, `duration_unit`, `duration_scope` | Tiempo interno del guardián en ms; no duración de tarea |
| `result_ok`, `exit_code` | Datos explícitos de resultado, cuando existen |
| Resto de `FIELDS` | Reservados y nulos cuando no hay extracción semántica implementada |

La normalización de transcripts es parcial. En particular no deriva tareas de mensajes,
no extrae todavía todos los bloques de herramientas ni costes/tokens anidados y no
interpreta razonamiento privado. Las agrupaciones de sesión son descriptivas; el grafo
causal requiere referencias de padre/invocación verificadas contra los originales.

## Métricas y diseño por ámbito

Población y ventana proceden del manifiesto, nunca del número de líneas de código.
Para cada cociente se publica numerador, denominador, unidad y registros desconocidos.
Si el denominador es cero: `NOT_APPLICABLE`; si no está identificado: `INCONCLUSIVE`.

| Métrica | Definición y unidad |
|---|---|
| C | tareas completadas / iniciadas, proporción |
| A | entregables aceptados / evaluados, proporción |
| R | tareas con retrabajo / completadas, proporción |
| E | errores / operaciones observadas identificadas, errores/operación |
| Pv | resultados aceptados verificables / horas transcurridas, resultados/hora |
| H | intervenciones humanas / tareas completadas, intervenciones/tarea |

Un digest identifica contenido, no una invocación. `core.telemetry.resumen` omite duraciones
ambiguas, separa espacio/runtime/run/herramienta y exige una sola decisión permitida y un
solo resultado por clave. Es conservador: también puede descartar repeticiones secuenciales
legítimas. La solución definitiva es propagar un ID de invocación, no otro heurístico temporal.

El benchmark debe bloquear aceptación ante cualquier fallo crítico de seguridad, aunque
la tarea termine antes. Comparar mediante bloques tarea × ámbito × riesgo, con igual
contexto, presupuesto, versiones e intervención; aleatorizar orden, usar checkouts aislados,
repetir y evaluar artefactos a ciegas. Definir tamaño de muestra mediante efecto mínimo
relevante y piloto; no contar eventos como observaciones independientes. Bootstrap por
tarea/sesión y Wilson sólo cuando los ensayos satisfagan sus supuestos. Registrar censura,
abandono y ausencias; no imputarlas como éxitos ni como errores.

| Ámbito | Resultado que debe verificarse |
|---|---|
| Contenido | requisitos, procedencia/licencia, rúbrica editorial, aceptación humana |
| Juegos | build, replay con semilla, invariantes, rendimiento bajo carga definida |
| Ingeniería | requisitos trazados, unidades, tolerancias, oráculo técnico independiente |
| Arquitectura | restricciones satisfechas, contratos, escenarios de fallo y revisión |
| Desarrollo | pruebas ocultas, regresión, seguridad y artefacto reproducible |

Una misma política transversal puede servir a todos; sus oráculos de calidad no son
intercambiables. No se deben asignar ámbitos a clientes por inferencias de nombres de carpetas.

## Recuperación local

`python3 scripts/review_product.py --output /ruta/privada/indices --corpus research=/ruta/corpus`

Separa categorías (`research`, `code`, `architecture`, `telemetry`, `findings`) en bases SQLite.
FTS5 da el baseline léxico. Los vectores son hashing de tokens SHA-256 con signo, 128
dimensiones, norma L2 y versión `sha256-token-hash/v1:128`; **no son embeddings semánticos**.
Los fragmentos tienen 80 líneas, hash, ubicación y rango. El índice actualiza documentos
por hash y retira borrados; no deduplica textos iguales entre documentos con distinta
procedencia. Autores, licencias y fechas requieren un catálogo de corpus separado.

Evaluar Recall@k, Precision@k, MRR y NDCG con relevancia adjudicada antes de escoger motor.
No promover hashing a retrieval semántico ni un smoke test de búsquedas a calidad general.
FAISS/Qdrant/LanceDB o modelos locales sólo se justifican si superan FTS con el mismo
presupuesto, privacidad y consultas retenidas. No enviar telemetría a servicios externos.

## Autoridad

Reglas deterministas conservan autorización. ML puede recomendar, detectar anomalías o
priorizar revisión en modo sombra. No aprueba operaciones, no firma evidencia y no cambia
políticas. No introducir bandits/RL en autorización. Retirar cualquier predictor que no
supere reglas simples en calibración, coste y riesgo de falsos negativos.

Verificación sintética: `python3 scripts/review_product.py --selftest`.
Validación del repositorio: las cuatro órdenes prescritas por `AGENTS.md`.
