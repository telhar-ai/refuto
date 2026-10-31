# ADR-0022 · Recuentos verificables e identidad nativa observada

**Estado:** aceptado, implementación acotada · **Fecha:** 2026-10-31.

## Problema y decisión

HECHO E3: el runner mezclaba éxitos ordinarios, omisiones y fallos esperados. Varias
incidencias de subtests podían superar el número de casos iniciados. Una comparación
del denominador de una corrida histórica con el censo actual obligaba a reescribir la
historia cuando se añadían pruebas.

`tests.runner.AccountingResult` registra una categoría por caso iniciado: PASS, FAIL,
ERROR, SKIP, XFAIL, XPASS o UNKNOWN. Ante varios resultados de subtests, prevalece
ERROR, FAIL, XPASS, XFAIL, SKIP y finalmente PASS. Una omisión parcial impide declarar
el caso completamente aprobado. Incidencias de setup/teardown de clase o módulo sin
caso iniciado se cuentan aparte. La suma de categorías debe igualar casos iniciados;
descubiertos, no iniciados e incidencias no son denominadores intercambiables.

XPASS sigue invalidando la suite. Una suite vacía o íntegramente omitida no aprueba.
Los fallos esperados conservan la política de unittest, pero nunca cuentan como PASS
ordinario. El censo se verifica contra su fila estructural; el resultado histórico se
verifica por coherencia aritmética, sin imputarle pruebas de un árbol posterior.

`refuto selftest --report /ruta/privada/resultado.json` emite `refuto.selftest/v1`,
publicado en `schemas/selftest.schema.json`. El informe contiene revisión y huella de
fuentes en ambos límites de la corrida. Una diferencia invalida su aprobación. Igualdad
en los límites **no excluye cambios transitorios restaurados**; para esa garantía hace
falta un checkout inmutable. Sin Git, la procedencia queda nula: un PASS de fixtures
sin Git no certifica una revisión. El informe no se escribe dentro del repositorio
público y un fallo al preservarlo no se presenta como éxito.

## Integridad del diario

HECHO E3: añadir detrás de una cola sin LF concatenaba objetos JSON. El escritor ahora
rechaza colas incompletas, ilegibles, no objeto, con metadatos parciales o con huella de
cola incompatible. Mantiene los bytes anteriores. No repara, trunca ni cicatriza.

El verificador rechaza valores JSON no objeto, metadatos parciales, UTF-8 inválido y
retorno a eventos sin cadena después de empezar una cadena. Un prefijo legado sigue
siendo legible y se cuenta aparte: su contenido **no queda autenticado por la cadena
posterior**. La validación previa al append sólo comprueba la cola; no garantiza la
integridad del prefijo completo. La verificación completa sigue siendo una operación
separada. Un fallo de fsync puede dejar bytes visibles sin confirmar durabilidad; no se
promete rollback ni exactly-once.

## Identidad disponible y límites

La captura conserva `session_id` y `tool_use_id` como `session_id` y `tool_call_id`
para Claude y Codex. Son strings opacos no vacíos de hasta 512 caracteres. Su estado es
`reported`, `incomplete` o `unavailable`. No autentican al productor ni alteran permisos.
No se adivinan alias de Kiro: sin contrato probado, esos campos quedan nulos.

Referencias primarias: [Codex Hooks](https://learn.chatgpt.com/docs/hooks) y
[Claude Hooks](https://code.claude.com/docs/en/hooks), consultadas el 2026-10-31.
Documentan el ID de llamada en pre y post; los tests de este repositorio usan ese
contrato en subprocesses del guardián. **No demuestran carga de hooks en sesiones
nativas ni cobertura universal por versión.**

El lector prioriza `(fuente, runtime, session_id, tool_call_id)` y exige cardinalidad
uno a uno. Replays, IDs incompletos o discrepancias de herramienta/entrada no generan
duraciones. Sin identidad nativa, conserva la correlación conservadora por entrada,
etiquetada separadamente. `entrada_digest` continúa siendo digest de contenido, nunca
ID de invocación. Un PostToolUse o exit code cero no verifica un efecto ni aceptación.

La fuente es una huella de la ruta resuelta del diario observado, calculada por el lector
por encima de cualquier valor aportado por el productor. El nombre visible de un espacio
no es identidad: dos raíces pueden tener el mismo nombre. Las copias y rotaciones en
otras rutas permanecen separadas; no se inventa continuidad entre archivos. La huella no
autentica el contenido ni anonimiza criptográficamente una ruta de baja entropía. Quien
llame directamente a `resumen` sin `leer` conserva el ámbito legado `_espacio`: esa API
no puede demostrar separación de fuentes que no recibió.

## Lo que no queda implementado

Un tool-call ID no identifica por sí solo la intención lógica compartida entre reintentos.
`invocation_id`, `attempt_id`, productor autenticado, causa, efecto, artefacto y aceptación
requieren contratos y productores explícitos; no se generan de proximidad temporal.
La máquina de estados lógica de ejecución continúa siendo propuesta del ADR-0009,
no una garantía de esta captura. No se redefinen los niveles E0–E4 de AGENTS.md como
niveles nuevos de autenticidad: autenticidad, observación y corrección son dimensiones
independientes.

## Verificación y criterio de cambio

Pruebas: `test_corredor`, `test_runner_report`, `test_ledger_incomplete`,
`test_ledger_concurrente`, `test_native_identity` y `test_telemetry`. Incluyen subtests,
omisiones, XPASS, setup fallido, cambios reales de fuentes en Git, salida abrupta de
proceso, cuota de archivo del kernel, colas incompletas, replay y reutilización de
contenido entre llamadas. La cuota produce EFBIG; no equivale a reproducir ENOSPC en
un disco real. Los tests de guardián no equivalen a pruebas de runtime nativo.

Revisar este contrato cuando haya identidad lógica propagada por productores y oráculos
de efectos independientes. Hasta entonces, no se habilita autorización probabilística
ni se atribuye aceptación de tareas desde estas métricas.
