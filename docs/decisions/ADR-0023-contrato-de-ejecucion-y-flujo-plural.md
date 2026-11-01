# ADR-0023 · Contrato de ejecución y preservación de bloques reportados

**Estado:** aceptado, alcance acotado · **Fecha:** 2026-10-31.

## Defectos reproducidos y cambio

HECHO E2/E3: `core.run` enviaba `headless=True` a Codex, cuya firma no lo admitía.
La aprobación estaba después de `exec`, donde el parser de Codex 0.151.0 la rechazaba.
El adaptador ahora acepta el contrato común y coloca la aprobación antes del subcomando,
manteniendo `on-request` y `workspace-write`. Eso demuestra construcción/parseo del
comando, no aplicación universal de hooks o restricciones por rol.

El ejecutor rechaza presupuestos inválidos o sin soporte nativo antes de pedir el
prompt o iniciar el proceso. Codex rechaza restricciones de herramientas y arranque MCP
estricto que no puede expresar. No se habilita una ejecución ilimitada para hacer pasar
un contrato presupuestado. Este cambio puede dejar pasos BLOCKED donde antes se ignoraba
el presupuesto o fallaba la firma Python. El presupuesto nativo no equivale a una cota
verificada de facturación total ni de servicios externos.

Claude recibe `--tools ""` ante un conjunto vacío, en vez de exponer sus herramientas
predeterminadas. Claude y Codex declaran transporte del prompt por stdin. El texto que
parece una opción no se añade como argumento de control ni aparece en el resumen de
argv. Otros adaptadores usan un separador de opciones y conservan sus limitaciones
de presupuesto y configuración; no se certifica su ejecución nativa por esta traducción.

Cada captura del prompt tiene nombre aleatorio exclusivo y referencia de contenido,
evitando sobrescribir la entrada de una ejecución anterior del mismo rol. En POSIX se
crea con modo 0600. Ese identificador es de un archivo de captura: **no es invocation_id**
ni implica que se conozca una relación entre reintentos. Se transmite al hijo el rol del
paso y, cuando existe, la ejecución orquestada; no se reutiliza la sesión ajena del padre.

## Cardinalidad y evidencia

`AgentSpec.normalize_events` devuelve una secuencia. Los adaptadores singulares existentes
siguen funcionando mediante un envoltorio. Claude preserva cada bloque `tool_use` de
`message.content`, en orden, con su índice e identificador reportado. No recorre objetos
anidados dentro de argumentos como si fueran llamadas. La API singular se conserva
para compatibilidad; los consumidores que necesitan todos los bloques deben usar la plural.

`core.run._invoke` consume la API plural y `execute_step` persiste metadatos como
`runtime/report`. Identificadores de llamada/sesión sólo se toman de campos que el
adaptador haya declarado; no se interpreta un ID JSON-RPC como ID de herramienta.

La proyección omite texto e inputs de herramientas. Declara `preserves_original=false`
y `source_preserved=false`: ni el digest de línea ni el extracto del comando permiten
reconstruir el stdout original completo. La captura forense de originales sigue siendo
un proceso separado. No se presenta esta proyección como normalización sin pérdida.

La cobertura separa registros recibidos, inválidos, no mapeados, errores de mapeo y
observaciones producidas. Un registro puede producir varias observaciones. Un flujo vacío
es NOT_APPLICABLE, nunca PASS. Un error del mapeador bloquea el paso. Un fallo al persistir
después de la ejecución conserva el paso BLOCKED con efectos IN_DOUBT: no los deshace.

Un retorno satisfactorio del proceso sólo demuestra `completion_scope=runtime_exit_only`.
El registro mantiene `acceptance=null`; no es una adjudicación de tarea. El coste leído
es el reportado por el runtime, no una factura. Valores no numéricos, negativos o no
finitos no se convierten en costes medidos.

## Validación y límites

`tests/contract/test_stream_contract.py` ejecuta procesos CLI sintéticos locales con el
mapeador real. Comprueba cardinalidad, índices, datos desconocidos, errores, budgets
rechazados antes de efectos, captura exclusiva del prompt, stdin, contexto del hijo y
fallo de auditoría después de un efecto observado. No representa una sesión de modelo real.

Los experimentos nativos opcionales deben separar tres controles: sin hook, escritura
protegida denegada y escritura permitida con pre/post. Deben preservar entrada, configuración,
versión, fuente y efecto. Un servidor de modelo sintético permite probar un runtime nativo
sin evaluar inteligencia del modelo ni consumir un servicio de inferencia de pago. La
confianza de hooks y el modo de aprobación usados son precondiciones explícitas; un fixture
con hooks previamente inspeccionados no prueba la aprobación de confianza persistida.

Permanecen fuera de este contrato la aceptación de objetivos, el agrupamiento lógico de
reintentos, la conservación completa de stdout, la autenticidad de productores, el aislamiento
de UID y la protección frente a todos los procesos/subagentes. No se instala ningún hook ni
se activa ningún motor en espacios existentes como parte de esta remediación.
