# Documentación

## Empezar

| | |
|---|---|
| [`../README.md`](../README.md) | qué es esto, qué runtime puede qué, y qué está probado |
| [`../INSTALL.md`](../INSTALL.md) | instalar en una máquina limpia y comprobar que quedó bien |
| [`../OPERATIONS.md`](../OPERATIONS.md) | gobernar un espacio, ejecutar, actualizar, diagnosticar |
| [`examples/end-to-end-run.md`](examples/end-to-end-run.md) | una ejecución real, fechada, con su coste y sus bloqueos |
| [`../TROUBLESHOOTING.md`](../TROUBLESHOOTING.md) | fallos observados, con causa y arreglo |

## Entender

| | |
|---|---|
| [`../ARCHITECTURE.md`](../ARCHITECTURE.md) | qué es núcleo, qué es adapter, y el reparto que decide si esto envejece bien |
| [`lifecycle/`](lifecycle/) | las 13 fases, con entrada, salida, puertas y revisión humana |
| [`agents/`](agents/) | los 22 roles, sus contratos, y cómo se elige el runtime |
| [`../SUPPORT_MATRIX.md`](../SUPPORT_MATRIX.md) | salida de ejemplo de `refuto docs`, fechada |
| [`decisions/`](decisions/) | 8 ADRs, cada uno con qué lo haría cambiar |

## Verificar

| | |
|---|---|
| [`estado-del-proyecto.md`](estado-del-proyecto.md) | **qué está probado, a qué nivel, y qué sigue abierto** |
| [`../SECURITY.md`](../SECURITY.md) | modelo de amenaza y las **27** pruebas adversariales |
| [`validation/informe.md`](validation/informe.md) | informe **histórico** del 2026-08-27: 7 comprobaciones ejecutadas y una sección de lo que no se validó |
| [`remediation/hallazgos.md`](remediation/hallazgos.md) | los 12 hallazgos de aquella auditoría y su estado |

## Fundamentar

| | |
|---|---|
| [`research/mcp.md`](research/mcp.md) | MCP 2026-07-28 y qué habla de verdad el ecosistema instalado |
| [`research/acp.md`](research/acp.md) | ACP v1 y los handshakes ejecutados el 2026-08-27 |
| [`research/agentes.md`](research/agentes.md) | qué tiene cada agente y qué NO se aplana |

## Adoptar

| | |
|---|---|
| [`../MIGRATION.md`](../MIGRATION.md) | adoptarlo sobre lo que ya funciona, sin big-bang |
| [`../CONTRIBUTING.md`](../CONTRIBUTING.md) | cómo extenderlo sin romperlo, y cómo se escribe una afirmación aquí |

---

**Retirado:** `docs/manual/` (manual de operación en `.docx`). Generaba un documento con la marca
personal del autor en los metadatos, sus capturas procedían de un repositorio privado de cliente,
y rehacer las figuras exigía un navegador externo, fuera de la regla de «sólo biblioteca
estándar». Lo que cubría está repartido entre [`../INSTALL.md`](../INSTALL.md) y
[`../OPERATIONS.md`](../OPERATIONS.md).
