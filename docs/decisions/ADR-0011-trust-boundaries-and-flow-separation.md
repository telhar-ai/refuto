# ADR-0011 · Fronteras de Confianza y Separación de Flujos Arquitectónicos

**Estado:** aceptado · **Fecha:** 2026-09-22 · **Decide:** aislamiento de seguridad y categorización de flujos en refuto

---

## Contexto

En sistemas complejos de agentes donde interactúan el operador humano, procesos de CLI autónomos, servidores externos de herramientas (MCP) y el sistema de archivos del host, mezclar los canales de control, datos y políticas introduce vulnerabilidades severas de seguridad (p.ej., elevación de privilegios del agente, desenganche de hooks, inyección de comandos o manipulación de logs).

## Problema

1. **Confusión de Planos:** Si un agente tiene acceso de escritura al archivo de política que lo gobierna (`.harness/policy.json`) o a los ganchos de ejecución (`.agents/hooks.json`), el agente puede modificarlos para desactivar su propia supervisión.
2. **Ambigüedad de Flujos en Arquitectura:** En los diagramas e implementaciones ingenuas, una sola flecha representa a la vez la llamada de comando, el paso de datos, la verificación de seguridad y la auditoría, ocultando qué componente tiene autoridad de decisión.

## Decisión

Se formalizan cuatro **Fronteras de Confianza (Trust Boundaries)** y seis **Flujos Arquitectónicos Ortogonales (Architectural Flows)**:

### 1. Fronteras de Confianza (Trust Boundaries)

```
[ TB-0: Entorno del Operador / Host no Confiado a Agentes ]
  │
  ├─► refuto core (Supervisor, Evaluador, Compilador de Políticas)
  │
  ▼
[ TB-1: Proceso del Agente Supervisado ]
  │
  ├─► Claude Code / Kiro CLI / Antigravity / Gemini CLI / OpenCode
  │   (Contexto de LLM, memoria conversacional, razonamiento)
  │
  ▼  PreToolUse Hook (Intercepción de Salida)
[ TB-2: Plano de Ejecución de Herramientas & MCP ]
  │
  ├─► Servidores MCP (Playwright, Git, SQLite, Shell Tools)
  │   (Procesos hijos confinados)
  │
  ▼
[ TB-3: Almacén de Evidencia y Políticas Protegidas ]
  │
  └─► .harness/policy.json, .harness/runs/, refuto.lock
      (Inmutables y protegidos contra escritura de TB-1 y TB-2)
```

1. **TB-0 (Host & Orchestrator Plane):** Controlado por el desarrollador o runner de CI. refuto ejecuta con privilegios para orquestar y compilar.
2. **TB-1 (Agent Runtime Subprocess):** Código de terceros y modelos de lenguaje. No se asume confiable; sus intenciones de escritura y ejecución deben ser interceptadas.
3. **TB-2 (Tool & MCP Subprocesses):** Servidores de herramientas locales o remotos. Expuestos a entrada externa; gobernados por el manifiesto lockfile (`refuto.lock`).
4. **TB-3 (Protected Storage & Audit Vault):** Zona protegida por `refuto guard`. El agente en TB-1 no puede escribir en esta zona ni directa ni indirectamente.

### 2. Separación de Flujos (Flow Separation)

En la implementación y en la documentación arquitectónica, los flujos deben diferenciarse con precisión semántica y visual:

| Flujo | Propósito | Origen ➔ Destino | Garantía |
|---|---|---|---|
| **Control Flow** | Orquestación del ciclo de vida, arranque de procesos y fases. | Orquestador ➔ Runtime del Agente | Determinismo de ejecución y timeouts. |
| **Data Flow** | Lectura y transformación de código fuente y artefactos del repositorio. | Repositorio ➔ Agente / Herramienta | Respeto a scopes y ramas git. |
| **Policy Flow** | Compilación de directivas y reglas de gobernanza. | `policy.json` ➔ Configuraciones locales de hooks | Compilación unidireccional sin reescritura inversa. |
| **Interception Flow** | Inspección y autorización dinámica previa al uso de herramientas. | Hook del Agente ➔ `refuto guard` | Bloqueo síncrono previo a I/O (`ALLOW` / `DENY`). |
| **Evidence Flow** | Registro de aserciones, telemetría y eventos forenses inmutables. | Runtimes y Puertas ➔ Grafo de Evidencia | Append-only, huellas SHA-256 inmutables. |
| **Approval Flow** | Escalado interactivo hacia el operador humano cuando se superan umbrales. | `refuto guard` ➔ Terminal del Operador | Interrupción segura hasta confirmación humana explícita. |

## Consecuencias

- **Invariante de Seguridad:** Un agente nunca puede autorizarse a sí mismo para eludir una regla de política.
- **Trazabilidad Inequívoca:** Cada acción en el sistema pertenece a una frontera de confianza explícita y es transportada por un flujo tipado.
