# Investigación Comparativa de Ecosistemas de Harneses y Agentes

**Fecha:** 2026-09-22 · **Ámbito:** Runtimes, protocolos de control, trazabilidad y gobierno epistémico.
**Nivel de evidencia:** Síntesis empírica (E2/E3/E4 en ejecuciones locales de referencia) contrastada con especificaciones primarias (E1).

---

## 1. El Problema del Gobierno en Runtimes de Agentes

Los sistemas de agentes autónomos y asistentes de codificación (Claude Code, Kiro CLI, Google Antigravity, Gemini CLI, OpenCode, Codex, OpenHands, SWE-agent) han evolucionado rápidamente hacia arquitecturas con capacidad de ejecución de herramientas (*tool-use*), interacción con el sistema de archivos, ejecución de comandos y orquestación multi-agente.

Sin embargo, el ecosistema presenta deficiencias sistemáticas en cinco vectores críticos:

1. **La Falacia de la Autogobernanza:** Un agente no puede fiscalizarse a sí mismo. Cuando las restricciones, políticas de seguridad y validaciones residen dentro del propio contexto o prompt del modelo, el agente puede alucinar cumplimiento, eludir directivas bajo presión de contexto o modificar sus propias instrucciones.
2. **Colapso Epistémico:** Los runtimes tradicionales reducen los resultados a estados binarios (`success`/`failure`) o texto no estructurado. No distinguen entre *lo dicho* por el modelo (E0), *lo documentado* (E1), *lo reproducible* (E2), *lo probado con aserciones* (E3) y *lo observado en runtime* (E4).
3. **Aprobación de Ámbitos Vacíos (*Vacuous Truth*):** En múltiples arneses de evaluación y ejecución, un comando de test que no encuentra archivos o ejecuta 0 pruebas devuelve código de salida `0`. El runtime interpreta esto como éxito total (`PASS`), permitiendo regresiones catastróficas.
4. **Desgobierno en la Cadena de Suministro (MCP/Tools):** La adopción del Model Context Protocol (MCP) expone a los agentes a servidores de herramientas locales y remotos sin control de versiones ni firmas criptográficas. Un servidor de herramientas comprometido o mutado en runtime inyecta comandos arbitrarios sin detección.
5. **Fragmentación Incompatible de Políticas:** Cada proveedor implementa su propio esquema de hooks y permisos (`.claude/settings.json`, `.kiro/agents/*.json`, `.agents/hooks.json`, `.gemini/policies/*.json`). Mantener políticas idénticas entre agentes diverge rápidamente.

---

## 2. Matriz Comparativa de Ecosistemas y Runtimes

| Dimensión | Runtimes de Proveedor (Claude Code, Kiro, Antigravity, Gemini) | Harneses de Benchmarking (SWE-bench, OpenHands, SWE-agent) | Frameworks de Orquestación (LangGraph, CrewAI, AutoGen) | Refuto (Agent Assurance Harness) |
|---|---|---|---|---|
| **Rol Primario** | Ejecutor de tareas de desarrollo interactivo y por lotes. | Evaluación masiva sobre datasets estáticos de problemas. | Programación de flujos de grafos de agentes y memoria conversacional. | **Sidecar supervisor, Guardián de ejecución, Compilador de políticas y Juez epistémico.** |
| **Punto de Inyección** | Proceso principal que aloja el bucle de razonamiento. | Contenedor o máquina virtual que aísla el entorno de prueba. | Código de aplicación que encapsula llamadas a APIs de LLM. | **Interceptores pre-herramienta (hooks nativos), CLI wrapper y pipeline de 13 fases.** |
| **Modelo de Política** | Reglas en prompt, listas de permitidos locales en JSON dependientes del CLI. | Parches git evaluados contra suites de pruebas del repositorio. | Guardrails sintácticos en prompts o validadores de esquemas Pydantic. | **Política única declarativa (`policy.json`) compilada determinísticamente hacia cada agente.** |
| **Integridad de Herramientas** | Configuración manual en `mcpServers`, sin hashing de dependencias. | Configuración fija por Dockerfile pre-construido. | Herramientas definidas en código fuente de la aplicación. | **Lockfile criptográfico (`refuto.lock`) con SHA-256 de binarios, argumentos y servidores.** |
| **Resolución de Verdad** | Heurística / LLM-as-a-judge / Código de salida del comando. | `pytest` / test runner del repositorio objetivo (`PASS`/`FAIL`). | Validación de tipos y salidas de nodos en grafos dirigidos. | **Escalera Epistémica E0–E4 y Lógica Cuatrivalente (con prohibición estricta de paso en vacío).** |
| **Auditoría y Evidencia** | Logs de terminal planos o streams JSON de sesión. | Logs de ejecución de pruebas y parches `.diff`. | Trazas en bases de datos vectoriales o plataformas SaaS propietarias. | **Grafos de evidencia inmutables con hashes de contenido, procedencia y logs W3C PROV-O.** |

---

## 3. Posicionamiento Arquitectónico de Refuto

Refuto **no** busca reemplazar los modelos fundacionales ni sustituir los runtimes de los proveedores. Su arquitectura se posiciona como una **capa ortogonal de aseguramiento (Assurance Plane)**:

```
[ Desarrollador / CI / Orquestador ]
                  │
                  ▼
         ┌─────────────────┐
         │  refuto engine  │ ◄─── policy.json (Única Fuente de Verdad)
         │  (Supervisor)   │ ◄─── refuto.lock (Manifiesto Criptográfico)
         └────────┬────────┘
                  │ Compila políticas y hooks
                  ▼
  ┌─────────────────────────────────────────────────────────┐
  │  Zona de Ejecución del Agente (Runtime Híbrido)          │
  │                                                         │
  │   ┌────────────────────────┐    PreToolUse Intercept    │
  │   │  Agente (Claude, Kiro, │ ──────────────────────┐    │
  │   │  Antigravity, Gemini)  │                       │    │
  │   └───────────┬────────────┘                       ▼    │
  │               │ Intenta Tool / Write      ┌───────────┐ │
  │               ▼                           │ refuto    │ │
  │        [ Tool Execution ] ◄───────────────│ Dynamic   │ │
  │               │                           │ Guard     │ │
  │               ▼                           └───────────┘ │
  │        [ Filesystem / OS ]                      ▲       │
  │                                                 │       │
  └─────────────────────────────────────────────────┼───────┘
                                                    │
                                     Valida paths protegidos,
                                     scopes de escritura,
                                     y tokens de sesión
```

### Funciones que Refuto aporta y ningún runtime resuelve de forma nativa:

1. **Compilación Agnóstica de Políticas:** Una política corporativa o de proyecto redactada una sola vez en `policy.json` se compila hacia los formatos específicos de Claude Code (`settings.local.json`), Kiro CLI (`agents/*.json`), Google Antigravity (`hooks.json`), Gemini CLI (`policies/harness.json`) y OpenCode (`opencode.harness.json`).
2. **Guardián Dinámico Pre-Ejecución (`refuto-guard`):** Se intercepta la llamada a herramientas de escritura o comandos antes de que el agente toque el disco. Si el agente intenta modificar archivos de política, desenganchar sus propios hooks o escribir en rutas sensibles, el guardián deniega la acción a nivel de proceso.
3. **Validación de Ámbito Vacío en Puertas de Aseguramiento:** Todas las puertas de verificación analizan el conteo de elementos evaluados. Una suite con 0 pruebas ejecutadas resulta en `FAIL`. Una puerta sin artefactos aplicables resulta en `NOT_APPLICABLE`, jamás en `PASS`.
4. **Cadena de Custodia de Evidencia (Evidence Graph):** Cada aseveración técnica genera un registro estructurado con huella SHA-256 del contenido, comando exacto, variables de entorno, marca temporal ISO 8601 y nivel epistémico formal.
