# ADR-0009 · Modelo Canónico de Ejecución y Flujo de Eventos

**Estado:** aceptado · **Fecha:** 2026-09-22 · **Decide:** arquitectura del runtime y trazabilidad de refuto

---

## Contexto

Refuto coordina múltiples runtimes de agentes (Claude Code, Kiro CLI, Google Antigravity, Gemini CLI, OpenCode). Históricamente, cada agente emitía sus propios formatos de salida (JSON Lines propietarios, eventos ACP v1 o texto no estructurado en stdout/stderr). Esto dificultaba la reproducibilidad forense, la comparación cross-agent y el análisis cuantitativo de sesiones.

## Problema

1. **Divergencia de Telemetría:** Cada agente estructura eventos de forma distinta (p.ej., Claude usa `system/init` y bloques `tool_use`, Kiro emite eventos ACP con `sessionUpdate`, Gemini emite texto enriquecido o JSON estructurado).
2. **Pérdida de Causalidad:** Sin identificadores canónicos de corrida (`run_id`) y secuencia monótona (`seq`), no es posible reconstruir la línea temporal determinística cuando hay llamadas concurrentes a herramientas o subagentes.
3. **Ausencia de Estado Durable:** Si el proceso del agente aborta o sufre un fallo de sistema, los eventos intermedios se perdían o quedaban incompletos.

## Decisión

Se adopta un **Modelo Canónico de Corrida y Eventos (Canonical Run & Event Model)** que desacopla la captura del procesamiento:

1. **Identificador Canónico de Corrida (`run_id`):**
   - Generado al inicio de cada ejecución mediante UUIDv4 / ULID con marca temporal estricta ISO 8601 UTC.
   - Vinculado unívocamente al hash del árbol git actual (`git_tree_hash`) y al hash de la política activa (`policy_hash`).

2. **Esquema Normalizado de Eventos (`CanonicalEvent`):**
   Todos los adapters transforman eventos propietarios a un esquema común antes de persistir en el diario de eventos:
   ```json
   {
     "run_id": "run-20260922-152000-a1b2c3d4",
     "seq": 42,
     "timestamp": "2026-09-22T15:20:01.123456Z",
     "phase": "PHASE_04_GUARD_ACTIVE",
     "event_type": "TOOL_INVOCATION_REQUESTED",
     "actor": {
       "type": "AGENT",
       "runtime": "claude-code",
       "version": "2.1.247"
     },
     "payload": {
       "tool_name": "replace_file_content",
       "target_path": "core/wire.py",
       "hash_pre": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
     },
     "verdict": "ALLOWED"
   }
   ```

3. **Diario de Eventos Inmutable en Disco (`events.jsonl`):**
   - Registro en modo append-only en `.harness/runs/<run_id>/events.jsonl`.
   - Cada línea es autocontenida y sincronizada (`fsync`) en puntos de control críticos.

4. **Máquina de Estados de la Corrida:**
   - Estados canónicos: `INITIALIZED` → `CONFIGURED` → `GUARD_ACTIVE` → `EXECUTING` → `EVALUATING` → `COMPLETED` | `FAILED` | `ABORTED`.
   - Transiciones estrictamente dirigidas y validadas por el harness.

## Consecuencias

- **Positivas:**
  - Capacidad de reproducibilidad forense completa (*replay* de ejecuciones históricas).
  - Normalización de métricas de coste, consumo de tokens y llamadas a herramientas entre agentes radicalmente distintos.
  - Facilidad para exportar trazas hacia OpenTelemetry (OTel) o almacenar en almacenamiento frío.
- **Negativas / Costes:**
  - Sobrecarga mínima de serialización en el pipeline de eventos (< 2ms por evento).
  - Obligatoriedad de implementar el mapeador canónico en cada nuevo adapter.

## Qué la haría cambiar

La adopción universal por parte de todos los proveedores de un estándar de eventos de streaming común y universalmente interoperable (como una evolución formal de ACP con telemetría OTel integrada).
