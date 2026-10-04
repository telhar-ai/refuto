# ADR-0001 · Adoptar MCP + ACP + `SKILL.md` en vez de inventar un modelo canónico

**Estado:** aceptado · **Fecha:** 2026-08-27 · **Decide:** arquitectura de refuto

## Contexto

El encargo pedía diseñar un *Canonical Agent Harness Model* con entidades propias (`Agent`,
`Session`, `Tool`, `Skill`, `Hook`, `Policy`…) y adaptadores que tradujeran hacia cada agente.

## Problema

Un vocabulario propio hay que mantenerlo contra cinco runtimes que evolucionan por su cuenta.
Si el ecosistema converge en otro sitio, cada adaptador se convierte en deuda: traduce del
estándar emergente al propio, para no ganar nada.

## Evidencia recogida (2026-08-27, versiones del documento 00 de la auditoría)

| Hecho | Cómo consta |
|---|---|
| kiro-cli 2.20.0, Gemini CLI 0.55.1 y OpenCode 1.2.27 responden `initialize` de **ACP v1** sobre stdio y devuelven un documento estructurado de capacidades | **ejecutado**: los tres handshakes, en 2,2 s, sin créditos |
| Los cuatro agentes que arrancan hablan **MCP** | ejecutado / `--help` del binario instalado |
| `kiro-cli --output-format stream-json` está documentado como «*the run's **ACP events** as JSON Lines*» | `--help` del binario instalado |
| Claude Code y Gemini CLI consumen los dos **`SKILL.md`** con frontmatter `name`+`description` | ejecutado: `gemini skills list --all` lista `.../builtin/skill-creator/SKILL.md` |
| Los proveedores escriben migradores **entre sí**: `claude import codex\|gemini`, `gemini hooks migrate` desde Claude Code | `--help` de los binarios instalados |
| MCP 2026-07-28 hace **obligatorio** `server/discover`: una llamada devuelve versiones, capacidades e identidad | documentación primaria de la especificación |

## Opciones

**A · Modelo canónico propio.** Control total del vocabulario. Coste: N adaptadores contra un
estándar inventado, y reescribirlos cada vez que el emergente gane terreno.

**B · Adoptar los estándares de facto y adaptar sólo a los que se salen.** Menos superficie, y
la trayectoria de convergencia a favor. Coste: se hereda la evolución de tres especificaciones
que no controlamos.

**C · Sin abstracción; un script por agente.** Es el estado que encontró la auditoría del
2026-08-27 sobre un conjunto de repositorios privado: tres arneses sin contrato común, y todos los
agentes compartidos entre repositorios divergidos entre copias.

## Decisión

**B.** El transporte de herramientas es MCP. El transporte de sesión es ACP donde se habla, y
el CLI nativo donde no. El formato de skill es `SKILL.md`.

Lo propio se reserva para lo que **ningún proveedor cubre**: manifiesto, lock criptográfico,
puertas cuyos estados no colapsan, y evidencia con procedencia.

## Consecuencias

- refuto hereda cambios de especificación que no controla → se mitiga registrando **qué
  revisión respondió realmente cada servidor**, no la que se pidió.
- El primer servidor MCP real interrogado (Playwright 1.63.0-alpha) responde **`initialize`
  (2025-06-18)**, no `server/discover`. La caída al handshake legado no es teórica: es el caso
  común hoy.
- Claude Code no habla ACP → su adapter usa `system/init` del flujo `stream-json`, que aporta
  lo mismo. Es la excepción que justifica que exista la capa de adapter.

## Qué la haría cambiar

Que ACP deje de evolucionar o se fragmente en variantes incompatibles; o que dos de los tres
agentes que hoy lo hablan lo retiren. En ese caso el core no cambia —sólo habla con adapters—;
cambian tres adapters.
