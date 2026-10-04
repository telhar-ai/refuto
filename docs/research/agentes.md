# Los cinco agentes · lo verificado en una máquina, un día

**Fecha:** 2026-08-27 · `darwin 25.4.0 arm64` · un solo equipo.
Todo lo de aquí es *EJECUTADO* o del `--help` del binario **instalado** entonces. Nada es de una
web.

> **Caduca.** Son versiones de agosto de 2026 en macOS arm64. Las banderas y las firmas cambian
> con cada versión, y la comprobación de firma sólo existe en macOS. Antes de apoyarse en una fila
> de estas tablas, vuelva a medirla con `refuto probe` en su máquina.

## Versiones

| Agente | Versión | Cómo se obtuvo | Peldaño |
|---|---|---|---|
| kiro-cli | 2.20.0 | `--version` | `FUNCTIONAL` |
| Claude Code | 2.1.247 | `--version` | `FUNCTIONAL` |
| Gemini CLI | 0.55.1 | `--version` | `FUNCTIONAL` |
| OpenCode | 1.2.27 | `--version` | `FUNCTIONAL` |
| OpenAI Codex | 0.103.0 | `package.json` (el binario no arranca) | `INSTALLED` |

## Firma de código — *EJECUTADO*, y cuatro veredictos distintos

| Agente | Veredicto | Detalle |
|---|---|---|
| kiro-cli | `VALID` | binario firmado y válido |
| Claude Code | `VALID` | |
| Gemini CLI | `UNSIGNED` | guion de Node; **no es un fallo**, nunca lleva firma |
| OpenCode | `INVALID` | `code or signature have been modified` — reubicación de Homebrew, o manipulación. **Se reporta; no bloquea**, porque el agente sí funciona |
| Codex | **`REVOKED`** | `CSSMERR_TP_CERT_REVOKED`, TeamIdentifier `2DC432GLL2`. macOS lo mata: `SIGKILL` |

Colapsar `UNSIGNED` e `INVALID` en «fallo» produciría ruido en cuatro de cinco agentes, y una
comprobación ruidosa se desactiva.

## Lo que sólo tiene uno, y no se aplana

| Capacidad | Quién | Evidencia |
|---|---|---|
| `--max-budget-usd` — tope de gasto por ejecución | **Claude Code** | ejecutado: `usd=0.074522` en una corrida real |
| `--json-schema` — salida estructurada validada | Claude Code | `--help` |
| `--safe-mode` — desactiva TODA personalización | Claude Code | `--help` |
| `claude import codex\|gemini` | Claude Code | `--help` |
| `--require-mcp-startup` con **código de salida 3** | **Kiro** | `--help` |
| `knowledgeBase` indexada automáticamente | Kiro | configuración de agente |
| `--cloud` — caja de arena remota (V3/KAS) | Kiro | `--help` |
| Policy Engine con `--admin-policy` separado del usuario | **Gemini** | `--help`; `--allowed-tools` ya marcado DEPRECATED |
| **Confianza de carpeta** que bloquea agentes y hooks del proyecto | Gemini | ejecutado: «Skipping project agents due to untrusted folder» |
| `gemini skills install <git-url>` | Gemini | `--help` |
| `gemini hooks migrate` desde Claude Code | Gemini | `--help` |
| `opencode serve` — **servidor HTTP persistente** | **OpenCode** | `--help` |
| `opencode export\|import` — sesión como JSON | OpenCode | `--help` |
| `opencode stats` — coste y tokens | OpenCode | `--help` |

La confianza de carpeta de Gemini merece énfasis: **es una propiedad de seguridad que los otros
no imponen igual**, y homogeneizarla sería quitarle a Gemini algo que hace bien. refuto la
reporta en vez de sortearla.

## Handshake sin llamar a ningún modelo — y la excepción

| Agente | Mecanismo | Qué devuelve |
|---|---|---|
| kiro, gemini, opencode | ACP `initialize` | `agentCapabilities`, `agentInfo`, `authMethods` |
| claude | `system/init` del flujo `--output-format stream-json` | versión, modelo, modo de permisos, servidores MCP, herramientas, agentes, comandos, plugins |
| codex | *ninguno verificable* | el binario no arranca |

## Validación de Claude Code como implementación de referencia — *EJECUTADO*

```
$ claude -p "…" --output-format stream-json --tools "Read" \
         --permission-mode dontAsk --max-budget-usd 0.30
SYSTEM   init      tools=1  model=claude-opus-5[1m]
TOOL_USE Read      …/verificacion/comun.py
TEXT     11
RESULT   success   turns=2   usd=0.074522   is_error=False
```

Privilegio mínimo por herramienta, sin interacción, evidencia como JSONL, coste medido y
resultado correcto. Es el mismo contrato de fase que ejecuta `kiro.sh`, dicho con otras
banderas — que es exactamente lo que la capa de adapter tiene que demostrar.
