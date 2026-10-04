# Matriz de compatibilidad

**Generado, no escrito.** Cada casilla sale de sondear los agentes de esta máquina; ninguna se rellena por inferencia. Vuelve a generarse con `refuto docs`.

Generado: 2026-08-30T15:58:51.008+00:00

> **Cómo leer esta copia.** Es una **salida de ejemplo**, fechada el 2026-08-30 y medida en una
> máquina macOS arm64 (Darwin 25.4.0) con esos cinco agentes instalados en esas versiones. **No es
> una promesa de soporte del producto**: dice lo que aquella máquina demostró aquel día. Ejecute
> `refuto docs` y obtendrá la suya, que sustituirá a este archivo entero —incluida esta nota, que
> el generador no escribe—.
>
> **Lo que esta matriz todavía no distingue:** «la política se compila» de «la política se
> aplica». La fila *Política compilable* dice `ADAPTER` para cinco agentes, y sólo en dos
> —`claude` y `kiro`— hay guardián enganchable con `policy wire`. Tampoco tiene fila para «abre
> sesión gobernada» ni para «guardián enganchado». Esas tres capacidades son verbos distintos y
> están en la tabla de capacidades del [`README.md`](README.md), escrita a mano hasta que
> `core/docs.py` la genere.
>
> `antigravity` no aparece aquí: tiene dialecto de gancho y enganche, y **no** tiene adapter ni
> sonda, así que la matriz —que se construye desde la sonda— no lo ve.

## Vocabulario

| Valor | Significa |
|---|---|
| `NATIVO` | Lo trae el agente y se comprobó ejecutándolo |
| `COMPROBADO` | El agente lo declaró en su propio handshake |
| `ADAPTER` | Lo aporta refuto traduciendo |
| `DECLARADO` | Consta en la documentación del CLI instalado; no se sondeó |
| `NO` | Consta que no existe |
| `BLOQUEADO` | No se pudo verificar: el agente no arranca en esta máquina |
| `?` | No verificado. Se declara; no se rellena |

## Estado de cada agente

| Agente | Peldaño | Versión | Protocolo | Firma | Nota |
|---|---|---|---|---|---|
| **claude** | `FUNCTIONAL` | 2.1.251 | claude-stream-json/v2.1.251 | VALID | VERIFIED no se intentó: requiere --deep (gasta créditos) |
| **codex** | `FUNCTIONAL` | 0.151.0 | codex-mcp-server/v0.151.0 | VALID | VERIFIED no se intentó: requiere --deep (gasta créditos) |
| **gemini** | `FUNCTIONAL` | 0.55.1 | acp/v1 | UNSIGNED | VERIFIED no se intentó: requiere --deep (gasta créditos) |
| **kiro** | `FUNCTIONAL` | 2.20.1 | acp/v1 | VALID | VERIFIED no se intentó: requiere --deep (gasta créditos) |
| **opencode** | `FUNCTIONAL` | 1.2.27 | acp/v1 | INVALID | VERIFIED no se intentó: requiere --deep (gasta créditos) |

## Capacidades

| Capacidad | claude | codex | gemini | kiro | opencode |
|---|---|---|---|---|---|
| Handshake estructurado | `COMPROBADO` | `COMPROBADO` | `COMPROBADO` | `COMPROBADO` | `COMPROBADO` |
| ACP v1 | `NO` | `NO` | `NATIVO` | `NATIVO` | `NATIVO` |
| MCP | `NATIVO` | `NATIVO` | `NATIVO` | `NATIVO` | `NATIVO` |
| Sesiones | `?` | `?` | `NATIVO` | `NATIVO` | `NATIVO` |
| Reanudar | `DECLARADO` | `DECLARADO` | `NATIVO` | `NATIVO` | `NATIVO` |
| SKILL.md | `NATIVO` | `?` | `DECLARADO` | `DECLARADO` | `?` |
| Política compilable | `ADAPTER` | `ADAPTER` | `ADAPTER` | `ADAPTER` | `ADAPTER` |
| Presupuesto en $ | `NATIVO` | `NO` | `NO` | `NO` | `?` |
| Aislamiento | `?` | `NATIVO` | `NATIVO` | `NATIVO` | `?` |
| Evidencia normalizada | `ADAPTER` | `ADAPTER` | `ADAPTER` | `ADAPTER` | `ADAPTER` |

## Notas por casilla

**Handshake estructurado** — ¿Se puede saber qué sabe hacer sin gastar créditos?
- `claude`: claude-stream-json
- `codex`: codex-mcp-server
- `gemini`: acp
- `kiro`: acp
- `opencode`: acp

**ACP v1** — Protocolo cliente↔agente, abierto
- `claude`: no aparece en su CLI
- `codex`: no aparece en su CLI
- `gemini`: initialize respondió v1
- `kiro`: initialize respondió v1
- `opencode`: initialize respondió v1

**MCP** — Protocolo de herramientas
- `claude`: 0 servidores en la sesión sondeada
- `codex`: 0 servidores en la sesión sondeada
- `gemini`: transportes: http, sse
- `kiro`: transportes: http
- `opencode`: transportes: http, sse

**Sesiones** — Estado conversacional gestionado por el agente
- `gemini`: loadSession
- `kiro`: loadSession
- `opencode`: fork, list, resume

**Reanudar** — Continuidad entre fases
- `claude`: bandera de reanudación en su CLI
- `codex`: bandera de reanudación en su CLI
- `gemini`: loadSession en el handshake
- `kiro`: loadSession en el handshake
- `opencode`: loadSession en el handshake

**SKILL.md** — Procedimientos cargados por descripción
- `claude`: 44 comandos en la sesión sondeada
- `codex`: no verificado en esta máquina en 0.151.0
- `gemini`: SKILL.md documentado en su CLI
- `kiro`: SKILL.md documentado en su CLI
- `opencode`: no verificado en esta máquina

**Política compilable** — La política canónica se traduce a su vocabulario
- `claude`: compilación completa
- `codex`: 3 regla(s) no aplicables
- `gemini`: 1 regla(s) no aplicables
- `kiro`: compilación completa
- `opencode`: 1 regla(s) no aplicables

**Presupuesto en $** — Tope de gasto por ejecución
- `claude`: --max-budget-usd
- `codex`: no hay bandera de presupuesto en 0.151.0
- `kiro`: no hay bandera de presupuesto en 2.20.0

**Aislamiento** — Ejecución acotada
- `codex`: --sandbox (seatbelt) · `codex sandbox` ejecuta órdenes acotadas
- `gemini`: --sandbox
- `kiro`: --cloud

**Evidencia normalizada** — Sus eventos entran al diario de refuto
- `claude`: eventos normalizados por el adapter
- `codex`: eventos normalizados por el adapter
- `gemini`: eventos normalizados por el adapter
- `kiro`: eventos normalizados por el adapter
- `opencode`: eventos normalizados por el adapter

