# MCP — investigación primaria

**Consultado:** 2026-08-27 · **Fuente:** `modelcontextprotocol.io`, especificación revisión
`2026-07-28` · *ESTÁNDAR*

> Nivel: `E1`. Es una lectura de la especificación externa hecha ese día y **no se ha vuelto a
> contrastar** con ella; lo que sí está en el código es lo que aquí se describe implementado
> (`core/mcp.py`). Si la revisión cambió, manda la especificación, no este documento.

## Revisión vigente: `2026-07-28`

Identificadores de versión `YYYY-MM-DD`; la fecha indica el último cambio incompatible. Las
revisiones se marcan *Draft*, *Current* o *Final*.

### Lo que cambió y afecta a refuto

| Cambio | Impacto |
|---|---|
| **MCP es stateless**: desaparece el handshake `initialize`/`notifications/initialized`. Cada petición lleva su versión y capacidades en `_meta` (`io.modelcontextprotocol/protocolVersion`, `…/clientCapabilities`) | el cliente de refuto manda `_meta` en cada llamada |
| **`server/discover` es obligatorio** para los servidores: una llamada devuelve `supportedVersions`, `capabilities` e identidad | **es la primitiva de descubrimiento de capacidades**: sustituye a sondear `tools/list` + `prompts/list` + `resources/list` |
| Desaparecen las sesiones de protocolo y `Mcp-Session-Id` de Streamable HTTP | el estado entre llamadas se pasa como argumento de herramienta |
| `subscriptions/listen` sustituye al GET y a `resources/subscribe` | no usado hoy por refuto |
| **Tasks sale del core** a una extensión oficial `io.modelcontextprotocol/tasks` | *EXPERIMENTAL para nuestros efectos*: no se adopta como dependencia |
| Campo **`extensions`** en `ClientCapabilities` y `ServerCapabilities` | negociación de capacidades de primera clase |
| **Contexto de traza OpenTelemetry** documentado en `_meta`: `traceparent`, `tracestate`, `baggage` (SEP-414) | ruta natural de observabilidad; **no implementado todavía** — ver RR-04 |
| Multi Round-Trip Requests: `resultType: "input_required"` con `inputRequests` | sustituye a peticiones iniciadas por el servidor |
| Todo resultado lleva `resultType` obligatorio | los clientes antiguos que lo omiten se leen como `"complete"` |
| **Deprecados**: Roots, Sampling, Logging; HTTP+SSE; Dynamic Client Registration (a favor de Client ID Metadata Documents) | no se adopta nada deprecado |

## Contraste con la realidad instalada — *EJECUTADO*

El primer servidor MCP real que interrogó refuto:

```
Playwright 1.63.0-alpha-2026-08-05
  respondió a:      initialize        ← NO implementa server/discover
  revisión:         2025-06-18
  capacidades:      tools
  herramientas:     24
```

**La especificación va tres revisiones por delante del ecosistema instalado.** Por eso
`core/mcp.py` intenta `server/discover` primero, cae a `initialize`, y **registra cuál
respondió**. Saber qué revisión habla cada servidor de verdad es parte del inventario, no un
detalle de implementación.

## Lo que refuto NO usa, y por qué

- **Tasks** (`io.modelcontextprotocol/tasks`): es una extensión, no core. Convertir una
  extensión en dependencia obligatoria sin registrar la decisión es cómo se acumula deuda.
- **Elicitation / MRTR**: refuto interroga; no conversa.
- **Autorización OAuth**: los servidores HTTP se declaran `BLOCKED` en vez de intentar
  autenticarse. Pedir credencial para sondear cambiaría lo que la sonda es.
