# ACP — Agent Client Protocol · investigación primaria

**Consultado:** 2026-08-27 · **Fuente:** `agentclientprotocol.com` + handshakes ejecutados
**Estado:** *ESTÁNDAR EMERGENTE* — especificación pública, v1, implementada por tres de los
cinco agentes instalados

## Qué es

JSON-RPC 2.0 entre un **cliente** (editor, IDE, orquestador) y un **agente**. Tres fases:

```
initialize            negocia versión y capacidades; opcionalmente `authenticate`
session/new|load      abre o reanuda una conversación
session/prompt        turno; el agente emite `session/update` y puede pedir permiso
```

Métodos del agente: `initialize`, `authenticate`, `session/new`, `session/prompt`,
`session/load`, `session/set_mode`, `session/cancel`, `logout`.
Métodos del cliente: `session/request_permission`, `fs/read_text_file`, `fs/write_text_file`,
operaciones de terminal, `elicitation/create`.

## Handshakes ejecutados — *VERIFICADO el 2026-08-27, macOS arm64 (Darwin 25.4.0)*

Los tres respondieron `initialize` sobre stdio **sin llamar a ningún modelo**, luego sin coste.
El sondeo completo de los cinco agentes de aquella máquina tardó **2,2 s** en paralelo: medido una
vez, aquel día, con esos binarios; depende de qué haya instalado y no es una propiedad del
producto.

Nota que evita una lectura de más: de los cinco, **Claude Code sí envía un prompt** (`-p hi`, con
tope `--max-budget-usd 0.05`) para obtener su `system/init`. Su coste no se midió. «Sin gastar
créditos» es exacto para los cuatro que hablan un handshake puro.

```
kiro-cli acp     → v1  "Kiro CLI Agent" 2.20.0
                   loadSession · promptCapabilities{image} · mcpCapabilities{http}
                   sessionCapabilities{} · auth{}

gemini --acp     → v1  "gemini-cli" 0.55.1
                   loadSession · promptCapabilities{image,audio,embeddedContext}
                   mcpCapabilities{http,sse}
                   authMethods: oauth-personal, gemini-api-key, vertex-ai, gateway

opencode acp     → v1  "OpenCode" 1.2.27
                   loadSession · mcpCapabilities{http,sse}
                   sessionCapabilities{fork,list,resume}
                   authMethods: opencode-login

codex acp        → BLOQUEADO: SIGKILL (H-01)
claude           → no expone ACP en su CLI 2.1.247
```

## Las dos consecuencias arquitectónicas

**1 · Descubrimiento de capacidades gratuito.** El agente declara lo que sabe hacer. No se
infiere de la documentación ni se supone de la versión: se pregunta, y responde él.

**2 · `session/request_permission` es un punto de política a nivel de protocolo.** El
**cliente** decide si una llamada a herramienta procede, con `toolCall` + `options` → `outcome`.
Eso permitiría aplicar la política canónica sin depender de la configuración de hooks de cada
proveedor.

**No está implementado hoy.** refuto usa ACP sólo para el handshake de sondeo; conducir la
sesión se hace por el CLI nativo, que es lo que los propios proveedores tienen probado en
producción. Ver riesgo residual **RR-03**: es la evolución natural y la que haría refuto
verdaderamente independiente del runtime.

## Cuidado con los nombres

Hay varios protocolos con siglas parecidas: *Agent Client Protocol*, *Agent Communication
Protocol*, *Agent Control Protocol*. **No son el mismo proyecto.** refuto habla el
primero, el de `agentclientprotocol.com`, y lo verifica ejecutando `initialize` — no
suponiéndolo por el nombre de la bandera.
