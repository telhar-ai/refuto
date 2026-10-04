# Matriz de hallazgos · estado de remediación — **documento histórico**

**Fecha:** 2026-08-27 · Los 12 hallazgos de aquella auditoría, ninguno perdido.

> **Léase con la fecha delante.** Es el registro de una auditoría del 2026-08-27 sobre un conjunto
> de repositorios **privado**, y de lo que se remedió entonces. No describe el estado actual del
> producto —para eso está [`../estado-del-proyecto.md`](../estado-del-proyecto.md)— y las partes
> que ocurrieron «en el conjunto auditado auditado» **no son reproducibles** por un tercero. Se conserva
> porque varios hallazgos explican por qué el código tiene la forma que tiene.

Vocabulario de estado, y se usa con rigor:

| Estado | Significa |
|---|---|
| `VERIFIED` | remediado **y** demostrado ejecutando; hay prueba automática que lo fija |
| `PARTIALLY VERIFIED` | remediado en parte; lo que falta se declara |
| `NOT VERIFIED` | hay código que lo aborda y **no** hay demostración |
| `BLOCKED` | no se puede remediar aquí; se declara por qué |
| `NOT APPLICABLE` | deja de aplicar por una decisión de diseño registrada |

---

## H-01 · Codex instalado e inejecutable — certificado revocado

**Severidad** CRÍTICO · **Estado** `VERIFIED` (detección) · `BLOCKED` (el agente en sí)

**Causa raíz.** Todo arnés auditado comprobaba disponibilidad con `command -v`. El techo de
lo que `which` puede afirmar es `INSTALLED`; el binario nativo de `@openai/codex@0.103.0` tiene
el certificado de firma revocado (`CSSMERR_TP_CERT_REVOKED`, TeamIdentifier `2DC432GLL2`) y
macOS lo mata con `SIGKILL`.

**Remediación.** `core/probe.py` — escalera de cinco peldaños con comprobación de firma del
**binario nativo detrás del lanzador**, y cuatro veredictos de firma (`VALID`, `UNSIGNED`,
`INVALID`, `REVOKED`).

**Archivos** `core/probe.py`, `core/acp.py`, `adapters/*.py`, `gates/g_agent.py`

**Pruebas** `tests/selftest/test_gates.py::TestGateAgent::test_negativo_agente_que_no_arranca`

**Evidencia**
```
$ refuto doctor
  ✗ INSTALLED    codex      0.103.0
      ↳ muerto por señal 9 — el certificado de firma del binario nativo está REVOCADO; reinstale
      ↳ firma REVOKED: …/vendor/aarch64-apple-darwin/codex/codex
  Resumen accionable
    → codex: certificado de firma REVOCADO → reinstale el agente
             (p. ej. `npm i -g @openai/codex@latest`) y vuelva a sondear
```

**Riesgo residual.** Codex sigue sin poder evaluarse. Reinstalar el paquete es un cambio en la
máquina del usuario y **no se hizo**. Toda su columna en la matriz sale `BLOQUEADO`, que es la
lectura correcta: el adapter existe; la evidencia de que funcione, no.

---

## H-02 · La fase `visual` dependía de un servidor MCP inexistente

**Severidad** CRÍTICO · **Estado** `VERIFIED`

**Causa raíz.** `sdd-verificacion-visual` declaraba `@navegador/*` y ningún `mcp.json` lo
configuraba. `kiro-cli agent validate` devolvía `rc=0`: valida **esquema**, no integridad
referencial. Y `--require-mcp-startup` exige que arranquen los servidores *habilitados* — un
servidor no declarado tampoco está habilitado, así que no se comprobaba.

**Remediación, en dos partes.**

1. *En refuto*: `core/mcp.py` + `gates/g_mcp.py` comprueban la cadena entera —herramienta
   declarada → servidor requerido → configuración → arranque → capacidad anunciada— con
   `server/discover` (MCP 2026-07-28) y caída a `initialize`.
2. *En el conjunto auditado*: se declaró el servidor que faltaba, **con evidencia**. `@playwright/mcp`
   estaba en la caché de npx, prueba de que se usó y nunca se declaró. Se interrogó antes de
   escribir nada: Playwright 1.63.0-alpha-2026-08-05, 24 herramientas, revisión 2025-06-18.

**Archivos** `core/mcp.py`, `gates/g_mcp.py`, `<espacio-privado>/{proyecto,plantilla}/.kiro/settings/mcp.json`

**Pruebas** `TestGateMcp` (5 casos) · `TestMcpMalicioso::test_un_servidor_fantasma_no_pasa_por_ausencia`

**Evidencia** — antes y después sobre el espacio real
```
antes:    ✗ FAIL     2 servidores exigidos · 1 configurados · 2 rotas
después:  ⊘ BLOCKED  2 servidores exigidos · 2 configurados · 0 rotas
          i «navegador» responde por initialize · revisiones ['2025-06-18'] · 24 herramientas
          i «figma» (http): requiere credencial de la sesión del agente
```

`BLOCKED`, no `PASS`: el servidor de Figma es HTTP y sólo se puede interrogar desde el propio
agente. Eso es lo que hay, y se dice.

---

## H-03 · «Proteger al juez» no protegía nada en la ruta del CLI

**Severidad** ALTO · **Estado** `VERIFIED`

**Causa raíz.** La misma política escrita en dos vocabularios —`.kiro/hooks/*.json` del IDE y
`hooks{}` del agente del CLI— y `guarda_rutas.py` enganchado sólo en el primero. El orquestador
siempre llama al CLI.

**Remediación.** Una política canónica (`core/policy.py`), un guardián único (`core/guard.py`)
que normaliza la carga de cada runtime, y `core/wire.py` que lo engancha **en la ruta del CLI**
con copia de seguridad, idempotencia y `unwire`.

**Archivos** `core/policy.py`, `core/guard.py`, `core/wire.py`, `gates/g_policy.py`,
`<espacio-privado>/proyecto/.kiro/agents/*.json` (5), `.kiro/hooks/harness-guard.json`,
`.claude/settings.harness.json`

**Pruebas** `tests/unit/test_policy.py` (16) · `tests/unit/test_wire.py` (7) ·
`tests/adversarial/test_attacks.py::TestModificarAlJuez` (4)

**Evidencia** — medido en el espacio real
```
antes:   guardián en la ruta del CLI: 0/5 agentes
después: guardián en la ruta del CLI: 5/5 agentes

$ echo '{"tool_name":"fs_write","path":"verificacion/v0_trazabilidad.py",…}' | <comando exacto del gancho>
harness-guard: BLOQUEADO — «verificacion/v0_trazabilidad.py» está protegida por «verificacion/**» …
rc=2

$ echo '{"tool_name":"fs_write","path":"app/ui.js","content":"export const x = 1;"}' | <ídem>
rc=0        ← permitido, en silencio
```

**Riesgo residual.** Es control **preventivo del lado del cliente**. El archivo vive en el
repositorio y el agente podría editarlo. La única capa fuera de su alcance es la rama protegida
y CI, y así se declara en `SECURITY.md`.

---

## H-04 · Un agente global de terceros rompe los comandos globales de Kiro

**Severidad** ALTO · **Estado** `PARTIALLY VERIFIED`

**Causa raíz.** `~/.kiro/agents/kirocrew.json` apunta con `prompt: file:///Volumes/KiroCrew/…`
a un volumen desmontado. `kiro-cli agent list` y `mcp list` fallan enteros para todos.

**Remediación.** refuto **no depende** de `kiro-cli agent list`: lee los agentes del
espacio directamente, y su descubrimiento aísla el fallo por entrada (un agente ilegible se
declara `skipped` con motivo, no rompe la corrida). El inventario detecta rutas absolutas rotas:
**84** en el conjunto auditado.

**Archivos** `core/inventory.py`, `core/wire.py`, `core/mcp.py`

**Pruebas** `TestEnganche::test_un_agente_ilegible_se_declara_no_se_salta`

**Lo que falta.** El fallo dentro de Kiro CLI sigue ahí: es un defecto del producto de un
tercero, y no se puede arreglar desde aquí. La acción es del usuario: retirar o corregir
`~/.kiro/agents/kirocrew.json`. **No se tocó**: es configuración global ajena al espacio
auditado.

---

## H-05 · Dos verdades sobre los agentes (workspace y global)

**Severidad** ALTO · **Estado** `NOT VERIFIED`

**Causa raíz.** `instala_agentes.py` publica copias con **rutas absolutas** a `~/.kiro/agents/`.
Hoy sin deriva de contenido, pero `kiro-cli agent list` emite 5 avisos de conflicto, y un `mv`
del espacio dejaría cinco agentes que aparecen y fallan al usarse.

**Estado.** El inventario **detecta** el patrón (rutas absolutas en configuración, con
comprobación de si el destino existe). **No se ha remediado la causa**: retirar la publicación
global cambiaría el flujo de trabajo del usuario, y esa es su decisión, no la de refuto.

**Acción recomendada.** `python3 herramientas/instala_agentes.py --retira`, y usar
`./kiro.sh chat`, que ya entra en el directorio correcto. Contradice la propia regla rectora del
espacio: *no versionar lo materializado, porque crea dos verdades y la copia envejece sin
avisar.*

---

## H-06 · El lock era evidencia, no guardia; el tag es mutable

**Severidad** ALTO · **Estado** `VERIFIED`

**Causa raíz.** `traer → reescribir el lock → comparar` es una tautología, y el ancla era una
etiqueta de git.

**Remediación.** `core/lock.py` con la secuencia correcta y tres invariantes probados.

**Archivos** `core/lock.py`, `gates/g_lock.py`

**Pruebas** `TestGateLock` (7, incluido `test_verify_nunca_escribe_el_lock`) ·
`TestSuministroYLock` (2)

**Evidencia** — ancla real fijada en el espacio SDD
```
uri     https://github.com/<organización-privada>/<origen>.git
ref     v3.0.1                                       (mutable)
commit  ea11fe8c09ee3e6e22735b853d33dd48f212d05f     (ancla real)
files   21        tree fd6abdb10a7fad1adbda7f9b

$ refuto verify --gate G-LOCK
  ✓ PASS  1 orígenes · 21 archivos anclados · 0 desviaciones
     i «nucleo»: la referencia «v3.0.1» sigue en ea11fe8c09ee…
```

**Riesgo residual RR-01.** El lock ancla por contenido y por commit; **no lleva firma**. Impide
la sustitución silenciosa, no acredita quién publicó ese commit.

---

## H-07 · La flota Claude se distribuye por copia y ya divergió

**Severidad** ALTO · **Estado** `PARTIALLY VERIFIED`

**Causa raíz.** Distribución por copia manual, sin manifiesto, sin lock, sin puerta.

**Remediación.** `gates/g_fleet.py` comprueba deriva en las tres direcciones (ausente, editado,
materializado sin ancla) y `core/inventory.py` la **mide** en todo el conjunto auditado.

**Evidencia** — medición mecánica, reproducible con `refuto inventory`
```
118 archivos de agente para 75 nombres distintos: 43 copias
14 agentes con contenido divergente entre copias
 6 skills con contenido divergente entre copias
84 referencias absolutas rotas
```

**Lo que falta.** El mecanismo existe y está probado, pero **la flota Claude todavía no se ha
migrado** a manifiesto + lock. Eso es la fase 3 de `MIGRATION.md` y toca cuatro repositorios de
producción: se hace con el usuario delante, no por sorpresa.

---

## H-08 · Skills a dos líneas de ser portables

**Severidad** MEDIO · **Estado** `VERIFIED`

**Causa raíz.** `experiencia/` declaraba `name: experiencia-y-accesibilidad` y `revision/`
declaraba `revision-adversarial`. Claude Code exige que `name` coincida con el directorio: dos
de las ocho no cargarían.

**Remediación.** `core/skill.py` con contrato verificable + `gates/g_skill.py`; y las dos líneas
corregidas en el conjunto auditado.

**Archivos** `core/skill.py`, `gates/g_skill.py`,
`<espacio-privado>/proyecto/.kiro/skills/{experiencia,revision}/SKILL.md`

**Pruebas** `tests/unit/test_skill.py` (16) · `TestGateSkill` (6) · `TestSkillMaliciosa` (2)

**Evidencia**
```
antes:   ✗ FAIL  8 skills · 2 incumplimientos
después: ✓ PASS  8 skills · 8 nombres distintos · 0 incumplimientos
         i 8 skills sin `harness.version`: no se pueden fijar en un lock
```

**Lo que falta.** Ninguna skill declara `harness.version`, así que no se pueden anclar. Se
reporta como observación, no como fallo: obligarlo hoy pondría en rojo a todo el mundo el primer
día.

---

## H-09 · El proyecto de referencia no pasa sus propias puertas

**Severidad** MEDIO · **Estado** `NOT VERIFIED` — *deliberadamente no remediado*

**Estado real, ejecutado hoy**: V0 en rojo (3 pruebas citan `REQ-022/023/024`, que no existen),
V2 en rojo (6 componentes declarados en `design.md` y ausentes del producto). 8 de 11 cumplen.

**Por qué no se remedió.** Arreglar V0 significa **decidir** si esos tres requisitos deben
existir o si esas tres pruebas sobran. Arreglar V2 significa decidir si el producto debe tener
esos seis componentes o si `design.md` promete de más. Las dos son decisiones de producto, no
defectos mecánicos, y refuto no las toma.

Lo que sí se hizo: `G-SDD` las **expone en el veredicto compuesto** en vez de dejarlas en un
informe que nadie mira.

---

## H-10 · El razonamiento sobre `--agent-engine` ya no describe el binario

**Severidad** MEDIO · **Estado** `PARTIALLY VERIFIED`

`kiro.sh:15-16` justifica `--agent-engine v2` porque «pasar `--agent` cae al motor v1». En
kiro-cli **2.20.0** el `--help` dice `v2 (default)`. La práctica sigue siendo buena; la razón
escrita es falsa hoy.

**Remediación estructural.** El manifiesto declara versiones y la sonda las comprueba: ya no se
razona sobre una versión que nadie declara. El comentario de `kiro.sh` **no se corrigió**:
es prosa del conjunto auditado y su corrección es del autor.

---

## H-11 · Documentación divergente del código

**Severidad** MEDIO · **Estado** `NOT APPLICABLE` para refuto · pendiente en el conjunto auditado (privado)

`verificar.py` dice «ocho puertas» (son once); `LEEME.md` dice «cuatro agentes» (son cinco) y
documenta `--trust-tools`, que `kiro.sh` deliberadamente no pasa.

**Decisión de diseño.** refuto ataca la clase de problema, no las tres instancias:
`SUPPORT_MATRIX.md` **se genera** (ADR-0008), así que no puede divergir. Las tres frases del
conjunto auditado son prosa de su autor y corregirlas no era de este trabajo.

> Nota del 2026-09-22: este hallazgo volvió a ocurrir **dentro de este propio repositorio** —la
> documentación decía 8 puertas donde hay 13, 24 pruebas adversariales donde hay 27, y 5 runtimes
> «soportados» donde el número depende del verbo—. Generar una tabla no basta si el resto de la
> prosa se escribe a mano: por eso ahora toda cifra lleva comando, fecha y máquina.

---

## H-12 · Tres copias de `kiro.sh` en dos versiones

**Severidad** BAJO · **Estado** `PARTIALLY VERIFIED`

Raíz: 316 líneas (`438a48d5`). `plantilla/herramientas/` y `proyecto/herramientas/`: 242 líneas,
idénticas entre sí (`435daca6`). Ninguna declarada canónica.

`refuto inventory` detecta la clase de problema (duplicados con contenido divergente). Declarar
cuál de las tres es canónica y materializar las otras dos desde ella es la fase 2 de la
migración: exige decidir cuál es, y esa decisión es del autor.

---

---

## Actualización tras el ciclo 3 · plataforma operativa

Tres hallazgos cambiaron de estado al construir la capa de plataforma.

### H-04 · `PARTIALLY VERIFIED` → `VERIFIED` (para refuto)

`core/discovery.py` no depende de ningún comando de Kiro: lee los agentes del espacio
directamente y **aísla el fallo por entrada**. Un `manifest.json` que resultó ser una lista JSON
—no un manifiesto— reventaba el descubrimiento entero; ahora se descarta con motivo y el resto
continúa. Comprobado con `test_un_manifest_que_es_una_lista_no_revienta`.

El defecto **dentro de Kiro CLI** sigue: es de un tercero. Sigue siendo acción del usuario.

### H-05 · `NOT VERIFIED` → `PARTIALLY VERIFIED`

`refuto bind` sustituye la necesidad de publicar agentes globalmente: el espacio se ata a su
núcleo y a su repositorio en `.harness/binding.json`, **por commit y no por ruta**, así que
mover el espacio no rompe nada y no hacen falta rutas absolutas en ningún sitio.
`refuto bind verify` detecta que el vínculo dejó de valer.

Retirar `instala_agentes.py` sigue siendo decisión del autor.

### H-11 · `NOT APPLICABLE` → `VERIFIED` (para refuto)

Además de `SUPPORT_MATRIX.md`, ahora se genera `context-report.md` en cada ejecución, con una
sección explícita de **«lo que refuto NO sabe»**. Un documento que declara sus propios huecos
no puede divergir en silencio: divergir sería dejar de listarlos.

---

## Riesgos residuales

| | Riesgo | Mitigación hoy | Qué haría falta |
|---|---|---|---|
| **RR-01** | El lock ancla por contenido y commit, **sin firma**: no acredita quién publicó | detecta sustitución silenciosa | firma de procedencia (Sigstore / attestations) — dependencia fuera de stdlib, ver ADR-0002 |
| **RR-02** | La política es preventiva y **del lado del cliente**: el agente puede editar sus propios ganchos | tres capas, y se declara que las dos primeras no son garantías | rama protegida + CI, que ya existen y están fuera del alcance del agente |
| **RR-03** | refuto usa ACP sólo para sondear; conduce las sesiones por el CLI nativo | los CLIs nativos están probados en producción por sus proveedores | conducir por `session/prompt` y aplicar política en `session/request_permission` |
| **RR-04** | La observabilidad es un diario JSONL local; **no hay trazas distribuidas** | procedencia completa por evento y por corrida | propagar `traceparent` en `_meta` de MCP (SEP-414) y exportar por OTLP |
| **RR-05** | Codex no evaluable | se declara `BLOQUEADO` en toda su columna | reinstalar el paquete |
| **RR-06** | El guardián corre en un proceso por escritura (~90 ms) | aceptable a la escala medida | si estorba, servidor persistente — pero eso añade estado |
| **RR-07** | El motor ejecuta **un paso cada vez**, sin paralelismo | el ciclo es secuencial por diseño: una fase consume lo que produjo la anterior | fases hermanas (p. ej. tres `IMPLEMENT`) podrían ir en paralelo; hoy no |
| **RR-08** | 9 de 22 roles **no declaran ninguna puerta**: su salida no la comprueba nadie | `G-ROLES` lo reporta como observación en cada corrida | escribir la puerta que falta, o declarar por qué ese rol no la necesita |
| **RR-09** | El ciclo completo de 13 fases **nunca se ha ejecutado entero** con agentes reales | se ejecutó `TEST` de extremo a extremo, con coste y bloqueos reales | ejecutarlo cuesta dinero y aporta poco que la fase probada no demuestre |
| **RR-10** | La instrucción del agente se deriva del contrato del rol, y **eso no es un método** | refuto gobierna el proceso; el método (SDD) vive en el núcleo | integrar los prompts del núcleo SDD como fuente del texto por fase |
