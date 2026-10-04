# Operación

Instalar una máquina limpia está en [`INSTALL.md`](INSTALL.md). Este documento empieza donde
aquél termina: con `refuto` ejecutable y un espacio que se quiere gobernar.

Todo lo que sigue escribe `refuto …`. Si no ha puesto `bin/` en el `PATH`, sustitúyalo por
`python3 /ruta/a/refuto/refuto.py …`.

## Requisitos

Python **3.10+**, `git` para procedencia y lock. `gh`/`glab` opcionales, sólo para `refuto work`.
No hay `pip install`: ver [ADR-0002](docs/decisions/ADR-0002-solo-biblioteca-estandar.md).

## Gobernar un espacio de trabajo

Un solo comando:

```bash
cd /ruta/al/espacio
refuto install
```

Deja el espacio operativo de principio a fin y **lo comprueba ejecutando el guardián**. Salida de
ejemplo (capturada el 2026-08-27 en macOS arm64; su máquina dirá otra cosa):

```
✓ política              .harness/policy.json
✓ manifiesto            .harness/harness.manifest.json
✓ vínculo               atado: repository · sin núcleo SDD: este espacio no está gobernado por uno
✓ runtimes              claude, kiro, gemini, opencode
✓ guardián              lanzador en .harness/bin/guard
✓ contexto              .harness/CONTEXTO.md, AGENTS.md, CLAUDE.md, GEMINI.md
✓ prueba del guardián   bloqueó una escritura sobre .harness/policy.json (deny)

  Espacio operativo.
```

Existe porque los pasos sueltos dejaban un espacio a medias con facilidad: el control enganchado
y sin contexto, o el contexto puesto y sin control. **Un espacio a medias es peor que uno sin
gobernar, porque parece gobernado.**

Ojo con la línea `runtimes`: dice qué agentes se detectaron, **no** que los cuatro tengan el
guardián enganchado. Hoy lo enganchan `claude`, `kiro` y `antigravity`; ver la tabla de
capacidades del [`README.md`](README.md).

### El contexto persistente, y por qué importa

`install` escribe `.harness/CONTEXTO.md` y deja un **bloque delimitado** en los archivos que cada
runtime lee por su cuenta:

| Runtime | Archivo | Cómo |
|---|---|---|
| Claude Code | `CLAUDE.md` | importa `@.harness/CONTEXTO.md` |
| OpenCode | `AGENTS.md` | contenido completo |
| Gemini CLI | `GEMINI.md` | contenido completo |
| Kiro | `.kiro/steering/zz-harness.md` | contenido completo |

Lo de **fuera** de los marcadores no se toca nunca. Por eso da igual cómo abra la sesión —
`refuto chat`, el CLI del agente a secas o la aplicación de escritorio—: el agente encuentra el
contexto solo.

Sin esto, abrir el agente en un espacio gobernado producía un asistente genérico que ofrecía
«explorar el repo» y descubría las restricciones chocando contra ellas. Con el contexto puesto,
la respuesta observada el 2026-08-27 con `claude 2.1.247` fue:

> «Estoy en un espacio gobernado […] un guardián externo intercepta cada escritura antes de que
> ocurra y registra los intentos bloqueados. No puedo tocar: `verificacion/**`, `.harness/**`,
> `gates/**`… con rutas resueltas, así que `..` y symlinks no lo sortean.»

### Declarar qué necesita el espacio

`install` deja `.harness/` con `policy.json` y `harness.manifest.json`. Edite el manifiesto para
declarar las exigencias del espacio:

```jsonc
{
  "agents": {
    "kiro":   { "required": true,  "min_level": "FUNCTIONAL" },
    "claude": { "required": false, "min_level": "FUNCTIONAL" }
  },
  "sources": {
    "nucleo": {
      "uri": "https://github.com/example-org/mi-estandar.git",
      "ref": "v1.2.0",
      "materialize": [ { "from": "verificacion/comun.py", "to": "verificacion/comun.py" } ]
    }
  },
  "skills": { "roots": [".kiro/skills"], "require_name_matches_directory": true },
  "mcp":    { "protocol_version": "2026-07-28", "required_servers": ["navegador"] }
}
```

Luego:

```bash
refuto lock plan       # qué se anclaría, antes de anclar nada
refuto lock update     # fija el commit inmutable y las huellas
refuto policy compile  # traduce la política a cada runtime
refuto policy wire     # engancha el guardián en la ruta del CLI
refuto verify          # ejecuta las puertas y emite evidencia
```

## Trabajar en modo conversación

```bash
refuto policy wire --agent claude    # una vez por espacio
refuto chat                          # abre la sesión, gobernada
```

**Qué comprueba `chat` antes de abrir, exactamente** (`E1`, `core/session.py`, 2026-09-22):

| Runtime | Comprobación previa |
|---|---|
| `claude` | **bloquea** si el gancho no está en `.claude/settings.local.json` |
| `kiro` | **bloquea** si el guardián no está en todos los agentes de `.kiro/agents/`. Con **cero** agentes declarados no bloquea: no hay nada que comprobar |
| `antigravity` | **bloquea** si no está enganchado (no es opción de `chat --agent` hoy; se alcanza por `policy wire`) |
| `gemini`, `opencode` | **bloquea**: no hay guardián enganchable para ellos. Abre sólo si el manifiesto declara `agents.<runtime>.unguarded: true`, y entonces avisa en el informe |

Dicho sin adornos: `refuto chat` se niega a abrir sin guardián **en claude y en kiro**. En gemini
y opencode la sesión lleva informe y contexto, pero una escritura prohibida no se bloquea. No lo
dé por gobernado.

Antes de abrir compone un informe de sesión —`.harness/state/session-brief.md`— y se lo inyecta
al agente como prompt de sistema. Contiene:

- dónde está: origen vinculado con su versión y su commit, repositorio, espacio de trabajo;
- la **especificación activa**: qué documentos hay, cuántos requisitos y cuántas tareas cerradas;
- **qué no puede tocar**, con la advertencia de que lo aplica un programa fuera de su control;
- **cómo se sabrá que terminó**: los estados y que `BLOCKED` no aprueba.

```bash
refuto chat --role frontend-engineer   # carga además el contrato del rol
refuto chat --spec mi-especificacion   # si hay varias especificaciones
refuto chat --agent kiro               # el mismo informe, otro runtime
refuto chat --resume                   # continúa la conversación anterior
refuto chat --dry-run                  # enseña el informe y la orden, sin abrir nada
refuto chat --provider clean           # ignora redirecciones de proveedor del shell
```

### Declarar a qué proveedor debe hablar

En el manifiesto, una vez:

```json
"provider": { "expect": "subscription" }
```

Valores: `subscription` · `api-key` · `bedrock` · `vertex` · `foundry` · `custom`.
`refuto install` lo declara como `subscription` por defecto.

Con la declaración puesta, `--provider auto` limpia el entorno en **dos** casos, y los dos son «la
sesión no va a hacer lo que usted cree»: la redirección está rota, **o** contradice lo que el
espacio declara. Sin declaración sólo puede detectar el primero — y una redirección válida hacia
un proveedor que usted no usa pasaría sin más: la sesión abre, funciona, y factura en el sitio
equivocado.

Todo lo que va después de las opciones se pasa tal cual al agente:

```bash
refuto chat -- --model opus --permission-mode acceptEdits
```

La apertura y el cierre quedan en `.harness/evidence/ledger.jsonl`.

## Cómo se abre una sesión, y qué se ha comprobado de cada forma

El guardián no vive en el comando con el que abre: vive en `.harness/bin/guard`, un guion que se
instala en el espacio y **se resuelve solo**. No depende del directorio actual, ni de que
`python3` esté en el `PATH`, ni de que `refuto` siga donde estaba cuando se instaló — si se
movió, **bloquea** en vez de aprobar por no encontrarse.

Estado de la comprobación, con Claude Code en macOS arm64, 2026-08-27:

| Cómo abre | Qué hace falta | Estado |
|---|---|---|
| `refuto chat` | nada más; comprueba las condiciones antes de abrir | `PASS` (observado) |
| el CLI del agente a secas, dentro del espacio | `refuto policy wire --agent claude`, una vez | `PASS` — el gancho dispara y bloquea |
| el CLI con `sudo` | lo mismo | `PASS` — bloquea, y devuelve la propiedad de `.harness/` a quien invocó |
| aplicación de escritorio | lo mismo | **`NOT_RUN`** — ver abajo |

Compruébelo usted mismo, sin conjeturas (esto **gasta créditos**, con tope):

```bash
claude -p "Escribe HECHO en .kiro/steering/PRUEBA.md" \
       --output-format stream-json --verbose --include-hook-events \
       --tools "Write" --permission-mode dontAsk --max-budget-usd 0.20
```

En el flujo aparecen `hook_started` y `hook_response`, el resultado trae `permission_denials: 1`,
y el archivo no se crea. La decisión queda en `.harness/evidence/ledger.jsonl`.

### Sobre abrir con `sudo`

**Funciona, y sigue siendo mala idea.** El guardián aguanta —bloquea igual, y devuelve al usuario
original la propiedad de lo que escribe en `.harness/`— pero un agente con privilegios de root
puede escribir en cualquier parte del sistema, y ahí `refuto` sólo alcanza lo que la herramienta
le declara. La regla `fuera-del-espacio` corta las rutas que ve; no hay nada detrás de ella.

**Límite conocido:** la devolución de propiedad cubre `.harness/` **del espacio**. Los archivos
de configuración del agente en el `$HOME` del usuario (`~/.claude`, `~/.claude.json` y
equivalentes) **quedan en propiedad de root**, y eso puede impedir que la siguiente sesión normal
arranque. `refuto doctor` detecta el caso dentro del espacio y da la orden exacta; fuera del
espacio, no mira.

Si una sesión con `sudo` deja archivos de otro dueño, **sin poder escribir el diario el rastro de
auditoría se corta sin que nada falle a la vista**; por eso el guardián lo dice dentro de la
decisión en vez de callarlo.

### Sobre las aplicaciones de escritorio

Una aplicación de escritorio puede hospedar **el mismo CLI** en una copia propia y compartir la
configuración del usuario, así que lee la misma configuración del proyecto y ejecuta los mismos
ganchos. (Observado en macOS con la aplicación de Claude, 2026-08-27; en otros sistemas, `NOT_RUN`.)

El lanzador está preparado para esa condición concreta: se probó con el entorno **vacío**
(`env -i`, sin `PATH`), que es como arranca un proceso lanzado desde una aplicación de escritorio,
y bloquea correctamente (`E3`).

Lo que **no** se ha comprobado de extremo a extremo (`NOT_RUN`) es una escritura bloqueada desde
dentro de la propia aplicación. Para cerrarlo, ejecute una sola vez, dentro del espacio y desde la
aplicación:

> «Escribe HECHO en `.kiro/steering/PRUEBA.md`»

Debe negarse citando el patrón `.kiro/steering/**`, y la decisión debe aparecer en
`.harness/evidence/ledger.jsonl`. Si no aparece, el gancho no se cargó y hay que decirlo.

## Empezar por lo que tiene pendiente

```bash
cd /ruta/al/espacio
refuto work                     # qué le han asignado, ya enrutado
refuto chat                     # abre la sesión; el agente saluda con sus pendientes
refuto chat --task 9            # o directamente sobre una tarea concreta
```

**Declare el runtime una vez**, en el manifiesto, y `work` deja de sondear lo que no usa:

```json
"agents":   { "claude": { "required": true, "min_level": "FUNCTIONAL" } },
"provider": { "expect": "subscription" }
```

Sin esa declaración, `work` sondea todos los agentes conocidos para usar uno, y el comando tarda
varios segundos más. (Se midió una mejora concreta en la máquina de desarrollo; como no quedó
registrada con fecha, método y máquina, **la cifra no se publica**: sólo la razón por la que la
declaración importa.)

`refuto work` pregunta a **GitHub o GitLab** por lo que le han asignado —usando la sesión que
usted ya tiene en `gh`/`glab`; no pide credenciales— y para cada historia resuelve **quién la
ejecuta y con qué runtime**. Ejemplo **sintético** del formato de salida:

```
PROJ-12  Extender el subsistema de programación de tareas
     Tipo         ARQ, BE
     Épica        Fundación
     spec         ✓ specs/PROJ-12/spec.md
     roles        solution-architect, backend-engineer, technical-writer
                  [CIERTO · declarado · evidencia L]
                  tipo-declarado: el proyecto declara Tipo: ARQ, BE
     runtime      claude [READY]
     revisión     HUMAN_APPROVAL
     abrir con    refuto chat --task 12
```

### De dónde sale la decisión, en este orden

| Fuente | Peso | Evidencia |
|---|---|---|
| Lo que el **proyecto declara** (`Tipo: ARQ, BE` en la tabla de la historia) | manda | `L` — leído |
| Las **etiquetas** de la forja | poco | `L` |
| Las **palabras** del título y el cuerpo | menos | `I` — inferido |

La primera manda porque es la única que no es conjetura: alguien del equipo escribió qué
disciplina hace falta. Las otras dos existen para proyectos que no lo declaran, y **se marcan como
inferencia**. Una clasificación equivocada enruta el trabajo a un rol con el privilegio
equivocado. Por debajo de `PROBABLE`, esto **pregunta** en vez de elegir.

Si su proyecto usa otro vocabulario, decláre­lo en el manifiesto y no toque el código:

```json
"classification": { "aliases": { "PLATAFORMA": ["release-engineer"] } }
```

## El ciclo diario

```bash
refuto verify              # ¿está integrable?
refuto evidence --last 20  # ¿qué ha pasado?
refuto policy audit        # ¿sigue enganchado el guardián?
```

## Códigos de salida

| Código | Significa | Qué hacer |
|---|---|---|
| `0` | integrable | seguir |
| `1` | hay puertas en rojo o no ejecutables | arreglar |
| `2` | hay puertas **bloqueadas** | conseguir lo que falta para poder comprobarlas |
| `64` | error de uso de la línea de órdenes (`EXIT_USAGE`) | corregir la orden |
| `130` | interrumpido (`SIGINT`) | — |

CI trata el `2` como fallo: en una tubería, «no se pudo comprobar» tiene que parar la integración.
Es un código distinto porque la acción de quien lo recibe es distinta.

**Colisión conocida, 2026-09-22:** `argparse` sale con **`2`** ante un error de sintaxis en la
orden —el mismo número que «bloqueado»—, mientras que el código del propio programa usa `64`. Un
script que sólo mire el código no puede distinguir «hay puertas bloqueadas» de «escribí mal la
orden». Está registrado en [`docs/estado-del-proyecto.md`](docs/estado-del-proyecto.md); hasta que
se unifique, compruebe también `stderr`.

## Dónde va `--verbose`

`--verbose` es opción **del parser raíz**, no de los subcomandos. Va **antes** del subcomando:

```bash
refuto --verbose selftest          # correcto
refuto --verbose probe --agent claude
refuto selftest --verbose          # ERROR: unrecognized arguments: --verbose, exit=2
```

Y un aviso que ahorra un diagnóstico falso: `selftest --suite <nombre-mal-escrito>` ejecuta **0
pruebas y sale con 0**. Un `OK` con `NO TESTS RAN` no es un aprobado; es un ámbito vacío. Medido
el 2026-09-21.

## Actualizar el origen anclado

```bash
refuto lock plan --source nucleo    # el diff, delante, antes de decidir
refuto lock update --source nucleo  # sólo si el diff es el esperado
refuto verify --gate G-LOCK --gate G-FLEET
```

Nunca ocurre solo. Ver [ADR-0004](docs/decisions/ADR-0004-lock-antes-de-escribir.md).

## Subcomandos menos usados

Ninguno de estos aparecía documentado y todos existen en el CLI (`E2`, `--help`, 2026-09-22):

| Orden | Qué hace | Cuidado |
|---|---|---|
| `refuto upgrade` (`actualizar`) | lleva el espacio a la versión del motor en disco | reescribe artefactos generados de `.harness/` |
| `refuto environments` (`entornos`) `show\|check` | contra qué entorno trabaja el espacio, y si sigue respondiendo | `check --write` actualiza el sondeo y la fecha |
| `refuto policy plan` | qué haría `compile`/`wire`, sin tocar nada | — |
| `refuto policy prune [--apply]` | retira reglas de permiso podridas | **sin `--apply` mide y no toca**; con `--apply` **reescribe `.claude/settings.json`** (deja copia) |
| `refuto policy wire --repos` | engancha además cada repositorio del espacio, todos al mismo guardián | toca N repositorios de una vez |
| `refuto lock init` | crea el lock vacío del espacio | — |
| `refuto memory remember\|export` | escribe y exporta memoria en capas | **no es evidencia**; no la cite como tal |

## Regenerar la matriz de compatibilidad

```bash
refuto docs        # reescribe SUPPORT_MATRIX.md con la sonda de ESTA máquina
```

La copia versionada es una salida de ejemplo fechada. Al ejecutar esto, se sustituye por la suya.

## Añadir un agente nuevo

1. `adapters/nuevo.py` con una subclase de `AgentSpec`. Obligatorio: `name`, `binary`,
   `version_args`, `start_args`, y **cómo hacer un handshake** — `speaks_acp=True` con `acp_args`,
   o `native_handshake()`.
2. Regístrelo en `adapters/registry.py`.
3. `refuto selftest --suite contract` — el contrato de adapter se comprueba solo.
4. `refuto --verbose probe --agent nuevo` — nótese el orden: `--verbose` va delante.
5. `refuto docs` para que entre en la matriz.

Y, si quiere que su política se **aplique** y no sólo se compile, hace falta además el dialecto de
gancho en `core/guard.py` y el enganche en `policy wire`. Eso es lo que separa las columnas de la
tabla de capacidades del README.

Lo que **no** hay que hacer: declarar capacidades que no se pueden sondear. Si no consta, va en
`declared` con evidencia `?`, y la matriz lo mostrará como no verificado. Es la respuesta
correcta.

## Ejecutar en CI

`.github/workflows/refuto.yml` (el nombre del archivo lo exige hoy
`scripts/check_wiring.py`; el flujo se llama `refuto`). Tres trabajos: contrato+suite en Python 3.10 y 3.13, puertas
sobre `examples/espacio-minimo`, y sonda de agentes que comprueba que **la sonda reporta su
ausencia** — no que los agentes existan.

**Estado del flujo: `NOT_RUN`.** Nunca ha corrido en verde en el runner. Hasta que lo haga,
ninguna afirmación de esta documentación puede apoyarse en «lo comprueba la CI».

Regla del archivo: **ningún paso se permite fallar en silencio.** Donde un código de salida
distinto de cero es esperado —la sonda sale con `1` en un runner sin agentes—, se **captura
explícitamente** y se juzga con un script, en vez de taparlo con `|| true`.
