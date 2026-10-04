# Arquitectura

## El reparto, que es la decisión que importa

```
CORE      lo que es verdad para cualquier agente   → manifiesto, lock, política, puertas, evidencia
ADAPTER   cómo lo dice ESTE agente                 → banderas, formatos, vocabularios
NATIVE    lo que sólo tiene ESTE agente            → se expone, no se aplana
```

El tercer punto es el que se suele romper. Cuatro ejemplos, todos leídos de los `--help` de los
binarios instalados el **2026-08-27** en macOS arm64 (`E1`; no se han vuelto a comprobar desde
entonces y las versiones habrán cambiado):

- `--max-budget-usd` existía en Claude Code 2.1.247 y no en Kiro 2.20.0.
- `--require-mcp-startup` existía en Kiro 2.20.0 y no en Claude Code.
- El Policy Engine con política administrativa separada, sólo en Gemini CLI 0.55.1.
- La confianza de carpeta que hace que Gemini **se niegue a cargar los hooks del proyecto**,
  también sólo en Gemini.

Un modelo agnóstico que borra esas cuatro para que la tabla quede simétrica ha empeorado los
cuatro agentes. Aquí se declaran en `native_extensions` y el core puede consultarlas sin depender
de ellas.

## Por qué no hay un protocolo propio

La primera versión de este encargo pedía un *modelo canónico* con vocabulario nuevo. Se descartó.
Lo medido el 2026-08-27, sobre los cinco agentes instalados en esa máquina:

- **ACP v1** lo hablaron **tres de los cinco** (`kiro` 2.20.0, `gemini` 0.55.1, `opencode`
  1.2.27), comprobado ejecutando `initialize` sobre stdio contra los binarios reales (`E4` de esa
  fecha).
- **MCP** lo hablaron los cuatro que arrancaban (`E4` de esa fecha).
- **`SKILL.md`** lo consumen Claude Code y Gemini CLI con el mismo frontmatter (`E1`: consta en
  la documentación de sus CLI instalados; no se probó cargando una skill en ambos).
- Los propios proveedores escriben migradores entre sí: `claude import codex|gemini`,
  `gemini hooks migrate` desde Claude Code (`E1`, leído en sus `--help` el 2026-08-27; **no
  ejecutados**).

Inventar vocabulario propio significaba mantener N adaptadores contra un estándar propio que
compite con uno emergente. Ver [ADR-0001](docs/decisions/ADR-0001-protocolos-de-facto.md).

**Lo que sí es propio** es lo que ningún proveedor cubre: manifiesto, lock, puertas con estados
que no colapsan, y evidencia con procedencia. Ese es el núcleo diferencial, y es justo la parte
que no depende de ningún agente.

## Capas

### 1 · Modelo (`core/model.py`)

Un `Result` y el invariante de que ninguno de los estados que no aprueban puede convertirse en
`PASS`. El contrato está probado en `tests/contract/` (`E3`), no sólo documentado.

Estados **implementados hoy** (`E2`, 2026-09-22): `PASS`, `FAIL`, `BLOCKED`, `NOT_EXECUTABLE`.
El contrato declarado del método incluye además `NOT_RUN`, `INCONCLUSIVE` y `NOT_APPLICABLE`, que
todavía no son valores del tipo. Es una divergencia conocida; su efecto práctico está descrito en
[`docs/estado-del-proyecto.md`](docs/estado-del-proyecto.md).

### 2 · Sonda (`core/probe.py`, `core/acp.py`)

La escalera de ejecutabilidad. `FUNCTIONAL` se alcanza con un handshake estructurado:

| Runtime | Cómo | ¿Llama a un modelo? |
|---|---|---|
| `kiro`, `gemini`, `opencode` | ACP `initialize` sobre stdio | no |
| `codex` | `initialize` de MCP contra `codex mcp-server` | no |
| `claude` | `system/init` del flujo `stream-json`, con `-p hi` y `--max-budget-usd 0.05` | **sí**: envía un prompt real, con tope |

Esa última fila es la razón por la que aquí no se escribe «sin gastar créditos» a secas: para
cuatro de los cinco es exacto; para Claude Code hay un envío real cuyo coste **no se ha medido**.
`VERIFIED` cuesta dinero siempre y es opt-in (`--deep`).

La sonda también comprueba la **firma del binario nativo**, que es lo que convierte «no arranca y
no sé por qué» en «el certificado está revocado». Distingue `VALID`, `UNSIGNED` (un guion de Node
nunca lleva firma), `INVALID` y `REVOKED`. Es una comprobación **de macOS**: usa `codesign`. En
Linux y Windows no hay equivalente implementado.

### 3 · Adapters (`adapters/`)

Cada uno traduce el modelo a las primitivas reales de su agente. Obligatorio: cómo sondear y cómo
hacer un handshake. Opcional pero contractual: `compile_policy`, `run_argv`, `normalize_event`,
`verify_task`.

**Un adapter que no soporta política no puede devolver `unenforceable: []`.** Eso diría que lo
aplica todo. Probado en `tests/contract/` (`E3`).

Hay **cinco** adapters registrados (`claude`, `codex`, `gemini`, `kiro`, `opencode`). El dialecto
de gancho de Antigravity vive en `core/antigravity.py` y **no** es un adapter: no se sondea ni
aparece en la matriz.

### 4 · Política (`core/policy.py`, `core/guard.py`, `core/wire.py`)

Tres capas, y ninguna se presenta como suficiente:

1. **Compilada** al vocabulario del runtime. Barata, la aplica el agente, no ve el contenido.
2. **Guardián**: un solo programa que los ganchos invocan. Ve el contenido y la ruta *resuelta*,
   así que atrapa lo que el patrón no ve. **Enganchado hoy en `claude`, `kiro` y `antigravity`**;
   ver la tabla de capacidades del [`README.md`](README.md).
3. **Fuera del alcance del agente**: rama protegida y CI. La única que el agente no puede tocar.

`core/wire.py` es un módulo aparte a propósito: compilar produce artefactos nuevos; enganchar toca
archivos que alguien escribió a mano. Riesgos distintos, verbos distintos, copia de seguridad
obligatoria. Tres rutas de escritura, que conviene no confundir:

| Verbo | Qué escribe |
|---|---|
| `policy compile --agent claude` | `.claude/settings.harness.json`, un archivo nuevo aparte |
| `policy wire --agent claude` | **fusiona** el gancho en `.claude/settings.local.json` (con copia previa si existía) |
| `policy prune --apply` | **reescribe** `.claude/settings.json` retirando reglas de permiso podridas (con copia) |

### 5 · Lock (`core/lock.py`)

```
LOCK CONOCIDO → TRAER → FIJAR SHA → VERIFICAR → COMPARAR → FALLAR SI DERIVA
              → ACTUALIZAR SÓLO SI SE PIDE
```

Tres invariantes, los tres probados en `tests/adversarial/` (`E3`):

- `verify()` **nunca** escribe el lock.
- El ancla persistida es un SHA, no una etiqueta.
- Una etiqueta movida produce `FAIL`, no un lock nuevo.

### 6 · Puertas (`gates/`)

**Trece** (`gates/base.py::GATES`, `E2`, 2026-09-22). Una de ellas —`G-SDD`— es un **puente**, no
una reimplementación: ejecuta el verificador que el espacio traiga
(`verificacion/verificar.py --json`) y traduce su vocabulario. Ese verificador **no forma parte de
este repositorio**; es un componente externo que el espacio aporta, y puede no ser obtenible por
un tercero. Sin él, la puerta no aplica.

| verificador externo | `refuto` |
|---|---|
| `cumple` | `PASS` |
| `no cumple` | `FAIL` |
| `pendiente` | `BLOCKED` |
| `no ejecutable` | `NOT_EXECUTABLE` |

La correspondencia exacta de estados es la única razón por la que el puente puede ser honesto. Si
un verificador no la tiene, no se traduce: se declara.

### 7 · Evidencia (`core/evidence.py`)

JSONL, sólo añadir, con procedencia (`commit`, `rama`, `dirty`, versiones, huella del equipo).
Dirección obligatoria:

```
evidencia estructurada → informe humano       NUNCA al revés
```

Un informe HTML del que después se extraen datos es una captura con pretensiones. Lo que se
audita dentro de un año es el JSONL.

### 8 · Documentación generada (`core/docs.py`)

`SUPPORT_MATRIX.md` se genera de la sonda con `refuto docs`: sólo puede decir lo que la máquina
que lo ejecuta acaba de demostrar, y cada casilla lleva su origen (`NATIVO`, `COMPROBADO`,
`ADAPTER`, `DECLARADO`, `NO`, `BLOQUEADO`, `?`). La copia versionada en este repositorio es, por
tanto, **una salida de ejemplo fechada**, no una promesa de soporte: léala con su fecha delante.

Lo que esa matriz **no** distingue todavía es «la política se compila» de «la política se aplica»:
una casilla `ADAPTER` puede significar cualquiera de las dos. Esa distinción está en la tabla de
capacidades del [`README.md`](README.md), escrita a mano hasta que el generador la produzca.

## Estructura del repositorio, y por qué no es la propuesta

Se pidió `core/ adapters/ agents/ skills/ policies/ gates/ schemas/ manifests/ locks/ evidence/
provenance/ …`. Se implementó más plano, y la razón es que **cinco de esos directorios no tienen
contenido propio**:

- `manifests/` y `locks/` viven **en el espacio de trabajo** (`.harness/`), no en el repositorio
  de `refuto`: son estado de cada proyecto, no código.
- `evidence/` y `provenance/` son lo mismo visto de dos formas; separarlos obligaría a
  correlacionarlos, que es trabajo a cambio de nada. Un evento lleva su procedencia dentro.
- `agents/` y `skills/` son contenido de los espacios gobernados, no de `refuto`.
- `policies/` colapsó en `core/policy.py` + los artefactos compilados.

Un directorio vacío es una promesa que alguien va a intentar cumplir rellenándolo.
