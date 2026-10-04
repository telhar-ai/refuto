# Propuesta — `refuto → cliente → proyecto`

> Todo lo medido aquí es del 2026-09-23, contra el árbol de refuto y contra un espacio real
> con motor propio. Las citas llevan símbolo, no número de línea, para que no envejezcan.

## 0 · Por qué hoy no se hereda nada

No es que la herencia esté rota. **No existe.** Medido:

```sh
grep -rn "extends|parent_policy|overlay|base_manifest" core schemas gates refuto.py
→ ninguna coincidencia
```

Cada espacio declara su política, su manifiesto y su método **completos**, desde cero. Dos
espacios del mismo cliente repiten las mismas reglas y divergen en cuanto uno se toca. Eso es
lo que estás viendo.

Pero hay una pieza que **sí** existe y que nadie está usando.

## 1 · El dato que cambia el diagnóstico

Los dos vocabularios de estado son casi el mismo:

| | |
|---|---|
| refuto | `PASS` `FAIL` `BLOCKED` `NOT_EXECUTABLE` `NOT_APPLICABLE` |
| el motor propio del espacio | `PASS` `FAIL` `BLOCKED` `NOT_APPLICABLE` `UNKNOWN` + `BLOCKED_BY_PLATFORM`, `HARNESS_DEFECT` |

Cuatro de cinco coinciden **literalmente**. No son dos filosofías distintas: es la misma, con
dos implementaciones y un par de estados extra donde el motor especializado afina más.

Y el informe que ese motor emite ya tiene la forma que el puente de refuto espera:

```json
{"schema": "…:informe:v1",
 "etapas": [{"etapa": "AUDIT", "estado": "PASS", "satisface": true, …}]}
```

## 2 · El puente ya está construido

`gates/g_sdd.py` es exactamente esto, y su ADR lo dice desde el principio
([ADR-0007](../decisions/ADR-0007-puente-no-reescritura.md)): **envolver el verificador
externo, no reescribirlo**. El contrato vive en el manifiesto:

```json
"integrations": {
  "spec_core": {
    "runner":     ".harness/hz",
    "args":       ["run", "--sin-sellar", "--json"],
    "report":     "…",
    "gates_key":  "etapas",
    "status_map": {"PASS": "PASS", "FAIL": "FAIL", "BLOCKED": "BLOCKED",
                   "NOT_APPLICABLE": "NOT_APPLICABLE",
                   "UNKNOWN": "NOT_EXECUTABLE",
                   "BLOCKED_BY_PLATFORM": "BLOCKED",
                   "HARNESS_DEFECT": "NOT_EXECUTABLE"}
  }
}
```

El espacio con motor propio **declara `G-SDD` en su lista de puertas y no declara
`integrations`**. Por eso la puerta responde `NOT_APPLICABLE` — «no hay verificador externo
declarado» — y el veredicto del motor especializado nunca entra en refuto.

Las dos últimas correspondencias no son decorativas. `UNKNOWN` → `NOT_EXECUTABLE` conserva la
distinción entre «no lo sé» y «está mal»; `HARNESS_DEFECT` → `NOT_EXECUTABLE` dice que el
instrumento falló, que no es lo mismo que el sujeto. Aplanarlos a `BLOCKED` perdería justo lo
que este sistema existe para no perder.

### El único hueco real

El puente lee un **fichero** (`report`); el motor imprime el JSON por **stdout**. Se cierra
por cualquiera de los dos lados, y conviene elegir a conciencia:

| | coste | dónde se toca |
|---|---|---|
| el motor acepta `--informe <ruta>` | una opción | el espacio especializado |
| el puente acepta `report: "-"` = stdout | una rama | `gates/**`, **protegido**: lo aplica una persona |

La primera se puede hacer hoy y no toca nada protegido. La segunda es más general y sirve
para cualquier verificador futuro que sólo hable por stdout.

## 3 · Las tres capas, y qué pertenece a cada una

La regla para decidir dónde va algo: **si cambiarlo sólo afecta a un proyecto, es del
proyecto; si afecta a todos los de un cliente, es del cliente; si cambiarlo cambiaría el
significado de `PASS`, es de refuto.**

```
refuto              el vocabulario y el motor
  │                 estados · contrato Result · guardián · identidad · evidencia
  │                 las 13 puertas · el puente a verificadores externos
  ▼
cliente             lo que comparten sus proyectos
  │                 política base · roles · puertas exigidas · método
  │                 fronteras de datos · clases de obra
  ▼
proyecto            lo que sólo es suyo
                    su spec · su lock · su verificador especializado
                    lo que añade, nunca lo que relaja
```

**La restricción que hace que esto no degenere:** una capa hija puede **añadir** puertas y
**endurecer** reglas. No puede quitar una puerta que el padre exige ni ensanchar una ruta que
el padre protege. Sin esa asimetría, «heredar» acaba significando «heredo lo cómodo», y la
capa de cliente se convierte en el sitio donde se van a relajar los controles.

## 4 · Tres etapas, en orden de dependencia

### Etapa 1 · Herencia del veredicto — casi disponible hoy

El espacio especializado declara `integrations.spec_core`. Su motor sigue siendo el juez de su
dominio; refuto **traduce** ese veredicto a su vocabulario y lo integra en la corrida.

- Requiere: cerrar el hueco stdout↔fichero (§2).
- No requiere: ningún cambio en `core/`, ni en el motor especializado más allá de una opción.
- Qué **no** resuelve: sigue sin haber capa de cliente. Dos proyectos del mismo cliente
  siguen repitiendo su política entera.

### Etapa 2 · Herencia de declaración — `NOT_RUN`

`extends` funciona hoy para **políticas** (etapa 3). Para el **manifiesto** —heredar la lista
de puertas, los roles y el método— no está implementado: `NOT_RUN`.


```json
{ "schema": "harness.manifest/v1",
  "extends": "cliente:obra-publica/v1",
  "gates": ["+G-ATESTACION"] }
```

Lo que hace falta decidir, y es lo único difícil de esta etapa:

| pregunta | por qué no se puede posponer |
|---|---|
| ¿dónde vive la declaración del cliente? | `~/.config/harness/registry.json` ya nombra espacios y apunta a su política: es el sitio natural |
| ¿qué se acumula y qué se sustituye? | las puertas se acumulan; el método se sustituye entero — un método a medias no es un método |
| ¿qué pasa si el padre no está? | `NOT_EXECUTABLE`. **Nunca** los valores por omisión: un manifiesto que dice `extends` y corre sin el padre parece gobernado y no lo está |

Ese último punto ya tiene precedente medido en este repositorio: `Policy.from_dict` levanta
`PoliticaIlegible` cuando no reconoce **ninguna** clave, precisamente porque un documento de
otro programa producía la política de fábrica y el espacio parecía gobernado sin estarlo.

### Etapa 3 · Refinamiento de política — **IMPLEMENTADO Y VERIFICADO**

> **Corrección del 2026-09-23.** Una versión anterior de este documento rotulaba esta etapa
> como «IMPLEMENTADO» cuando el refinamiento sólo existía en un comando de consulta:
> `Policy.load()` —lo que ejecuta el guardián— llamaba a `from_dict()` y **no resolvía
> `extends`**. Medido contra el guardián real, un proyecto que heredaba una orden denegada
> por su cliente obtenía `permissionDecision: "allow"`. La etiqueta era el defecto: cerraba
> el gate con documentación. Ya no: `Policy.load` resuelve la cadena y hay una prueba que
> ejecuta el guardián como proceso y lee su decisión.

`core/refinement.py::politica_efectiva`, invocado desde `core/policy.py::load` y por tanto
desde `core/guard.py`. `refuto policy refine` es una **presentación** de la misma resolución,
no una segunda semántica — llama a la misma función.

`extends` es una **ruta relativa al directorio del propio fichero de política**, o absoluta.
No es un nombre contra el censo: resolver por nombre exige decidir dónde vive la capa de
cliente, y esa decisión no está tomada.

Y esa base vale también para **lo que se teclea**: `init --extends RUTA` resuelve la ruta
relativa desde `<espacio>/.harness/`, no desde el directorio actual, de modo que el argumento y
el valor almacenado son la misma cadena. Hasta el 2026-09-23 no lo eran —se validaba contra el
directorio actual y se guardaba con `referencia_a(..., desde=harness_dir)`—, así que con
`--workspace`, que es la forma de dar de alta un espacio ajeno y donde el directorio actual ni
siquiera pertenece al árbol del espacio, la forma relativa **fallaba siempre** y sólo servía la
absoluta: justo la que `referencia_a` evita, porque no sobrevive a mover ni clonar el árbol.
Falló cerrado —no escribió nada—, pero su mensaje mandaba a materializar la capa base, que no
era el problema; un error que diagnostica mal cuesta más que no tenerlo. Fijado en
`tests/adversarial/test_herencia_efectiva.py::test_la_ruta_relativa_se_resuelve_DESDE_EL_HIJO_no_desde_el_cwd`.

La invariante:

```
restricciones(hijo)  ⊇  restricciones(padre)
```

Cada campo de `Policy` declara su monotonía, y **ninguno puede quedarse sin declararla**: el
módulo no se importa si falta alguna. Un campo sin regla se heredaría como suponga quien lo
escribió, que es como no decidirlo.

| campo | regla | por qué |
|---|---|---|
| `protected_paths` `secret_read_deny` `command_deny` `command_ask` `network_rules` | **ACUMULA** | el efectivo es la UNIÓN: retirar no es violación, es **inexpresable** |
| `writable_paths` `external_write_allow` | **REDUCE** | abren agujeros en lo protegido: el hijo puede cerrarlos, nunca abrir otros |
| `block_secret_content` | **ENDURECE** | `true` del padre no se puede poner a `false` |
| `schema` `version` `default_modes` | **PROPIO** | metadatos y modo de interacción: no son restricciones |

**Por qué `ACUMULA` no detecta sino que impide.** La primera versión exigía que el hijo
repitiera cada entrada del padre so pena de «retirarla». Además de detectar mal —un hijo que
añadía una ruta y no repetía las heredadas se rechazaba—, obligaba a la repetición exacta que
la herencia existe para eliminar: un cliente con veinte rutas forzaba veinte copias por
proyecto, y a la tercera copia alguien recorta. Con la unión, **no hay sintaxis para retirar**.
No se puede violar lo que no se puede decir, y eso es más fuerte que detectarlo.

La detección sigue haciendo falta en `REDUCE`, donde la unión sí ensancharía de verdad.

Otra corrección respecto a la primera versión: se dijo que `writable_paths`
**no se heredaría**. Es peor. Sin heredarlos, el hijo los declara desde cero y puede escribir
cualquiera — es decir, puede abrir un agujero que el padre no tenía. `REDUCE` conserva la
intención (nadie abre nada nuevo) y además propaga los cierres del padre.

**Lo que NO es:** no es `{**padre, **hijo}`. Un `merge` deja que el hijo sustituya cualquier
clave, y sustituir es relajar cuando la clave es una restricción. Medido: con un `merge`
ingenuo, **los 10 ataques de `tests/adversarial/test_monotonia.py` sobreviven**.

Y cuando el hijo intenta relajar, **no se aplica ninguna parte**. Una política a medias es
indistinguible de una política, y esa indistinguibilidad es el fallo.

### Qué pasa cuando la cadena no resuelve

Todos estos casos levantan `HerenciaIrresoluble`, **subclase de `PoliticaIlegible`**. El
guardián ya denegaba ante esa excepción, así que la herencia falla cerrado sin tocar una
línea del guardián — el sitio donde un `except` nuevo y mal puesto costaría más caro.

Medido contra el guardián real, cada uno por su entrada de verdad:

| caso | decisión |
|---|---|
| padre ausente | `deny` |
| padre ilegible | `deny` |
| padre de otro contrato | `deny` |
| hijo que ensancha `writable_paths` | `deny` |
| hijo que apaga `block_secret_content` | `deny` |
| ciclo en la cadena | `deny` |
| `extends_digest` que ya no coincide | `deny` |
| **herencia legítima** | `allow`, y deniega lo que el padre prohíbe |

La última fila es el control que impide cerrar esto con un «deniega todo».

### Cómo se sabe que no se puede deshacer sin enterarse

La mutación `M7` de `scripts/mutate_probe.py` desactiva la resolución en `Policy.load`. Su testigo declarado
es `test_una_regla_que_SOLO_esta_en_el_padre_se_aplica`, y muere por él. Es decir: si alguien
revierte este cambio, la prueba del guardián cae — no la del refinamiento en aislamiento, que
seguiría pasando y no demostraría nada.

### Cómo se da de alta un cliente, y por qué el alta era el agujero

La etapa 3 estaba implementada y **sin un solo uso**: ninguna política real declaraba
`extends`. No era descuido. `refuto install` e `init` escribían `Policy.default().to_dict()`
—la norma **entera**, copiada— en cada espacio nuevo, así que el primer acto del alta era
producir un documento autónomo que a partir de ahí divergía en silencio. La herencia existía
en el motor y no tenía por dónde entrar.

Desde el 2026-09-23 la capa 1 es un documento y el alta puede nacer heredando:

```sh
refuto policy base > policies/base.json        # una persona, una vez: ese fichero está protegido
refuto --workspace ~/…/acme       init --extends /ruta/a/policies/base.json
refuto --workspace ~/…/acme/web   init --extends ~/…/acme/.harness/policy.json
```

El hijo que se escribe tiene **cuatro claves** —`schema`, `name`, `version`, `extends`— y nada
más. Lo que no declara no puede divergir. `--anchor` añade `extends_digest`, y no es la
omisión: anclado, cualquier cambio del padre deja de resolver hasta que alguien lo revise, que
es lo correcto para una capa que no debe moverse sola y demasiado rígido para una capa de
cliente que evoluciona.

`extends` se escribe **relativo** al `.harness/` del hijo (`../../.harness/policy.json`): un
cliente y sus proyectos se mueven juntos, y la referencia relativa sobrevive a eso mientras la
absoluta no sobrevive a nada más. Si el padre no existe o la cadena no refina, **no se escribe
nada**: un `policy.json` que existe y no gobierna haría que el paso siguiente de `install` lo
diera por hecho.

## 5 · Qué probar antes de creerse cada etapa

Ninguna se puede dar por buena sin su prueba de falsación:

| etapa | la prueba que la sujeta |
|---|---|
| 1 | el veredicto del motor externo llega **tal cual**: si el motor dice `FAIL`, la corrida de refuto dice `FAIL` |
| 1 | un motor externo **ausente** da `NOT_EXECUTABLE`, nunca `NOT_APPLICABLE` — «no lo encontré» no es «no aplica» |
| 2 | un hijo que intenta **quitar** una puerta del padre es rechazado |
| 2 | `extends` a un padre inexistente da `NOT_EXECUTABLE`, no valores por omisión |
| 3 | un hijo que intenta **ensanchar** `protected_paths` del padre es rechazado |
| 3 | un `writable_paths` del padre **no** llega al hijo |

Las de «intenta relajar y es rechazado» son las importantes. Las otras comprueban que
funciona; éstas comprueban que **no se puede usar para lo que no es**.

## 6 · Lo que esta propuesta no afirma

- Que el motor especializado deba desaparecer. Su dominio —atestación, admisión de obra
  externa, clases— no está en refuto y no tiene por qué estarlo. ADR-0007 dice envolver, no
  absorber.
- Que las tres etapas sean necesarias. La 1 resuelve lo que preguntaste —que el veredicto se
  herede— y las otras dos resuelven la repetición entre proyectos de un mismo cliente. Son
  problemas distintos y se pueden decidir por separado.
- Que las tres estén implementadas. La **1** sigue siendo propuesta y la **2** `NOT_RUN`; sólo
  la 3 corre, con las pruebas del §4. Una versión anterior de esta lista decía «nada de las
  etapas 2 y 3 existe» **después** de que la 3 se implementara: la frase sobrevivió a lo que
  describía y contradecía al §4 dentro del mismo documento. Corregido el 2026-09-23. Es el
  mismo defecto que el §4 documenta en su propia cabecera —una etiqueta que se queda quieta
  mientras el código se mueve— y aparecer dos veces en un texto sobre no cerrar gates con
  documentación es exactamente el motivo de dejarlo escrito en vez de borrarlo.

## 7 · `POLICY` ≠ `ENFORCEMENT` ≠ `ASSURANCE`

Tres cosas distintas que se confunden con facilidad, y confundirlas atribuye a refuto una
capacidad que no tiene.

| | qué es | quién lo hace aquí |
|---|---|---|
| **POLICY** | qué está permitido | `.harness/policy.json`, y su refinamiento |
| **ENFORCEMENT** | qué **impide físicamente** una acción prohibida | el guardián como `PreToolUse` del runtime, la protección de rama del servidor, el sandbox del sistema operativo |
| **ASSURANCE** | qué **demuestra** que el contrato se cumplió | las 13 puertas, la evidencia, la falsación |

El ejemplo que lo separa:

```
policy       un agente no modifica producción
enforcement  el sandbox o la autorización deniegan la operación
assurance    refuto comprueba la política, comprueba el enganche, y observa la denegación
```

**Refuto hace enforcement en un solo sitio y de forma limitada**: el guardián intercepta
`PreToolUse` del runtime que lo tenga enganchado. Eso no es un sandbox. Un agente que se
salte el runtime —o que corra sin el gancho— escribe igual. Lo que refuto sí puede demostrar
es que el gancho estaba puesto y que la denegación ocurrió, porque queda en el diario.

Medido en esta sesión: la protección de rama que sí sería enforcement de verdad **no está
disponible** (`HTTP 403`, requiere plan de pago), y lo que hay en su lugar es un gancho local
que se salta con `--no-verify`. Está declarado como tal en `docs/operations/DEVSECOPS.md`. Un
control que se presenta como barrera cuando es un recordatorio hace creer que hay defensa
donde hay costumbre.

## 8 · Preparación para agentes — conceptual, `NOT_RUN`

La cadena que refuto debe poder gobernar:

```
principal → delega → agente → pide capacidad → herramienta/acción → recurso → efecto → evidencia
```

Qué hay hoy de cada pieza, medido:

| pieza | estado |
|---|---|
| `Identity` | **parcial** — identidad tipada de ejecución (`ses_` `orq_` `ver_` `ctx_`), ADR-0012 |
| `Capability` | **parcial** — `core/capability.py` con 7 estados y catálogo |
| `Tool` / `Action` | **parcial** — el guardián decide por herramienta y patrón de argumentos |
| `Evidence` | **sí** — `Evidence` ya lleva `kind, summary, command, source, exit_code, stdout_digest, excerpt, redacted` |
| `Authority` / `Delegation` | **`NOT_RUN`** — no existe `parent_run_id` ni frontera de autoridad |
| `Agent` como principal gobernable | **`NOT_RUN`** |

**Lo que NO se construyó a propósito**, y es un criterio de parada, no una omisión:
orquestación de LLM, planificador, memoria de agente, runtime multi-agente. Eso pertenece a
las capas que *consumen* refuto. Refuto debe gobernarlas, no convertirse en ellas — y un
sustrato que empieza a planificar deja de poder juzgar con independencia lo que planifica.

## 9 · Límites actuales, declarados

| | estado | por qué |
|---|---|---|
| **`policy wire --repos` no alcanza la capa de proyecto** | `FAIL` | ver abajo |
| herencia de **manifiesto** (`extends` de puertas/roles/método) | `NOT_RUN` | sólo la política refina |
| resolución del padre **por nombre** contra el censo | `NOT_RUN` | exige decidir dónde vive la capa de cliente; hoy `extends` es una ruta |
| adaptador stdout del verificador externo | `BLOCKED` | vive en `gates/**`, protegido por política |
| `G-SDD`: integración declarada con ejecutor ausente | **inconsistencia** | devuelve `BLOCKED`; el contrato de estados dice `NOT_EXECUTABLE` («falta el ejecutor»). En `gates/**` |
| segunda máquina | `BLOCKED` | sólo existe una · `LIMITATION: single-host` |

### El cableado colapsa la tercera capa · `FAIL`, medido el 2026-09-23

La cadena de tres capas funciona cuando el guardián se invoca con el proyecto como espacio
—hay prueba: `TestLasTresCapasEnDirectoriosDistintos`—. Pero el cableado real no lo invoca
así. `.harness/bin/guard` termina en `exec … --workspace "$WORKSPACE"` con `WORKSPACE=$0/../..`:
el espacio que **aloja** el guardián, no el repositorio desde el que se le llama. Y
`core/guard.py` lee `workspace/.harness/policy.json` sin ascender nunca.

Medido: con `policy wire --repos`, una ruta que **sólo** protege la política del proyecto
(`infra/**`) obtiene `allow`. El `.harness/policy.json` del repositorio no se lee jamás.

`core/wire.py::wire_claude_repos` lo declara como virtud —«una política, un guardián, N
punteros»— y lo es: N copias de una norma divergen y N punteros no. El problema no es el
diseño, es su alcance: resuelve dos capas y **hace inexpresable la tercera**, mientras el resto
del sistema afirma tener tres.

El censo ya tiene decidida la salida y tampoco está implementada:
`~/.config/harness/registry.json` → `resolucion.precedencia` regla 3 dice «`.harness/` hacia
arriba — ascenso desde `$PWD`, como git y direnv». Eso es exactamente lo que le falta al
guardián: con el espacio ya fijado, ascender desde el directorio real hasta el
`.harness/policy.json` más cercano **acotado al espacio**, y usarlo como hoja de la cadena. Un
repositorio que no declara nada no paga nada; uno que declara, hereda.

Su coste, que hay que decidir a conciencia antes de tocar el guardián: el diario de evidencia
seguiría anclado al espacio mientras la política la pondría el repositorio. Dos anclas en el
mismo evento es justo la clase de ambigüedad que este documento existe para no introducir, así
que el cambio no va sin declarar cuál de las dos cita cada campo.
