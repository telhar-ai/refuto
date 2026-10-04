# Modelo de seguridad

## La premisa

**El agente evaluado es el adversario.** No porque sea malicioso, sino porque un agente bajo
presión de contexto hace lo que sea para terminar la tarea, y «editar la verificación para que
pase» es una forma perfectamente razonable de terminarla si nadie lo impide.

De ahí la regla que ordena todo lo demás: **un agente no puede ser juez de sí mismo.**

## Las tres capas, y ninguna se presenta como suficiente

| Capa | Qué ve | Qué NO ve | ¿Puede el agente tocarla? |
|---|---|---|---|
| **1 · Política compilada** al runtime | patrones de ruta y de orden | el contenido escrito | sí — vive en el repositorio |
| **2 · Guardián** (`core/guard.py`) | ruta **resuelta**, contenido, y los efectos **demostrables** de una orden | lo que haga una orden opaca (`python3 -c`, `make`, un binario propio) | sí — vive en el repositorio |
| **3 · Atestación** (`core/trust.py`, `core/evidence.py`) | si el juez o la evidencia cambiaron desde el veredicto | quién los cambió | sí — pero **no sin dejar rastro** |
| **4 · Rama protegida y CI** | el resultado, sobre el repositorio remoto | nada de lo anterior en el momento | **no** |

Las dos primeras son **preventivas**: acercan el fallo al momento de escribir. La tercera es
**detectiva**: no impide, delata. La cuarta es el control. Presentar la capa 1 como garantía
sería vender lo que no se tiene.

## La propiedad que se afirma, y la que no

Se afirma `I6'`, no `I6`:

```
I6   Agent ∉ Authority(Judge)           NOT_PROVEN — ver abajo
I6'  Modified(Judge) ⟹ ¬PASS            demostrada
```

**Por qué `I6` no se afirma**, y son dos razones independientes:

- **Indecidibilidad.** El efecto exacto de una orden de consola no es computable: para
  cualquier máquina `M`, `python3 -c 'if M(w) para: open("gates/base.py","w")'` escribe en el
  juez si y sólo si `M` para. Todo analizador estático es incorrecto o incompleto. Uno
  correcto tendría que denegar `python3`, `make` y cualquier binario compilado.
- **Frontera de proceso.** El agente corre con el uid del operador sobre el mismo sistema de
  archivos y puede ejecutar procesos. El guardián es un gancho **consultivo**: una vez el
  runtime ejecuta `bash -c …`, la única autoridad es el núcleo del sistema operativo.

Lo que sí se hace: `core/effects.py` calcula `Ê ⊆ Effects`, las escrituras **demostrables**
desde la sintaxis, y `decide_command` las pasa por la misma regla de rutas que `decide_write`.
Cubre redirección, anexado, `tee`, edición en sitio, copia, movimiento, borrado, truncado,
encadenamiento, envoltura, intérpretes con `-c` y travesía con `..`. Lo que no se puede
demostrar se marca `opaco` y **se permite**, dejando constancia en el diario — denegar todo
intérprete haría inusable la herramienta, y un control inusable se desactiva.

Probado en `tests/adversarial/test_efectos_cruzados.py`: el producto cartesiano de 18
mecanismos de escritura × 10 rutas protegidas, más su control de falsos positivos sobre
rutas libres. Ver [ADR-0013](docs/decisions/ADR-0013-raiz-de-confianza-y-modelo-de-efectos.md)
y [`docs/assurance/FORMAL-MODEL.md`](docs/assurance/FORMAL-MODEL.md).

## Raíz de confianza de la política

`Trusted(Π) ⟺ Reachable(Π, R) ∧ Monotone(cadena) ∧ Acyclic(cadena)`.

La monotonía sola era **relativa**: se demostraba `hijo ⊒ padre` en cada arista y el hijo
elegía el padre, así que apuntar `extends` a una política laxa vaciaba el gobierno sin violar
una sola arista. Ahora toda política se compone con la línea base del motor (`R`,
`core/trust.py`) como padre implícito. En los campos que acumulan el efectivo es la unión, así
que vaciar `protected_paths` o `command_deny` no es una violación que haya que cazar: es algo
que **no se puede escribir**.

## Integridad de la evidencia

El diario es una cadena de huellas (`hᵢ = H(hᵢ₋₁ ‖ canonical(eventoᵢ))`) y el artefacto de
cada corrida se compromete con `engine_digest`, `policy_digest` y la cabeza del diario. Al
leer se reconcilian: si discrepan, el veredicto reportado pasa a `NO INTEGRABLE`; si la
integridad no se puede establecer, `INCONCLUSIVE`.

**Es tamper-evidencia, no tamper-proofing.** Un adversario que reescriba la cadena entera y
todas sus copias publicadas produce un diario coherente. Lo que ya no puede es editar una
línea y marcharse. Y hay un ataque que la cadena por sí sola no ve: **cortar la cola** deja
los eslabones restantes consistentes. Se cierra publicando la cabeza fuera del árbol; sin
ancla publicada queda `NOT_PROVEN`.

**Dónde está enganchada de verdad la capa 2** (medido el 2026-09-22, `E1`, lectura de
`refuto.py::policy wire` y `core/guard.py`): `claude`, `kiro` y `antigravity`. Para `gemini` y
`opencode` la política **se compila y no se engancha**; `codex` no tiene gancho. En esos tres, la
única capa efectiva es la 3. Ver la tabla de capacidades del [`README.md`](README.md).

## Amenazas con prueba adversarial

**27 pruebas** en `tests/adversarial/test_attacks.py` (`grep -c "def test_"`, 2026-09-22),
incluidas en el `478/478` medido ese día en macOS arm64 con Python 3.14.6 y 3.12.

**No se ejecutan en CI todavía.** El flujo de GitHub Actions existe y **nunca ha corrido en
verde** (`NOT_RUN`). Cualquier frase que diga «comprobado en CI» es falsa hasta que haya un run
enlazable.

| Amenaza | Cómo se detiene | Prueba |
|---|---|---|
| Reescribir el juez (`verificacion/`, `gates/`) | patrón de ruta protegida | `TestModificarAlJuez` ×4 |
| Reescribir la política o el lock | ídem | ídem |
| Falsificar la evidencia | `evidencia/**`, `evidence/**` protegidos | ídem |
| Travesía de directorios (`../../../etc/passwd`) | `realpath` antes de comparar | `TestTravesiaDeRutas` |
| **Enlace simbólico** a `verificacion/` desde `docs/` | `realpath` sigue el enlace | `test_enlace_simbolico_que_apunta_al_juez` |
| Enlace simbólico que sale del espacio | ídem | `test_enlace_simbolico_que_sale_del_espacio` |
| Escribir un secreto al árbol (AWS, GitHub, GitLab, JWT, clave privada, asignaciones) | redacción sobre el contenido | `TestFugaDeCredenciales` |
| Que el **diario** se convierta en el sitio donde vive el secreto | se redacta antes de escribir | `test_la_evidencia_no_guarda_el_secreto_en_claro` |
| Órdenes destructivas (`rm -rf`, `dd`, `mkfs`, `git clean -fdx`) | lista de rechazo | `TestEjecucionDeOrdenes` |
| Descargar y ejecutar (`curl … \| sh`) | ídem | ídem |
| **Etiqueta de git movida** en el origen | ancla por SHA + comparación contra el lock previo | `TestSuministroYLock` ×2 |
| Sustitución de un archivo materializado | huella por archivo | ídem |
| **Skill que suplanta a otra** (mismo `name`, distinto sitio) | detección de nombre duplicado | `TestSkillMaliciosa` |
| Servidor MCP fantasma (declarado, inexistente) | integridad referencial | `TestMcpMalicioso` |
| Servidor MCP que no arranca | interrogación real | ídem |
| **Inyección de prompt** que ordena desactivar la política | el guardián no lee prompts; lee escrituras | `TestInyeccionDePrompt` |
| Ejecución arbitraria vía la carga del gancho | la carga es datos; nunca se evalúa | `test_el_guardian_no_ejecuta_nada_de_la_carga` |
| Carga del gancho corrupta | **bloquea por precaución** | `TestEntradaMalformada` |

Nivel de estas filas: `E3` — hay una prueba automática que falla si dejan de ser ciertas. `E3` no
es `E4`: fija el comportamiento del guardián contra cargas sintéticas, no contra un agente real
intentándolo. La única observación `E4` de un bloqueo en vivo está fechada el 2026-08-27 con
`claude 2.1.247` y `kiro 2.20.0` (ver [`docs/validation/informe.md`](docs/validation/informe.md)).

## Sobre la inyección de prompt

No se intenta detectar con expresiones regulares. Se detiene **limitando lo que el agente puede
hacer cuando la obedece**: el guardián no lee prompts, lee escrituras, y las escrituras
prohibidas siguen prohibidas.

La propiedad que eso da, dicha sin exagerar: **no depende de reconocer el texto del ataque**. No
es una defensa completa — el guardián sólo ve lo que el gancho le pasa, y un runtime sin gancho o
una sesión con privilegios de root quedan fuera de su alcance (ver «Lo que este modelo NO
cubre»).

## Secretos

- **Nunca** se piden credenciales para sondear. Un servidor HTTP que necesita autenticación se
  declara `BLOCKED`; no se intenta autenticar. Pedir credencial para sondear cambiaría lo que la
  sonda es.
- La redacción va **antes** de escribir, no al mostrar. Un secreto que llegó al disco ya se
  filtró aunque después se tape.
- **Nueve patrones** (`core/digest.py`, `E2`), cada uno por una forma real de filtrar algo. No se
  añaden preventivos: cada uno cuesta falsos positivos, y un redactor ruidoso se desactiva a la
  semana.

## Cadena de suministro

| Superficie | Estado | Nivel |
|---|---|---|
| Origen del estándar | anclado por **commit**, no por etiqueta; huella por archivo; `--check-remote` detecta la etiqueta movida | `E3` |
| Firma del binario del agente | comprobada; cuatro veredictos (`VALID`/`UNSIGNED`/`INVALID`/`REVOKED`). **Sólo macOS**: la comprobación usa `codesign` | `E4` para el caso `REVOKED` observado el 2026-08-27 |
| Dependencias de `refuto` | **ninguna**: sólo biblioteca estándar, comprobado en local con `scripts/check_stdlib_only.py` el 2026-09-22. En CI, `NOT_RUN` | `E2` |
| Servidores MCP | se interrogan antes de confiar; se registra qué revisión hablan de verdad | `E3` |
| Firma de procedencia del lock | **falta** — riesgo residual RR-01 | — |

## Lo que este modelo NO cubre

- **Exfiltración hacia el servicio del modelo.** El registro de la herramienta incluye lo que
  está en un archivo abierto. El control es que el dato **no esté en el árbol**, no que no salga:
  lo segundo no está en nuestra mano. Es más débil que un guardarraíl en la puerta del modelo, y
  por eso se declara compensatorio.
- **Lo que ocurre dentro del agente.** `refuto` observa entradas y salidas.
- **Una orden opaca que escribe donde no debe.** `python3 -c`, `make`, un binario propio: su
  efecto no se deriva de sus argumentos y `Ê` lo declara en vez de suponerlo. La respuesta es
  la capa 3 (atestación): la escritura no se impide, pero ningún veredicto posterior puede ser
  `PASS` si el juez cambió. `I6` en su forma fuerte queda `NOT_PROVEN`.
- **Truncar la cola del diario** sin un ancla publicada fuera del árbol. `NOT_PROVEN`.
- **Un agente que corre sin el gancho enganchado.** Hoy eso incluye `gemini`, `opencode` y
  `codex`. La capa 4 es la respuesta.
- **Una sesión con `sudo`.** El guardián sigue decidiendo sobre lo que la herramienta le declara,
  pero un proceso con privilegios de root escribe donde quiera, incluida la configuración del
  propio usuario fuera del espacio.
- **Windows y Linux.** El modelo está descrito para los tres, y sólo se ha ejecutado en macOS
  arm64. En los otros dos, `NOT_RUN`.

## Reportar un problema

Use los **avisos de seguridad privados de GitHub** de este repositorio:

> Pestaña **Security** → **Report a vulnerability** (GitHub Private Security Advisories).

Eso abre un canal privado con quien mantiene el repositorio, sin exponer el fallo mientras se
arregla. **No abra una incidencia pública** para un fallo explotable, y no envíe correo a personas
concretas: si el canal privado no está disponible en su fork, dígalo en una incidencia sin
detalles y se habilitará.

Qué esperar: acuse de recibo y una primera valoración. No hay compromiso de plazo publicado;
prometer uno que no se puede sostener sería el mismo defecto que este proyecto existe para no
cometer.

Si el problema es de un agente de terceros —por ejemplo un certificado de firma revocado—
repórtelo también a su proveedor: `refuto` lo detecta, no lo arregla.
