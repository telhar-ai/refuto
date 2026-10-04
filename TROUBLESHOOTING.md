# Diagnóstico

Cada entrada es un fallo **observado**, con la fecha y la máquina en que se observó. No hay casos
hipotéticos. Donde falta la fecha es porque el registro no la conservó: se dice, en vez de
inventarla.

Todas las órdenes suponen `refuto` en el `PATH` (ver [`INSTALL.md`](INSTALL.md)); si no, escriba
`python3 /ruta/a/refuto/refuto.py …`.

## «`--verbose` no funciona» / `unrecognized arguments: --verbose`

Observado el 2026-09-21 (macOS arm64). `--verbose` es opción **del parser raíz**, no de los
subcomandos: va **antes** del subcomando.

```bash
refuto --verbose probe --agent claude     # correcto
refuto probe --agent claude --verbose     # error: unrecognized arguments: --verbose, exit=2
```

Lo mismo con `selftest`, `run` y el resto. Y cuidado con el vecino de este error:
`selftest --suite <nombre-mal-escrito>` ejecuta **0 pruebas y sale con `0`**. Un `OK` con
`NO TESTS RAN` no es un aprobado: es un ámbito vacío. Medido el 2026-09-21.

## «El agente está instalado y `refuto` dice `INSTALLED`, no `FUNCTIONAL`»

Es el diagnóstico correcto: `INSTALLED` significa que se resuelve en el `PATH` y **no arranca o no
responde**. Mire el motivo:

```bash
refuto --verbose probe --agent <nombre>
```

| Motivo | Qué es | Arreglo |
|---|---|---|
| `muerto por señal 9` + firma `REVOKED` | el sistema operativo lo mata: certificado de firma revocado | reinstalar el paquete (`npm i -g <paquete>@latest`) |
| `colgado más de N s` | arranca y no termina; a veces el mismo fallo de firma se manifiesta así | ídem, y comprobar `codesign -v` a mano |
| `sin respuesta a initialize` | arranca pero no completa el handshake | comprobar la sesión: `<agente> auth` / login |
| `ejecutable no encontrado` | no está en el `PATH` del proceso que sondea | instalar, o quitarlo de `agents` en el manifiesto |

Caso concreto observado el **2026-08-27** en macOS arm64: un agente en el `PATH`, con versión
declarada, muerto por `SIGKILL` con `CSSMERR_TP_CERT_REVOKED`. La comprobación de firma usa
`codesign`, así que **sólo aplica en macOS**; en Linux y Windows esa columna no informa.

## «`kiro-cli agent list` falla con `File URI not found: /Volumes/…`»

Un agente **global** de terceros apunta a un volumen desmontado y rompe los comandos globales para
todos. Observado el 2026-08-27; es el hallazgo H-04.

```bash
ls ~/.kiro/agents/          # localizar el que apunta fuera
```

`refuto` no depende de ese comando: lee los agentes del espacio directamente. Pero Kiro sí, y
mientras el archivo esté ahí seguirá fallando. Retírelo o corrija su `prompt`.

## «`refuto verify` sale con 2 y no entiendo por qué»

`2` es `BLOCKED`: hay puertas que **no se pudieron comprobar**. No es un fallo del código
evaluado.

| Puerta | `BLOCKED` significa |
|---|---|
| `G-AGENT` | el manifiesto no declara ningún agente `required`: no hay nada que exigir |
| `G-LOCK` | no hay `harness.lock.json` → `refuto lock update` |
| `G-FLEET` | el manifiesto no declara `sources` |
| `G-MCP` | hay un servidor **HTTP** que sólo se puede interrogar desde el propio agente |
| `G-SDD` | el espacio no tiene `verificacion/verificar.py`: **no aplica aquí** |

Dos notas que evitan una lectura falsa:

- La fila de `G-SDD` es semánticamente `NOT_APPLICABLE`, no `BLOCKED`. El tipo `Result` no tiene
  ese valor todavía; está registrado en
  [`docs/estado-del-proyecto.md`](docs/estado-del-proyecto.md).
- **`G-MCP` sin ningún servidor declarado devuelve `PASS`** («nada que verificar»), no `BLOCKED`.
  Es un ámbito vacío aprobando, y es un defecto conocido, no el comportamiento deseado. Verificado
  el 2026-09-21 en `gates/g_mcp.py`.

Y `2` también lo devuelve `argparse` ante un error de sintaxis en la orden. Si su script sólo mira
el código de salida, no puede distinguirlos: mire también `stderr`.

## «La sesión abre bien y el primer mensaje da `API Error: Invalid URL`»

Es el fallo más desconcertante que tiene esto, porque **todo lo demás parece correcto**: el agente
arranca, declara su versión, responde el handshake, la sonda lo da por `FUNCTIONAL`. Lo único que
falla es el destino — y el destino no se ve hasta que se envía el primer mensaje.

La causa es una variable de entorno del shell que enruta el agente a otro proveedor:

```bash
refuto doctor
```

```
  A dónde habla
    ● <proveedor alternativo>
      ANTHROPIC_BASE_URL = /ruta/rota  (redirige TODAS las peticiones a otro endpoint)
      ✗ …no es una URL válida (falta esquema o servidor). Es la causa habitual de
        «API Error: Invalid URL»: la sesión abre bien y muere en el primer mensaje.
      ! esta sesión NO usará su suscripción: irá a «<proveedor alternativo>».
      dónde buscarlo:  grep -nE 'ANTHROPIC_BASE_URL' ~/.zshrc ~/.bashrc …
```

**Arreglo inmediato**, sin tocar nada:

```bash
refuto chat --provider clean
```

Ignora toda redirección y usa su suscripción. Con `--provider auto` —el valor por defecto— eso
ocurre solo cuando la redirección está **rota**: si es deliberada y funciona, se respeta.

**Arreglo permanente**: la orden que `doctor` imprime dice en qué archivo está definida la
variable. `refuto` **no lee sus dotfiles**; sólo dice qué variable está puesta, qué efecto tiene y
dónde mirar.

Por qué la sonda no lo detecta: `FUNCTIONAL` se comprueba con un handshake **local** que no toca
la red. Eso es deliberado —es lo que permite sondear sin llamar a ningún modelo en cuatro de los
cinco runtimes— pero deja este hueco, y por eso el enrutado se diagnostica aparte.

## «En Windows, el guardián bloquea TODO — hasta lo que debería permitir»

Observado en una rama de portabilidad, antes de integrarla. El registro de cada decisión pedía
`os.geteuid()`, que en Windows no existe; la excepción caía en el aviso de «auditoría
interrumpida», y ese aviso hace salir con `2` a propósito —un rastro que se corta en silencio es
peor que no tenerlo—, así que **también las escrituras legítimas quedaban bloqueadas**. Se
reconoce por esta línea:

```
harness-guard: AUDITORÍA INTERRUMPIDA: … (AttributeError: module 'os' has no attribute 'geteuid')
```

Los otros dos síntomas de la misma familia: `refuto doctor` devolvía un `Traceback` de
`UnicodeEncodeError` en vez de un veredicto, y todo agente se declaraba `NOT_INSTALLED` con
`AttributeError: module 'os' has no attribute 'killpg'`.

Los tres tienen arreglo en el árbol actual. **Advertencia honesta:** ese arreglo **no se ha
ejecutado nunca en Windows sobre este árbol** (`NOT_RUN`); lo medido fue en una rama aislada. Si
usa Windows, trate el conjunto como no verificado.

Lo que sí cambia: `refuto policy wire` instala `guard` y `guard.cmd`, y el gancho usa el segundo.
Si un gancho antiguo todavía dice `HARNESS_GUARD_RUNTIME=claude "…/guard"`, `cmd.exe` no lo
ejecuta —no falla: no corre— y hay que volver a ejecutar `policy wire`.

## «El guardián bloquea una escritura legítima»

```bash
refuto policy show     # ver la política vigente
```

Si el patrón sobra, quítelo de `.harness/policy.json`. Lo que **no** hay que hacer es desenganchar
el guardián: un control que estorba se corrige, no se desactiva.

Si el bloqueo es por contenido (`contenido-con-secreto`), el arreglo no es la política: es sacar
el secreto del archivo. Para datos de ejemplo, use valores evidentemente falsos.

## «`policy audit` dice 0/N justo después de `policy wire`»

Fue un defecto real, ya corregido. La causa **cambió** con el producto, así que conviene leerla
entera: `audit()` buscaba la marca `harness-guard` dentro del campo `command` del gancho; al pasar
el gancho a invocar el lanzador `.harness/bin/guard`, ese campo dejó de contener la cadena que el
auditor buscaba. Una comprobación que conoce sólo una forma del control caduca con el control.

Si vuelve a ocurrir es una regresión, y `tests/unit/test_wire.py::test_engancha_y_audit_lo_ve`
debería haberla parado.

## «Una skill no carga»

Casi siempre es `name` ≠ nombre del directorio.

```bash
refuto verify --gate G-SKILL
```

## «El servidor MCP arranca a mano y `refuto` dice que no responde»

Dos causas observadas durante la construcción:

1. **El servidor es HTTP** y necesita la credencial de la sesión del agente. `refuto` no la tiene
   y no la pide: sale `BLOCKED`, no `FAIL`.
2. **El proceso deja hijos vivos.** Los lanzadores de Node crean hijos que heredan los
   descriptores; matar sólo al padre cuelga a quien esté leyendo. `refuto` mata el **grupo**. Si
   escribe su propio cliente, hágalo también.

## «`refuto probe` se cuelga»

No debería: cada sonda tiene tope y se corre en paralelo. Si ocurre, es un agente que no cierra
sus descriptores. Reprodúzcalo aislado:

```bash
refuto --verbose probe --agent <nombre>
```

Las dos causas encontradas mientras se construía esto: leer `stderr` de un proceso vivo (bloquea
hasta EOF) y matar el proceso sin matar el grupo. Las dos están documentadas en `core/acp.py`.

## «Quiero deshacer lo que `policy wire` cambió»

```bash
refuto policy unwire     # restaura desde .harness/backup/
```

**Límite conocido** (`E1`, `core/wire.py`, 2026-09-22): la copia de seguridad sólo guarda archivos
que **ya existían**. Un archivo que `wire` **creó** —el caso típico es
`.claude/settings.local.json` en un espacio que no lo tenía— **no se borra** al desenganchar:
`unwire` restaura, no elimina. Compruébelo y bórrelo a mano si quiere volver al estado exacto.
