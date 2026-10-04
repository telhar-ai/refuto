# Registro de remediación de frontera

Cada cambio de esta fase responde el mismo contrato, y no se declara cerrado sin él:

```
CHANGE_ID · PROPERTY · PREVIOUS_FAILURE · THREAT · DESIGN · IMPLEMENTATION
REGRESSION_TEST · ADVERSARIAL_TEST · MUTATION_TEST · RUNTIME · EVIDENCE
VERIFIER · VERDICT · REMAINING_LIMITATION
```

«Las pruebas pasan» no es evidencia suficiente para ninguna de las casillas.

---

## Baseline congelado

> **Corregido el 2026-09-25 (STEP 1).** La tabla de abajo es la que se declaró al abrir la fase.
> Dos de sus cifras no resisten la comprobación y se sustituyen por el baseline operativo que
> sigue. Se conserva porque retirarla borraría la constancia de que se creyó.

| | declarado | comprobado |
|---|---|---|
| commit | `e948152` | ✓ |
| `engine_digest` | `4335648eb8bd…` | **✗ irreproducible** |
| ficheros atestados | 78 | ✓ (73 `.py` + 5 `.json`) |
| suite | 830 · 9 `expectedFailure` | **✗ eran 847 · 8** |
| diario | 2015 eventos · 978 legado | 978 legado ✓ · el total crece |
| máquina | macOS 26.4.1 arm64 · Python 3.14.6 · **single-host** | ✓ |

### Baseline operativo de remediación

```
HISTORICAL_BASELINE          commit = e9481525b4df2941…
OBSERVED_RECONSTRUCTION      d303f8f46ccc070b… — NO es un engine_digest declarado:
                             es la reconstrucción del motor en ese commit, corroborada
                             de forma independiente por 4 artefactos reales de
                             .harness/evidence/ (19:14–20:41 del 2026-09-25)
DECLARED_DIGEST 4335648e…    RETRACTED / UNVERIFIED — no sale de ninguna lectura del
                             repositorio ni consta en ninguno de los 37 artefactos
DECLARED_DIGEST 47d7b7f7…    RETRACTED / UNVERIFIED — ídem
```

**Cinco cosas distintas que este repositorio nombra parecido, y la deuda que eso deja:**

```
commit identity         qué código hay          git rev-parse HEAD
engine digest           qué juez corre          core.trust.digest_motor() — 78 ficheros
runtime evidence digest qué se observó          engine_digest DENTRO de un artefacto
ledger head             hasta dónde llega       core.evidence.cabeza()
checkpoint              qué se publicó fuera    NO EXISTE — FG-4
```

> **Deuda de assurance declarada.** El artefacto `harness.run/v1` llama `engine_digest` a su
> campo, que es *runtime evidence digest*: el valor del engine digest **en el instante de la
> corrida**. Son lo mismo sólo si el árbol no cambió entremedias, y aquí cambia. El nombre
> invita a confundirlos y ya lo hizo una vez: es como `4335648e…` llegó a citarse como si fuera
> el ancla de un commit. No se renombra en este cambio —sería tocar el esquema publicado
> mientras se remedia otra cosa—, queda escrito.

**Regla permanente sobre hashes (STEP 2 §24).** Un digest sólo cuenta como verificable si trae
`OBJETO + FUNCIÓN + BYTES DE ENTRADA + CÁLCULO REPRODUCIBLE + CONTEXTO`. Aparecer escrito en
documentación, en este registro, en la memoria o en un comentario **no lo hace evidencia**: lo
deja en `UNVERIFIED`. Ésa es la regla que `4335648e…` incumplió durante toda una fase.

**Regla permanente sobre el diario (STEP 2 §26).** El número de eventos NO es un ancla estable
—2015 → 2033 → 2069 → 2082 → 2135 en un día—. Toda prueba que necesite estado congelado crea su
propio fixture aislado; ninguna se mide contra el diario vivo.

Los cinco fallos reproducidos contra el motor real, que **no se borran al corregirse** sino que
pasan a regresión permanente:

```
R-01  find -exec · $D · ${D} · ${V:-x}        → opaco=False con ruta no resuelta
R-02  borrar el diario                        → verificación satisfecha contra un ancla
R-03  Write con ruta dict/lista/num/null      → allow sobre gates/base.py
R-04  TOCTOU / sustitución por enlace         → Decision sin identidad de objeto
R-05  deny + escritura posterior              → divergencia decisión↔efecto no observada
```

---

## C-02 · Ledger fail-closed

```
CHANGE_ID:        C-02
PROPERTY:         La ausencia del artefacto de evidencia no es integridad de la evidencia
PREVIOUS_FAILURE: R-02 — verificar_cadena() devolvía {ok: True, eventos: 0} con el fichero
                  borrado, retornando ANTES de consultar `esperado`
THREAT:           evidence deletion por el sujeto. Coste del ataque: `rm ledger.jsonl`.
                  Ejecutable por cualquier proceso con uid 501 (FORMAL-MODEL §6.2)
```

### DESIGN

`ok: bool` colapsaba seis situaciones que **se arreglan distinto**. Estado explícito:

```
AUSENTE · VACIO · INTEGRA · ROTA · DESALINEADA · INSUFICIENTE
```

La ausencia sólo aprueba **cuando no hay expectativa de evidencia**: un ancla publicada
(`esperado`) o un mínimo exigido (`eventos_minimos`). Sin ninguna de las dos, «no hay diario» y «no
ha pasado nada» son indistinguibles y aprobar es correcto — es el caso de un espacio recién creado.
Con cualquiera de ellas, es una contradicción.

La asimetría que delataba el defecto: **vaciar** el fichero sí se detectaba con ancla, porque la
función seguía adelante y el ancla no aparecía en una cadena vacía; **borrarlo** no, porque se
retornaba antes de mirar.

`eventos_minimos` es la forma mínima de la regla de suficiencia: **integridad ≠ suficiencia**, y
colapsarlas deja que «miré poco» pase por «no encontré nada».

### Resultado

| dimensión | resultado |
|---|---|
| REGRESSION_TEST | `test_brechas_de_assurance.py::test_R02_…` — `@expectedFailure` retirado, reproducción conservada íntegra, con aserción sobre `estado` para que no retenga por el motivo equivocado |
| ADVERSARIAL_TEST | `test_ledger_ataques.py` — 17 pruebas; los 12 ataques como suite permanente |
| MUTATION_TEST | **12/12 muertas por su testigo** · `NC1 VIVA` · `NC2 MUERTA_ESTRUCTURAL`. Tres mutaciones nuevas: `M-LEDGER-01`, `M-LEDGER-02`, `M-EVIDENCE-03` |
| RUNTIME | 3 decisiones del guardián real → `INTEGRA/3/ok`; tras borrar → `AUSENTE/ok=False` |
| EVIDENCE | `engine_digest 4335648e… → 47d7b7f7…` · `core/evidence.py 84e4f59d… → 9837f4dc…` · 847/847 · preflight `PASS` 15 controles |
| VERIFIER | diario real del repositorio intacto (`INTEGRA`, 2039 eventos); 71 pruebas de lo previamente probado sin regresión |
| **VERDICT** | **PASS en el motor** |

### Clasificación de los 12 ataques

| resultado | n | cuáles |
|---|---:|---|
| detectado sin ancla | 4 | borrar/modificar evento intermedio · final · primero |
| sólo con ancla | 7 | reescritura coherente · sustitución por otro diario · truncación · cadena alternativa · rollback · vaciado · *(y el cerrado)* |
| no aplica | 1 | añadir eventos tras el ancla — **es el funcionamiento normal de un diario de sólo añadir** |

`NO_APLICA` importa tanto como los otros dos. Marcarlo como «no detectado» habría inflado el
inventario de amenazas con un comportamiento correcto, y un inventario inflado se deja de leer.

### REMAINING_LIMITATION

**P0-E sigue ABIERTO.** El motor está cerrado; la operación no:

- **SC-1 · No existe orden para obtener el ancla.** `refuto evidence` tiene `--last`, `--kind`,
  `--json`. `core/evidence.py` llegó a citar `refuto evidence --anchor`, que **no existe** —
  `--anchor` sólo está en `install` e `init`, para anclar el origen del lock. No hay función
  `ancla`/`anchor` en `core/`, y `cabeza()` no se expone por CLI ni por MCP. Corregido el
  docstring; la orden sigue sin existir. **Los 7 ataques que dependen del ancla están cerrados en
  el motor y abiertos en la práctica.**
- **SC-2 · ~~`verificar_cadena` no tiene consumidor de producción. Ni una puerta, ni un comando:
  sólo tests.~~** **RETRACTADO el 2026-09-25 (STEP 1).** Es falso, y se obtuvo leyendo
  importaciones sin ejecutar nada — el mismo error de instrumento que la retractación del final
  de este documento confiesa, cometido dos párrafos más arriba. La cadena real es
  `refuto status` → `refuto.py::latest_verification` → `evidence.py::reconciliar` →
  `verificar_cadena`, probada instrumentando la función y ejecutando la orden: **1 llamada,
  `INTEGRA`, 2069 eventos**. Se conserva tachado, no borrado.

  **SC-2′ (reformulado, y sigue ABIERTO tras C-R07-R06).** Existe consumidor de producción; lo
  que no existe es un consumidor que ejerza el **modo fuerte**: se invoca con `esperado=''`, así
  que en operación se comprueba la INTEGRIDAD y no la SUFICIENCIA. Los siete ataques que
  dependen del ancla siguen abiertos fuera del motor. Depende de SC-1 · FG-4.

`check_citas.py` no detectó SC-1 porque verifica citas a **código**, no a **órdenes del CLI**. Es
el mismo vacío de vigilancia que `check_mediciones.py` cubrió para las cifras medidas.

### Lo que la investigación de frontera añadió después

Al contrastar con [C2SP tlog-checkpoint](https://c2sp.org/tlog-checkpoint@v1.0.0) se ve que
`esperado` y `eventos_minimos` **son las dos mitades de un checkpoint**, implementadas por separado
y sin firmar. La forma canónica las une —`origin`, `size`, `root hash`— y unirlas no es cosmético:
un ancla que lleva el tamaño detecta la truncación por comparación directa, en vez de obligar a
buscar un hash dentro de la cadena. Ver [`docs/research/sistemas-de-frontera.md`](../research/sistemas-de-frontera.md).

---

## C-R07-R06 · El estado operacional y su código de salida

```
CHANGE_ID:        C-R07-R06
PROPERTY:         P-R07 · un consumidor automático nunca recibe código 0 cuando el estado
                          reportado no es operacionalmente satisfactorio
                  P-R06 · la destrucción o ausencia de evidencia necesaria para establecer
                          el estado permanece OBSERVABLE en la frontera operativa
PREVIOUS_FAILURE: R-07 — `status` calculaba `integrity='contradice'`, IMPRIMÍA «NO INTEGRABLE
                  — la evidencia no se sostiene» y devolvía PASS/0
                  R-06 — 5 eventos `deny` destruidos y salida IDÉNTICA byte a byte, con el
                  mismo `next`
THREAT:           evidence deletion + silent success. Coste del ataque: `rm ledger.jsonl`.
                  Consumidor afectado: cualquier `refuto status && …` en CI
```

### DESIGN

**La causa no era la falta de contrato.** `core.envelope._EXIT_POR_ESTADO` ya derivaba el código
del estado, y `cmd_status` ya lo usaba. El defecto era que sólo se le pasaban **dos** estados:

```python
estado = INCONCLUSIVE if ilegibles else PASS
```

La integridad —ya calculada, ya guardada en `ver["integrity"]`, ya impresa— no entraba en la
decisión. Por eso `if status != PASS: exit(1)` habría tapado el síntoma sin tocar la causa: el
problema no era el mapeo, era que el estado se construía ignorando lo que se sabía.

La tabla, ahora en `_estado_de_status()` y auditable en un solo sitio:

| entrada | estado | código |
|---|---|---|
| evidencia **contradicha**, o cadena `ROTA`/`DESALINEADA`/`INSUFICIENTE` | `FAIL` | 1 |
| evidencia **ilegible**, o integridad `indeterminado` | `INCONCLUSIVE` | 2 |
| resto | `PASS` | 0 |

`FAIL` gana a `INCONCLUSIVE` — al revés que en las puertas. Una contradicción **demostrada** no
se degrada a «no pude determinarlo» porque además otra fuente fuera ilegible: rebajarla perdería
el único hecho firme que hay.

**La expectativa, derivada de algo material.** `status` consulta ahora el diario por derecho
propio, con `eventos_minimos=1` **si hay artefactos de corrida**: un artefacto no se escribe
solo, y escribirlo deja eventos. Es la regla de C-02 —la ausencia sólo aprueba sin expectativa—
aplicada en la frontera operativa en vez de dentro del motor.

### Resultado

| dimensión | resultado |
|---|---|
| REGRESSION_TEST | `test_estado_operacional.py::RegresionesDeCR07R06` — 3 pruebas. **Verificadas como regresión, no como especificación:** revertida `_estado_de_status` a su conducta previa, **9 pruebas se ponen rojas**; restaurado y comprobado por sha256 (`40f1044d44b63704`) |
| ADVERSARIAL_TEST | A-01…A-10 por el **CLI real** en subproceso. A-09 `NOT_APPLICABLE` con motivo: `DEGRADED` no existe en `STATUSES` y añadirlo es una decisión de contrato, no un paso de este cambio |
| MUTATION_TEST | **5 MUERTAS** (`M-R07-01/02/04/06/07`) por catálogo de 9 escenarios · `M-R07-03` `NO_APLICABLE` (no hay `DEGRADED`) · `M-R07-05` muerta **en el CLI**, no en la función pura: su testigo compara el texto impreso con el código del proceso real |
| RUNTIME | 6 escenarios con el binario real y hash del diario antes/después: `A-01 0→0` · `A-02 0→1` · `A-03 0→1` · `A-04 0→1` · `A-06 0→1` · `R-06 0→0 pero salida observable` |
| EVIDENCE | suite **871/871** (era 847; +24) · `check_stdlib_only`, `check_schemas`, `check_wiring`, `check_mediciones`, `check_citas` los cinco `rc=0` |
| VERIFIER | `check_mediciones` **detectó por su cuenta** que el README quedaba desfasado (847→871, adversarial 271→295) y puso la suite en rojo hasta corregirlo. Una cifra medida no pudo quedarse mintiendo |

### VERIFIER · las cuatro preguntas

```
¿El estado mostrado coincide con el calculado?         SÍ — es el mismo valor
¿El exit code coincide con el estado?                  SÍ — lo deriva _EXIT_POR_ESTADO
¿Puede un consumidor distinguir éxito de no éxito?     SÍ — 0 vs 1 vs 2, medido en 6 escenarios
¿Puede un fallo de evidencia volverse éxito en silencio?  NO con expectativa · SÍ sin ella
```

### VERDICT

```
P-R07   PASS
P-R06   DEGRADED
```

**`P-R06` no es `PASS` y no se fuerza.** Con expectativa material queda cerrado (`A-02`, `A-06`:
exit 1). Sin ninguna expectativa —espacio sin artefactos— «no hay diario» y «no ha pasado nada»
son indistinguibles dentro de un único fichero mutable: es un límite de información, no un
parche que falte. Lo que sí se cerró es el **silencio**: la salida ya no es idéntica antes y
después del borrado (`INTEGRA · 5 eventos` → `AUSENTE · 0 eventos`). Cerrar la otra mitad exige
un ancla publicada fuera del árbol, que es **FG-4**, y no se finge desde aquí.

### REMAINING_LIMITATION

- **Excepción declarada y probada:** una última verificación con **puertas en rojo** sigue dando
  `PASS`/0. `refuto verify` es la autoridad sobre ese veredicto y ya sale con 1; `status`
  responde «¿pude establecer el estado y se sostiene lo que reporto?». Mapearlo a `FAIL` haría
  indistinguible «hay trabajo» de «lo que te cuento no se sostiene». Está en `test_A05` y en el
  docstring, no heredado por omisión.
- **SC-2′ abierto:** el consumidor de producción existe pero invoca el modo débil (`esperado=''`).
- **Un solo uid.** Quien borra el diario puede borrar también los artefactos y el binario. Esto
  eleva el coste del ataque; no lo cierra. `LOCAL_ASSURANCE`, nunca `EXTERNAL`.
- **23 de 25 órdenes no emiten sobre.** Sólo 7 usan `responder()`; el resto devuelve códigos a
  mano. C-R07-R06 arregla `status`, **no** audita las otras 18. Gap nuevo: **FG-6**.

```
ASSURANCE_GAIN:    la integridad de la evidencia llega por primera vez al código de salida
                   de la orden que la comunica. Antes se calculaba, se imprimía y se perdía.
NEW_ATTACKS_FOUND: ninguno nuevo durante la implementación
NEW_GAPS_FOUND:    FG-6 · 18 de 25 órdenes eligen su código de salida a mano, fuera de la
                   tabla que deriva el estado. `status` era una de ellas de hecho aunque
                   llamara a `responder()`. Las otras no están auditadas.
NEW_ASSUMPTIONS:   que la presencia de un artefacto de corrida implica que hubo eventos que
                   lo escribieron. Es cierta por construcción de `write_run`, y es la única
                   expectativa que este cambio introduce.
```

---

## R-03 · Admisión y confusión de representación

```
CHANGE_ID:        R-03
PROPERTY:         Ninguna representación alternativa —por tipo, coerción, serialización o
                  estructura— obtiene los privilegios de la canónica
PREVIOUS_FAILURE: 13 representaciones de la MISMA escritura al juez → 10 con `allow`, y el
                  diario anotando `Write · allow · target=''`
THREAT:           type confusion + container bypass en la carga del gancho. El runtime es un
                  sistema externo que versiona su formato por su cuenta: el día que mueva un
                  campo, el guardián deja de gobernar en silencio y aprobando
```

### ROOT_CAUSE — dos defectos, no uno

```python
def _first(doc, keys):
    for key in keys:
        value = _dig(doc, key)
        if isinstance(value, str) and value:   # ← un dict se DESCARTA sin decirlo
            return value
    return ""                                   # ← indistinguible de «la clave no estaba»
```

`evaluate` veía `path=""`, no encolaba decisión, y como el NOMBRE de la herramienta **sí** se
había reconocido, concluía «la carga no trae ruta ni orden que evaluar» → `allow`. Es el ataque
canónico **entrada ambigua → normalización → pérdida de información → validación → allow**.

Y `_dig` tenía el mismo colapso un nivel más arriba: `not isinstance(node, dict)` trataba
«el contenedor existe con la forma equivocada» como «la clave no está». **Este segundo no estaba
en el inventario de STEP 1: apareció al medir el arreglo del primero.**

### DESIGN

Tres situaciones donde antes había dos, y coerción **prohibida**:

```
ADMISIBLE    cadena no vacía bajo una clave declarada      → ese valor
AUSENTE      ninguna clave declarada presente              → legítimo (Read, Grep)
ILEGIBLE     una clave ESTÁ con valor inservible, o el contenedor está mal formado
INADMISIBLE  herramienta de escritura declarada sin ninguna ruta legible
```

No se coacciona a propósito, y `A-R03-17/18` demuestran por qué no es escrúpulo sino propiedad:
con **señuelo** —`{"seguro": "obra.txt", "real": "gates/base.py"}`— la coerción elige un valor y
la escritura real puede ser el otro. Con un contenedor de un solo valor la coerción acertaba y
parecía inocua; con señuelo aprueba el juez.

`ASK`, no `DENY`, por el mismo criterio ya establecido para `carga-no-reconocida`, del que esto
es el caso **parcial**: un `deny` ante el primer cambio de esquema dejaría el espacio
inutilizable, y un espacio inutilizable se arregla desenganchando el gancho — y entonces se deja
de mirar el canal entero.

`_ESCRITURA` **no inventa nombres**: los toma de `core.wire.CLAUDE_MATCHER`,
`adapters.kiro.KIRO_WRITE_TOOLS` y los matchers de `gemini`/`opencode`. No es una segunda
política; es la misma, hecha consultable desde el guardián.

### Resultado

| dimensión | resultado |
|---|---|
| REGRESSION_TEST | `G3::test_DEUDA_una_herramienta_de_escritura_sin_ruta_legible_no_se_aprueba` — `@expectedFailure` retirado, **las cinco cargas conservadas íntegras**. La alarma de diseño funcionó: la suite reportó `unexpectedSuccess` e invalidó la corrida hasta retirar el decorador |
| ADVERSARIAL_TEST | `test_admision_r03.py` — 18 pruebas · **21 representaciones** clasificadas una a una · 6 cargas legítimas como control positivo · 4 dialectos |
| MUTATION_TEST | **9 MUERTAS** (`M-R03-01/02/04/06/07/08/09/10/11`). `M-R03-03/05` no se instrumentan aparte: caen dentro de `M-R03-09` (aplanado), que es su forma más fuerte |
| RUNTIME | guardián real, 7 cargas: `deny` a la canónica · `ask` a dict/señuelo/contenedor/clave-no-listada/Bash · `allow` a la legítima. Diario: 3 reglas distintas, **cero** `Write·allow·target=''` |
| EVIDENCE | suite **889/889** (era 871; +18) · `expectedFailure` **8 → 7** · 6 controles del repositorio `rc=0` · ruff limpio |
| VERIFIER | revertido `_dig`+`_campo`+`escribe` a la conducta previa: **28 fallos** en la suite endurecida y **5** en G3; las 19 cargas inadmisibles vuelven a `ALLOW`. Restaurado y comprobado por sha256 (`e4eae036fb0c88b9`) |

### Lo que la prueba de mutación encontró, y que yo no había puesto

Seis mutaciones salieron **VIVAS** en la primera pasada. No porque el arreglo fallara, sino
porque **mi catálogo era insuficiente**: con un contenedor de un solo valor, coaccionar
`{"path": "gates/base.py"}` acierta la ruta y sale `deny`, así que la mutación no se distinguía.
Faltaban los señuelos (`A-R03-17/18`), el contenedor mal formado sobre una **orden**
(`A-R03-19`) y el `null` sobre una orden (`A-R03-21`). Sin ellos habría declarado muertas unas
mutaciones que el catálogo no sabía ver.

Una redundancia que conviene decir en voz alta: `A-R03-14` (contenedor mal formado sobre
`Write`) **no** distingue la reversión de `_dig`, porque `escritura-sin-ruta` la rescata por otro
camino. El testigo genuino es `A-R03-19`, sobre `Bash`. Afirmar que el arreglo de `_dig` es
necesario para todo sería más de lo que la medición sostiene: es necesario para las **órdenes**.

### VERDICT

```
R-03            PASS · alcance declarado (dialecto claude medido; los otros tres por declaración)
A ADMISSION     FAIL → DEGRADED
```

**A no pasa a `PASS`, y la distinción no es retórica.** El defecto R-03 está cerrado para todo
el espacio de representaciones medido. La dimensión no lo está porque sigue abierta su deuda
hermana: `test_DEUDA_existe_un_contrato_de_admision_versionado` continúa en `@expectedFailure`
—`_SHAPES` no declara `schema_version`—, así que **una deriva de esquema del runtime sigue
siendo indetectable por construcción**. Y `_ESCRITURA` es una lista mantenida a mano: una
herramienta de escritura con nombre nuevo y campo de ruta nuevo volvería a salir `allow`.

### REMAINING_LIMITATION

- **El efecto demostrado es el de la EVIDENCIA, no el del sistema de ficheros.** No se afirma
  que Claude Code fuera a escribir con un `dict` por ruta: refuto es un gancho **previo** y no
  ejecuta. Lo que sí se demostró es que el diario registraba `Write · allow · target=''` — una
  escritura jamás examinada, anotada como examinada y aprobada, indistinguible de un `Read`.
  Certeza falsa, la misma clase que `opaco=False` en R-01.
- **`ask` es una recomendación.** Que el efecto quede ausente depende de que el runtime honre el
  gancho. Eso es `D ENFORCEMENT`, que sigue en `FAIL` de frontera: un uid único.
- **Inventario a mano en dos sitios** (`_SHAPES`, `_ESCRITURA`) sin versión que detecte la
  deriva. Es la deuda que cierra el `schema_version` pendiente.

```
ASSURANCE_GAIN:    la admisión distingue por primera vez «no venía» de «venía y no se pudo
                   leer», y una escritura inexaminable ya no se registra como aprobada.
NEW_ATTACKS_FOUND: el BYPASS DEL CONTENEDOR (`{"tool_input": "…"}` no-objeto), encontrado al
                   medir el arreglo del primer defecto, no en el inventario de STEP 1.
                   Y la coerción con SEÑUELO, encontrada por la prueba de mutación.
NEW_GAPS_FOUND:    ninguno nuevo de frontera. Se confirma FG-6 sin tocarlo: R-03 no añadió
                   ningún mapeo manual de estado → código, y C-R07-R06 sigue verde.
NEW_ASSUMPTIONS:   que los nombres de herramienta de escritura de cada runtime son los que sus
                   propios adaptadores ya declaraban. Verificable leyéndolos; no se inventó
                   ninguno.
```

---

## R-01 · La cadena de resolución del efecto

```
CHANGE_ID:        R-01
PROPERTY:         La distinción entre «resolví» y «no resolví» sobrevive a TODA la cadena:
                  entrada → resolución → decisión → efecto → evidencia
PREVIOUS_FAILURE: `$D` · `${D}` · `${V:-x}` · `find -exec` → `opaco=False` con ruta no
                  resuelta. `Ê` afirmaba escribir en un fichero llamado «$D»
THREAT:           certeza falsa registrada. No es que estas órdenes pasen —`python3 -c`
                  también pasa y está bien—: es que se anotaban como examinadas
```

### ROOT_CAUSE

`opaco: bool` colapsaba dos situaciones opuestas en el mismo `False`, y de ahí salían **tres**
defectos distintos:

```
cp a b                  opaco=False  ← se derivó todo: la certeza es real
echo x > $D             opaco=False  ← se derivó «$D», que no es una ruta   ← AMBIGUO
find . -exec truncate   opaco=False  ← `find` está en _LECTORES y -exec escribe
```

Y `_EXPANSION` no casaba ni `$VAR` ni `${V:-x}`: su patrón exigía `?`, `+` o `=` dentro de las
llaves. `:-` no está.

### DESIGN — el mismo movimiento que R-03, aplicado un canal más abajo

Cinco estados donde había un booleano, separados por el criterio de siempre —**se arreglan
distinto**—:

```
SIN_SUJETO    no había nada que derivar
RESUELTO      se derivó entero. La certeza es real
DESCONOCIDO   el programa no está modelado      → se arregla añadiéndolo a la tabla
NO_RESOLUBLE  está modelado y no se deriva      → no se arregla nunca; se declara
AMBIGUO       se derivó algo que NO es una ruta → el único que MIENTE
```

`opaco` deja de ser el tipo y pasa a ser una **propiedad derivada** de `resolucion`. Se conserva
porque está en el esquema del diario y en más de 2000 eventos ya escritos, pero ya no puede
decir `False` sobre algo que no se resolvió: no hay forma de fijarlo a mano.

**Un destino sin resolver no se coacciona ni se descarta.** Sale de `escrituras` y entra en
`sin_resolver`. Las dos alternativas son defectos: dejarlo en `escrituras` afirma un fichero
llamado `$D`; tirarlo afirma que no hay escritura. Es la lección de `core.guard._campo`, literal.

**Y la decisión distingue `AMBIGUO` de `NO_RESOLUBLE`,** que es donde está la ganancia real. Con
`python3 -c` no se sabe **si** escribe; con `echo x > $D` se sabe **que** escribe y no **adónde**.
Lo segundo es estrictamente más información, y se responde con `ask` (`destino-sin-resolver`) —
el mismo hecho que `campo-ilegible`, un canal más arriba, y la misma respuesta.

`find -exec` sigue saliendo **`allow`**, igual que `python3 -c`, y es correcto: denegar todo
intérprete haría inusable la herramienta y un control inusable se desactiva. Lo que cambió no es
la decisión sino que la ignorancia quede declarada.

### La asimetría entre escrituras y lecturas, que me costó una regresión

Al introducir el cambio filtré **también** los tokens sin expandir de `lecturas`. Medido acto
seguido: `echo $MI_SERVICIO_PASSWORD` pasaba de `ask` a **`allow`**. Había debilitado un control
de credenciales sin querer, porque `_lecturas_secretas` usa el **nombre de la variable** para
detectarlas por su forma. En `lecturas` el token sin resolver **es** el dato; en `escrituras` es
una mentira. La asimetría está ahora escrita en el código con su medición.

### Resultado

| dimensión | resultado |
|---|---|
| REGRESSION_TEST | `G1::test_DEUDA_una_orden_que_no_se_pudo_resolver…` y `G1::test_DEUDA_ninguna_ruta_derivada…` — **dos** `@expectedFailure` retirados, las cuatro órdenes ciegas conservadas íntegras |
| ADVERSARIAL_TEST | `test_resolucion_r01.py` — 23 pruebas organizadas **por salto de la cadena**: entrada→resolución (6) · composición (3) · resolución→decisión (4) · decisión→evidencia (3) · mutaciones (7). 8 órdenes ciegas · 10 controles positivos |
| MUTATION_TEST | **7 MUERTAS**: no comprobar la expansión · coaccionar la ruta cruda · descartarla en silencio · `find` como lector · componer por el primero en vez de por lo peor · decisión sin `sin_resolver` · diario sin `resolucion` |
| RUNTIME | guardián real, 10 órdenes: 4 estados distintos registrados en el diario · `ask` a lo ambiguo · `deny` a lo resuelto y protegido · `allow` a lo no resoluble |
| EVIDENCE | suite **912/912** (era 889; +23) · `expectedFailure` **7 → 5** · 6 controles `rc=0` · ruff limpio |
| VERIFIER | revertido el núcleo: **24 fallos** en la suite endurecida y **7** en `G1`. Restaurado y comprobado por sha256 (`29d3d720c9b44071`) |

### VERDICT

```
R-01          PASS
B DECISION    DEGRADED  (sin cambio)
```

**`B` no se mueve, y conviene decir por qué no.** R-01 corrige lo que la decisión *sabe* sobre el
efecto, no la decisión misma: sigue sin ser reproducible por un tercero, y `Ê ⊆ Effects` sigue
siendo incompleto por construcción (FORMAL-MODEL §6.1). Lo que se cerró es una fuente concreta de
afirmación falsa dentro de una aproximación que sigue siendo aproximación.

### REMAINING_LIMITATION

- **`Ê` sigue sin ser computable.** Esto reduce superficie; no la cierra. Un binario propio o un
  `make` siguen pudiendo escribir donde quieran, y ahora se dice.
- **Los comodines de globbing no se tratan como expansión.** `*`, `?`, `[` se expanden contra
  ficheros que YA existen, así que el conjunto derivado sigue acotado por el árbol; una variable
  puede valer cualquier cosa. Meterlos marcaría ambiguo medio `find` legítimo sin ganar
  propiedad. **Es una frontera declarada, no un olvido**, y está escrita en `_SIN_EXPANDIR`.
- **`lecturas` conserva tokens sin resolver.** Inerte —no se comparan contra rutas protegidas—
  pero es una asimetría que hay que conocer antes de tocar ese módulo.
- **La suite tiene un error INTERMITENTE, y no está diagnosticado.** Observado **2 veces en
  unas 15 corridas** durante esta fase; nunca reproducible a demanda —seis corridas dirigidas
  a capturarlo salieron verdes—, así que no hay traza. **Causa no establecida.** La hipótesis
  más cercana es la concurrencia del diario ya conocida en este repositorio (varios guardianes
  escribiendo y la cadena declarándose manipulada), pero **no está comprobada** y no se
  presenta como diagnóstico. Queda abierto: una suite que falla 1 de cada 7 veces sin
  explicación no es una suite verde, y decir lo contrario sería el defecto que esta fase
  persigue.

```
ASSURANCE_GAIN:    el diario distingue por primera vez TRES modos de ignorancia
                   (`AMBIGUO`/`NO_RESOLUBLE`/`DESCONOCIDO`) donde antes había un booleano, y
                   una escritura a destino desconocido la decide una persona en vez de pasar
                   como certeza.
NEW_ATTACKS_FOUND: ninguno nuevo. `find -delete` y `find -execdir` se añadieron por
                   completitud de la clase que `-exec` ya destapaba.
NEW_GAPS_FOUND:    ninguno de frontera.
NEW_ASSUMPTIONS:   que un glob acota el destino al árbol existente y una variable no. Es lo
                   que sostiene la frontera de `_SIN_EXPANDIR`, y es falsable: un glob sobre
                   una ruta absoluta fuera del espacio la rompería.
```

---

## R-04 · Identidad de objeto y TOCTOU

### TOCTOU DESIGN REVIEW — primero, y lo que decidió el alcance

```
PREVENTION      impedir que la sustitución ocurra          NO ALCANZABLE
DETECTION       notar que ocurrió                          BLOQUEADA en E
ATTESTATION     dejar constancia de sobre qué se decidió   ALCANZADA
RECONCILIATION  cruzar lo decidido con lo ocurrido         BLOQUEADA en E
```

**`PREVENTION` no es un pendiente: no tiene dónde ponerse.** refuto es un gancho `PreToolUse`.
Decide, devuelve, y el proceso **termina**. Quien abre el fichero es otro proceso, más tarde.
No falta código; falta punto de programa.

**Y la medición de plataforma, aunque cierta, resultó irrelevante.** Re-medido aquí:

```
O_RDONLY                   ABRIÓ a través del enlace intermedio
O_RDONLY | O_NOFOLLOW      ABRIÓ                             ← sólo cubre el último componente
O_RDONLY | O_NOFOLLOW_ANY  RECHAZÓ (ELOOP)                   ← sí protege
flag inventado 0x400000    ACEPTADO EN SILENCIO              ← el símbolo no prueba soporte
```

Todo eso protege **al abrir**, y `decide_write` **nunca abre el objetivo**: usa `realpath`, que
sigue los enlaces **a propósito**, porque un enlace dentro del espacio apuntando al juez es
exactamente el ataque que hay que ver (`test_control_un_enlace_existente_se_detecta_al_decidir`
ya lo probaba). Añadir una sonda de capacidad para una primitiva que el programa no usa sería
complejidad sin ganancia de assurance, y se rechaza por §28. **La medición se conserva en el
registro; el código no la necesita.** Es el hallazgo más útil de este design review: la
respuesta correcta era no implementar lo que el plan sugería.

```
CHANGE_ID:        R-04
PROPERTY:         La evidencia identifica SOBRE QUÉ OBJETO se decidió, no sólo sobre qué nombre
PREVIOUS_FAILURE: la `Decision` no llevaba `dev`/`ino`/tipo. Dos eventos sobre
                  «obra/salida.txt» podían ser sobre dos ficheros distintos y nada lo decía
THREAT:           sustitución del objeto entre T1 y T5. Coste: `unlink` + recrear
```

### DESIGN

`identidad_de()` con `lstat` —no `stat`, que seguiría el enlace y haría indistinguibles el
enlace y su objetivo, justo la sustitución que interesa ver— y cuatro estados, por el mismo
criterio de siempre:

```
EXISTE         el objeto está: (dev, ino, tipo, nlink)
AUSENTE        no está y su padre sí: se atestigua el PADRE, que determina dónde aterrizará
SIN_PADRE      ni el objeto ni su padre existen
INDETERMINADO  no se pudo mirar (permisos, E/S). NO es «no está»
```

`AUSENTE` no es un caso de borde: es el más frecuente —crear un fichero— y es donde la TOCTOU
toma otra forma. No hay objeto que atestiguar, así que se atestigua **el directorio que va a
recibir la escritura**, porque sustituir ESE directorio es el ataque equivalente.

La identidad se adjunta **en un solo sitio**, sobre la decisión que salga, y no en cada `return`.
Repartirla por las cuatro ramas garantizaba que la siguiente rama que alguien añadiera saliera
sin ella, y una identidad que falta sólo a veces es peor que no tenerla: parece que está.

### Resultado

| dimensión | resultado |
|---|---|
| REGRESSION_TEST | `G4::test_DEUDA_la_decision_declara_sobre_que_objeto_se_emitio` — decorador retirado y **reescrita**, ver abajo |
| ADVERSARIAL_TEST | `test_identidad_objeto_r04.py` — 13 pruebas: 3 de atestación · 5 de sustitución (borrar+recrear · por enlace · el directorio padre · **2 controles negativos**) · 2 de evidencia · **3 de frontera** |
| MUTATION_TEST | la reversión de la atestación es la mutación, y mata **10 fallos + 5 errores** en la suite endurecida y 1 en `G4` |
| RUNTIME | guardián real, `before/action/after`: mismo `target`, inodo `187947229 → 187947231`, distinguible en el diario |
| EVIDENCE | suite **925/925** (era 912; +13) · `expectedFailure` **5 → 4** · 6 controles `rc=0` · ruff limpio |
| VERIFIER | `test_portabilidad` **detectó por su cuenta** que usé `os.geteuid()` directo en vez del envoltorio de `core.proc`; y `check_mediciones`, otra vez, que el README quedaba desfasado |

### La prueba que hubo que reescribir, y por qué consta

`G4` asertaba `hasattr(d, c) for c in ("dev", "inode", "identidad", "objetivo")`: una lista de
nombres **adivinados antes de que el campo existiera**. STEP 1 ya la clasificó como
`ESPECIFICACIÓN` por eso. Habría seguido roja con la propiedad cerrada sólo porque el campo se
llamó `objeto`, **y habría pasado en verde con un campo vacío que no distinguiera nada**.

Ahora comprueba la propiedad —que la identidad exista **y sirva para distinguir una
sustitución**—. La versión anterior queda descrita en el docstring en vez de borrada.

### Las fronteras, escritas como aserciones

`LoQueEstaArquitecturaNoAlcanza` no es prosa: son tres pruebas que **fallan si el límite cambia
en silencio**. `test_no_hay_observador_en_T5` se pondrá roja el día que alguien implemente
`PostToolUse`, obligando a reescribir el contrato en vez de dejarlo afirmando menos de lo que el
sistema hace. `test_PREVENTION_no_es_alcanzable` falla si `decide_write` empieza a abrir el
objetivo.

### VERDICT

```
R-04            ATTESTATION alcanzada · DETECTION y RECONCILIATION BLOQUEADAS en E
D ENFORCEMENT   FAIL (frontera) — sin cambio
```

**No se declara `PASS` de R-04.** El defecto reproducido está cerrado —la decisión ya declara
sobre qué objeto se emitió— pero la propiedad que R-04 nombra («lo autorizado en T1 es lo
afectado en T5») **no se puede demostrar sin un observador en T5**. Lo que hay es su
precondición, y llamarlo `PASS` sería exactamente el tipo de afirmación que esta fase persigue.

### RETRACTACIÓN · 2026-09-30 · la identidad NO distingue la sustitución en ext4

Lo que sigue corrige por arriba lo que esta sección afirmó el 2026-09-25, y la corrección es
sobre el **alcance**, no sobre el mecanismo.

R-04 se midió **sólo en macOS**. En APFS los números de inodo no se reutilizan, así que borrar
y recrear con el mismo nombre daba otro `ino` y `LaIdentidadDistingueCadaSustitucion` pasaba.
**En ext4 el inodo liberado se reutiliza de inmediato**, y entonces `(dev, ino, tipo, nlink)` es
**idéntico** a los dos lados de la sustitución. Medido el **2026-09-30** en GitHub Actions
(`ubuntu-latest`, Python 3.10 **y** 3.13, PR #7): **4 pruebas en rojo**, con el mismo `ino`
—`9180471`— antes y después.

No se vio antes porque estas pruebas **nacieron después de la última corrida verde en Linux**:
llegaron en esta rama, y la CI verde de PR #6 es anterior a ellas. Es el fallo que este
repositorio advierte de sí mismo, cometido aquí: **una propiedad medida en una plataforma y
afirmada para todas.** Diseño ≠ implementación ≠ despliegue.

**Qué se hizo.** La identidad añade `nacimiento_us` desde `st_birthtime` donde el sistema lo
expone (macOS, BSD, Windows), y `core.policy.IDENTIDAD_DISTINGUE_REUSO_DE_INODO` declara si
puede o no distinguir el reúso. Donde no puede, las pruebas de sustitución **declaran
`NOT_APPLICABLE` con su motivo** en vez de fallar o —peor— de aprobar en falso, y dos controles
negativos exigen que el predicado y los campos de la identidad digan lo mismo: el día que uno
cambie, el otro pone la corrida en rojo y hay que volver aquí.

**Por qué no se cierra.** `ctime_ns` está descartado: cambia también al reescribir el contenido,
y la identidad responde «¿es este fichero?», no «¿tiene el mismo contenido?» — usarlo convertiría
la atestación en una alarma que salta siempre, y hay una prueba que lo fija. Y Linux **no expone
la hora de creación por `os.stat`**: está en `statx`, que CPython no enlaza. Con `lstat` no hay
campo que consultar. Cerrarlo pide otro instrumento: `statx`, o retener un descriptor entre
decisión y ejecución — que un gancho `PreToolUse`, que decide y devuelve, no tiene.

**Estado corregido:** `ATTESTATION` alcanzada en todas las plataformas · **`DETECTION` de la
sustitución con reúso de inodo: `NOT_APPLICABLE` en ext4, alcanzada en APFS.**

### REMAINING_LIMITATION

- **La ventana DENTRO de la decisión sigue abierta.** `realpath()` y `lstat()` son dos
  travesías del sistema de archivos; entre ellas el objeto puede cambiar, así que la identidad
  atestiguada puede no ser la del objeto que se comparó contra la política. No se cierra
  —haría falta resolver y medir en una sola operación, y `realpath` no la ofrece— y queda
  fijada en `test_la_ventana_dentro_de_la_decision_sigue_abierta`. Es de microsegundos y exige
  una carrera local; en un modelo de uid único, quien puede ganarla puede además borrar el
  diario.
- **Nadie compara las identidades todavía.** Se atestiguan y no se cruzan, porque el
  consumidor natural es el observador de T5. Deliberadamente **no** se añadió una API de
  comparación sin consumidor: sería repetir el defecto que SC-2 destapó —una verificación que
  existe y nunca se ejecuta fuera de la suite—.

```
ASSURANCE_GAIN:    la evidencia pasa de registrar un NOMBRE a registrar un OBJETO. La pregunta
                   «¿es el mismo fichero?» tiene por primera vez con qué responderse.
NEW_ATTACKS_FOUND: ninguno nuevo. La sustitución del DIRECTORIO PADRE en una creación no
                   estaba en el inventario y se cubre.
NEW_GAPS_FOUND:    la ventana interna realpath→lstat, declarada arriba.
NEW_ASSUMPTIONS:   que `(dev, ino)` identifica un objeto de forma estable mientras exista.
                   Cierta en un sistema de archivos local; falsable sobre NFS, donde los
                   inodos se reciclan con otra semántica. Fuera del baseline single-host.
```

---

## Estado A–H tras R-04

```
A  ADMISSION        DEGRADED                   21/21 representaciones; contrato sin versión
B  DECISION         DEGRADED                   lo que sabe ya no miente; no reproducible
C  POLICY           DEGRADED                   monotonía probada; norma = código
D  ENFORCEMENT      FAIL (frontera)            consultivo; uid único. R-04 NO lo mueve:
                    PASS (barandilla)          atestiguar no es impedir
E  OBSERVATION      DESIGNED_NOT_IMPLEMENTED   0 PostToolUse · bloquea DETECTION de R-04
F  EVIDENCE         DEGRADED                   ahora identifica objetos; ancla inobtenible
G  EXTERNAL TRUST   DESIGNED_NOT_IMPLEMENTED   ancla nunca publicada
H  IDENTITY         FAIL                       identidad de OBJETO sí; de PRINCIPAL no
```

`H` merece una precisión: R-04 cierra la **identidad de objeto**, que es una de las siete que
`H` distingue. Las otras seis —principal, sesión, petición, decisión, operación, evidencia—
siguen igual. Leer esto como «H mejoró» sería confundir `identity` con `object identity`, que es
la confusión que la propia matriz existe para impedir.

---

## Estado A–H tras R-01

```
A  ADMISSION        DEGRADED                   21/21 representaciones; contrato sin versión
B  DECISION         DEGRADED                   lo que la decisión SABE ya no miente;
                                               la decisión sigue sin ser reproducible
C  POLICY           DEGRADED                   monotonía probada; norma = código
D  ENFORCEMENT      FAIL (frontera)            consultivo; uid único
                    PASS (barandilla)          canal Write 6/6
E  OBSERVATION      DESIGNED_NOT_IMPLEMENTED   0 PostToolUse · 0 efectos observados
F  EVIDENCE         DEGRADED                   C-02 + C-R07-R06 cerrados; ancla inobtenible
G  EXTERNAL TRUST   DESIGNED_NOT_IMPLEMENTED   ancla nunca publicada
H  IDENTITY         FAIL                       euid en 2033/2082 · 49 eventos sin principal
```

Nada cambia de estado. R-01 mejora la CALIDAD de `B` sin cerrarla, y es importante no leer
«se cerró un defecto de B» como «B mejoró de estado»: la dimensión mide si la decisión es
reproducible y demostrable, no si una de sus entradas dejó de mentir.

---

## Estado A–H tras R-03

```
A  ADMISSION        DEGRADED                   21/21 representaciones medidas se rechazan;
                                               contrato SIN VERSIÓN → deriva indetectable
B  DECISION         DEGRADED                   decide bien; no reproducible
C  POLICY           DEGRADED                   monotonía probada; norma = código
D  ENFORCEMENT      FAIL (frontera)            consultivo; uid único
                    PASS (barandilla)          canal Write 6/6
E  OBSERVATION      DESIGNED_NOT_IMPLEMENTED   0 PostToolUse · 0 efectos observados
F  EVIDENCE         DEGRADED                   C-02 + C-R07-R06 cerrados; ancla inobtenible
G  EXTERNAL TRUST   DESIGNED_NOT_IMPLEMENTED   ancla nunca publicada
H  IDENTITY         FAIL                       euid en 2033/2082 · 49 eventos sin principal
```

`A` mejora y **nada más se mueve**. En particular `F` no mejora por que el diario deje de
mentir sobre las escrituras inexaminables: eso corrige un dato de entrada, no la capacidad de
demostrar la integridad frente a quien puede borrarlo.

---

## Estado A–H tras C-R07-R06

```
A  ADMISSION        FAIL                       7 de 8 formas aprueban escritura al juez
B  DECISION         DEGRADED                   decide bien; no reproducible
C  POLICY           DEGRADED                   monotonía probada; norma = código
D  ENFORCEMENT      FAIL (frontera)            consultivo; uid único
                    PASS (barandilla)          canal Write 6/6
E  OBSERVATION      DESIGNED_NOT_IMPLEMENTED   0 PostToolUse · 0 efectos observados
F  EVIDENCE         DEGRADED                   motor cerrado (C-02) · propagación cerrada
                                               (C-R07-R06) · ancla inobtenible (SC-1, SC-2′)
G  EXTERNAL TRUST   DESIGNED_NOT_IMPLEMENTED   ancla nunca publicada
H  IDENTITY         FAIL                       euid en 2033/2082 · 49 eventos sin principal
```

Lo que **no** cambió, y conviene decirlo: C-R07-R06 mejora `F` y no toca `A`–`E`, `G` ni `H`.
Un estado operacional que ya no miente hace *auditables* los demás fallos; no los arregla.

---

## Estado A–H tras C-02

```
A  ADMISSION        FAIL                       5 de 16 formas aprueban escritura al juez
B  DECISION         DEGRADED                   decide bien; no reproducible
C  POLICY           DEGRADED                   monotonía probada; norma = código
D  ENFORCEMENT      FAIL (frontera)            consultivo; uid único
                    PASS (barandilla)          canal Write 6/6
E  OBSERVATION      DESIGNED_NOT_IMPLEMENTED   0 PostToolUse · 0 efectos observados
F  EVIDENCE         FAIL → DEGRADED            motor cerrado; ancla inobtenible (SC-1, SC-2)
G  EXTERNAL TRUST   DESIGNED_NOT_IMPLEMENTED   ancla nunca publicada
H  IDENTITY         FAIL                       2 de 6 transiciones con principal
```

```
P0-B  Evidence sufficiency   CERRADO en el motor
P0-E  Ledger fail-closed     CERRADO en el motor · ABIERTO en operación
```

Según el criterio de cierre, **P0-E no puede declararse cerrado**: falta evidencia de runtime de
que alguien invoque la verificación en una corrida real.

---

## Mediciones de plataforma que condicionan el trabajo pendiente

Medido el 2026-09-25 en macOS 26.4.1 arm64, con un enlace simbólico en un componente **intermedio**:

```
O_RDONLY                   → ABRIÓ a través del enlace
O_RDONLY | O_NOFOLLOW      → ABRIÓ a través del enlace     ← insuficiente
O_RDONLY | O_NOFOLLOW_ANY  → rechazó (ELOOP)               ← sí protege
flag inventado 0x400000    → ACEPTADO EN SILENCIO          ← el kernel ignora bits desconocidos
```

Tres consecuencias para `R-04`:

1. `O_NOFOLLOW` **no basta**: sólo cubre el último componente.
2. `os.O_NOFOLLOW_ANY` existe en esta plataforma y sí cubre todos.
3. **Un flag no soportado no se distingue de uno aplicado.** Cualquier uso de estas banderas exige
   una comprobación de arranque —abrir a través de un enlace intermedio y exigir que falle— y
   declarar `DEGRADED` si no falla. Mismo principio que `NC1`/`NC2` en la sonda de mutación.

Y el límite estructural: refuto es un hook **previo** a una herramienta que ejecuta **otro
proceso**; no abre el fichero. Puede vincular la decisión a una identidad de objeto y **detectar**
la sustitución después, no impedirla. `R-04` es `DEGRADED` en el mejor caso alcanzable.

---

## Autocrítica sobre las pruebas de reproducción

De las nueve pruebas escritas en la fase anterior, sólo cuatro son reproducciones:

| clase | n | qué son |
|---|---:|---|
| REPRODUCCIÓN | 4 | ejecutan el ataque por el motor real y miden la respuesta |
| ESPECIFICACIÓN | 4 | no reproducen nada: exigen un campo que aún no existe |
| REPRODUCCIÓN DÉBIL | 1 | `G5` busca un `kind` inexistente: añadir el evento sin implementar la detección la haría pasar |

Las cuatro `ESPECIFICACIÓN` son legítimas como contrato de diseño y **no son evidencia de
defecto**. `G5` debe reescribirse para aserta sobre el efecto observado antes de usarse como
criterio de aceptación.

## Retractación

En informes previos afirmé que «el ancla existe (`refuto evidence --anchor`) y nadie la publica».
Es falso: repetí el docstring sin verificarlo contra el CLI. Es el error exacto que esta auditoría
persigue, cometido al auditarla.
