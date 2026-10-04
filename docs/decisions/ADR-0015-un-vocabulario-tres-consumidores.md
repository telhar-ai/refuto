# ADR-0015 — Un vocabulario, tres consumidores

```yaml
decision: toda orden emite `harness.envelope/v1`; el código de salida lo deriva el estado y un
          estado que no aprueba está obligado a declarar qué toca después
date: 2026-09-24
status: IMPLEMENTADA (parcial — 7 de 24 órdenes migradas) · 656/656 pruebas pasan
refina: ADR-0005 (cuatro estados, hoy seis), ADR-0009 (canonical run and event model)
question: >
  refuto habla bien a las personas. ¿Qué forma tiene que tener su salida para que una máquina y
  un agente puedan actuar sobre ella sin adivinar, sin romper a quien ya la consume, y sin
  mantener dos formatos?
```

## Contexto — lo medido, no lo recordado

Medido el 2026-09-24 sobre el árbol de trabajo:

| | |
|---|---|
| `--json` presente en | **11 de 24** órdenes |
| contratos `harness.*/vN` que el código emite | **20** |
| publicados en `schemas/` | **3** |
| helper común de emisión | **ninguno** — 20 `json.dumps` en línea |
| separación stdout/stderr | correcta |
| `refuto context --json` | salida válida en stdout y **exit 2** |

Dos hechos, y el segundo explica el primero. Veinte formas distintas no son un protocolo: son
veinte protocolos, ninguno descubrible ni validable. Y la causa no es descuido, es estructura —
sin un sitio donde emitir, no hay dónde imponer una forma.

El código de salida era el defecto más caro de los dos, porque es invisible desde la cara que sí
funciona: una persona lee el texto y no mira el código. En CI, `refuto context --json && …` no
encadena nunca. Para un agente, el resultado correcto es indistinguible de un fallo del arnés.

Había además un cimiento fuerte sin aprovechar: `Result` con seis estados
(`PASS FAIL BLOCKED NOT_EXECUTABLE NOT_APPLICABLE INCONCLUSIVE`), probado en
`tests/contract/test_result_contract.py`. Lo usaban las puertas y nadie más.

## Decisión

1. **Se unifica el SOBRE, no la carga útil.** `harness.envelope/v1` lleva `command`, `status`,
   `exit`, `workspace`, `run_id`, `generated_at`, `provenance`, `payload` y `next`. Cada orden
   sigue emitiendo su contrato **intacto** bajo `payload`. Unificar los veinte habría sido
   reescribir veinte formatos a la vez y perder lo que cada uno tiene de más.
2. **El código de salida lo deriva el estado.** Tabla en `core.envelope._EXIT_POR_ESTADO`, y el
   módulo **no se importa** si un estado se queda sin código — misma idea que
   `core.refinement.REGLAS` con la monotonía. Ninguna orden vuelve a elegir un número a mano.
3. **`next[]` es contrato.** Un estado en `EXIGEN_SIGUIENTE` sin un solo `next` levanta
   `ValueError` **en la orden que lo cometió**, no en el emisor. Cada paso declara `why`, un `do`
   **ejecutable** y `who` ∈ `persona | maquina | agente`.
4. **Con `--json`, stdout lleva sólo el sobre.** `main()` captura la salida humana y la reencamina
   a stderr.

### Por qué `next` y no sólo un formato

Es la lección más cara del repositorio, y viene medida. Un agente al que se denegó su directorio
de entregables —porque el nombre colisionaba con uno reservado— se llevó 9,2 GB y 197 ficheros a
`/tmp`, fuera de git y en una ruta que el sistema borra a los tres días. Nadie se lo pidió y
ninguna regla se lo sugirió: simplemente no había ninguna indicación de cuál era la salida.

Un control que deniega sin nombrar la alternativa no protege, **desvía** — y adonde desvía no lo
elige quien escribió la regla. Por eso no se puede expresar un «esto está mal» sin decir qué se
hace con ello. La restricción es del tipo, no del estilo de quien escribe la orden.

### Por qué los turnos son tres y la distinción es operativa

`maquina` significa **idempotente y sin decisión**: automatizable en CI sin que nadie mire.
`persona` significa que hay un juicio que el arnés no puede emitir — aceptar un riesgo residual,
anclar un origen, aprobar una especificación. `agente` es trabajo que un agente de código puede
hacer y alguien revisará.

Marcar de `persona` lo que es de `maquina` cuesta fricción. Marcar de `maquina` lo que es de
`persona` cuesta una aprobación que nadie dio, que es de lo que este programa existe para
proteger. La asimetría no es estética: decide hacia qué lado se equivoca el sistema.

## Alternativas consideradas

**Exponer refuto como servidor MCP** para que un agente lo invoque como herramientas. Es la cara
de AI más directa y `core/mcp.py` ya habla el protocolo *como cliente*. **Rechazada como primer
paso, no como destino**: construirla sobre veinte formas ad hoc congelaría la inconsistencia en
un `tools/list`. Con el sobre en pie, el servidor es una proyección mecánica.

**`--for=human|machine|agent`.** Tres modos de salida por orden. Rechazada: multiplica por tres la
superficie que hay que probar y las tres caras no necesitan datos distintos, sino el mismo dato
con distinta presentación. La presentación ya la resuelve el TTY.

**Guardar `if not opts.json:` en cada `print`.** Son cientos de guardas y la que se olvide rompe
el protocolo **en silencio**, que es la peor clase de rotura. La captura en `main()` lo resuelve
en un sitio y además no pierde el texto humano.

**Hacer del sobre una bandera nueva** (`--envelope`) y dejar `--json` como estaba. Rechazada: dos
formatos de máquina es exactamente lo que este ADR existe para no tener. El coste se paga una vez,
con `payload_of` como puente.

## Tradeoff aceptado

**La tabla estado→código es gruesa y se declara.** Seis estados no caben en cuatro códigos sin
colapsar alguno: `PASS` y `NOT_APPLICABLE` comparten el 0. No contradice «un ámbito vacío nunca
aprueba» —esa regla gobierna el veredicto de una PUERTA, donde `run_all` trata `NOT_APPLICABLE`
aparte—; aquí se responde «¿hay algo que arreglar?», y mapearlo a 1 haría fallar el CI de todo
espacio que legítimamente no declara MCP. Quien necesite la distinción **lee `status`**. Esa frase
es parte del contrato, no una disculpa.

**La migración es parcial y visible.** 7 de 24 órdenes migradas. Una orden sin migrar se comporta
exactamente como antes, incluido el JSON que ya emitía. Se prefiere una migración orden a orden,
con la suite verde en cada paso, a un cambio masivo sobre veinte formatos que nadie puede revisar.

**Cambia la forma de `--json` en las órdenes migradas.** `verify` y `probe` tenían consumidores
reales (`scripts/gate_summary.py`, `scripts/check_probe_honesty.py`, leídos por
`.github/workflows/refuto.yml`) y se migraron en el mismo commit vía `payload_of`, que acepta las
dos formas. Un consumidor externo migra con un acceso: `["payload"]`.

## Verificación — qué prueba que esto funcionó

```sh
python3 refuto.py selftest                              # 656/656 · 2026-09-24
python3 -m unittest tests.contract.test_envelope_contract
python3 scripts/check_schemas.py                        # envelope.schema.json en el subconjunto
```

- `tests/contract/test_envelope_contract.py` (20 pruebas): la proyección es total, un estado
  inventado no tiene código por omisión, un estado que no aprueba exige `next` **y** con `next` se
  acepta (la contraparte, sin la cual la primera se satisface rechazando todo sobre), los sobres
  reales validan contra el esquema publicado **y** el validador no está mudo.
- Los códigos de salida de `verify` se conservan exactamente (1, 2, 2, 0), comprobado en
  `tests/selftest/test_gates.py`.
- Contrastado de punta a punta: `doctor --json` y `verify --json` emiten stdout parseable que
  valida contra `schemas/envelope.schema.json`, con el texto humano íntegro en stderr.
