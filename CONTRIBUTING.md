# Contribuir

## Idioma

La prosa —documentación, comentarios, mensajes de error— está en **español**. El vocabulario
técnico establecido va en inglés (`PASS`, `commit`, `stdio`, `hook`), y también los
identificadores del código. No hay traducción al inglés; si envía una, dígalo en la propuesta para
decidir antes cómo se mantiene sincronizada.

## Las cinco reglas

**1 · Cada archivo justifica su existencia con un comportamiento concreto.** La pregunta es *¿qué
comportamiento hace posible esto?* Si no hay respuesta, el archivo sobra.

**2 · Cada restricción viene de un fallo observado.** No se añaden reglas preventivas por si
acaso: cada línea compite por atención. Si no puede citar el fallo, no la añada.

**3 · Una puerta nueva trae sus cuatro pruebas:** positivo, negativo, entrada corrupta y
dependencia ausente.

> Lo que la suite comprueba hoy, dicho con exactitud (`E2`, `tests/selftest/test_gates.py`,
> 2026-09-22): `TestSuiteCubreTodasLasPuertas` exige que **exista una clase `TestGate<Id>`** por
> cada puerta registrada. **No cuenta las pruebas ni comprueba sus tipos.** Es decir: la regla de
> los cuatro casos es una convención revisada por personas, no algo mecánico. Si quiere hacerla
> mecánica, ese cambio es bienvenido y hay que cambiar esa prueba.

**4 · Nada fuera de la biblioteca estándar.** `scripts/check_stdlib_only.py` lo comprueba.
Ejecútelo en local: la CI existe y **nunca ha corrido en verde** (`NOT_RUN`), así que no delegue
en ella.

**5 · Ninguna capacidad se declara sin evidencia.** Si no se puede sondear, va en `declared` con
evidencia `?`. La matriz lo mostrará como no verificado, y eso es correcto.

## Cómo se escribe una afirmación

Toda afirmación que entre en la documentación lleva **nivel de evidencia**, y toda cifra lleva
**comando, fecha y máquina**. Sin eso no entra.

`E0` dicho · `E1` documentado o leído en el código · `E2` reproducible con un comando · `E3`
probado por la suite · `E4` observado en ejecución, fechado.

Estados permitidos para una comprobación: `PASS` `FAIL` `BLOCKED` `NOT_RUN` `INCONCLUSIVE`
`NOT_APPLICABLE`. «Pendiente» no es un estado; `NOT_RUN` sí. Y un ámbito vacío **nunca** aprueba:
una comprobación que no encontró nada que comprobar queda `NOT_RUN` o `NOT_APPLICABLE` con motivo,
no `PASS`.

Lo que no se acepta: superlativos, afirmaciones de novedad sin arte previo citado, y verbos como
«garantiza» donde lo medido es «se observó una vez».

## Añadir una puerta

```python
# gates/g_ejemplo.py
GATE_ID, TITLE = "G-EJEMPLO", "Qué comprueba, dicho en una línea"
THRESHOLD = "el umbral exacto, con el número"

def run(ctx) -> Result:
    if <falta la dependencia>:
        return Result(GATE_ID, TITLE, BLOCKED, measure="qué falta y cómo conseguirlo")
    ...
    return Result(GATE_ID, TITLE, PASS if not findings else FAIL, ...)
```

Regístrela en `gates/base.py`, decláre­la en el manifiesto, y escriba su clase `TestGateEjemplo`.

**Nunca** devuelva `PASS` cuando no pudo comprobar. Es la única regla que no admite matices — y
hay dos sitios del árbol donde todavía se viola, listados en
[`docs/estado-del-proyecto.md`](docs/estado-del-proyecto.md). Arreglarlos es trabajo bienvenido.

## Añadir un adapter

Ver [`OPERATIONS.md`](OPERATIONS.md). El contrato se comprueba solo:

```bash
python3 refuto.py selftest --suite contract
```

Incluye una prueba que impide la mentira cómoda: un adapter que no soporta política **no puede**
devolver `unenforceable: []`.

Y tenga presente qué **no** le da un adapter: sondeo y compilación de política, sí; sesión
gobernada y guardián enganchado, no. Esos son verbos distintos, con código distinto
(`chat --agent`, `core/guard.py`, `policy wire`). La tabla de capacidades del
[`README.md`](README.md) existe para que nadie los confunda.

## Estilo

Los comentarios explican **por qué**, no qué: el qué está en el código. Los comentarios largos de
este repositorio no son adorno: cada uno de los que empieza con «la primera versión de esto…»
documenta un defecto que costó una depuración, y existe para que no se repita.

## Antes de proponer un cambio

```bash
python3 scripts/check_stdlib_only.py
python3 scripts/check_schemas.py
python3 scripts/check_wiring.py
python3 refuto.py --verbose selftest      # --verbose va ANTES del subcomando
```

Y diga en la propuesta **con qué intérprete y en qué sistema** los ejecutó. Hoy sólo hay medición
en macOS arm64; Linux y Windows están en `NOT_RUN` y una ejecución suya ahí es información
valiosa, aunque salga en rojo.
