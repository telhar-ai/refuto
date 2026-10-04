# Cuatro puertas dicen `BLOCKED` cuando lo que hay es un ámbito vacío

**Medido el 2026-09-23** sobre la evidencia real de la corrida de CI `35803449286`, trabajo
«Puertas sobre el espacio de ejemplo», ejecutor `ubuntu-latest` sin agentes instalados.

> **`gates/**` está denegado por política para el agente que escribe esto.** El cambio se
> propone con el bloque exacto y **para** aquí, como manda `AGENTS.md`. Aplicarlo es de una
> persona. Esa separación es el punto entero del sistema: un agente que edita lo que lo evalúa
> no está aprobando, está moviendo la puerta.

## Lo medido

```sh
gh run download 35803449286 -n evidencia -D /tmp/ev
python3 scripts/gate_summary.py /tmp/ev/refuto-run.json
```

```
reparto: {'BLOCKED': 7, 'NOT_APPLICABLE': 2, 'PASS': 4}
NO INTEGRABLE TODAVÍA — hay puertas que no se pudieron comprobar
```

De los siete `BLOCKED`, **cuatro declaran en su propia medida que no hay sujeto**:

| puerta | medida que emite | lo que realmente dice |
|---|---|---|
| `G-AGENT` | «el manifiesto no declara ningún agente requerido: **no hay nada que exigir**» | ámbito vacío |
| `G-FLEET` | «el manifiesto no declara orígenes que materializar: **nada que comprobar**» | ámbito vacío |
| `G-TRACE` | «no se encontró ningún documento de requisitos: **no hay cadena que comprobar**» | ámbito vacío |
| `G-PR` | «este espacio **no es un repositorio git**: no hay cambio que revisar» | ámbito vacío |

Los otros tres sí son `BLOCKED` legítimos y deben quedarse como están:

| puerta | por qué SÍ es BLOCKED |
|---|---|
| `G-SECURITY` | «herramientas: ninguna» — hay árbol que escanear y no hay escáner. No poder comprobar. |
| `G-LOCK` | falta `harness.lock.json`: el espacio no declara con qué origen se materializó. |
| `G-HUMAN` | 5 revisiones exigidas, 0 decididas. La ausencia de decisión humana debe permanecer observable. |

## Por qué importa, y por qué no es cosmético

`BLOCKED` significa **«no se pudo comprobar»**. `NOT_APPLICABLE` significa **«no hay nada que
comprobar aquí»**. Son epistemológicamente distintos y tienen consecuencias distintas:

- `BLOCKED` manda a quien lo recibe a **buscar la causa y desbloquearla**. En estos cuatro casos
  no hay nada que desbloquear: el espacio simplemente no tiene ese sujeto.
- `BLOCKED` llena de amarillo cualquier espacio normal, y un aviso que sale siempre se deja de
  leer. **ADR-0005** ya lo dice en su columna «qué la haría
  cambiar»: *«ya está cambiando: faltan `NOT_RUN`, `INCONCLUSIVE` y `NOT_APPLICABLE`, que hoy
  se dicen todos con `BLOCKED`»*. Esto es esa predicción, medida.
- `G-SDD` **ya fue corregida** exactamente así (`gates/g_sdd.py:119` devuelve `NOT_APPLICABLE`
  con motivo, y su docstring explica que antes devolvía `BLOCKED` y «llenaba de amarillo
  cualquier espacio normal»). Las otras cuatro se quedaron atrás.

## El invariante que NO se debe romper al aplicarlo

`core/model.py::Result.__post_init__` **ya exige** que todo `NOT_APPLICABLE` traiga `measure`
no vacío, y la mutación `M2` de `scripts/mutate_probe.py` lo sujeta con su testigo
`test_no_aplica_exige_motivo_declarado`. Así que el cambio no puede degenerar en un
«no aplica» mudo: si alguien lo intenta, el constructor levanta `ValueError`.

**Ámbito vacío nunca aprueba.** `NOT_APPLICABLE` no es `PASS` y `verdict_of` no lo cuenta como
tal — lo fija `test_no_aplica_no_retiene_pero_tampoco_aprueba`
(`tests/contract/test_result_contract.py:33`), y `NON_PASSING` lo incluye explícitamente (línea 28).

## El bloque, puerta por puerta

El patrón es el mismo en las cuatro, y es el que ya usa `g_sdd.py`: **antes** de intentar
medir, comprobar si hay sujeto; si no lo hay, devolver `NOT_APPLICABLE` con el motivo escrito.

```python
# gates/g_agent.py — donde hoy devuelve BLOCKED por «no declara ningún agente requerido»
if not requeridos:
    return Result(
        GATE_ID, TITLE, NOT_APPLICABLE, severity=INFO, threshold=THRESHOLD,
        measure="el manifiesto de este espacio no declara ningún agente requerido en "
                "`agents`: no hay sujeto que sondear. No es un fallo ni un bloqueo — es que "
                "la puerta no tiene a quién examinar aquí. Declare los agentes que este "
                "espacio necesita para que esta puerta tenga algo que exigir.")
```

```python
# gates/g_fleet.py — donde hoy devuelve BLOCKED por «no declara orígenes que materializar»
if not origenes:
    return Result(
        GATE_ID, TITLE, NOT_APPLICABLE, severity=INFO, threshold=THRESHOLD,
        measure="el manifiesto no declara ningún origen en `sources`: no hay flota "
                "materializada cuya deriva medir. Sin sujeto no hay deriva posible.")
```

```python
# gates/g_trace.py — donde hoy devuelve BLOCKED por «no se encontró ningún documento de requisitos»
if not documentos:
    return Result(
        GATE_ID, TITLE, NOT_APPLICABLE, severity=INFO, threshold=THRESHOLD,
        measure="no hay ningún documento de requisitos en este espacio: no existe cadena "
                "INTENCIÓN→REQUISITO→…→EVIDENCIA que recorrer. Un espacio sin requisitos "
                "escritos no tiene trazabilidad que incumplir.")
```

```python
# gates/g_pr.py — donde hoy devuelve BLOCKED por «no es un repositorio git»
if not es_repo_git:
    return Result(
        GATE_ID, TITLE, NOT_APPLICABLE, severity=INFO, threshold=THRESHOLD,
        measure="este espacio no es un repositorio git: no hay rama, ni commits, ni cambio "
                "que constituya una unidad de revisión. La puerta no tiene sujeto.")
```

**Las rutas y nombres de variable de arriba son ilustrativos**: quien lo aplique debe leer cada
fichero y colocar la comprobación donde hoy se construye el `BLOCKED`, conservando el `measure`
que ya está escrito y que ya describe correctamente la situación.

## Qué hay que probar después de aplicarlo

Cada puerta tiene cuatro casos de auto-prueba en `tests/selftest/test_gates.py`. El caso
«dependencia ausente» de estas cuatro espera hoy `BLOCKED`; pasará a exigir `NOT_APPLICABLE`
**con motivo no vacío**, igual que `TestGateSdd`. Y hace falta el caso simétrico, que es el
que impide que esto se convierta en una excusa:

```python
def test_con_sujeto_la_puerta_SI_aplica(self):
    """En cuanto hay un agente declarado, la puerta ya no puede escurrirse por NOT_APPLICABLE."""
    ...
    self.assertNotEqual(NOT_APPLICABLE, r.status,
                        f"con sujeto declarado no puede declararse fuera de ámbito: {r.measure}")
```

## Lo que este documento NO afirma

- Que aplicarlo ponga CI en verde. **No lo hará**, y no debe: quedarían `G-SECURITY`
  (sin escáneres en el ejecutor), `G-LOCK` y `G-HUMAN`, que son `BLOCKED` legítimos. El
  trabajo «espacio» seguirá saliendo con 2, que es lo correcto — `BLOCKED` no es aprobado.
- Que las cuatro sean el único caso. Se midieron **estas** en **este** espacio de ejemplo. Otro
  espacio puede exponer más.
