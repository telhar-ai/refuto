# ADR-0012 — Cuatro cosas distintas no pueden llamarse igual

```yaml
decision: identidad tipada y correlación explícita entre ejecuciones
date: 2026-09-22
status: PROPUESTA — implementación NOT_RUN
refina: ADR-0009 (canonical run and event model)
question: >
  ¿Cómo se resuelve que cuatro entidades con ciclos de vida distintos se identifiquen con
  el mismo formato `run_<hex16>` y no se puedan enlazar entre sí?
```

> **Nota de numeración.** Este ADR nació como `docs/adr/ADR-0001` en una sesión que no
> comprobó el índice existente. Era una colisión: `ADR-0001` ya era
> [protocolos-de-facto](ADR-0001-protocolos-de-facto.md), citado desde `core/acp.py:9`. Se
> renumeró a 0012 y `docs/adr/` se eliminó. El namespace canónico es `docs/decisions/`.

## Relación con ADR-0009

ADR-0009 decide *que* debe haber un modelo canónico de corrida y eventos. Este ADR **no lo
sustituye**: aporta el diagnóstico medido que ADR-0009 no tiene y que su implementación
necesita — cuántos acuñadores hay, dónde aterriza cada uno y cuántos enlaces existen.

Una divergencia que hay que resolver al implementar: ADR-0009 declara el formato
`run-20260922-152000-a1b2c3d4`; el código emite `run_<hex16>` (`core/model.py::new_run_id`). Medido el
2026-09-22: **ninguno** de los ocho identificadores que ADR-0009 declara (`CanonicalEvent`,
`git_tree_hash`, `policy_hash`, `seq`, …) aparece en el árbol. ADR-0009 describe un destino,
no un estado.

## Contexto — lo medido, no lo recordado

`core/model.py::new_run_id` define **un** generador:

```python
def new_run_id() -> str:
    return f"run_{uuid.uuid4().hex[:16]}"
```

y lo llaman **cuatro** sitios, cada uno para una entidad distinta que aterriza en un almacén
distinto:

| # | acuñador | entidad | almacén | enlaces salientes |
|---|---|---|---|---|
| 1 | `core/run.py::plan` | ejecución orquestada | `.harness/state/run_<id>.json` | `context_run_id` |
| 2 | `core/session.py::plan` | sesión interactiva | eventos `session/*` del ledger | ninguno |
| 3 | `core/runcontext.py::build` | contexto construido | `.harness/context/` | ninguno |
| 4 | `refuto.py::cmd_verify` | verificación | `.harness/evidence/<id>.json` | ninguno |

De seis enlaces posibles entre las cuatro, existe **uno**.

### Los síntomas, que ya se habían visto sin diagnosticar

- `refuto status` dice «no hay ninguna ejecución registrada» inmediatamente después de un
  `refuto verify` que imprimió la ruta de su evidencia. Ninguno de los dos miente: `status` lee
  la familia 1 y `verify` escribe la familia 4.
- El vocabulario de eventos lleva **dos** terminales, `run/finish` (familia 1) y `run/complete`
  (familia 4), que un lector razonable toma por sinónimos.
- Una sesión (familia 2) no se puede atar a las verificaciones que ocurrieron dentro de ella.
  La pregunta «¿qué verificó esta sesión?» no tiene respuesta mecánica.

### Por qué esto no es cosmético

§14 exige poder reconstruir `claim → verdict → gate → rule → observation → event → artifact →
command → environment`. La cadena se corta en el primer salto: un veredicto de la familia 4 no
sabe en qué sesión ocurrió ni qué ejecución lo pidió. **Un identificador que no distingue no
identifica.**

## Alternativas consideradas

### A · Un solo `run_id` para todo

Fusionar las cuatro en una. **Rechazada por medición, no por gusto:** los ciclos de vida no
coinciden. Una sesión contiene N verificaciones; una verificación puede ocurrir sin sesión
(`refuto verify` en CI); un contexto se reconstruye sin que haya ejecución. Forzar una sola
identidad obligaría a inventar una ejecución sintética cada vez que falte — y una entidad
inventada para cuadrar un modelo es exactamente el dato falso que este sistema persigue.

### B · Renombrar los ficheros por familia

`state/orch_*.json`, `evidence/ver_*.json`. Resuelve la ambigüedad **en el disco** pero no la
cadena: seguirían sin enlazarse. Además rompe a cualquier lector externo de `run_*.json` sin
darle nada a cambio. Insuficiente por sí sola.

### C · Identidad tipada + bloque de correlación  ← **ELEGIDA**

Dos cambios, y el segundo es el que importa:

1. **Prefijo por tipo.** `ses_` sesión · `orq_` orquestación · `ver_` verificación ·
   `ctx_` contexto. El tipo deja de deducirse del directorio, que es una propiedad del
   almacenamiento y no de la entidad.
2. **Bloque `correlation` en todo artefacto y todo evento**, con los ancestros que se conozcan:

   ```json
   "correlation": {
     "session_id": "ses_…",   // o "" si no hubo sesión — y "" significa «no hubo»,
     "orchestration_id": "orq_…",  // no «no lo sé»
     "context_id": "ctx_…",
     "parent_id": ""          // §21: subagente → padre
   }
   ```

Un campo ausente y un campo vacío no son lo mismo y el esquema lo distingue: ausente es «esta
versión no lo escribía», vacío es «se comprobó y no había». Es la misma regla que ya rige en
`sesiones_vivas` y en G-MCP — no confundir ausencia de medición con medición de ausencia.

## Tradeoff aceptado

Cambiar el prefijo rompe a quien haga `glob("run_*.json")`. Se acepta **con migración**:

- los lectores (`core.run.latest`, `load`) aceptan **ambos** prefijos indefinidamente;
- los escritores emiten sólo el prefijo nuevo;
- `run_*` queda declarado como legado en el esquema, sin fecha de retirada hasta que haya
  evidencia de que nadie lo lee;
- una prueba de compatibilidad construye un `.harness/state/run_<hex>.json` con el formato
  viejo y exige que `latest()` lo encuentre. Si esa prueba se cae, la migración rompió a
  alguien.

Coste asumido: dos formatos vivos a la vez. Se prefiere a una rotura silenciosa, que es lo que
§31 prohíbe.

## Verificación — qué prueba que esto funcionó

| propiedad | prueba | estado |
|---|---|---|
| los cuatro prefijos son distinguibles sin mirar el directorio | `test_identidad::test_el_tipo_se_lee_del_id` | `NOT_RUN` |
| un artefacto viejo `run_*` sigue siendo legible | `test_identidad::test_compatibilidad_prefijo_legado` | `NOT_RUN` |
| una verificación dentro de una sesión enlaza con ella | `test_identidad::test_verify_en_sesion_correlaciona` | `NOT_RUN` |
| `correlation` ausente ≠ `correlation` vacía | `test_identidad::test_vacio_no_es_ausente` | `NOT_RUN` |
| la cadena §14 se reconstruye de veredicto a entorno | `test_identidad::test_cadena_completa` | `NOT_RUN` |

Mientras estas cinco estén en `NOT_RUN`, este ADR describe una intención, no una propiedad.
`NOT_RUN` no es `PASS`.
