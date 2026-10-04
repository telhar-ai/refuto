# ADR-0005 · Cuatro estados, y `BLOCKED` no aprueba

**Estado:** aceptado · **Fecha:** 2026-08-27

## Problema

Con dos estados, «no se pudo comprobar» tiene que ir a alguno de los dos. Si va a verde, la
puerta deja de ser una puerta en la primera semana. Si va a rojo, un espacio recién clonado sale
en rojo — y así es como la gente aprende a ignorar el rojo.

## Decisión

```
PASS            cumple
FAIL            incumple
BLOCKED         no se intentó: falta una dependencia declarada
NOT_EXECUTABLE  se intentó y la comprobación misma no pudo correr
```

Con el invariante, probado en `tests/contract/`: **ninguna transición del sistema convierte
`BLOCKED` o `NOT_EXECUTABLE` en `PASS`.**

Tres códigos de salida, no dos: `0` integrable · `1` rojo o no ejecutable · `2` bloqueado.
CI trata el `2` como fallo: en una tubería, «no se pudo comprobar» tiene que parar la
integración. Pero es un código distinto porque la acción de quien lo recibe es distinta.

> **Revisión del 2026-09-22 — dos límites de esta decisión, medidos.**
>
> 1. **Faltan estados.** El contrato del método usa `PASS FAIL BLOCKED NOT_RUN INCONCLUSIVE
>    NOT_APPLICABLE`; el tipo `Result` sólo tiene cuatro. La consecuencia se ve en `gates/g_sdd.py`,
>    que dice `BLOCKED` para expresar «aquí no aplica», y en `g_agent.py`, `g_fleet.py`,
>    `g_human.py` y `g_trace.py`, que lo dicen para «no había nada que comprobar». Tres cosas
>    distintas bajo una palabra.
> 2. **`BLOCKED` no cubre todavía el ámbito vacío.** `gates/g_mcp.py` sin ningún servidor
>    declarado devuelve **`PASS`** («nada que verificar»), y `tests/runner.py` con cero pruebas
>    ejecutadas sale con **`0`**. Los dos son aprobados vacuos, justo lo que este ADR existe para
>    impedir, y siguen abiertos. Ver [`../estado-del-proyecto.md`](../estado-del-proyecto.md).
>
> 3. **El `2` colisiona** con el que `argparse` devuelve ante un error de uso.

## Por qué esto importa más de lo que parece

Las dos veces que la propia suite de refuto encontró un defecto real en refuto fueron
casos de este tipo:

1. `core/mcp.py` se tragaba un `mcp.json` corrupto y devolvía `PASS` con el texto «nada que
   verificar». El fallo silencioso exacto que esa puerta existe para impedir, cometido por la
   puerta.
2. `--offline` saltaba también los servidores **stdio**, que son procesos locales y no necesitan
   red. En CI —que suele correr sin salida a internet— esa puerta no comprobaba nada y lo decía
   en verde.

Los dos los encontró el caso de prueba «entrada corrupta» y el caso «dependencia ausente»: los
dos casos que no salen del camino feliz, y por eso los que faltan cuando falta alguno.

## Herencia

El verificador externo sobre el que se auditó esto ya había hecho la misma distinción, con otras
palabras: `cumple`, `no cumple`, `pendiente`, `no ejecutable`. La correspondencia es exacta, y es
la única razón por la que `G-SDD` puede envolver sus puertas sin traicionarlas. Ese verificador no
forma parte de este repositorio: es un componente que el espacio aporta.
