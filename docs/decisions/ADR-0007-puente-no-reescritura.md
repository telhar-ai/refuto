# ADR-0007 · Las puertas del verificador externo se envuelven, no se reescriben

**Estado:** aceptado · **Fecha:** 2026-08-27

## Contexto

El conjunto auditado el 2026-08-27 incluía un verificador propio con once puertas de verificación en Python (`V0`–`V9`, `VC`) con
contrato de resultado único, evidencia con procedencia y **un caso negativo por puerta que se
ejecuta y dispara**: 12 casos, 12 disparos, comprobado el 2026-08-27.

## Opciones

**A · Reescribirlas** al vocabulario de refuto. Simetría total. Coste: tirar el activo mejor
construido de aquel conjunto para ganar consistencia de nombres, y con él las 12 pruebas negativas
que nadie va a volver a escribir.

**B · Envolverlas** con un puente que traduzca su vocabulario.

**C · Ignorarlas** y que refuto sea otra capa más. Es como se llegó a tener tres arneses.

## Decisión

**B.** `gates/g_sdd.py` ejecuta `verificacion/verificar.py --json`, lee `evidencia/informe.json`
y traduce:

| verificador externo | refuto |
|---|---|
| `cumple` | `PASS` |
| `no cumple` | `FAIL` |
| `pendiente` | `BLOCKED` |
| `no ejecutable` | `NOT_EXECUTABLE` |

La correspondencia es **exacta** porque los dos sistemas hicieron la misma distinción de forma
independiente. Esa coincidencia es la única razón por la que el puente puede ser honesto: si
hubiera que colapsar `pendiente` en algo, el puente estaría mintiendo.

## Consecuencias

- El veredicto compuesto respeta la jerarquía del verificador: `NOT_EXECUTABLE` manda sobre `FAIL`,
  porque significa que ni siquiera se sabe cuántos fallos hay.
- Un espacio sin `verificacion/verificar.py` sale `BLOCKED` con el motivo «no aplica aquí» — no
  `FAIL`. No tener esas puertas no es incumplir. (Semánticamente es `NOT_APPLICABLE`; el tipo
  `Result` no tiene ese valor todavía: ver [`../estado-del-proyecto.md`](../estado-del-proyecto.md).)
- refuto **no** se convierte en dueño de esas puertas. Siguen viviendo donde estén, con su
  versión y su lock.
- **Límite para quien adopte esto:** el verificador que `G-SDD` envuelve **no viene en este
  repositorio**. Si su espacio no tiene uno, esta puerta no aplica y punto; no hay nada que
  instalar. El contrato que tendría que cumplir —ruta del verificador, fichero de informe, tabla
  de estados— está hoy fijado en el código y debería declararse en el manifiesto.
