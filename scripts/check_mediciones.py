#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Las cifras que el README declara MEDIDAS tienen que seguir dando eso.

Por qué existe, y por qué no bastaba `check_citas.py`
------------------------------------------------------
Este repositorio ya vigila dos clases de afirmación: `check_citas.py` comprueba que una cita a
código siga apuntando a lo que dice, y `check_wiring.py` que las cifras ESTRUCTURALES (13
puertas, 22 roles, 13 fases, 5 adapters) sigan siendo ciertas. Las dos funcionan: el 2026-09-25
las siete cifras estructurales del README cuadraban todas.

Lo que no tenía vigilante son las cifras de CORRIDA —cuántas pruebas hay, cuántos controles
ejecuta el preflight—, que son justamente las que el README cita como `E3` y `E4`. Medido ese
mismo día sobre `69bcd6a`:

    afirmación del README          dice              medido
    suite                          685/685           748/748
    reparto adversarial            137               200
    preflight                      13 controles      14 controles

Las tres llevan fecha `2026-09-25`. El commit que las puso al día (`bf9f061`) fue seguido de
cinco commits que añadieron 730 líneas de pruebas sin tocar la tabla. No es descuido de quien
escribió: es que una cifra que cambia con cada commit y que nadie comprueba **sólo puede
envejecer**, y este repositorio sostiene que «una cifra sin su orden, su fecha y su máquina no
es una medición». Éstas tenían orden, fecha y máquina, y eran falsas — que es peor, porque la
procedencia hace que se lean como verificadas.

Qué NO comprueba
----------------
Los tiempos (`188 s`, `368 s`). Dependen de la máquina y de la carga, así que exigir que
coincidan haría fallar el control en el portátil de cualquier otro — y un control que falla por
motivos que no son el defecto se desactiva. Se comprueban los RECUENTOS, que son propiedades
del árbol y no de quien lo ejecuta.

Y **cuántas pruebas PASAN tampoco**, que es distinto de no vigilarlo: ver abajo.

El control exigía declarar que todo pasa
----------------------------------------
Hasta el 2026-09-30 la afirmación «la suite pasa entera → `**N/M**`» se comprobaba capturando
el NUMERADOR y exigiendo que fuera igual al total que descubre el cargador. El efecto es más
grave que un patrón mal puesto: hacía **imposible declarar un fallo**. Con dos pruebas en rojo,
la única forma de dejar este control en verde era escribir `1373/1373` — una cifra falsa— y la
única forma de escribir la verdadera era dejarlo en rojo. Un vigilante que sólo acepta la
respuesta «todo bien» no vigila: presiona.

Ahora se separan las dos cosas, porque no son de la misma clase:

- el **denominador** es una propiedad del ÁRBOL. Se mide aquí y se compara.
- el **numerador** es el resultado de una CORRIDA. No se puede medir sin ejecutar la suite, y
  ejecutarla dentro de un control de segundos lo convertiría en un control que nadie corre. No
  se comprueba, y por eso se dice: lo verifica la corrida de CI, no este guion.

Lo que sí se puede exigir sin ejecutar nada es la COHERENCIA de lo declarado, y es lo que cierra
el hueco: que el numerador no pase del denominador, y que si hay fallos la tabla los declare con
un número que cuadre. Así, «1371 de 1373» obliga a escribir «2 fallan», y «1373/1373» con fallos
declarados es contradictorio y se rechaza.
"""

from __future__ import annotations

import re
import sys
import unittest
from pathlib import Path

RAIZ = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(RAIZ))

SUITES = ("unit", "contract", "selftest", "adversarial")


def _pruebas_por_suite() -> dict:
    """El recuento del CARGADOR, que es el que decide qué se ejecuta.

    No `grep -c "def test_"`: el propio README documenta que esa cuenta daba 686 contra 685
    reales porque una cadena contenía el texto. Se pregunta a quien manda.
    """
    fuera = {}
    for s in SUITES:
        fuera[s] = unittest.TestLoader().discover(
            str(RAIZ / "tests" / s), top_level_dir=str(RAIZ)).countTestCases()
    return fuera


def _controles_del_preflight() -> int:
    import importlib.util

    spec = importlib.util.spec_from_file_location("_pf", RAIZ / "scripts" / "preflight.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return len(mod._chequeos())                                       # noqa: SLF001


#: Cada afirmación: cómo se localiza en el README, qué la mide, y cómo se llama en el mensaje.
#:
#: El patrón captura UN número. Se busca en el fichero entero y no en una línea fija: anclar a
#: un número de línea convertiría cualquier edición del README en un fallo de este control, que
#: es como se enseña a ignorarlo.
COMPROBACIONES = (
    # El DENOMINADOR: cuántas pruebas hay. Propiedad del árbol, medible aquí.
    ("total de la suite", r"selftest`\s*→\s*\*\*\d+/(\d+)",
     lambda: sum(_pruebas_por_suite().values())),
    ("reparto: unit", r"\bunit (\d+) ·", lambda: _pruebas_por_suite()["unit"]),
    ("reparto: contract", r"· contract (\d+) ·", lambda: _pruebas_por_suite()["contract"]),
    ("reparto: selftest", r"· selftest (\d+) ·", lambda: _pruebas_por_suite()["selftest"]),
    ("reparto: adversarial", r"· adversarial (\d+) =",
     lambda: _pruebas_por_suite()["adversarial"]),
    ("suma del reparto", r"adversarial \d+ = \*\*(\d+)\*\*",
     lambda: sum(_pruebas_por_suite().values())),
    ("controles del preflight", r"→ \*\*PASS, (\d+) controles\*\*", _controles_del_preflight),
)


#: `**N/M**` de la fila de la suite: (pasan, total) declarados.
RE_RESULTADO = r"selftest`\s*→\s*\*\*(\d+)/(\d+)"
#: `**N fallan**`, la declaración explícita de cuántas están en rojo.
RE_FALLAN = r"\*\*(\d+) fallan\*\*"


def coherencia_del_resultado(readme: str) -> list:
    """Que lo declarado no se contradiga. No mide la corrida: mide la aritmética de la tabla.

    Es lo único de `pasan/total` que se puede exigir sin ejecutar la suite, y basta para que no
    se pueda ocultar un fallo: declarar menos pasadas que el total OBLIGA a decir cuántas fallan,
    y decir que todas pasan mientras se declaran fallos es contradictorio.
    """
    m = re.search(RE_RESULTADO, readme)
    if not m:
        return [f"«resultado de la suite»: no se encontró `pasan/total` con `{RE_RESULTADO}`. "
                f"O se reescribió la fila y hay que actualizar este control, o la afirmación "
                f"desapareció — las dos cosas las decide una persona, no este guion."]
    pasan, total = int(m.group(1)), int(m.group(2))
    mf = re.search(RE_FALLAN, readme)
    declarados = int(mf.group(1)) if mf else 0
    problemas = []
    if pasan > total:
        problemas.append(f"«resultado de la suite»: declara que pasan {pasan} de {total}, que "
                         f"son más de las que hay")
    elif pasan < total and not mf:
        problemas.append(f"«resultado de la suite»: declara {pasan} de {total} y no dice cuántas "
                         f"fallan. Un hueco de {total - pasan} sin declarar se lee como «alguna "
                         f"falla, no sé cuál»; escriba «**{total - pasan} fallan**» y cuáles")
    elif declarados != total - pasan:
        problemas.append(f"«resultado de la suite»: declara {pasan} de {total} —{total - pasan} "
                         f"en rojo— pero dice que fallan {declarados}")
    return problemas


def revisar(readme: str, comprobaciones=None, *, coherencia: bool | None = None) -> tuple:
    """`(problemas, comprobadas)` sobre un texto. La lógica, separada del fichero.

    Recibe el TEXTO y no la ruta para poder ejercitar los bordes —una afirmación que ya no está,
    una cifra que cambió— sin reescribir el README del repositorio. Un control que sólo se puede
    probar sobre su propio objeto real se prueba en el caso bueno y se supone el malo, que es
    justo el que importa.

    `coherencia` añade `coherencia_del_resultado`. Por omisión se activa sólo cuando se revisan
    las comprobaciones reales: con un juego sintético, exigir la fila de la suite haría fallar a
    quien sólo quería ejercitar un patrón.
    """
    if coherencia is None:
        coherencia = comprobaciones is None
    comprobaciones = COMPROBACIONES if comprobaciones is None else comprobaciones
    problemas, comprobadas = [], 0
    if coherencia:
        problemas.extend(coherencia_del_resultado(readme))
        comprobadas += 1
    for nombre, patron, medir in comprobaciones:
        m = re.search(patron, readme)
        if not m:
            problemas.append(
                f"«{nombre}»: no se encontró la afirmación en README.md con el patrón "
                f"`{patron}`. O se reescribió la tabla y hay que actualizar este control, o la "
                f"afirmación desapareció — las dos cosas las decide una persona, no este guion.")
            continue
        declarado, real = int(m.group(1)), medir()
        comprobadas += 1
        if declarado != real:
            problemas.append(f"«{nombre}»: el README declara {declarado} y hoy son {real}")
    return problemas, comprobadas


def main() -> int:
    if not COMPROBACIONES:
        print("  no hay ninguna afirmación que comprobar: un ámbito vacío no aprueba",
              file=sys.stderr)
        return 2

    readme = (RAIZ / "README.md").read_text(encoding="utf-8")
    problemas, comprobadas = revisar(readme)

    for p in problemas:
        print(f"  ✗ {p}", file=sys.stderr)
    if problemas:
        print(f"\n  {len(problemas)} de {len(COMPROBACIONES) + 1} mediciones del README ya no dan "
              f"eso. Vuelva a medirlas y actualice la tabla; una cifra con fecha de hoy que hoy "
              f"es falsa se lee como verificada, y eso es peor que no ponerla.", file=sys.stderr)
        return 1
    print(f"  ✓ {comprobadas} mediciones del README siguen dando lo que declaran")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
