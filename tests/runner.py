# -*- coding: utf-8 -*-
"""Ejecutor de las suites. `unittest` de la biblioteca estándar: nada que instalar.

    python3 refuto.py selftest
    python3 refuto.py selftest --suite adversarial --verbose
"""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SUITES = ("unit", "contract", "selftest", "adversarial")


def run_suites(only: list | None = None, verbose: bool = False) -> int:
    """Corre las suites pedidas. Devuelve 0 sólo si se ejecutó algo y todo pasó.

    Ámbito vacío no aprueba
    -----------------------
    Esto devolvía 0 cuando `bad == 0`, sin mirar `total`. Así, `selftest --suite zzz`
    —una suite que no existe— imprimía `NO TESTS RAN`, `0/0 pruebas pasan` y salía con **0**:
    un aprobado vacuo dentro del programa cuyo propósito declarado es impedirlos. En CI, una
    suite renombrada dejaba el trabajo en verde sin ejecutar una sola prueba.

    Un nombre de suite que no existe se declara aparte de «la suite existe y está vacía»:
    son dos errores distintos y se arreglan distinto.
    """
    sys.path.insert(0, str(ROOT))
    names = [s for s in SUITES if not only or s in only]
    desconocidas = [s for s in (only or []) if s not in SUITES]
    if desconocidas:
        print(f"\n  suite desconocida: {', '.join(desconocidas)}. "
              f"Las que hay: {', '.join(SUITES)}.")
        return 1
    loader = unittest.TestLoader()
    master = unittest.TestSuite()
    for name in names:
        directory = ROOT / "tests" / name
        if not directory.is_dir():
            continue
        master.addTests(loader.discover(str(directory), pattern="test_*.py",
                                        top_level_dir=str(ROOT)))
    runner = unittest.TextTestRunner(verbosity=2 if verbose else 1, stream=sys.stdout)
    result = runner.run(master)
    total = result.testsRun
    malas, motivos = veredicto(result)
    print(f"\n  {total - malas}/{total} pruebas pasan · suites: "
          f"{', '.join(names) or '(ninguna)'}")
    if total == 0:
        print("  0 pruebas ejecutadas. Eso NO es un aprobado: es que no se comprobó nada. "
              "Revise el nombre de la suite o el patrón de descubrimiento.")
        return 1
    for m in motivos:
        print(f"  {m}")
    return 0 if malas == 0 else 1


def veredicto(result) -> tuple[int, list]:
    """Cuántas pruebas dejan la corrida en rojo, y por qué. Función aparte para poder
    probarla con un `TestResult` fabricado, sin montar una suite entera.

    El tercer cubo, y por qué faltaba
    ---------------------------------
    Esto contaba `failures + errors` y nada más. `unittest` tiene un tercer cubo que también
    invalida la corrida y que `wasSuccessful()` sí consulta: **`unexpectedSuccesses`**.

    Cuándo aparece. Alguien marca una prueba `@unittest.expectedFailure` para mantener
    VISIBLE un defecto conocido sin romper la cadena — es la única forma honesta de no
    perder la constancia de algo que no se puede arreglar todavía. El día que el defecto se
    corrige, esa prueba pasa, y `unittest` lo llama `unexpectedSuccess` precisamente porque
    es información: el decorador sobra.

    Con el recuento viejo, ese día no pasaba nada. La corrida salía verde, el decorador se
    quedaba puesto para siempre, y a partir de ahí esa prueba **no comprobaba nada**: pasara
    o fallara, el resultado era el mismo. El mecanismo que existe para no perder de vista un
    defecto se quedaba mudo justo cuando el defecto se arreglaba.

    Medido el 2026-09-23. Encontrado en otro espacio con la misma forma de recuento y
    verificado aquí: `bad = len(result.failures) + len(result.errors)` — el tercer cubo no
    estaba.
    """
    fallos = len(result.failures)
    errores = len(result.errors)
    inesperadas = len(getattr(result, "unexpectedSuccesses", []) or [])
    motivos = []
    if fallos or errores:
        motivos.append(f"{fallos + errores} fallan. Un juez que no se prueba a sí mismo deja "
                       f"de ser un juez.")
    if inesperadas:
        nombres = ", ".join(str(t).split(" ")[0]
                            for t in result.unexpectedSuccesses[:4])
        motivos.append(
            f"{inesperadas} pasaron estando marcadas `@expectedFailure`: {nombres}. "
            f"Eso NO es una buena noticia silenciosa — es que el defecto que documentaban "
            f"se arregló y el decorador sobra. Retírelo, o la prueba deja de comprobar nada.")
    return fallos + errores + inesperadas, motivos
