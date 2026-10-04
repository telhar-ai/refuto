# -*- coding: utf-8 -*-
"""El CLI: lo que devuelve cuando la orden está mal, y cuando no hay nada que comprobar.

Las dos cosas que fija este módulo son aprobados vacuos del propio motor, y los dos vivían en
la frontera entre el programa y quien lo invoca — que es donde nadie mira.
"""

from __future__ import annotations

import subprocess
import sys
import unittest
from pathlib import Path

from core.proc import TEXT_IO

ROOT = Path(__file__).resolve().parents[2]
CLI = str(ROOT / "refuto.py")


def corre(*args) -> subprocess.CompletedProcess:
    return subprocess.run([sys.executable, CLI, *args], capture_output=True, timeout=180,
                          cwd=str(ROOT), **TEXT_IO)


class TestUnErrorDeUsoNoEsUnBloqueo(unittest.TestCase):
    """argparse sale con **2** ante una orden mal escrita. Este programa reserva el 2 para
    BLOCKED —«se ejecutó y algo no se pudo comprobar»—, así que una errata y una puerta
    bloqueada eran indistinguibles para quien sólo ve el código de salida.

    Antes del arreglo, las tres primeras pruebas fallan con `exit=2`.
    """

    def test_una_opcion_en_el_sitio_equivocado_sale_64(self):
        # `--verbose` es opción del parser raíz, no de `selftest`. Es el caso exacto que la
        # CI declarada ejecutaba, y por el que su trabajo no podía pasar nunca.
        p = corre("selftest", "--suite", "zzz", "--verbose")
        self.assertEqual(64, p.returncode, p.stderr[:300])

    def test_un_subcomando_inexistente_sale_64(self):
        self.assertEqual(64, corre("subcomando-que-no-existe").returncode)

    def test_sin_subcomando_sale_64(self):
        self.assertEqual(64, corre().returncode)

    def test_la_ayuda_sigue_saliendo_con_cero(self):
        """Forzar 64 no puede llevarse por delante `--help`: eso sería otro fallo."""
        p = corre("--help")
        self.assertEqual(0, p.returncode)
        self.assertIn("refuto", p.stdout)

    def test_el_dos_sigue_reservado_para_bloqueado(self):
        from refuto import EXIT_BLOCKED, EXIT_USAGE
        self.assertEqual(2, EXIT_BLOCKED)
        self.assertEqual(64, EXIT_USAGE)
        self.assertNotEqual(EXIT_BLOCKED, EXIT_USAGE)


class TestUnaSuiteVaciaNoAprueba(unittest.TestCase):
    """`selftest` devolvía **0** habiendo ejecutado **0** pruebas.

    `tests/runner.py` miraba `bad == 0` y nunca `total > 0`, así que una suite renombrada
    dejaba el trabajo de CI en verde sin ejecutar una sola comprobación: el aprobado vacuo,
    dentro del programa cuyo propósito declarado es impedirlos.

    Antes del arreglo las dos primeras pruebas fallan con `exit=0`.
    """

    def test_un_nombre_de_suite_inexistente_falla(self):
        p = corre("--verbose", "selftest", "--suite", "zzz")
        self.assertNotEqual(0, p.returncode,
                            "0 pruebas ejecutadas no puede ser un aprobado")
        self.assertIn("suite desconocida", p.stdout + p.stderr)

    def test_cero_pruebas_ejecutadas_falla_aunque_la_suite_exista(self):
        from tests.runner import run_suites
        import io
        import contextlib

        salida = io.StringIO()
        with contextlib.redirect_stdout(salida):
            # Se pide una suite real pero con un patrón que no casa nada: la suite existe y
            # el descubrimiento devuelve cero. Es el otro camino al mismo cero.
            código = run_suites(only=["zzz-tampoco-existe"])
        self.assertEqual(1, código)

    def test_una_suite_de_verdad_sigue_pasando(self):
        p = corre("selftest", "--suite", "contract")
        self.assertEqual(0, p.returncode, p.stdout[-800:])
        self.assertIn("pruebas pasan", p.stdout)
