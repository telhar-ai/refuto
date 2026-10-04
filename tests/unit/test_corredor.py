# -*- coding: utf-8 -*-
"""El corredor de la suite, medido a sí mismo.

Quien decide si refuto pasa es `tests/runner.py`. Si su recuento se equivoca, todo lo que
este repositorio afirma sobre sí mismo hereda ese error — y lo hereda en la dirección
cómoda, porque un recuento incompleto siempre cuenta de menos.

El defecto que cierran, medido el 2026-09-23
--------------------------------------------
`bad = len(result.failures) + len(result.errors)`. Falta el tercer cubo:
**`unexpectedSuccesses`**, que `wasSuccessful()` sí consulta.

Aparece cuando alguien marca una prueba `@unittest.expectedFailure` para mantener visible un
defecto conocido sin romper la cadena. El día que el defecto se corrige, la prueba pasa y
`unittest` lo llama *unexpected success* porque es información: el decorador sobra.

Con el recuento viejo ese día no pasaba nada. La corrida salía verde, el decorador se quedaba
puesto para siempre, y desde entonces esa prueba **no comprobaba nada**: pasara o fallara, el
resultado era idéntico.
"""

from __future__ import annotations

import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from core.proc import TEXT_IO
from tests.runner import veredicto

RAIZ = Path(__file__).resolve().parents[2]


class _Resultado:
    """Un `TestResult` fabricado. Sólo lo que `veredicto()` mira."""

    def __init__(self, fallos=0, errores=0, inesperadas=0):
        self.failures = [("t", "tb")] * fallos
        self.errors = [("t", "tb")] * errores
        self.unexpectedSuccesses = [f"test_x_{i} (mod.Clase)" for i in range(inesperadas)]


class TestElRecuentoCubreLosTresCubos(unittest.TestCase):

    def test_una_prueba_que_pasa_marcada_como_fallo_esperado_pone_en_rojo(self):
        """El caso que el recuento viejo dejaba pasar."""
        malas, motivos = veredicto(_Resultado(inesperadas=1))
        self.assertEqual(1, malas, "un unexpectedSuccess no contó como rojo")
        self.assertTrue(motivos, "se puso en rojo sin decir por qué")
        self.assertIn("el decorador sobra", " ".join(motivos),
                      "el motivo no dice qué hacer con ello")

    def test_coincide_con_wasSuccessful_de_unittest(self):
        """La biblioteca estándar ya tenía la respuesta; el recuento propio discrepaba.

        Se comprueba contra `wasSuccessful()` real, no contra una reimplementación: si una
        versión futura de unittest añadiera un cuarto cubo, esta prueba lo destaparía.
        """
        for fallos, errores, inesperadas in ((0, 0, 0), (1, 0, 0), (0, 1, 0), (0, 0, 1),
                                             (1, 1, 1), (2, 0, 3)):
            real = unittest.TestResult()
            real.failures = [("t", "tb")] * fallos
            real.errors = [("t", "tb")] * errores
            real.unexpectedSuccesses = ["t"] * inesperadas
            malas, _ = veredicto(real)
            self.assertEqual(
                real.wasSuccessful(), malas == 0,
                f"discrepa con wasSuccessful() en "
                f"(fallos={fallos}, errores={errores}, inesperadas={inesperadas})")

    def test_una_corrida_limpia_no_inventa_motivos(self):
        malas, motivos = veredicto(_Resultado())
        self.assertEqual(0, malas)
        self.assertEqual([], motivos, "una corrida limpia no debe imprimir motivos")

    def test_los_tres_cubos_se_suman(self):
        malas, motivos = veredicto(_Resultado(fallos=2, errores=1, inesperadas=3))
        self.assertEqual(6, malas)
        self.assertEqual(2, len(motivos), "los dos motivos deben declararse por separado")


class TestDePuntaAPunta(unittest.TestCase):
    """La comprobación cara, y la que de verdad cierra el caso: se ejecuta el corredor.

    Probar `veredicto()` en aislamiento demuestra que la función cuenta bien. No demuestra
    que el corredor la use. Esta prueba monta una suite desechable con un
    `@expectedFailure` que PASA y exige que `refuto.py selftest` salga en rojo.
    """

    def test_el_corredor_sale_en_rojo_con_un_fallo_esperado_que_pasa(self):
        with tempfile.TemporaryDirectory() as d:
            suite = Path(d) / "suite"
            (suite / "casos").mkdir(parents=True)
            (suite / "__init__.py").write_text("", encoding="utf-8", newline="\n")
            (suite / "casos" / "__init__.py").write_text("", encoding="utf-8", newline="\n")
            (suite / "casos" / "test_ok.py").write_text(
                "import unittest\n\n"
                "class C(unittest.TestCase):\n"
                "    @unittest.expectedFailure\n"
                "    def test_el_defecto_ya_no_esta(self):\n"
                "        self.assertTrue(True)   # pasa: el decorador sobra\n",
                encoding="utf-8", newline="\n")
            guion = (
                "import sys, unittest\n"
                f"sys.path.insert(0, {str(RAIZ)!r})\n"
                "from tests.runner import veredicto\n"
                f"s = unittest.defaultTestLoader.discover({str(suite / 'casos')!r}, "
                f"pattern='test_*.py', top_level_dir={str(suite)!r})\n"
                "r = unittest.TextTestRunner(verbosity=0).run(s)\n"
                "malas, motivos = veredicto(r)\n"
                "print('MALAS=%d' % malas)\n"
                "print('ACUERDO=%s' % (r.wasSuccessful() == (malas == 0)))\n"
                "sys.exit(0 if malas == 0 else 1)\n")
            p = subprocess.run([sys.executable, "-c", guion], capture_output=True,
                               cwd=str(RAIZ), **TEXT_IO)
            salida = (p.stdout or "") + (p.stderr or "")
            self.assertIn("MALAS=1", salida, salida)
            self.assertIn("ACUERDO=True", salida, salida)
            self.assertEqual(1, p.returncode,
                             "el corredor salió con 0 teniendo un fallo esperado que pasó")


if __name__ == "__main__":
    unittest.main()
