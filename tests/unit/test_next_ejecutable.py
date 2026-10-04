# -*- coding: utf-8 -*-
"""Lo que refuto le dice a alguien que haga tiene que poder ejecutarse.

El defecto que estas pruebas fijan, medido el 2026-09-25
--------------------------------------------------------
Una puerta con más de seis hallazgos imprimía `… y N más (use --verbose)`. Quien lo leía
escribía lo natural:

    $ refuto verify --offline --verbose
    refuto: error: unrecognized arguments: --verbose        → salida 64

`--verbose` es una bandera GLOBAL y va antes del subcomando. El mensaje no mentía sobre la
bandera; mentía sobre la ORDEN, que es lo único que una persona puede pegar en la consola.

`core.envelope.Siguiente` ya declara esta regla para el campo `do` —«una orden ejecutable, no
una descripción… “actualice la política” no se puede ejecutar y `refuto policy reconcile
--apply` sí»— y el texto que lee una persona no estaba cubierto por nada.

Lo que se comprueba no es el TEXTO del mensaje: es que la orden que contenga la acepte el
parser real de `refuto`. Fijar la cadena obligaría a tocar la prueba cada vez que se reescriba
la frase, y una prueba que estorba se borra.
"""

from __future__ import annotations

import argparse
import contextlib
import io
import re
import unittest

from core.model import FAIL, Finding, Result
from core.report import render

#: Una orden de refuto dentro de un texto para humanos: desde `refuto` hasta el final de la
#: frase o del paréntesis que la envuelva.
_ORDEN = re.compile(r"\brefuto\s+([^\n)·]+)")


def _ordenes_de(texto: str) -> list:
    return [m.group(1).strip().rstrip(".,") for m in _ORDEN.finditer(texto)]


def _acepta(argv: list) -> tuple:
    """`(ok, motivo)`. Usa el parser REAL, no una copia — una copia diverge y deja de medir."""
    from refuto import build_parser

    parser = build_parser()
    err = io.StringIO()
    try:
        with contextlib.redirect_stderr(err), contextlib.redirect_stdout(io.StringIO()):
            parser.parse_args(argv)
    except SystemExit as exc:
        return False, f"salida {exc.code}: {err.getvalue().strip()[:160]}"
    except argparse.ArgumentError as exc:
        return False, str(exc)
    return True, ""


def _resultado_con_muchos_hallazgos() -> Result:
    return Result("G-PRUEBA", "Puerta de prueba", FAIL,
                  threshold="umbral de prueba", measure="12 sujetos · 12 hallazgos",
                  findings=[Finding(f"fichero_{i}.py", f"hallazgo {i}", i) for i in range(12)])


class TestElConsejoDeLaPuertaSeEjecuta(unittest.TestCase):
    def test_la_orden_que_imprime_el_resumen_la_acepta_el_parser(self):
        texto = render([_resultado_con_muchos_hallazgos()], "NO INTEGRABLE")
        ordenes = _ordenes_de(texto)
        self.assertTrue(ordenes, f"el resumen recorta hallazgos y no dice cómo verlos:\n{texto}")
        for orden in ordenes:
            with self.subTest(orden=orden):
                ok, motivo = _acepta(orden.split())
                self.assertTrue(ok, f"refuto imprime «refuto {orden}» y su propio parser la "
                                    f"rechaza ({motivo}). Un consejo que no se puede pegar en "
                                    f"la consola manda a quien lo lee a adivinar")

    def test_el_recorte_sigue_ocurriendo_o_la_prueba_no_mide_nada(self):
        """Control negativo: si `render` dejara de recortar, lo de arriba pasaría vacío."""
        texto = render([_resultado_con_muchos_hallazgos()], "NO INTEGRABLE")
        self.assertIn("y 6 más", texto)

    def test_con_verbose_no_recorta_y_no_aconseja_nada(self):
        texto = render([_resultado_con_muchos_hallazgos()], "NO INTEGRABLE", verbose=True)
        self.assertNotIn("más (", texto, "aconseja `--verbose` a quien ya lo usó")
        self.assertIn("hallazgo 11", texto)

    def test_la_forma_que_fallaba_sigue_fallando(self):
        """El control que impide que la prueba de arriba pase por el motivo equivocado.

        Si algún día `verify` aceptara `--verbose` como bandera propia, el defecto original
        dejaría de existir y esta prueba tendría que retirarse — pero mientras no lo acepte,
        aconsejarla sería el defecto de siempre.
        """
        ok, _ = _acepta(["verify", "--offline", "--verbose"])
        if ok:
            self.skipTest("`verify` ya acepta `--verbose`: el defecto original desapareció")
        ok_global, motivo = _acepta(["--verbose", "verify", "--offline"])
        self.assertTrue(ok_global, f"la forma correcta tampoco se acepta: {motivo}")


class TestTodoNextDeLaCLIEsEjecutable(unittest.TestCase):
    """La misma regla, sobre el `do` del sobre: es contrato, no cortesía."""

    def test_los_next_del_preflight_nombran_ordenes_que_existen(self):
        import importlib.util
        import sys
        from pathlib import Path

        raiz = Path(__file__).resolve().parents[2]
        spec = importlib.util.spec_from_file_location("preflight", raiz / "scripts/preflight.py")
        pf = importlib.util.module_from_spec(spec)
        sys.modules["preflight"] = pf
        spec.loader.exec_module(pf)

        for c in pf._chequeos():                                       # noqa: SLF001
            propuesta = c.arreglo or " ".join(c.argv or ())
            argv = propuesta.split()
            # `refuto.py` tiene que ser lo que se EJECUTA, no un argumento: `bandit -r …
            # refuto.py scripts` lo nombra como fichero a analizar, y juzgarlo con el parser de
            # refuto medía otra cosa. Sólo cuenta en la posición 0 (`refuto.py …`) o en la 1
            # (`python3 refuto.py …`).
            corte = next((i for i in (0, 1) if i < len(argv)
                          and argv[i].endswith("refuto.py")), None)
            if corte is None:
                continue        # una orden de otra herramienta (`ruff`, `brew`) no la juzga esto
            argv = argv[corte + 1:]
            if not argv:
                continue
            with self.subTest(control=c.nombre):
                ok, motivo = _acepta(argv)
                self.assertTrue(ok, f"el control «{c.nombre}» propone «{propuesta}» y el parser "
                                    f"de refuto la rechaza ({motivo})")


if __name__ == "__main__":
    unittest.main()
