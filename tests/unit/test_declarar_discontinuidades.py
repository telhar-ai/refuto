# -*- coding: utf-8 -*-
"""El guion que declara discontinuidades: lo que se niega a hacer.

Una herramienta que escribe en `evidence/` —ruta protegida— sólo vale si es más prudente que
quien la ejecuta. Lo que se mide aquí no es que sepa escribir el fichero, sino que **no lo
escriba** cuando lo que encuentra no es lo que dice declarar:

    una huella que no reproduce su contenido  → eso es una EDICIÓN, no una carrera
    un `prev` que no existe en el diario      → el evento se ancló a algo que nunca hubo
    una línea que no es JSON                  → el diario no se lee entero
    sin `--firma`                             → una discontinuidad reconocida por nadie

El caso de tres escritores está aquí por una razón concreta: la primera versión buscaba «el
evento anterior encadena al mismo `prev`», y con eso un espacio real de 30.459 eventos daba un
falso «revisar a mano» — el tercer escritor se había anclado a la cabeza que dejó el primero.
"""

from __future__ import annotations

import json
import shutil
import subprocess  # nosec B404
import sys
import tempfile
import unittest
from pathlib import Path

from core.evidence import _eslabon, append_event, ledger_path, ruta_discontinuidades
from core.proc import TEXT_IO

RAIZ = Path(__file__).resolve().parents[2]
GUION = RAIZ / "scripts" / "declarar_discontinuidades.py"


class _Base(unittest.TestCase):
    def setUp(self):
        self.ws = Path(tempfile.mkdtemp(prefix="declarar-")).resolve()
        (self.ws / ".harness" / "evidence").mkdir(parents=True)
        for i in range(8):
            append_event(self.ws, {"kind": "policy/decision", "outcome": "allow", "n": i})

    def tearDown(self):
        shutil.rmtree(self.ws, ignore_errors=True)

    def _lineas(self) -> list:
        return ledger_path(self.ws).read_text(encoding="utf-8").splitlines()

    def _escribir(self, ls: list) -> None:
        ledger_path(self.ws).write_text("\n".join(ls) + "\n", encoding="utf-8", newline="\n")

    def _reencadenar(self, ls: list, idx: int, nuevo_prev: str) -> list:
        """Rehace la línea `idx` (0-based) sobre otro `prev`, con su huella coherente, y arrastra
        las siguientes. Es lo que produce una carrera real."""
        ev = json.loads(ls[idx])
        ev["prev"] = nuevo_prev
        ev.pop("h", None)
        ev["h"] = _eslabon(nuevo_prev, ev)
        ls[idx] = json.dumps(ev, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
        previo = ev["h"]
        for j in range(idx + 1, len(ls)):
            e = json.loads(ls[j])
            e["prev"] = previo
            e.pop("h", None)
            e["h"] = _eslabon(previo, e)
            ls[j] = json.dumps(e, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
            previo = e["h"]
        return ls

    def correr(self, *extra: str):
        return subprocess.run([sys.executable, str(GUION), str(self.ws), *extra],    # nosec B603
                              cwd=str(RAIZ), capture_output=True, timeout=120, **TEXT_IO)


class TestSeNiegaCuandoNoEsUnaCarrera(_Base):

    def test_una_huella_que_no_cuadra_no_se_declara(self):
        ls = self._lineas()
        ev = json.loads(ls[3]); ev["outcome"] = "deny"          # editado, sin recalcular `h`
        ls[3] = json.dumps(ev, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
        self._escribir(ls)
        p = self.correr("--escribir", "--firma", "prueba")
        self.assertNotEqual(0, p.returncode)
        self.assertIn("EDICION", p.stdout)
        self.assertFalse(ruta_discontinuidades(self.ws).exists())

    def test_un_prev_que_nunca_existio_no_se_declara(self):
        """El evento se ancló a algo que no está en el diario: eso no es concurrencia."""
        ls = self._reencadenar(self._lineas(), 4, "f" * 64)
        self._escribir(ls)
        p = self.correr("--escribir", "--firma", "prueba")
        self.assertNotEqual(0, p.returncode)
        self.assertIn("no es la carrera", p.stdout)
        self.assertFalse(ruta_discontinuidades(self.ws).exists())

    def test_una_linea_ilegible_no_se_declara(self):
        ls = self._lineas()
        ls[2] = "{ esto no es json"
        self._escribir(ls)
        p = self.correr("--escribir", "--firma", "prueba")
        self.assertNotEqual(0, p.returncode)
        self.assertIn("NO es JSON", p.stdout)
        self.assertFalse(ruta_discontinuidades(self.ws).exists())

    def test_sin_firma_no_escribe(self):
        ls = self._reencadenar(self._lineas(), 4, json.loads(self._lineas()[2])["h"])
        self._escribir(ls)
        p = self.correr("--escribir")
        self.assertEqual(64, p.returncode)
        self.assertIn("firma", p.stdout)
        self.assertFalse(ruta_discontinuidades(self.ws).exists())


class TestLoQueSiDeclara(_Base):

    def _carrera_de_dos(self) -> None:
        """Dos escritores sobre la misma cabeza: la línea 5 encadena a lo mismo que la 4."""
        ls = self._lineas()
        self._escribir(self._reencadenar(ls, 4, json.loads(ls[3])["prev"]))

    def _carrera_de_tres(self) -> None:
        """Tres escritores: el tercero se ancla a la cabeza que dejó el PRIMERO. Es el caso que
        la primera versión marcaba como sospechoso sin serlo."""
        ls = self._lineas()
        ls = self._reencadenar(ls, 4, json.loads(ls[3])["prev"])     # segundo, sobre la misma
        self._escribir(self._reencadenar(ls, 5, json.loads(ls[3])["h"]))   # tercero, sobre el 1º

    def test_en_seco_no_escribe_nada(self):
        self._carrera_de_dos()
        p = self.correr()
        self.assertEqual(0, p.returncode, p.stdout + p.stderr)
        self.assertIn("se escribiria", p.stdout)
        self.assertFalse(ruta_discontinuidades(self.ws).exists())

    def test_una_carrera_de_dos_se_declara_y_la_cadena_cicatriza(self):
        from core.evidence import CICATRIZADA, verificar_cadena
        self._carrera_de_dos()
        p = self.correr("--escribir", "--firma", "prueba")
        self.assertEqual(0, p.returncode, p.stdout + p.stderr)
        r = verificar_cadena(self.ws)
        self.assertEqual(CICATRIZADA, r["estado"])
        self.assertEqual(1, len(r["cicatrices"]))

    def test_una_carrera_de_tres_tambien(self):
        from core.evidence import CICATRIZADA, verificar_cadena
        self._carrera_de_tres()
        p = self.correr("--escribir", "--firma", "prueba")
        self.assertEqual(0, p.returncode, p.stdout + p.stderr)
        self.assertNotIn("revisar", p.stdout)
        self.assertEqual(CICATRIZADA, verificar_cadena(self.ws)["estado"])

    def test_la_firma_queda_escrita(self):
        self._carrera_de_dos()
        self.correr("--escribir", "--firma", "quien-responde")
        doc = json.loads(ruta_discontinuidades(self.ws).read_text(encoding="utf-8"))
        self.assertTrue(doc["entries"])
        for e in doc["entries"]:
            self.assertEqual("quien-responde", e["declared_by"])
            self.assertTrue(e["cause"].strip())

    def test_un_diario_sano_no_declara_nada(self):
        p = self.correr("--escribir", "--firma", "prueba")
        self.assertEqual(0, p.returncode)
        self.assertIn("nada que declarar", p.stdout)
        self.assertFalse(ruta_discontinuidades(self.ws).exists())

    def test_sin_diario_no_revienta(self):
        ledger_path(self.ws).unlink()
        p = self.correr()
        self.assertNotEqual(0, p.returncode)
        self.assertIn("no hay diario", p.stdout)


if __name__ == "__main__":
    unittest.main()
