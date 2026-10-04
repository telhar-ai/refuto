# -*- coding: utf-8 -*-
"""La política efectiva se puede citar, y el cambio del padre se nota.

Tres límites del diseño anterior, medidos el 2026-09-23 y cerrados aquí. Los tres eran del
mismo tipo: **la herencia funcionaba y no se podía auditar**.

1 · La evidencia no sabía qué política la gobernó
    El evento del diario decía qué regla denegó, no de qué política efectiva salió. Con
    herencia esa pregunta pasa de ociosa a central: la regla pudo venir del cliente, y el
    cliente pudo cambiar después.

2 · La identidad vivía en estado mutable de módulo
    `politica_efectiva.ultima_identidad`. Con dos espacios resueltos en el mismo proceso —lo
    que hace `refuto verify`— la segunda identidad pisaba a la primera, así que un evento
    podía citar la política de OTRO espacio.

3 · La huella de ejecución digería sólo el fichero del hijo
    `core/run.py::fingerprint` hacía `sha256(policy.json)`. El cliente podía cambiar entero
    —retirar una ruta protegida, abrir una orden— sin que el fichero del proyecto se tocara,
    y `compare_fingerprint` decía que el entorno seguía igual. **La reanudación afirmaba
    reproducibilidad sobre una política distinta.**
"""

from __future__ import annotations

import json
import subprocess
import sys
import unittest
from pathlib import Path

from core.policy import Policy
from core.proc import TEXT_IO
from core.run import compare_fingerprint, fingerprint
from tests.fixtures import Workspace

RAIZ = Path(__file__).resolve().parents[2]

CLIENTE = {"schema": "harness.policy/v1", "name": "cliente", "version": "1",
           "command_deny": ["solo-del-cliente:*"]}
HIJO = {"schema": "harness.policy/v1", "name": "proyecto", "version": "1",
        "extends": "cliente.json"}


def _montar(ws, hijo=HIJO, padre=CLIENTE):
    h = ws.root / ".harness"
    h.mkdir(parents=True, exist_ok=True)
    if padre is not None:
        (h / "cliente.json").write_text(json.dumps(padre), encoding="utf-8", newline="\n")
    (h / "policy.json").write_text(json.dumps(hijo), encoding="utf-8", newline="\n")
    return h / "policy.json"


class TestTodaPoliticaCargadaSePuedeCitar(unittest.TestCase):

    def test_con_herencia(self):
        with Workspace("id-con") as ws:
            pol = Policy.load(_montar(ws))
            self.assertTrue(getattr(pol, "identidad_efectiva", None),
                            "una política heredada se cargó sin identidad citable")

    def test_sin_herencia(self):
        """Si sólo las heredadas llevaran identidad, «no hay digest» sería indistinguible de
        «no se pudo calcular», y esa ambigüedad es la que el vocabulario existe para evitar."""
        with Workspace("id-sin") as ws:
            pol = Policy.load(_montar(ws, hijo={"schema": "harness.policy/v1",
                                                "command_deny": ["propia:*"]}, padre=None))
            self.assertTrue(getattr(pol, "identidad_efectiva", None))

    def test_la_identidad_viaja_con_la_politica_no_en_el_modulo(self):
        """Regresión del estado mutable compartido.

        Se resuelven DOS espacios seguidos, como hace `refuto verify`, y se exige que cada
        política conserve la suya. Con la variable de módulo, la segunda pisaba a la primera.
        """
        with Workspace("id-a") as a, Workspace("id-b") as b:
            pa = Policy.load(_montar(a))
            pb = Policy.load(_montar(b, padre={**CLIENTE, "command_deny": ["otra:*"]}))
            self.assertNotEqual(pa.identidad_efectiva.efectivo,
                                pb.identidad_efectiva.efectivo,
                                "dos espacios distintos comparten identidad")
            # Y la primera no se contaminó al resolver la segunda.
            self.assertEqual(pa.identidad_efectiva.efectivo,
                             Policy.load(a.root / ".harness" / "policy.json")
                             .identidad_efectiva.efectivo)


class TestElEventoCitaLaPoliticaQueDecidio(unittest.TestCase):

    def test_una_denegacion_lleva_el_digest_efectivo(self):
        with Workspace("id-evento") as ws:
            _montar(ws)
            subprocess.run([sys.executable, "-m", "core.guard", "--runtime", "claude",
                            "--stdin", "--workspace", str(ws.root),
                            "--command", "solo-del-cliente --x"],
                           input="{}", capture_output=True, cwd=str(RAIZ), **TEXT_IO)
            diario = ws.root / ".harness" / "evidence" / "ledger.jsonl"
            self.assertTrue(diario.is_file(), "el guardián no dejó rastro")
            ev = json.loads(diario.read_text(encoding="utf-8").strip().splitlines()[-1])
            self.assertEqual("deny", ev["outcome"])
            self.assertTrue(ev.get("policy_digest"),
                            "el evento no dice qué política efectiva lo decidió")
            esperado = Policy.load(ws.root / ".harness" / "policy.json")
            self.assertEqual(esperado.identidad_efectiva.efectivo, ev["policy_digest"],
                             "el digest del evento no es el de la política que gobierna")


class TestLaHuellaCubreLaCadenaEntera(unittest.TestCase):

    def test_un_cambio_SOLO_en_el_padre_se_detecta(self):
        """El más grave de los tres: sin esto, reanudar afirmaba reproducibilidad sobre otra
        política."""
        with Workspace("id-huella") as ws:
            _montar(ws)
            antes = fingerprint(ws.root)
            # El cliente cambia. El fichero del proyecto NO se toca.
            (ws.root / ".harness" / "cliente.json").write_text(
                json.dumps({**CLIENTE, "command_deny": ["solo-del-cliente:*", "otra:*"]}),
                encoding="utf-8", newline="\n")
            despues = fingerprint(ws.root)
            self.assertNotEqual(antes["policy_digest"], despues["policy_digest"],
                                "el padre cambió y la huella no se enteró")
            problemas = compare_fingerprint(antes, despues)
            self.assertTrue(any("política" in p for p in problemas),
                            f"el cambio no se reporta como tal: {problemas}")

    def test_sin_cambios_la_huella_es_estable(self):
        """El control: si variara sola, «cambió la política» dejaría de significar nada."""
        with Workspace("id-estable") as ws:
            _montar(ws)
            self.assertEqual(fingerprint(ws.root)["policy_digest"],
                             fingerprint(ws.root)["policy_digest"])
            self.assertEqual([], compare_fingerprint(fingerprint(ws.root),
                                                     fingerprint(ws.root)))

    def test_una_cadena_irresoluble_no_finge_una_huella(self):
        with Workspace("id-irres") as ws:
            _montar(ws, hijo={"schema": "harness.policy/v1", "extends": "no-existe.json"},
                    padre=None)
            self.assertEqual("irresoluble", fingerprint(ws.root)["policy_digest"])

    def test_la_huella_no_revienta_sin_politica(self):
        with Workspace("id-nada") as ws:
            (ws.root / ".harness").mkdir(parents=True, exist_ok=True)
            self.assertEqual("", fingerprint(ws.root)["policy_digest"])


if __name__ == "__main__":
    unittest.main()
