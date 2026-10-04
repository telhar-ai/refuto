# -*- coding: utf-8 -*-
"""Conformidad del verificador de refuto con los 21 vectores canónicos de concordia.

Tres verificadores tienen que decir lo mismo (encargo FASE 2 §14):

    concordia (Rust, `hicon verify-entry`)  ↔  refuto (`core.concordia`)  ↔  vectores canónicos

Los vectores viven copiados en `tests/fixtures/concordia_vectors/` (origen:
`ai/concordia/contracts/vectors/`, commit `3843613`). Si `CONCORDIA_VECTORS` apunta al origen, se
exige identidad byte a byte con la copia: una copia que derive del origen no es una conformidad,
es un recuerdo. Si `HICON_BIN` apunta al binario, se ejecuta el diferencial contra Rust; si no,
esa mitad queda declarada `NOT_RUN` (un `skip` con motivo), nunca aprobada por omisión.

Cada vector declara `expected` y, los negativos, `reason_contains`: el motivo se comprueba, no
sólo el veredicto. Un verificador que rechaza por el motivo equivocado está rechazando por
casualidad.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess  # nosec B404 — ejecutar el verificador de referencia ES la medición
import tempfile
import unittest
from pathlib import Path

from core.concordia import verificar_certificado, verificar_equivocacion
from core.proc import TEXT_IO

RAIZ = Path(__file__).resolve().parents[2]
VECTORES = RAIZ / "tests" / "fixtures" / "concordia_vectors"
HICON = os.environ.get("HICON_BIN", "")


def _vectores() -> list:
    return sorted(VECTORES.glob("*.json"))


class TestVectoresCanonicos(unittest.TestCase):

    def test_hay_veintiun_vectores_y_ninguno_de_mas(self):
        nombres = [p.name for p in _vectores()]
        self.assertEqual(21, len(nombres), nombres)
        self.assertEqual([f"{i:02d}" for i in range(1, 22)], [n[:2] for n in nombres])

    def test_cada_vector_da_el_veredicto_y_el_motivo_que_declara(self):
        for p in _vectores():
            v = json.loads(p.read_text(encoding="utf-8"))
            with self.subTest(vector=p.name):
                if v["expected"] == "EQUIVOCATION":
                    r = verificar_equivocacion(v["membership"], v["equivocation"])
                    self.assertTrue(r["valido"], r)
                    self.assertEqual("EQUIVOCATION", r["codigo"])
                    self.assertEqual(2, r["culpable"], "el vector 21 acusa al miembro 2")
                    continue
                r = verificar_certificado(v["membership"], v["entry"])
                if v["expected"] == "VALID":
                    self.assertTrue(r["valido"], f"{p.name}: {r['motivo']}")
                    self.assertGreaterEqual(len(r["signers"]), r["required"])
                    self.assertEqual(v["entry"]["entry_digest"], r["entry_digest"])
                else:
                    self.assertFalse(r["valido"], f"{p.name} debía ser INVALID y verificó")
                    texto = r["motivo"] + " " + " ".join(r["rejected"])
                    self.assertIn(v["reason_contains"], texto,
                                  f"{p.name}: se esperaba «{v['reason_contains']}» en «{texto}»")

    def test_20_la_basura_se_descuenta_y_se_lista_sin_tumbar_el_quorum(self):
        v = json.loads((VECTORES / "20-valid-with-garbage-attestations.json").read_text(encoding="utf-8"))
        r = verificar_certificado(v["membership"], v["entry"])
        self.assertTrue(r["valido"])
        self.assertEqual([0, 1, 2], r["signers"])
        self.assertEqual(2, len(r["rejected"]), r["rejected"])
        self.assertTrue(any("InvalidSignature" in x and "replica 3" in x for x in r["rejected"]), r["rejected"])
        self.assertTrue(any("DuplicateSigner" in x and "replica 0" in x for x in r["rejected"]), r["rejected"])

    def test_el_pin_manda_sobre_una_membresia_bien_formada(self):
        """El vector 18 es una membresía coherente pero AJENA: sin pin, el verificador la acepta
        como bien formada (SPEC §8.1); con pin, se rechaza antes de mirar el certificado."""
        v18 = json.loads((VECTORES / "18-forged-membership-same-epoch.json").read_text(encoding="utf-8"))
        v01 = json.loads((VECTORES / "01-valid-seq1.json").read_text(encoding="utf-8"))
        pin = v01["membership"]["membership_digest"]
        r = verificar_certificado(v18["membership"], v01["entry"], pin=pin)
        self.assertFalse(r["valido"])
        self.assertEqual("PinMismatch", r["codigo"])
        # y con el pin correcto, la entrada 01 bajo su membresía verifica
        self.assertTrue(verificar_certificado(v01["membership"], v01["entry"], pin=pin)["valido"])
        # y un pin cualquiera distinto la rechaza aunque TODO lo demás sea correcto
        self.assertEqual("PinMismatch", verificar_certificado(v01["membership"], v01["entry"], pin="ab" * 32)["codigo"])

    def test_la_copia_es_identica_al_origen_si_el_origen_esta(self):
        origen = os.environ.get("CONCORDIA_VECTORS", "")
        if not origen:
            self.skipTest("NOT_RUN: CONCORDIA_VECTORS no apunta al origen; la identidad con el origen no se comprobó")
        origen_p = Path(origen)
        for p in _vectores():
            with self.subTest(vector=p.name):
                self.assertEqual((origen_p / p.name).read_bytes(), p.read_bytes(), f"{p.name} difiere del origen")
        self.assertEqual({p.name for p in _vectores()}, {p.name for p in origen_p.glob("*.json")},
                         "hay vectores de más o de menos respecto del origen")


@unittest.skipUnless(HICON and shutil.which(HICON) or (HICON and Path(HICON).is_file()),
                     "NOT_RUN: HICON_BIN no apunta a `hicon`; el diferencial con Rust no se ejecutó")
class TestDiferencialConHicon(unittest.TestCase):
    """El verificador de referencia (Rust) y el de refuto (Python) deben coincidir en los 21."""

    def _hicon(self, membership: dict, entry: dict | None, equivocation: dict | None = None) -> tuple:
        with tempfile.TemporaryDirectory() as d:
            m = Path(d) / "m.json"
            m.write_text(json.dumps(membership), encoding="utf-8")
            args = [HICON, "verify-entry", "--membership", str(m)]
            if equivocation is not None:
                e = Path(d) / "p.json"
                e.write_text(json.dumps(equivocation), encoding="utf-8")
                args += ["--equivocation", str(e)]
            else:
                e = Path(d) / "e.json"
                e.write_text(json.dumps(entry), encoding="utf-8")
                args += ["--entry", str(e)]
            p = subprocess.run(args, capture_output=True, timeout=60, **TEXT_IO)  # nosec B603
            return p.returncode, (p.stdout + p.stderr).strip()

    def test_los_dos_verificadores_coinciden_en_los_veintiuno(self):
        for p in _vectores():
            v = json.loads(p.read_text(encoding="utf-8"))
            with self.subTest(vector=p.name):
                if v["expected"] == "EQUIVOCATION":
                    rc, out = self._hicon(v["membership"], None, v["equivocation"])
                    r = verificar_equivocacion(v["membership"], v["equivocation"])
                    self.assertEqual((rc == 0), r["valido"], f"{p.name}: hicon={out!r} refuto={r}")
                    continue
                rc, out = self._hicon(v["membership"], v["entry"])
                r = verificar_certificado(v["membership"], v["entry"])
                self.assertEqual((rc == 0), r["valido"], f"{p.name}: hicon={out!r} refuto={r}")
                if r["valido"]:
                    m = re.search(r"signers=\[([0-9, ]*)\] required=(\d+) entry_digest=([0-9a-f]{64}) rejected=\[(.*)\]", out)
                    self.assertIsNotNone(m, f"{p.name}: salida de hicon irreconocible: {out!r}")
                    firmantes = [int(x) for x in m.group(1).replace(" ", "").split(",") if x]
                    self.assertEqual(firmantes, r["signers"], f"{p.name}: firmantes distintos")
                    self.assertEqual(int(m.group(2)), r["required"], f"{p.name}: q distinto")
                    self.assertEqual(m.group(3), r["entry_digest"], f"{p.name}: entry_digest distinto")
                    n_rechazadas = len(re.findall(r'"[^"]*"', m.group(4)))
                    self.assertEqual(n_rechazadas, len(r["rejected"]), f"{p.name}: rechazadas distintas: {out!r} / {r['rejected']}")
                else:
                    # el CÓDIGO de motivo debe coincidir (el detalle es libre en cada lado)
                    self.assertIn(r["codigo"], out, f"{p.name}: motivo distinto: hicon={out!r} refuto={r['codigo']}")

    def test_mutaciones_aleatorias_de_firma_coinciden(self):
        """Doscientas mutaciones de un bit sobre las firmas del vector 01: los dos rechazan las
        mismas. Una divergencia aquí sería un falso PASS en un lado o en el otro."""
        import base64
        import random
        v = json.loads((VECTORES / "01-valid-seq1.json").read_text(encoding="utf-8"))
        rnd = random.Random(0x5EED)
        for _ in range(200):
            e = json.loads(json.dumps(v["entry"]))
            i = rnd.randrange(len(e["attestations"]))
            sig = bytearray(base64.b64decode(e["attestations"][i]["signature_b64"]))
            bit = rnd.randrange(512)
            sig[bit // 8] ^= 1 << (bit % 8)
            e["attestations"][i]["signature_b64"] = base64.b64encode(bytes(sig)).decode()
            rc, out = self._hicon(v["membership"], e)
            r = verificar_certificado(v["membership"], e)
            self.assertEqual((rc == 0), r["valido"], f"bit {bit} de la firma {i}: hicon={out!r} refuto={r['codigo']}")
            self.assertFalse(r["valido"], "con exactamente q firmas, un bit cambiado no puede seguir verificando")


if __name__ == "__main__":
    unittest.main()
