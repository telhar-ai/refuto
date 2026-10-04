# -*- coding: utf-8 -*-
"""`core.ed25519`: el verificador puro se contrasta por las dos puntas.

1. RFC 8032 §7.1 TEST 1 (clave, clave pública derivada y firma del mensaje vacío).
2. Regeneración BYTE A BYTE del vector 01 de concordia desde la semilla sintética de `testkit.rs`
   con la firma de prueba (`tests/fixtures/ed25519_firma.py`): si la firma de prueba coincide con
   `ed25519-dalek` en tres firmas reales, y `core.ed25519` las verifica, verificador y firmante de
   prueba quedan contrastados contra la referencia a la vez.
3. Lo que tiene que RECHAZAR: mensaje distinto, cada uno de los 512 bits de la firma cambiado,
   `S ≥ L`, `R` no canónico, clave de orden pequeño, longitudes incorrectas, tipos incorrectos.
"""

from __future__ import annotations

import base64
import hashlib
import json
import unittest
from pathlib import Path

from core import ed25519 as E
from tests.fixtures import ed25519_firma as F

VECTORES = Path(__file__).resolve().parents[1] / "fixtures" / "concordia_vectors"

SK1 = bytes.fromhex("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60")
PK1 = bytes.fromhex("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a")
SIG1 = bytes.fromhex("e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e0652249015"
                     "55fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b")


class TestRFC8032(unittest.TestCase):

    def test_test_vector_1_verifica(self):
        self.assertTrue(E.verify(PK1, b"", SIG1))

    def test_la_firma_de_prueba_reproduce_el_test_vector_1(self):
        self.assertEqual(PK1, F.clave_publica(SK1))
        self.assertEqual(SIG1, F.firmar(SK1, b""))

    def test_mensaje_distinto_no_verifica(self):
        self.assertFalse(E.verify(PK1, b"x", SIG1))
        self.assertFalse(E.verify(PK1, b"\x00", SIG1))

    def test_cada_bit_de_la_firma_cambiado_se_rechaza(self):
        for bit in range(512):
            sig = bytearray(SIG1)
            sig[bit // 8] ^= 1 << (bit % 8)
            self.assertFalse(E.verify(PK1, b"", bytes(sig)), f"bit {bit}")

    def test_cada_bit_de_la_clave_cambiado_se_rechaza(self):
        for bit in range(256):
            pk = bytearray(PK1)
            pk[bit // 8] ^= 1 << (bit % 8)
            self.assertFalse(E.verify(bytes(pk), b"", SIG1), f"bit {bit}")


class TestVector01DeConcordia(unittest.TestCase):
    """El export y las tres firmas del vector 01 salen IDÉNTICOS desde la semilla `0x5EED_0001`."""

    def test_export_y_firmas_identicos_a_dalek(self):
        v = json.loads((VECTORES / "01-valid-seq1.json").read_text(encoding="utf-8"))
        export, secretos = F.membresia_sintetica(n=4, red="test-net", epoch=1)
        self.assertEqual(v["membership"], export)
        carga = base64.b64decode(v["entry"]["payload_b64"])
        e = F.certificar(export, secretos, seq=1, carga=carga)
        self.assertEqual(v["entry"], e)


class TestRechazos(unittest.TestCase):

    def setUp(self):
        self.sk = hashlib.sha256(b"clave de prueba").digest()
        self.pk = F.clave_publica(self.sk)
        self.msg = b"mensaje"
        self.sig = F.firmar(self.sk, self.msg)
        self.assertTrue(E.verify(self.pk, self.msg, self.sig))

    def test_s_mayor_o_igual_que_L_se_rechaza(self):
        """Maleabilidad: `S + L` es otra codificación de la misma firma. La referencia la
        rechaza; refuto también."""
        s = int.from_bytes(self.sig[32:], "little")
        malo = self.sig[:32] + (s + E.L).to_bytes(32, "little")
        self.assertFalse(E.verify(self.pk, self.msg, malo))
        # y exactamente L
        self.assertFalse(E.verify(self.pk, self.msg, self.sig[:32] + E.L.to_bytes(32, "little")))

    def test_R_no_canonico_se_rechaza(self):
        """Una `y ≥ p` es una codificación NO canónica: sólo un adversario la produce. dalek la
        tolera al decodificar (reduce módulo p); refuto la rechaza en `_decode`."""
        # y = 1 es la identidad, canónica: decodifica.
        self.assertIsNotNone(E._decode((1).to_bytes(32, "little")))
        # y = 1 + p codifica el MISMO punto de forma no canónica: no decodifica.
        self.assertIsNone(E._decode((1 + E.P).to_bytes(32, "little")))
        # y = p − 1 con bit de signo: x = 0 y signo 1 es «−0», no canónico.
        self.assertIsNone(E._decode(((E.P - 1) | (1 << 255)).to_bytes(32, "little")))
        # y una firma cuyo R lleva y = 1 + p no verifica, sea lo que sea S.
        self.assertFalse(E.verify(self.pk, self.msg, (1 + E.P).to_bytes(32, "little") + self.sig[32:]))
        # una y fuera de la curva (sin raíz cuadrada) tampoco decodifica
        for y in range(2, 40):
            pt = E._decode(y.to_bytes(32, "little"))
            if pt is None:
                break
        else:
            self.fail("ninguna y en 2..39 quedó fuera de la curva; la sonda no es concluyente")

    def test_clave_de_orden_pequeno_se_rechaza(self):
        # El punto de orden 1 (identidad) y el de orden 2 codificados.
        identidad = E.encode_point(E.IDENTITY)
        orden2 = (E.P - 1).to_bytes(32, "little")     # y = −1, x = 0
        for pk in (identidad, orden2):
            self.assertFalse(E.verify(pk, self.msg, self.sig))
            self.assertFalse(E.verify(pk, b"", bytes(64)))

    def test_longitudes_y_tipos_incorrectos_no_revientan(self):
        self.assertFalse(E.verify(self.pk[:31], self.msg, self.sig))
        self.assertFalse(E.verify(self.pk + b"\x00", self.msg, self.sig))
        self.assertFalse(E.verify(self.pk, self.msg, self.sig[:63]))
        self.assertFalse(E.verify(self.pk, self.msg, self.sig + b"\x00"))
        self.assertFalse(E.verify(self.pk, self.msg, b""))
        self.assertFalse(E.verify(b"", self.msg, self.sig))
        self.assertFalse(E.verify("no bytes", self.msg, self.sig))         # type: ignore[arg-type]
        self.assertFalse(E.verify(self.pk, "no bytes", self.sig))          # type: ignore[arg-type]
        self.assertFalse(E.verify(self.pk, self.msg, None))                # type: ignore[arg-type]

    def test_una_firma_de_otra_clave_no_verifica(self):
        otro = F.clave_publica(hashlib.sha256(b"otra").digest())
        self.assertFalse(E.verify(otro, self.msg, self.sig))

    def test_la_firma_es_determinista(self):
        self.assertEqual(self.sig, F.firmar(self.sk, self.msg))


if __name__ == "__main__":
    unittest.main()
