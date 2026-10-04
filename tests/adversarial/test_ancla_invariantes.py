# -*- coding: utf-8 -*-
"""Invariantes del ancla certificada como propiedades, no como ejemplos (FASE 2 §13).

Sobre membresías y certificados generados con claves sintéticas y un generador determinista:

    valid ⟹ |signers| ≥ q            valid ⟹ signers ⊆ membresía (índices y etiquetas)
    valid ⟹ digest(membresía) = pin  valid ⟹ cada firma verifica sobre el sujeto de la entrada
    valid ⟹ entry_digest = H(prev ‖ payload_digest)

Y las negaciones, cada una sobre un certificado con EXACTAMENTE q firmas genuinas (si sobran, una
firma rota no invalida: SPEC §5, y el test lo diría):

    firma inválida ⟹ ¬valid   firmante desconocido ⟹ ¬valid   pin distinto ⟹ ¬valid
    quórum insuficiente ⟹ ¬valid   sin certificado ⟹ ¬PASS   evidencia mutada ⟹ ¬PASS

Monotonía: añadir atestaciones INVÁLIDAS a un certificado válido no lo invalida (disponibilidad
bajo f bizantinos) ni cambia sus firmantes; añadirlas a uno inválido no lo valida; QUITAR una
atestación necesaria no mantiene el veredicto. Y sobre la evidencia: borrar el ancla o el diario
nunca mantiene PASS.
"""

from __future__ import annotations

import base64
import hashlib
import json
import random
import shutil
import tempfile
import unittest
from pathlib import Path

from core import concordia as C
from core.evidence import append_event, ledger_path, verificar_cadena
from core.model import FAIL, INCONCLUSIVE, PASS
from core.trust import digest_motor
from tests.fixtures import ed25519_firma as F

RONDAS = 40
#: El motor REAL: `estado_del_anclaje` comprueba que el ancla la certificó el que juzga ahora.
MOTOR = digest_motor()


def _rnd_bytes(rnd: random.Random, n: int) -> bytes:
    return bytes(rnd.getrandbits(8) for _ in range(n))


def _membresia(rnd: random.Random) -> tuple:
    n = rnd.choice([4, 5, 7])
    return F.membresia_sintetica(n=n, red=f"red-{rnd.randrange(10**6)}", epoch=rnd.randrange(1, 5),
                                 seed=rnd.getrandbits(48))


def _entrada(rnd: random.Random, export: dict, secretos: list, *, firmantes: list | None = None) -> tuple:
    ms = C.reconstruir_membresia(export)
    seq = rnd.randrange(1, 50)
    prev = bytes(32) if seq == 1 else _rnd_bytes(rnd, 32)
    carga = C.carga_ordenada(rnd.getrandbits(64), rnd.randrange(1, 10**6), _rnd_bytes(rnd, rnd.randrange(0, 200)))
    if firmantes is None:
        firmantes = rnd.sample(range(ms.n), ms.q)
    return F.certificar(export, secretos, seq=seq, carga=carga, prev=prev, firmantes=firmantes), ms


class TestInvariantesPositivos(unittest.TestCase):

    def test_todo_certificado_valido_cumple_las_cinco_propiedades(self):
        rnd = random.Random(20260927)
        for ronda in range(RONDAS):
            export, secretos = _membresia(rnd)
            e, ms = _entrada(rnd, export, secretos)
            r = C.verificar_certificado(export, e, pin=ms.digest)
            with self.subTest(ronda=ronda, n=ms.n):
                self.assertTrue(r["valido"], r["motivo"])
                self.assertGreaterEqual(len(r["signers"]), ms.q)
                self.assertEqual(r["required"], ms.q)
                for i in r["signers"]:
                    self.assertIsNotNone(ms.miembro(i))
                    self.assertIn(i, {a["replica"] for a in e["attestations"]})
                self.assertEqual(ms.digest, export["membership_digest"])
                self.assertEqual(e["entry_digest"], C.entry_digest(bytes.fromhex(e["prev_entry_digest"]),
                                                                    bytes.fromhex(e["payload_digest"])))
                self.assertEqual(r["entry_digest"], e["entry_digest"])
                self.assertEqual([], r["rejected"])


class TestNegaciones(unittest.TestCase):

    def _q_exactas(self, rnd):
        export, secretos = _membresia(rnd)
        e, ms = _entrada(rnd, export, secretos)
        self.assertEqual(ms.q, len(e["attestations"]))
        return export, secretos, e, ms

    def test_firma_invalida_implica_no_valid(self):
        rnd = random.Random(1)
        for _ in range(RONDAS):
            export, _, e, ms = self._q_exactas(rnd)
            i = rnd.randrange(len(e["attestations"]))
            sig = bytearray(base64.b64decode(e["attestations"][i]["signature_b64"]))
            bit = rnd.randrange(512)
            sig[bit // 8] ^= 1 << (bit % 8)
            e["attestations"][i]["signature_b64"] = base64.b64encode(bytes(sig)).decode()
            r = C.verificar_certificado(export, e, pin=ms.digest)
            self.assertFalse(r["valido"])
            self.assertEqual("InsufficientQuorum", r["codigo"])

    def test_firmante_desconocido_implica_no_valid(self):
        rnd = random.Random(2)
        for _ in range(RONDAS):
            export, _, e, ms = self._q_exactas(rnd)
            i = rnd.randrange(len(e["attestations"]))
            e["attestations"][i]["replica"] = ms.n + rnd.randrange(1, 100)
            r = C.verificar_certificado(export, e, pin=ms.digest)
            self.assertFalse(r["valido"])
            self.assertTrue(any("UnknownMember" in x for x in r["rejected"]), r)

    def test_pin_distinto_implica_no_valid(self):
        rnd = random.Random(3)
        for _ in range(RONDAS):
            export, _, e, ms = self._q_exactas(rnd)
            otro = hashlib.sha256(_rnd_bytes(rnd, 8)).hexdigest()
            r = C.verificar_certificado(export, e, pin=otro)
            self.assertFalse(r["valido"])
            self.assertEqual("PinMismatch", r["codigo"])

    def test_quorum_insuficiente_implica_no_valid(self):
        rnd = random.Random(4)
        for _ in range(RONDAS):
            export, secretos = _membresia(rnd)
            ms = C.reconstruir_membresia(export)
            k = rnd.randrange(0, ms.q)                     # 0..q−1 firmantes
            e, _ = _entrada(rnd, export, secretos, firmantes=rnd.sample(range(ms.n), k))
            r = C.verificar_certificado(export, e, pin=ms.digest)
            self.assertFalse(r["valido"])
            self.assertEqual("InsufficientQuorum", r["codigo"])


class TestMonotonia(unittest.TestCase):

    def test_anadir_basura_a_un_valido_no_lo_invalida_ni_cambia_sus_firmantes(self):
        rnd = random.Random(5)
        for _ in range(RONDAS):
            export, secretos = _membresia(rnd)
            e, ms = _entrada(rnd, export, secretos)
            antes = C.verificar_certificado(export, e, pin=ms.digest)
            self.assertTrue(antes["valido"])
            basura = []
            for _ in range(rnd.randrange(1, 4)):
                tipo = rnd.choice(["firma_rota", "duplicado", "desconocido", "ajena"])
                a = dict(rnd.choice(e["attestations"]))
                if tipo == "firma_rota":
                    a["signature_b64"] = base64.b64encode(_rnd_bytes(rnd, 64)).decode()
                elif tipo == "desconocido":
                    a["replica"] = ms.n + 3
                elif tipo == "ajena":
                    ajeno = F.secreto_sintetico(0xBAD, rnd.randrange(100))
                    msg = C.sujeto(ms.network, ms.epoch, a["replica"], e["seq"], bytes.fromhex(e["payload_digest"]),
                                   bytes.fromhex(e["prev_entry_digest"]), bytes.fromhex(ms.digest))
                    a["signature_b64"] = base64.b64encode(F.firmar(ajeno, msg)).decode()
                basura.append(a)
            e2 = dict(e, attestations=e["attestations"] + basura)
            despues = C.verificar_certificado(export, e2, pin=ms.digest)
            self.assertTrue(despues["valido"], despues["motivo"])
            self.assertEqual(antes["signers"], despues["signers"])
            self.assertEqual(len(basura), len(despues["rejected"]), "toda la basura queda LISTADA")

    def test_anadir_basura_a_un_invalido_no_lo_valida(self):
        rnd = random.Random(6)
        for _ in range(RONDAS):
            export, secretos = _membresia(rnd)
            ms = C.reconstruir_membresia(export)
            e, _ = _entrada(rnd, export, secretos, firmantes=rnd.sample(range(ms.n), ms.q - 1))
            self.assertFalse(C.verificar_certificado(export, e, pin=ms.digest)["valido"])
            usados = {a["replica"] for a in e["attestations"]}
            libre = next(i for i in range(ms.n) if i not in usados)
            a = dict(e["attestations"][0], replica=libre, member_id=ms.members[libre][0],
                     signature_b64=base64.b64encode(_rnd_bytes(rnd, 64)).decode())
            e2 = dict(e, attestations=e["attestations"] + [a, dict(e["attestations"][0])])
            r = C.verificar_certificado(export, e2, pin=ms.digest)
            self.assertFalse(r["valido"])

    def test_quitar_una_atestacion_necesaria_no_mantiene_valid(self):
        rnd = random.Random(7)
        for _ in range(RONDAS):
            export, secretos = _membresia(rnd)
            e, ms = _entrada(rnd, export, secretos)
            self.assertTrue(C.verificar_certificado(export, e, pin=ms.digest)["valido"])
            e2 = dict(e, attestations=e["attestations"][1:])
            self.assertFalse(C.verificar_certificado(export, e2, pin=ms.digest)["valido"])


class TestMonotoniaDeLaEvidencia(unittest.TestCase):
    """Eliminar evidencia requerida no mantiene PASS; añadir evidencia inválida no cambia un PASS."""

    def setUp(self):
        self.ws = Path(tempfile.mkdtemp(prefix="ancla-inv-")).resolve()
        (self.ws / ".harness" / "evidence").mkdir(parents=True)
        for i in range(4):
            append_event(self.ws, {"kind": "policy/decision", "outcome": "deny", "n": i})
        self.export, self.secretos = F.membresia_sintetica(n=4, red="inv")
        self.pin = self.export["membership_digest"]
        self.cfg = {"provider": "concordia", "endpoints": [], "membership_digest": self.pin}
        with F.ConcordiaFalso(self.export, self.secretos) as srv:
            self.cfg["endpoints"] = [srv.url]
            r = C.anclar(self.ws, self.cfg, run_id="ver_i", engine_digest=MOTOR, policy_digest="p",
                         manifest=None, pin=self.pin, cadena=verificar_cadena(self.ws))
        self.assertEqual(PASS, r["estado"], r["motivo"])
        self.path = Path(r["path"])
        self.manifest = {"anchoring": self.cfg}

    def tearDown(self):
        shutil.rmtree(self.ws, ignore_errors=True)

    def _estado(self) -> str:
        return C.estado_del_anclaje(self.ws, self.manifest)["estado"]

    def test_base_pass(self):
        self.assertEqual(PASS, self._estado())

    def test_borrar_el_ancla_no_mantiene_pass(self):
        self.path.unlink()
        self.assertEqual(INCONCLUSIVE, self._estado())

    def test_borrar_el_diario_no_mantiene_pass(self):
        ledger_path(self.ws).unlink()
        self.assertEqual(FAIL, self._estado())

    def test_anadir_un_ancla_invalida_mas_reciente_no_convierte_el_pass_en_pass_de_otra_cosa(self):
        """Un ancla ilegible más reciente: el estado deja de ser PASS (INCONCLUSIVE), nunca sube."""
        (self.path.parent / "zzz-nueva.json").write_text("{ no json")
        self.assertEqual(INCONCLUSIVE, self._estado())

    def test_dos_anclas_del_mismo_seq_no_se_pisan(self):
        """Tras un reinicio total del clúster el log vuelve a seq 1: la segunda ancla NO sobrescribe
        la primera (el nombre lleva el entry_digest)."""
        append_event(self.ws, {"kind": "policy/decision", "outcome": "deny", "n": 9})
        with F.ConcordiaFalso(self.export, self.secretos) as srv:      # clúster nuevo: log vacío
            cfg = dict(self.cfg, endpoints=[srv.url])
            r = C.anclar(self.ws, cfg, run_id="ver_j", engine_digest=MOTOR, policy_digest="p",
                         manifest=None, pin=self.pin, cadena=verificar_cadena(self.ws))
        self.assertEqual(PASS, r["estado"])
        self.assertEqual(1, json.loads(r["ancla"]["entry_raw"])["seq"])
        self.assertNotEqual(str(self.path), r["path"])
        self.assertTrue(self.path.is_file() and Path(r["path"]).is_file())
        self.assertEqual(2, len(C.anclas(self.ws)["legibles"]))


if __name__ == "__main__":
    unittest.main()
