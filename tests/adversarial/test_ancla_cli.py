# -*- coding: utf-8 -*-
"""El ancla certificada en los caminos REALES de `verify`, `status` y `evidence` (FASE 2 §8).

Se ejecuta el CLI de verdad, como en CI, contra un concordia FALSO en un hilo. Lo que se afirma:

    clúster disponible + certificado válido      → PASS
    clúster no disponible                        → NOT_EXECUTABLE (código 2), nunca PASS
    certificado inválido                         → FAIL (código 1)
    sin pin                                      → BLOCKED (código 2)
    --offline con anclaje declarado              → BLOCKED
    ancla no ejecutada (status sin ancla)        → INCONCLUSIVE
    espacio sin `anchoring`                      → comportamiento histórico intacto

Y la separación que hay que preservar: el estado de VERIFICACIÓN (las puertas) y el estado del
ANCLA se imprimen y viajan por separado; sólo se funden en el estado agregado, donde ninguno de
los dos puede convertir al otro en PASS. `refuto verify --gate G-MANIFEST` mantiene la corrida
en décimas de segundo: la puerta que se ejecuta es la que valida el propio manifiesto, así que
también prueba que la sección `anchoring` pasa su esquema.
"""

from __future__ import annotations

import json
import os
import subprocess  # nosec B404 — ejecutar el CLI real ES la medición
import sys
import tempfile
import unittest
from pathlib import Path

from core import concordia as C
from core.envelope import EXIT_BLOCKED, EXIT_FAIL, EXIT_OK
from core.evidence import append_event, ledger_path
from core.model import BLOCKED, FAIL, INCONCLUSIVE, NOT_EXECUTABLE, PASS
from core.proc import TEXT_IO
from tests.fixtures.ed25519_firma import ConcordiaFalso, membresia_sintetica

RAIZ = Path(__file__).resolve().parents[2]
EXPORT, SECRETOS = membresia_sintetica(n=4, red="cli")
PIN = EXPORT["membership_digest"]


def _cli(ws: Path, *args: str, env: dict | None = None) -> tuple:
    import contextlib
    import io
    import refuto
    old_env = dict(os.environ)
    try:
        e = dict(os.environ)
        e.pop(C.ENV_PIN, None)
        e.update(env or {})
        os.environ.clear()
        os.environ.update(e)
        argv = ["--workspace", str(ws), *args, "--json"]
        out_buf = io.StringIO()
        err_buf = io.StringIO()
        with contextlib.redirect_stdout(out_buf), contextlib.redirect_stderr(err_buf):
            rc = refuto.main(argv)
        raw_out = out_buf.getvalue()
        try:
            doc = json.loads(raw_out)
        except json.JSONDecodeError:
            doc = {"_raw": raw_out[-1500:], "_err": err_buf.getvalue()[-1500:]}
        return rc, doc
    finally:
        os.environ.clear()
        os.environ.update(old_env)


def _espacio(url: str | None, *, pin: str | None = PIN, agentes: dict | None = None, eventos: int = 3) -> Path:
    ws = Path(tempfile.mkdtemp(prefix="ancla-cli-")).resolve()
    (ws / ".harness" / "evidence").mkdir(parents=True)
    for i in range(eventos):
        append_event(ws, {"kind": "policy/decision", "outcome": "deny", "n": i})
    manifest = {"schema": "harness.manifest/v1", "harness": {"version": "0.1.0", "min_python": "3.10"},
                "workspace": {"name": "ancla-cli", "profile": "standard"},
                "agents": agentes or {}, "gates": ["G-MANIFEST"]}
    if url is not None:
        anch = {"provider": "concordia", "endpoints": [url], "timeout_s": 1.5, "pinned_by": "prueba",
                "pinned_at": "2026-09-27"}
        if pin:
            anch["membership_digest"] = pin
        manifest["anchoring"] = anch
    (ws / ".harness" / "harness.manifest.json").write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    return ws


class TestVerify(unittest.TestCase):

    def test_cluster_disponible_y_certificado_valido_es_pass(self):
        with ConcordiaFalso(EXPORT, SECRETOS) as srv:
            ws = _espacio(srv.url)
            rc, d = _cli(ws, "verify", "--gate", "G-MANIFEST")
        self.assertEqual((EXIT_OK, PASS), (rc, d.get("status")), d)
        a = d["payload"]["anchor"]
        self.assertTrue(a["declarado"])
        self.assertEqual(PASS, a["estado"])
        self.assertEqual(1, a["seq"])
        self.assertEqual([0, 1, 2], a["signers"])
        self.assertTrue(Path(a["path"]).is_file())
        # el diario registró el anclaje DESPUÉS del run/complete
        kinds = [json.loads(l)["kind"] for l in ledger_path(ws).read_text().splitlines()]
        self.assertEqual(["run/complete", C.KIND_ANCLA], kinds[-2:])
        # y el checkpoint certificado es la cabeza que había tras el run/complete
        doc = json.loads(Path(a["path"]).read_text())
        eventos = ledger_path(ws).read_text().splitlines()
        self.assertEqual(json.loads(eventos[-2])["h"], doc["checkpoint"]["root"])
        self.assertEqual(len(eventos) - 1, doc["checkpoint"]["size"])
        self.assertEqual(d["run_id"], doc["checkpoint"]["run_id"])

    def test_cluster_caido_no_es_pass(self):
        ws = _espacio("http://127.0.0.1:9")
        rc, d = _cli(ws, "verify", "--gate", "G-MANIFEST")
        self.assertEqual((EXIT_BLOCKED, NOT_EXECUTABLE), (rc, d.get("status")), d)
        self.assertEqual(NOT_EXECUTABLE, d["payload"]["anchor"]["estado"])
        self.assertTrue(any("ancla" in s["why"] for s in d["next"]))
        # las puertas, por su lado, aprobaron: la verificación y el ancla son dos dimensiones
        self.assertEqual("PASS", d["payload"]["gates"][0]["status"])

    def test_certificado_invalido_es_fail(self):
        with ConcordiaFalso(EXPORT, SECRETOS, modo="firma_rota") as srv:
            ws = _espacio(srv.url)
            rc, d = _cli(ws, "verify", "--gate", "G-MANIFEST")
        self.assertEqual((EXIT_FAIL, FAIL), (rc, d.get("status")), d)
        self.assertEqual(FAIL, d["payload"]["anchor"]["estado"])

    def test_sin_pin_es_blocked(self):
        with ConcordiaFalso(EXPORT, SECRETOS) as srv:
            ws = _espacio(srv.url, pin=None)
            rc, d = _cli(ws, "verify", "--gate", "G-MANIFEST")
        # sin `membership_digest` el manifiesto además incumple su esquema: G-MANIFEST en FAIL
        self.assertEqual(EXIT_FAIL, rc, d)
        self.assertIn(d["payload"]["anchor"]["estado"], (BLOCKED,))
        self.assertIn("pin", d["payload"]["anchor"]["motivo"])

    def test_pin_solo_del_invocador_basta(self):
        with ConcordiaFalso(EXPORT, SECRETOS) as srv:
            ws = _espacio(srv.url, pin=None)
            # G-MANIFEST fallará (esquema), pero el ancla se toma con el pin del invocador
            rc, d = _cli(ws, "verify", "--gate", "G-MANIFEST", "--membership-digest", PIN)
        self.assertEqual(PASS, d["payload"]["anchor"]["estado"], d["payload"]["anchor"])
        self.assertEqual(FAIL, d["status"], "la puerta en rojo sigue mandando")

    def test_pin_del_invocador_que_discrepa_es_fail(self):
        with ConcordiaFalso(EXPORT, SECRETOS) as srv:
            ws = _espacio(srv.url)
            rc, d = _cli(ws, "verify", "--gate", "G-MANIFEST", env={C.ENV_PIN: "ab" * 32})
        self.assertEqual((EXIT_FAIL, FAIL), (rc, d.get("status")), d)
        self.assertIn("dos autoridades", d["payload"]["anchor"]["motivo"])

    def test_offline_con_anclaje_declarado_es_blocked(self):
        with ConcordiaFalso(EXPORT, SECRETOS) as srv:
            ws = _espacio(srv.url)
            rc, d = _cli(ws, "verify", "--gate", "G-MANIFEST", "--offline")
            self.assertEqual(0, len(srv.peticiones), "--offline no debe tocar el clúster")
        self.assertEqual((EXIT_BLOCKED, BLOCKED), (rc, d.get("status")), d)

    def test_espacio_sin_anchoring_no_cambia(self):
        ws = _espacio(None)
        rc, d = _cli(ws, "verify", "--gate", "G-MANIFEST")
        self.assertEqual((EXIT_OK, PASS), (rc, d.get("status")), d)
        self.assertFalse(d["payload"]["anchor"]["declarado"])
        self.assertFalse((ws / ".harness" / "evidence" / "anchors").exists())

    def test_puertas_en_rojo_y_ancla_valida_es_fail(self):
        """Separación: el ancla PASS no rescata una verificación en rojo."""
        with ConcordiaFalso(EXPORT, SECRETOS) as srv:
            ws = _espacio(srv.url, agentes={"inexistente": {"required": True}})
            rc, d = _cli(ws, "verify", "--gate", "G-MANIFEST")
        self.assertEqual((EXIT_FAIL, FAIL), (rc, d.get("status")), d)
        self.assertEqual(PASS, d["payload"]["anchor"]["estado"])
        self.assertEqual("FAIL", d["payload"]["gates"][0]["status"])


class TestStatus(unittest.TestCase):

    def test_status_sin_ancla_con_anclaje_declarado_es_inconclusive(self):
        ws = _espacio("http://127.0.0.1:9")
        rc, d = _cli(ws, "status")
        self.assertEqual((EXIT_BLOCKED, INCONCLUSIVE), (rc, d.get("status")), d)
        self.assertEqual(INCONCLUSIVE, d["payload"]["anchor"]["estado"])
        self.assertTrue(any(s["do"] == "refuto evidence --anchor" for s in d["next"]))

    def test_status_no_habla_con_el_cluster(self):
        with ConcordiaFalso(EXPORT, SECRETOS) as srv:
            ws = _espacio(srv.url)
            _cli(ws, "evidence", "--anchor")
            n = len(srv.peticiones)
            rc, d = _cli(ws, "status")
            self.assertEqual(n, len(srv.peticiones), "status releyó OFFLINE, sin pedir nada")
        self.assertEqual((EXIT_OK, PASS), (rc, d.get("status")), d)
        self.assertEqual(PASS, d["payload"]["anchor"]["estado"])

    def test_status_con_diario_truncado_tras_el_ancla_es_fail(self):
        with ConcordiaFalso(EXPORT, SECRETOS) as srv:
            ws = _espacio(srv.url)
            _cli(ws, "evidence", "--anchor")
        L = ledger_path(ws).read_text().splitlines()
        ledger_path(ws).write_text("\n".join(L[:2]) + "\n")
        rc, d = _cli(ws, "status")
        self.assertEqual((EXIT_FAIL, FAIL), (rc, d.get("status")), d)

    def test_status_sin_pin_es_blocked(self):
        ws = _espacio("http://127.0.0.1:9", pin=None)
        rc, d = _cli(ws, "status")
        self.assertEqual((EXIT_BLOCKED, BLOCKED), (rc, d.get("status")), d)

    def test_status_de_un_espacio_sin_anchoring_no_cambia(self):
        ws = _espacio(None)
        rc, d = _cli(ws, "status")
        self.assertEqual((EXIT_OK, PASS), (rc, d.get("status")), d)
        self.assertFalse(d["payload"]["anchor"]["declarado"])

    def test_verificacion_en_rojo_con_ancla_valida_mantiene_la_excepcion_documentada(self):
        """`status` responde «¿se sostiene lo que reporto?»: puertas en rojo + ancla PASS → PASS
        con el trabajo en `next` (excepción declarada en `_estado_de_status`)."""
        with ConcordiaFalso(EXPORT, SECRETOS) as srv:
            ws = _espacio(srv.url, agentes={"inexistente": {"required": True}})
            _cli(ws, "verify", "--gate", "G-MANIFEST")
            rc, d = _cli(ws, "status")
        self.assertEqual((EXIT_OK, PASS), (rc, d.get("status")), d)
        self.assertEqual(PASS, d["payload"]["anchor"]["estado"])
        self.assertTrue(any("puerta" in s["why"] for s in d["next"]))

    def test_status_tras_un_verify_sin_ancla_no_es_pass(self):
        """Regresión (falsador, 2026-09-27): verify PASS con ancla → clúster caído → verify
        NOT_EXECUTABLE sin ancla → `status` reportaba PASS con el ancla de la corrida ANTERIOR.
        Ahora: INCONCLUSIVE, con el motivo del último intento registrado en el diario."""
        with ConcordiaFalso(EXPORT, SECRETOS) as srv:
            ws = _espacio(srv.url)
            rc, d1 = _cli(ws, "verify", "--gate", "G-MANIFEST")
            self.assertEqual(PASS, d1["status"])
        rc, d2 = _cli(ws, "verify", "--gate", "G-MANIFEST")          # el clúster ya no está
        self.assertEqual(NOT_EXECUTABLE, d2["status"])
        rc, d = _cli(ws, "status")
        self.assertEqual((EXIT_BLOCKED, INCONCLUSIVE), (rc, d.get("status")), d)
        self.assertEqual(INCONCLUSIVE, d["payload"]["anchor"]["estado"])
        self.assertIn(d2["run_id"], d["payload"]["anchor"]["motivo"])
        self.assertIn("NOT_EXECUTABLE", d["payload"]["anchor"]["motivo"])

    def test_status_tras_un_verify_con_certificado_invalido_es_fail(self):
        """El mismo patrón con un FAIL registrado: el hecho no se degrada a duda."""
        with ConcordiaFalso(EXPORT, SECRETOS, modo="firma_rota") as srv:
            ws = _espacio(srv.url)
            rc, d1 = _cli(ws, "verify", "--gate", "G-MANIFEST")
            self.assertEqual(FAIL, d1["status"])
            rc, d = _cli(ws, "status")
        self.assertEqual((EXIT_FAIL, FAIL), (rc, d.get("status")), d)

    def test_status_elige_el_ancla_de_la_ultima_verificacion(self):
        with ConcordiaFalso(EXPORT, SECRETOS) as srv:
            ws = _espacio(srv.url)
            rc, d1 = _cli(ws, "verify", "--gate", "G-MANIFEST")
            rc, d = _cli(ws, "status")
        self.assertEqual(d1["run_id"], d["payload"]["anchor"]["checkpoint"]["run_id"])


class TestEvidence(unittest.TestCase):

    def test_anchor_y_anchor_check(self):
        with ConcordiaFalso(EXPORT, SECRETOS) as srv:
            ws = _espacio(srv.url)
            rc, d = _cli(ws, "evidence", "--anchor")
            self.assertEqual((EXIT_OK, PASS), (rc, d.get("status")), d)
            rc, d = _cli(ws, "evidence", "--anchor-check")
            self.assertEqual((EXIT_OK, PASS), (rc, d.get("status")), d)
            self.assertEqual(1, d["payload"]["seq"])

    def test_anchor_sin_anchoring_declarado_es_blocked(self):
        ws = _espacio(None)
        rc, d = _cli(ws, "evidence", "--anchor")
        self.assertEqual((EXIT_BLOCKED, BLOCKED), (rc, d.get("status")), d)

    def test_anchor_con_cluster_caido_es_not_executable(self):
        ws = _espacio("http://127.0.0.1:9")
        rc, d = _cli(ws, "evidence", "--anchor")
        self.assertEqual((EXIT_BLOCKED, NOT_EXECUTABLE), (rc, d.get("status")), d)

    def test_la_lectura_del_diario_sigue_igual(self):
        ws = _espacio(None)
        rc, d = _cli(ws, "evidence", "--last", "2")
        self.assertEqual(EXIT_OK, rc)
        self.assertIsInstance(d, list)
        self.assertEqual(2, len(d))


if __name__ == "__main__":
    unittest.main()
