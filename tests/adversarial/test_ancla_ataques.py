# -*- coding: utf-8 -*-
"""La batería adversarial del ancla certificada (FASE 2 §12): intentos de FALSIFICAR un PASS.

Cada caso declara `input → estado esperado`, ejecuta contra `core.concordia` con un concordia
FALSO en un hilo (`tests/fixtures/ed25519_firma.ConcordiaFalso`) o contra un ancla ya escrita, y
comprueba el estado REAL. La regla que todos verifican es una sola:

    la ausencia, insuficiencia o invalidez de evidencia de concordia NUNCA se convierte en PASS

Los estados son los de refuto (`core.model`): FAIL cuando hay un hecho en contra; NOT_EXECUTABLE
cuando se intentó y no se pudo (clúster caído, plazo, basura); BLOCKED cuando falta una dependencia
declarada (el pin); INCONCLUSIVE cuando no se puede establecer la relación con el diario.

Cuatro familias: certificado · evidencia · disponibilidad · seguridad. Y al final el recuento: el
inventario declara cuántos casos hay, para que quitar uno no pase en silencio.
"""

from __future__ import annotations

import base64
import hashlib
import json
import shutil
import tempfile
import unittest
from pathlib import Path

from core import concordia as C
from core.evidence import append_event, ledger_path, verificar_cadena
from core.model import BLOCKED, FAIL, INCONCLUSIVE, NOT_EXECUTABLE, PASS
from core.trust import digest_motor
from tests.fixtures.ed25519_firma import ConcordiaFalso, certificar, membresia_sintetica

EXPORT, SECRETOS = membresia_sintetica(n=4, red="ataques")
PIN = EXPORT["membership_digest"]
AJENA = membresia_sintetica(n=4, red="ataques", seed=0xA7A0)     # misma red y época, otras claves


def _espacio(eventos: int = 5) -> Path:
    ws = Path(tempfile.mkdtemp(prefix="ancla-ataques-")).resolve()
    (ws / ".harness" / "evidence").mkdir(parents=True)
    for i in range(eventos):
        append_event(ws, {"kind": "policy/decision", "outcome": "deny", "n": i})
    return ws


def _cfg(url: str, **extra) -> dict:
    cfg = {"provider": "concordia", "endpoints": [url], "membership_digest": PIN, "timeout_s": 1.5}
    cfg.update(extra)
    return cfg


def _manifest(cfg: dict | None) -> dict:
    m = {"schema": "harness.manifest/v1", "harness": {"version": "0.1.0"}, "agents": {}, "gates": [],
         "workspace": {"name": "ataques"}}
    if cfg is not None:
        m["anchoring"] = cfg
    return m


#: El motor REAL, no uno inventado: desde el 2026-09-28 `estado_del_anclaje` comprueba que el
#: ancla la certificó el motor que ahora juzga, y un `"e" * 64` dejaría todas estas pruebas en
#: INCONCLUSIVE por la discrepancia en vez de medir lo que cada una dice medir.
MOTOR = digest_motor()


def _anclar(ws: Path, cfg: dict, pin: str = PIN, run_id: str = "ver_t") -> dict:
    return C.anclar(ws, cfg, run_id=run_id, engine_digest=MOTOR, policy_digest="p" * 64,
                    manifest=_manifest(cfg), pin=pin, cadena=verificar_cadena(ws))


class _Caso(unittest.TestCase):
    def setUp(self):
        self.ws = _espacio()
        self.registro: list = []

    def tearDown(self):
        shutil.rmtree(self.ws, ignore_errors=True)

    def esperar(self, ataque: str, esperado, real: str, evidencia: str = ""):
        ok = real in esperado if isinstance(esperado, (set, tuple)) else real == esperado
        self.assertTrue(ok, f"«{ataque}»: se esperaba {esperado} y se obtuvo {real}. {evidencia}")
        self.assertNotEqual(PASS, real) if esperado != PASS else None


# ═══════════════════════════════════════════════════════════════════════════════════════
class TestCertificado(_Caso):
    """Familia 1: el certificado que sirve el clúster está mal, y refuto tiene que verlo."""

    def _con(self, modo: str, **kw) -> dict:
        with ConcordiaFalso(EXPORT, SECRETOS, modo=modo, **kw) as srv:
            return _anclar(self.ws, _cfg(srv.url))

    def test_camino_feliz_es_pass(self):
        r = self._con("normal")
        self.esperar("certificado genuino con q firmas", PASS, r["estado"], r["motivo"])
        self.assertEqual([0, 1, 2], r["ancla"]["verification"]["signers"])

    def test_firma_modificada(self):
        r = self._con("firma_rota")
        self.esperar("un bit de una de las q firmas", FAIL, r["estado"], r["motivo"])
        self.assertIn("InsufficientQuorum", r["motivo"])
        self.assertIn("InvalidSignature", r["motivo"])

    def test_firmante_desconocido_fuera_de_membresia(self):
        r = self._con("firmante_ajeno")
        self.esperar("firma de una clave que no está en la membresía, bajo un índice real", FAIL, r["estado"], r["motivo"])

    def test_firmante_duplicado_no_suma(self):
        r = self._con("duplicado")
        self.esperar("q−1 genuinas + la primera repetida", FAIL, r["estado"], r["motivo"])
        self.assertIn("DuplicateSigner", r["motivo"])

    def test_quorum_insuficiente_en_todas_las_replicas(self):
        r = self._con("sin_quorum")
        self.esperar("q−1 atestaciones en la única réplica", NOT_EXECUTABLE, r["estado"], r["motivo"])

    def test_quorum_insuficiente_servido_parcial_por_la_unica_replica(self):
        """La única réplica sirve q−1 de un certificado que en realidad tiene q: sin otra a la que
        preguntar, no hay certificado completo. NOT_EXECUTABLE, no PASS (y no FAIL: no hay hecho
        en contra, hay evidencia insuficiente)."""
        r = self._con("parcial")
        self.esperar("q−1 servidas por la única réplica", NOT_EXECUTABLE, r["estado"], r["motivo"])

    def test_otra_membresia_coherente_no_pasa_el_pin(self):
        r = self._con("otra_membresia", ajena=AJENA)
        self.esperar("membresía forjada, misma red y época, digest recomputado", FAIL, r["estado"], r["motivo"])
        self.assertIn("PinMismatch", r["motivo"])

    def test_membresia_manipulada_con_digest_original(self):
        r = self._con("membresia_manipulada")
        self.esperar("clave sustituida, digest original", FAIL, r["estado"], r["motivo"])

    def test_carga_distinta_certificada(self):
        r = self._con("carga_distinta")
        self.esperar("el clúster certifica OTRA carga", NOT_EXECUTABLE, r["estado"], r["motivo"])

    def test_payload_b64_que_no_casa(self):
        r = self._con("payload_ajeno")
        self.esperar("payload_b64 ≠ payload_digest", FAIL, r["estado"], r["motivo"])
        self.assertIn("PayloadMismatch", r["motivo"])

    def test_campo_desconocido_en_la_entrada(self):
        r = self._con("campo_extra")
        self.esperar("campo fuera del contrato en la entrada", FAIL, r["estado"], r["motivo"])
        self.assertIn("Malformed", r["motivo"])

    def test_replay_de_una_entrada_anterior(self):
        """Segunda anclada: el clúster sirve la PRIMERA entrada con el payload_digest de la segunda.
        La firma cubre el payload_digest real, así que la reutilización se cae por firma."""
        with ConcordiaFalso(EXPORT, SECRETOS, modo="normal") as srv:
            r1 = _anclar(self.ws, _cfg(srv.url), run_id="ver_1")
            self.assertEqual(PASS, r1["estado"])
            srv.modo = "replay"
            append_event(self.ws, {"kind": "policy/decision", "outcome": "deny", "n": 99})
            r2 = _anclar(self.ws, _cfg(srv.url), run_id="ver_2")
        self.esperar("replay de la entrada 1 disfrazada de 2", FAIL, r2["estado"], r2["motivo"])

    def test_verificador_directo_rechaza_todas_las_mutaciones_del_sujeto(self):
        """Sobre un certificado genuino con exactamente q firmas: cada campo del sujeto alterado
        produce INVALID, con el motivo que la especificación dice."""
        carga = C.carga_ordenada(7, 1, b"checkpoint")
        e = certificar(EXPORT, SECRETOS, seq=1, carga=carga)
        self.assertTrue(C.verificar_certificado(EXPORT, e, pin=PIN)["valido"])
        casos = {
            "seq alterada": ({"seq": 2, "prev_entry_digest": "11" * 32,
                              "entry_digest": C.entry_digest(bytes.fromhex("11" * 32), bytes.fromhex(e["payload_digest"]))},
                             "InsufficientQuorum"),
            "payload_digest alterado (cadena recomputada)": (
                {"payload_digest": "22" * 32, "entry_digest": C.entry_digest(bytes(32), bytes.fromhex("22" * 32)),
                 "payload_b64": None}, "InsufficientQuorum"),
            "entry_digest alterado": ({"entry_digest": "33" * 32}, "BrokenChain"),
            "prev ≠ 0 en seq 1": ({"prev_entry_digest": "44" * 32}, "BrokenChain"),
            "red distinta": ({"network_id": "55" * 32}, "WrongNetwork"),
            "época distinta": ({"membership_version": 2}, "WrongMembership"),
            "digest de membresía distinto": ({"membership_digest": "66" * 32}, "WrongMembership"),
            "protocolo desconocido": ({"protocol_version": "concordia/pbft/v2"}, "UnknownProtocol"),
            "seq 0": ({"seq": 0}, "Malformed"),
            "hex malformado": ({"payload_digest": "zz"}, "Malformed"),
            "firma truncada": ({"attestations": [dict(e["attestations"][0], signature_b64=base64.b64encode(
                base64.b64decode(e["attestations"][0]["signature_b64"])[:63]).decode())] + e["attestations"][1:]},
                "InsufficientQuorum"),
            "member_id que no corresponde al índice": (
                {"attestations": [dict(e["attestations"][0], member_id=e["attestations"][1]["member_id"])] + e["attestations"][1:]},
                "InsufficientQuorum"),
            "índice fuera de la membresía": (
                {"attestations": [dict(e["attestations"][0], replica=9)] + e["attestations"][1:]}, "InsufficientQuorum"),
            "sin atestaciones": ({"attestations": []}, "InsufficientQuorum"),
            "atestaciones no es lista": ({"attestations": "x"}, "Malformed"),
            "campo extra": ({"timestamp": 1}, "Malformed"),
            "atestación con campo extra": (
                {"attestations": [dict(e["attestations"][0], ts=1)] + e["attestations"][1:]}, "InsufficientQuorum"),
        }
        for nombre, (cambios, codigo) in casos.items():
            m = json.loads(json.dumps(e))
            for k, v in cambios.items():
                if v is None:
                    m.pop(k, None)
                else:
                    m[k] = v
            r = C.verificar_certificado(EXPORT, m, pin=PIN)
            with self.subTest(caso=nombre):
                self.assertFalse(r["valido"], f"«{nombre}» verificó: {r}")
                self.assertEqual(codigo, r["codigo"], f"«{nombre}»: motivo {r['motivo']}")

    def test_serializacion_distinta_de_la_misma_entrada_da_el_mismo_veredicto(self):
        """El veredicto es del CONTENIDO, no del texto: reordenar claves o cambiar espacios no
        cambia nada; pero un carácter dentro de una firma sí."""
        carga = C.carga_ordenada(7, 1, b"checkpoint")
        e = certificar(EXPORT, SECRETOS, seq=1, carga=carga)
        texto_a = json.dumps(e, sort_keys=True, separators=(",", ":"))
        texto_b = json.dumps(e, indent=4)
        self.assertNotEqual(texto_a, texto_b)
        self.assertTrue(C.verificar_certificado(EXPORT, json.loads(texto_a), pin=PIN)["valido"])
        self.assertTrue(C.verificar_certificado(EXPORT, json.loads(texto_b), pin=PIN)["valido"])
        roto = texto_a.replace(e["attestations"][1]["signature_b64"][:6], "AAAAAA", 1)
        self.assertFalse(C.verificar_certificado(EXPORT, json.loads(roto), pin=PIN)["valido"])

    def test_los_tipos_json_ambiguos_no_cuelan(self):
        """`true` no es `1`, `"1"` no es `1`: un verificador que confunda tipos acepta lo que la
        referencia (Rust, tipado) rechaza al deserializar."""
        carga = C.carga_ordenada(7, 1, b"checkpoint")
        e = certificar(EXPORT, SECRETOS, seq=1, carga=carga)
        for campo, valor in (("seq", True), ("seq", "1"), ("seq", 1.0), ("membership_version", "1")):
            m = dict(e, **{campo: valor})
            r = C.verificar_certificado(EXPORT, m, pin=PIN)
            self.assertFalse(r["valido"], f"{campo}={valor!r} verificó")
        m = json.loads(json.dumps(e))
        m["attestations"][0]["replica"] = True
        self.assertFalse(C.verificar_certificado(EXPORT, m, pin=PIN)["valido"])
        m = json.loads(json.dumps(EXPORT))
        m["members"][0]["index"] = False
        self.assertEqual("BadMembership", C.verificar_certificado(m, e, pin=PIN)["codigo"])


# ═══════════════════════════════════════════════════════════════════════════════════════
class TestEvidencia(_Caso):
    """Familia 2: el ancla ya está escrita y alguien toca la evidencia después."""

    def setUp(self):
        super().setUp()
        with ConcordiaFalso(EXPORT, SECRETOS) as srv:
            self.r = _anclar(self.ws, _cfg(srv.url), run_id="ver_a")
        self.assertEqual(PASS, self.r["estado"])
        self.path = Path(self.r["path"])
        self.manifest = _manifest(_cfg("http://127.0.0.1:9"))   # status no habla con el clúster

    def _status(self, **kw) -> dict:
        return C.estado_del_anclaje(self.ws, self.manifest, **kw)

    def test_estado_base_es_pass_offline(self):
        s = self._status()
        self.esperar("ancla íntegra, diario íntegro", PASS, s["estado"], s["motivo"])

    def test_ancla_borrada(self):
        self.path.unlink()
        s = self._status()
        self.esperar("borrar el fichero del ancla", INCONCLUSIVE, s["estado"], s["motivo"])

    def test_ancla_truncada(self):
        self.path.write_text(self.path.read_text()[:200])
        s = self._status()
        self.esperar("truncar el ancla", INCONCLUSIVE, s["estado"], s["motivo"])
        self.assertTrue(s["ilegibles"])

    def test_ancla_con_mismo_nombre_y_otro_contenido(self):
        """El ataque del §9: ejecución válida, artefacto reemplazado después conservando el nombre."""
        doc = json.loads(self.path.read_text())
        otro = json.loads(json.dumps(doc))
        otro["checkpoint"]["root"] = "ab" * 32           # declara otra raíz
        self.path.write_text(json.dumps(otro))
        s = self._status()
        self.esperar("mismo nombre, checkpoint declarado ≠ carga certificada", FAIL, s["estado"], s["motivo"])

    def test_ancla_con_carga_y_checkpoint_coherentes_pero_certificado_de_otra_carga(self):
        doc = json.loads(self.path.read_text())
        cp = dict(doc["checkpoint"], root="cd" * 32)
        payload = C.canonico(cp)
        doc["checkpoint"], doc["payload_b64"] = cp, base64.b64encode(payload).decode()
        self.path.write_text(json.dumps(doc))
        s = self._status()
        self.esperar("checkpoint y carga reescritos, certificado antiguo", FAIL, s["estado"], s["motivo"])

    def test_ancla_de_otro_espacio(self):
        """Un ancla válida de OTRO diario copiada aquí: el certificado verifica, pero su root no
        está en este diario."""
        otro_ws = _espacio(eventos=3)
        try:
            with ConcordiaFalso(EXPORT, SECRETOS) as srv:
                r = _anclar(otro_ws, _cfg(srv.url), run_id="ver_otro")
            self.path.write_text(Path(r["path"]).read_text())
        finally:
            shutil.rmtree(otro_ws, ignore_errors=True)
        s = self._status()
        self.esperar("ancla de otro diario", FAIL, s["estado"], s["motivo"])

    def test_ancla_con_certificado_de_otra_entrada(self):
        doc = json.loads(self.path.read_text())
        e = json.loads(doc["entry_raw"])
        e["payload_digest"] = "ef" * 32
        e["entry_digest"] = C.entry_digest(bytes(32), bytes.fromhex("ef" * 32))
        doc["entry_raw"] = json.dumps(e)
        self.path.write_text(json.dumps(doc))
        s = self._status()
        self.esperar("certificado de otra entrada", FAIL, s["estado"], s["motivo"])

    def test_diario_truncado_por_detras_del_ancla(self):
        L = ledger_path(self.ws).read_text().splitlines()
        ledger_path(self.ws).write_text("\n".join(L[:2]) + "\n")
        s = self._status()
        self.esperar("truncar la cola del diario", FAIL, s["estado"], s["motivo"])

    def test_diario_reescrito_coherente(self):
        ledger_path(self.ws).unlink()
        for i in range(6):
            append_event(self.ws, {"kind": "policy/decision", "outcome": "allow", "n": i})
        s = self._status()
        self.esperar("diario reescrito entero y coherente (ataque 05)", FAIL, s["estado"], s["motivo"])

    def test_diario_borrado(self):
        ledger_path(self.ws).unlink()
        s = self._status()
        self.esperar("borrar el diario", FAIL, s["estado"], s["motivo"])

    def test_diario_vaciado(self):
        ledger_path(self.ws).write_text("")
        s = self._status()
        self.esperar("vaciar el diario", FAIL, s["estado"], s["motivo"])

    def test_rollback_a_una_copia_anterior(self):
        """El ancla se tomó con 5 eventos (+1 del propio anclaje). Volver a una copia con 3 es
        rollback: el root certificado ya no está."""
        L = ledger_path(self.ws).read_text().splitlines()
        ledger_path(self.ws).write_text("\n".join(L[:3]) + "\n")
        s = self._status()
        self.esperar("rollback a una copia anterior", FAIL, s["estado"], s["motivo"])

    def test_anadir_eventos_despues_del_ancla_no_es_ataque(self):
        for i in range(3):
            append_event(self.ws, {"kind": "policy/decision", "outcome": "deny", "n": 100 + i})
        s = self._status()
        self.esperar("añadir eventos tras el ancla (funcionamiento normal)", PASS, s["estado"], s["motivo"])

    def test_evento_de_anclaje_manipulado_rompe_la_cadena(self):
        """El evento `evidence/anchor` está encadenado: editarlo rompe el diario (y status lo ve)."""
        L = ledger_path(self.ws).read_text().splitlines()
        ev = json.loads(L[-1])
        self.assertEqual(C.KIND_ANCLA, ev["kind"])
        ev["status"] = "FAIL"
        L[-1] = json.dumps(ev, ensure_ascii=False)
        ledger_path(self.ws).write_text("\n".join(L) + "\n")
        self.assertFalse(verificar_cadena(self.ws)["ok"])
        s = self._status()
        self.esperar("editar el evento de anclaje", FAIL, s["estado"], s["motivo"])

    def test_la_ancla_no_lleva_secretos(self):
        texto = self.path.read_text()
        for s in SECRETOS:
            self.assertNotIn(s.hex(), texto)
            self.assertNotIn(base64.b64encode(s).decode(), texto)


# ═══════════════════════════════════════════════════════════════════════════════════════
class TestDisponibilidad(_Caso):
    """Familia 3: el clúster no está, tarda o contesta mal. Nada de esto es PASS."""

    def _con(self, modo: str, **kw) -> dict:
        with ConcordiaFalso(EXPORT, SECRETOS, modo=modo, **kw) as srv:
            return _anclar(self.ws, _cfg(srv.url))

    def test_caido(self):
        r = self._con("caido")
        self.esperar("clúster caído", NOT_EXECUTABLE, r["estado"], r["motivo"])
        self.assertIsNone(r["ancla"])

    def test_timeout(self):
        r = self._con("lento")
        self.esperar("plazo vencido", NOT_EXECUTABLE, r["estado"], r["motivo"])

    def test_respuesta_vacia(self):
        r = self._con("vacio")
        self.esperar("200 con cuerpo vacío", NOT_EXECUTABLE, r["estado"], r["motivo"])

    def test_json_malformado(self):
        r = self._con("basura")
        self.esperar("200 con basura", NOT_EXECUTABLE, r["estado"], r["motivo"])

    def test_orden_aceptada_pero_nunca_ordenada(self):
        r = self._con("no_ordena")
        self.esperar("accepted:true y la entrada nunca aparece", NOT_EXECUTABLE, r["estado"], r["motivo"])

    def test_orden_rechazada_con_502(self):
        r = self._con("acepta_pero_502")
        self.esperar("/v1/order → 502", NOT_EXECUTABLE, r["estado"], r["motivo"])

    def test_certificado_incompleto_en_una_replica_se_completa_en_otra(self):
        """La réplica lenta sirve q−1; la otra sirve q. El consumidor pregunta a las dos."""
        with ConcordiaFalso(EXPORT, SECRETOS, modo="parcial") as lenta, \
                ConcordiaFalso(EXPORT, SECRETOS, comparte_log_con=lenta) as sana:
            cfg = _cfg(lenta.url)
            cfg["endpoints"] = [lenta.url, sana.url]
            r = _anclar(self.ws, cfg)
        self.esperar("réplica con certificado incompleto + réplica completa", PASS, r["estado"], r["motivo"])
        self.assertTrue(r["ancla"]["incomplete_replicas"], "la réplica incompleta queda anotada")

    def test_el_fallo_deja_evento_pero_no_ancla(self):
        self._con("caido")
        eventos = [json.loads(l) for l in ledger_path(self.ws).read_text().splitlines()]
        ultimo = eventos[-1]
        self.assertEqual(C.KIND_ANCLA, ultimo["kind"])
        self.assertEqual(NOT_EXECUTABLE, ultimo["status"])
        self.assertFalse(list(C.dir_anclas(self.ws).glob("*.json")) if C.dir_anclas(self.ws).is_dir() else [])

    def test_diario_roto_no_se_ancla(self):
        L = ledger_path(self.ws).read_text().splitlines()
        ev = json.loads(L[2])
        ev["outcome"] = "allow"
        L[2] = json.dumps(ev)
        ledger_path(self.ws).write_text("\n".join(L) + "\n")
        with ConcordiaFalso(EXPORT, SECRETOS) as srv:
            r = _anclar(self.ws, _cfg(srv.url))
        self.esperar("anclar un diario ROTO", FAIL, r["estado"], r["motivo"])


# ═══════════════════════════════════════════════════════════════════════════════════════
class TestSeguridad(_Caso):
    """Familia 4: la membresía, el pin y la frontera de confianza."""

    def test_sin_pin_es_blocked(self):
        cfg = _cfg("http://127.0.0.1:9")
        del cfg["membership_digest"]
        p = C.resolver_pin(cfg)
        self.esperar("manifiesto sin pin", BLOCKED, p["estado"], p["motivo"])
        s = C.estado_del_anclaje(self.ws, _manifest(cfg))
        self.esperar("status sin pin", BLOCKED, s["estado"], s["motivo"])

    def test_pin_malformado_es_fail(self):
        p = C.resolver_pin(_cfg("x", membership_digest="ABC"))
        self.esperar("pin que no es hex de 32 bytes", FAIL, p["estado"], p["motivo"])

    def test_dos_fuentes_que_discrepan_es_fail(self):
        p = C.resolver_pin(_cfg("x"), externo="ab" * 32)
        self.esperar("manifiesto e invocador discrepan", FAIL, p["estado"], p["motivo"])
        self.assertIsNone(p["pin"])

    def test_dos_fuentes_que_coinciden_es_pass_con_fuente_ambas(self):
        p = C.resolver_pin(_cfg("x"), externo=PIN)
        self.assertEqual(PASS, p["estado"])
        self.assertEqual("ambas", p["fuente"])

    def test_solo_invocador_basta(self):
        cfg = _cfg("x")
        del cfg["membership_digest"]
        p = C.resolver_pin(cfg, externo=PIN)
        self.assertEqual((PASS, "invocador"), (p["estado"], p["fuente"]))

    def test_cambiar_el_pin_despues_invalida_las_anclas_anteriores(self):
        """«Cómo se audita un cambio»: un pin nuevo deja todo lo anclado antes en FAIL, visible."""
        with ConcordiaFalso(EXPORT, SECRETOS) as srv:
            r = _anclar(self.ws, _cfg(srv.url))
        self.assertEqual(PASS, r["estado"])
        s = C.estado_del_anclaje(self.ws, _manifest(_cfg("x", membership_digest=AJENA[0]["membership_digest"])))
        self.esperar("pin cambiado tras anclar", FAIL, s["estado"], s["motivo"])
        self.assertIn("PinMismatch", s["motivo"])

    def test_el_pin_nunca_se_toma_del_cluster(self):
        """Aunque el clúster sirva una membresía perfectamente coherente, sin pin no hay PASS."""
        cfg = _cfg("x")
        del cfg["membership_digest"]
        with ConcordiaFalso(EXPORT, SECRETOS) as srv:
            cfg["endpoints"] = [srv.url]
            m = _manifest(cfg)
            s_antes = C.estado_del_anclaje(self.ws, m)
        self.esperar("clúster coherente y sin pin", BLOCKED, s_antes["estado"], s_antes["motivo"])

    def test_inyectar_una_clave_en_la_membresia_servida(self):
        """El atacante añade su clave como quinto miembro: n=5 cambia f/q y el digest → PinMismatch."""
        export = json.loads(json.dumps(EXPORT))
        export["members"].append({"index": 4, "member_id": "member-0004", "public_key_hex": "77" * 32})
        export["quorum_rule"] = {"n": 5, "f": 1, "q": 4, "formula": C.QUORUM_FORMULA}
        ms = C.Membresia(bytes.fromhex(export["network_id"]), 1, [(m["member_id"], bytes.fromhex(m["public_key_hex"])) for m in export["members"]])
        export["membership_digest"] = ms.digest
        e = certificar(EXPORT, SECRETOS, seq=1, carga=b"x")
        r = C.verificar_certificado(export, e, pin=PIN)
        self.esperar("membresía con una clave inyectada", FAIL, FAIL if not r["valido"] else PASS, r["motivo"])
        self.assertEqual("PinMismatch", r["codigo"])

    def test_una_respuesta_remota_con_valid_true_no_es_pass(self):
        """Si el clúster devolviera un veredicto («valid: true»), refuto lo ignora: no hay campo que
        lo represente en el contrato, así que es un campo extra → Malformed."""
        e = certificar(EXPORT, SECRETOS, seq=1, carga=b"x", firmantes=[0])
        e["valid"] = True
        r = C.verificar_certificado(EXPORT, e, pin=PIN)
        self.assertFalse(r["valido"])

    def test_solo_local_hasta_la_publicacion(self):
        """Decisión de la persona (2026-09-27): el anclaje sólo contra loopback. Un endpoint remoto
        es BLOCKED antes de abrir ninguna conexión, y el esquema del manifiesto lo rechaza también."""
        from core.schema import load_schema, validate
        # Hosts de documentación (RFC 2606 / RFC 5737): el repositorio es público y su preflight rechaza
        # direcciones privadas y formas de correo. Los dos casos con `@` se construyen por
        # concatenación para que el fuente no contenga la forma `x@y.z` contigua.
        remotos = ["http://concordia.example", "https://203.0.113.5:8300", "http://concordia:8300",
                   "http://127.0.0.1.evil.example:8300", "ftp://127.0.0.1:8300", "http://[::2]:8300", "no-es-url",
                   "http://LOCALHOST:1", "http://user@" + "127.0.0.1" + "@evil.example:8300",
                   "http://127.0.0.1:8300" + "@evil.example"]
        for e in remotos:
            self.assertFalse(C.es_local(e), e)
            cfg = _cfg(e)
            r = _anclar(self.ws, cfg)
            self.esperar(f"endpoint no local {e}", BLOCKED, r["estado"], r["motivo"])
            self.assertIn("sólo contra réplicas locales", r["motivo"])
            errores = validate(_manifest(cfg), load_schema("manifest.schema.json"))
            self.assertTrue(errores, f"el esquema aceptó {e}")
        # y ninguno de esos intentos dejó evento de red ni ancla
        kinds = [json.loads(l)["kind"] for l in ledger_path(self.ws).read_text().splitlines()]
        self.assertNotIn(C.KIND_ANCLA, kinds)
        for e in ["http://127.0.0.1:8300", "http://localhost:8300/", "https://[::1]:8443", "http://127.0.0.1"]:
            self.assertTrue(C.es_local(e), e)
            self.assertEqual([], validate(_manifest(_cfg(e)), load_schema("manifest.schema.json")), e)
        # un endpoint local seguido de uno remoto también se bloquea: la lista entera tiene que ser local
        cfg = _cfg("http://127.0.0.1:9")
        cfg["endpoints"].append("http://concordia.example:8300")
        self.esperar("lista con un remoto", BLOCKED, _anclar(self.ws, cfg)["estado"])

    def test_el_verificador_offline_no_toca_la_red(self):
        """`verificar_ancla` con endpoints imposibles: si intentara la red, fallaría distinto."""
        with ConcordiaFalso(EXPORT, SECRETOS) as srv:
            r = _anclar(self.ws, _cfg(srv.url))
        v = C.verificar_ancla(self.ws, r["ancla"], pin=PIN)
        self.assertEqual(PASS, v["estado"], v["motivo"])
        # y sin ningún servidor vivo, igual
        v2 = C.verificar_ancla(self.ws, r["ancla"], pin=PIN)
        self.assertEqual(PASS, v2["estado"])


class TestRecuento(unittest.TestCase):
    def test_el_inventario_declara_cuantos_ataques_hay(self):
        import inspect
        n = sum(1 for cls in (TestCertificado, TestEvidencia, TestDisponibilidad, TestSeguridad)
                for nombre, _ in inspect.getmembers(cls, inspect.isfunction) if nombre.startswith("test_"))
        self.assertEqual(50, n, f"el inventario declara 50 casos adversariales y hay {n}: "
                                f"si quitó uno, diga por qué en la clasificación")


if __name__ == "__main__":
    unittest.main()
