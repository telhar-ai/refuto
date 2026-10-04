# -*- coding: utf-8 -*-
"""`core.regla_validez`: el consumo de la identidad de regla de concordia (`CERTIFICATE-SPEC §11`).

Lo que se fija aquí:

1. **La forma canónica**, contra los valores que concordia publica: 1 532 bytes y
   `probe_set_digest = c85f3039…`. Se recomputa con la biblioteca estándar y sin leer el
   código de concordia, que es lo que hace consumible el mecanismo (`ADR-0002`).
2. **La divergencia MEDIDA el 2026-09-30**: refuto difiere de la regla estricta en la sonda
   `05` y sólo en ésa. El test la fija a propósito. Si alguien relaja `ed25519._decode` para
   que los digests casen, esto lo dice: hacer que case debilitando el verificador es
   exactamente lo que no se debe hacer.
3. **Ninguna entrada degenerada aprueba**, y cada una da una resolución distinta: reportar
   una divergencia de regla como «firma inválida» la haría indistinguible de una réplica
   bizantina, que es el error que el mecanismo existe para eliminar.
4. **El paso de recomputar no se puede omitir**: un documento con los veredictos de una regla
   y el digest de otra tiene que rechazarse.
"""

from __future__ import annotations

import hashlib
import json
import threading
import unittest
from http.server import BaseHTTPRequestHandler, HTTPServer

from core import concordia as C
from core import regla_validez as R
from core.model import BLOCKED, FAIL, INCONCLUSIVE, PASS

# Valores PUBLICADOS por concordia (`hicon validity-rule`, `CERTIFICATE-SPEC §11.7`).
# Son la contraparte externa: si el conjunto de sondas de refuto se moviera, dejarían de casar.
CONCORDIA_PROBE_SET_DIGEST = "c85f30395910d730a9e46f25e6bdb2960dca69671154f9e3f803a2b6e81e7a6d"
CONCORDIA_ESTRICTA_VERDICTS = "ASSKSKKKSSK"
CONCORDIA_ESTRICTA_DIGEST = "e886de20d82a5d13209f9d74f600dd5db1eca7b4d3cbf90a76fc66cc6e36ba16"
# La regla PERMISIVA (`e57bc7a`, dalek `verify`) — recuperada por fuerza bruta sobre las
# 3^11 = 177 147 combinaciones posibles el 2026-09-30: preimagen única.
CONCORDIA_PERMISIVA_VERDICTS = "ASSKSAASSSS"
CONCORDIA_PERMISIVA_DIGEST = "e017379690ee5c985b62c1e50ed09b878226ed69f3ef25fa52d6e6b9d9a9bd36"

BYTES_FORMA_CANONICA = 1532
SONDA_DIVERGENTE = "05-noncanonical-y-encoding-admitted"


def documento(verdicts: str, /, **override) -> dict:
    """Un documento de identidad COHERENTE para `verdicts` (digest recomputado)."""
    doc = {
        "rule_id": R.RULE_ID,
        "probe_count": len(R.SONDAS),
        "verdicts": verdicts,
        "probe_set_digest": R.PROBE_SET_DIGEST,
        "digest": hashlib.sha256(R.forma_canonica(verdicts)).hexdigest(),
    }
    doc.update(override)
    return doc


class FormaCanonica(unittest.TestCase):
    """§11.4 — reproducible con sólo la biblioteca estándar."""

    def test_longitud_y_digest_del_instrumento(self):
        canon = R.forma_canonica(CONCORDIA_ESTRICTA_VERDICTS)
        self.assertEqual(len(canon), BYTES_FORMA_CANONICA)
        sin_v = R.forma_canonica(None)
        # Sin los bytes de veredicto: exactamente una sonda menos.
        self.assertEqual(len(sin_v), BYTES_FORMA_CANONICA - len(R.SONDAS))
        self.assertEqual(hashlib.sha256(sin_v).hexdigest(), CONCORDIA_PROBE_SET_DIGEST)

    def test_reproduce_el_digest_estricto_de_concordia(self):
        """Mismo instrumento + mismos veredictos = mismo digest. Es lo que hace comparable."""
        canon = R.forma_canonica(CONCORDIA_ESTRICTA_VERDICTS)
        self.assertEqual(hashlib.sha256(canon).hexdigest(), CONCORDIA_ESTRICTA_DIGEST)

    def test_reproduce_el_digest_permisivo(self):
        """La regla que el clúster ejecutaba. Separar las dos es el propósito del mecanismo."""
        canon = R.forma_canonica(CONCORDIA_PERMISIVA_VERDICTS)
        self.assertEqual(hashlib.sha256(canon).hexdigest(), CONCORDIA_PERMISIVA_DIGEST)

    def test_las_dos_reglas_se_separan_en_cuatro_sondas(self):
        dif = [i for i, (a, b) in enumerate(zip(CONCORDIA_ESTRICTA_VERDICTS,
                                                CONCORDIA_PERMISIVA_VERDICTS, strict=True)) if a != b]
        self.assertEqual(len(dif), 4)
        self.assertNotEqual(CONCORDIA_ESTRICTA_DIGEST, CONCORDIA_PERMISIVA_DIGEST)

    def test_el_probe_set_digest_no_depende_de_los_veredictos(self):
        """Identifica el INSTRUMENTO. Si dependiera de la regla, no podría decir «no comparable»."""
        self.assertEqual(R.forma_canonica(None),
                         R.forma_canonica(None, R.SONDAS))
        for v in (CONCORDIA_ESTRICTA_VERDICTS, CONCORDIA_PERMISIVA_VERDICTS):
            ident = {"verdicts": v}
            self.assertEqual(hashlib.sha256(R.forma_canonica(None)).hexdigest(),
                             CONCORDIA_PROBE_SET_DIGEST, ident)

    def test_sondas_ordenadas_y_sin_repetidos(self):
        ids = [s[0] for s in R.SONDAS]
        self.assertEqual(ids, sorted(ids))
        self.assertEqual(len(set(ids)), len(ids))

    def test_orden_incorrecto_no_se_canonicaliza_en_silencio(self):
        revueltas = tuple(reversed(R.SONDAS))
        with self.assertRaises(ValueError):
            R.forma_canonica(None, revueltas)

    def test_longitud_de_veredictos_incoherente(self):
        with self.assertRaises(ValueError):
            R.forma_canonica("AS")

    def test_veredicto_ilegible(self):
        malo = "Z" + CONCORDIA_ESTRICTA_VERDICTS[1:]
        with self.assertRaises(ValueError):
            R.forma_canonica(malo)


class IdentidadPropia(unittest.TestCase):

    def test_es_determinista(self):
        self.assertEqual(R.identidad_propia(), R.identidad_propia())

    def test_usa_el_mismo_instrumento_que_concordia(self):
        """Si esto falla, las sondas se movieron y nada es comparable."""
        self.assertEqual(R.identidad_propia()["probe_set_digest"], CONCORDIA_PROBE_SET_DIGEST)
        self.assertEqual(R.PROBE_SET_DIGEST, CONCORDIA_PROBE_SET_DIGEST)

    def test_el_control_positivo_se_acepta(self):
        """Una regla que rechaza la firma válida de RFC 8032 no es estricta: está rota."""
        self.assertEqual(R.identidad_propia()["verdicts"][0], R.ACEPTA)

    def test_conjunto_vacio_no_produce_identidad(self):
        """Un ámbito vacío nunca aprueba: tampoco identifica una regla."""
        with self.assertRaises(ValueError):
            R.identidad_propia(())


class DivergenciaMedida(unittest.TestCase):
    """El hecho medido el 2026-09-30, fijado para que no se pierda ni se «arregle» en silencio."""

    def test_refuto_difiere_de_la_estricta_solo_en_la_sonda_05(self):
        propios = R.identidad_propia()["verdicts"]
        dif = [R.SONDAS[i][0] for i, (a, b) in
               enumerate(zip(CONCORDIA_ESTRICTA_VERDICTS, propios, strict=True)) if a != b]
        self.assertEqual(dif, [SONDA_DIVERGENTE],
                         "la divergencia con concordia cambió: mídela y declárala, no la absorbas")

    def test_la_divergencia_es_de_etapa_y_en_direccion_segura(self):
        """concordia admite la clave `y` no canónica y falla en la firma (S); refuto la rechaza
        en admisión (K). refuto rechaza MÁS, que es la dirección segura — pero es otra regla."""
        i = [n for n, s in enumerate(R.SONDAS) if s[0] == SONDA_DIVERGENTE][0]
        self.assertEqual(CONCORDIA_ESTRICTA_VERDICTS[i], R.RECHAZA_FIRMA)
        self.assertEqual(R.identidad_propia()["verdicts"][i], R.RECHAZA_CLAVE)

    def test_el_digest_propio_no_es_el_de_concordia(self):
        self.assertNotEqual(R.identidad_propia()["digest"], CONCORDIA_ESTRICTA_DIGEST)

    def test_consumir_la_estricta_declara_divergencia_no_firma_invalida(self):
        r = R.consumir(documento(CONCORDIA_ESTRICTA_VERDICTS,
                                 digest=CONCORDIA_ESTRICTA_DIGEST))
        self.assertEqual(r["resolucion"], R.REGLA_DIVERGENTE)
        self.assertEqual(r["estado"], FAIL)
        self.assertEqual([d["sonda"] for d in r["divergentes"]], [SONDA_DIVERGENTE])
        self.assertIn(SONDA_DIVERGENTE, r["motivo"])


class Consumir(unittest.TestCase):

    def test_la_propia_identidad_concuerda(self):
        """`CONCUERDA` tiene que ser alcanzable, o el `PASS` nunca estaría probado."""
        r = R.consumir(R.identidad_propia())
        self.assertEqual(r["resolucion"], R.CONCUERDA)
        self.assertEqual(r["estado"], PASS)
        self.assertEqual(r["divergentes"], [])

    def test_ausente_no_aprueba(self):
        r = R.consumir(None)
        self.assertEqual(r["resolucion"], R.NO_DECLARADA)
        self.assertEqual(r["estado"], BLOCKED)

    def test_documento_incoherente_veredictos_de_una_regla_digest_de_otra(self):
        """El paso que no se puede omitir (§11.5.3): sin él, esto pasaría como válido."""
        doc = documento(CONCORDIA_PERMISIVA_VERDICTS, digest=CONCORDIA_ESTRICTA_DIGEST)
        r = R.consumir(doc)
        self.assertEqual(r["resolucion"], R.DOCUMENTO_INCOHERENTE)
        self.assertEqual(r["estado"], FAIL)

    def test_coherente_pero_mentiroso_se_caza_en_la_comparacion(self):
        """Un publicador que recomputa su digest pasa el paso 3. El paso 4 es quien lo para:
        el digest publicado es una afirmación, no una autoridad."""
        todo_acepta = R.ACEPTA * len(R.SONDAS)
        r = R.consumir(documento(todo_acepta))
        self.assertEqual(r["resolucion"], R.REGLA_DIVERGENTE)
        self.assertEqual(r["estado"], FAIL)
        self.assertGreater(len(r["divergentes"]), 0)

    def test_instrumento_distinto_no_es_discrepar(self):
        r = R.consumir(documento(CONCORDIA_ESTRICTA_VERDICTS, probe_set_digest="00" * 32))
        self.assertEqual(r["resolucion"], R.INSTRUMENTO_DISTINTO)
        self.assertEqual(r["estado"], INCONCLUSIVE)

    def test_otra_regla_no_se_compara(self):
        r = R.consumir(documento(CONCORDIA_ESTRICTA_VERDICTS, rule_id="otra/regla/v1"))
        self.assertEqual(r["resolucion"], R.INSTRUMENTO_DISTINTO)

    def test_probe_count_contradictorio(self):
        r = R.consumir(documento(CONCORDIA_ESTRICTA_VERDICTS, probe_count=99))
        self.assertEqual(r["resolucion"], R.INSTRUMENTO_DISTINTO)

    def test_ninguna_entrada_degenerada_aprueba(self):
        degenerados = [
            None, [], "", 0, 3.14, {},
            {"rule_id": R.RULE_ID},
            documento(CONCORDIA_ESTRICTA_VERDICTS, verdicts=None),
            documento(CONCORDIA_ESTRICTA_VERDICTS, verdicts=""),
            documento(CONCORDIA_ESTRICTA_VERDICTS, verdicts="ASSKSKKKSS"),
            documento(CONCORDIA_ESTRICTA_VERDICTS, verdicts="ASSKSKKKSSZ"),
            documento(CONCORDIA_ESTRICTA_VERDICTS, digest="00" * 32),
            documento(CONCORDIA_ESTRICTA_VERDICTS, digest=None),
        ]
        for d in degenerados:
            r = R.consumir(d)
            self.assertNotEqual(r["estado"], PASS, f"aprobó con {d!r}")
            self.assertIn(r["resolucion"], R.ESTADO_DE)
            self.assertTrue(r["motivo"], f"sin motivo para {d!r}")

    def test_toda_resolucion_trae_la_identidad_propia(self):
        """Para que quien lee la evidencia pueda comparar sin volver a ejecutar nada."""
        for d in (None, {}, R.identidad_propia(),
                  documento(CONCORDIA_ESTRICTA_VERDICTS, digest=CONCORDIA_ESTRICTA_DIGEST)):
            self.assertEqual(R.consumir(d)["propio"]["probe_set_digest"], R.PROBE_SET_DIGEST)

    def test_consumir_nunca_lanza_por_la_forma_de_la_entrada(self):
        for d in (None, [], "x", 0, {"verdicts": 3}, {"rule_id": None},
                  documento(CONCORDIA_ESTRICTA_VERDICTS, probe_count="once")):
            R.consumir(d)   # no debe lanzar


class EtapaDelRechazo(unittest.TestCase):
    """`ed25519.admite_clave` es R1 aislada de R2 (§11.2)."""

    def test_clave_valida_se_admite(self):
        pk = bytes.fromhex(R.SONDAS[0][1])
        self.assertTrue(R.ed25519.admite_clave(pk))

    def test_orden_pequeno_y_longitud_se_rechazan_en_admision(self):
        for hexa in ("00" * 32, "01" + "00" * 31, "11" * 31):
            self.assertFalse(R.ed25519.admite_clave(bytes.fromhex(hexa)), hexa)

    def test_tipos_incorrectos_no_lanzan(self):
        for malo in (None, "", 0, [], b"", bytearray(32)):
            R.ed25519.admite_clave(malo)

    def test_tres_veredictos_alcanzables(self):
        self.assertEqual(set(R.identidad_propia()["verdicts"]),
                         {R.ACEPTA, R.RECHAZA_FIRMA, R.RECHAZA_CLAVE})


class ReglaPorHTTP(unittest.TestCase):
    """`core.concordia.regla_de_validez`: lo que se lee de una réplica viva.

    El caso que más importa es el tercero: el clúster desplegado el 2026-09-30 corre `e57bc7a`,
    que NO publica `validity_rule`. Una réplica que contesta 200 sin el campo no puede
    aprobar — es el mismo patrón que una herramienta de análisis que cae, no escanea nada y
    deja la puerta en verde."""

    def _con_status(self, cuerpo: bytes | None, codigo: int = 200):
        """Levanta un notario que sirve `cuerpo` en `/v1/status` y devuelve la resolución."""
        class H(BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def do_GET(self):
                if cuerpo is None:
                    self.send_response(404)
                    self.end_headers()
                    return
                self.send_response(codigo)
                self.send_header("content-type", "application/json")
                self.send_header("content-length", str(len(cuerpo)))
                self.end_headers()
                self.wfile.write(cuerpo)

        srv = HTTPServer(("127.0.0.1", 0), H)
        hilo = threading.Thread(target=srv.serve_forever, daemon=True)
        hilo.start()
        try:
            return C.regla_de_validez(f"http://127.0.0.1:{srv.server_address[1]}",
                                      plazo=C.Plazo(5))
        finally:
            srv.shutdown()
            srv.server_close()

    def test_replica_que_publica_nuestra_regla_concuerda(self):
        cuerpo = json.dumps({"validity_rule": R.identidad_propia()}).encode()
        r = self._con_status(cuerpo)
        self.assertEqual(r["resolucion"], R.CONCUERDA)
        self.assertEqual(r["estado"], PASS)

    def test_replica_con_la_regla_estricta_de_concordia_diverge(self):
        ident = documento(CONCORDIA_ESTRICTA_VERDICTS, digest=CONCORDIA_ESTRICTA_DIGEST)
        r = self._con_status(json.dumps({"validity_rule": ident}).encode())
        self.assertEqual(r["resolucion"], R.REGLA_DIVERGENTE)
        self.assertEqual(r["estado"], FAIL)

    def test_replica_anterior_al_mecanismo_no_aprueba(self):
        """200, JSON legítimo, sin `validity_rule`: el clúster vivo. `BLOCKED`, nunca `PASS`."""
        cuerpo = json.dumps({"view": 3, "is_primary": True, "commit": "e57bc7a"}).encode()
        r = self._con_status(cuerpo)
        self.assertEqual(r["resolucion"], R.NO_DECLARADA)
        self.assertEqual(r["estado"], BLOCKED)

    def test_status_ausente_no_aprueba(self):
        r = self._con_status(None)
        self.assertEqual(r["resolucion"], R.NO_DECLARADA)
        self.assertEqual(r["estado"], BLOCKED)
        self.assertIn("/v1/status", r["motivo"])

    def test_status_ilegible_no_aprueba(self):
        r = self._con_status(b"no soy json")
        self.assertEqual(r["resolucion"], R.NO_DECLARADA)
        self.assertEqual(r["estado"], BLOCKED)

    def test_validity_rule_de_tipo_absurdo_no_aprueba(self):
        for valor in ("x", 3, [], {}, None):
            r = self._con_status(json.dumps({"validity_rule": valor}).encode())
            self.assertNotEqual(r["estado"], PASS, valor)

    def test_el_diagnostico_siempre_trae_la_clave(self):
        """Una réplica caída también declara su regla: sin la clave, «no se comprobó» se
        confundiría con «no diverge» por la ausencia de un campo."""
        d = C.diagnosticar_endpoint("http://127.0.0.1:1", plazo=C.Plazo(1))
        self.assertIn(d["status"], (C.UNAVAILABLE, C.NOT_EXECUTABLE))
        self.assertEqual(d["validity_rule"]["resolucion"], R.NO_DECLARADA)
        self.assertEqual(d["validity_rule"]["estado"], BLOCKED)

    def test_la_regla_no_coacciona_el_estado_del_diagnostico(self):
        """Divergir de regla y estar caída son cosas distintas y se arreglan distinto."""
        self.assertNotIn(R.REGLA_DIVERGENTE, (C.VALID, C.INVALID, C.UNAVAILABLE))
        d = C.diagnosticar_endpoint("http://127.0.0.1:1", plazo=C.Plazo(1))
        self.assertNotEqual(d["status"], R.REGLA_DIVERGENTE)


if __name__ == "__main__":
    unittest.main()
