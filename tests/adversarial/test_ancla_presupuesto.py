# -*- coding: utf-8 -*-
"""Lo que la auditoría del 2026-09-28 encontró abierto en el ancla certificada, y que ahora se
cierra con una prueba cada cosa. Tres familias, todas nacidas de una medición, no de una idea:

**Presupuesto.** `timeout_s` se leía como plazo por PETICIÓN y se entregaba a `urlopen`. El plazo
de `urllib` es por operación de socket y se reinicia con cada byte recibido, así que una réplica
que gotea la respuesta lo alarga sin vencerlo nunca; y el bucle de espera sólo miraba el reloj
ENTRE pasadas. Medido contra un clúster hostil local: **34,4 s declarando 2 s** con una réplica y
**104,7 s** con cuatro. Aquí se exige que la duración quede acotada, no sólo que el estado sea el
correcto: el estado ya lo era (`NOT_EXECUTABLE`), y aun así un `verify` se colgaba dos minutos.

**Atribución.** El checkpoint graba `engine_digest` y nadie lo volvía a mirar. Medido: se ancló
con un motor, se releyó el ancla con otro **mutado**, y el resultado fue `PASS` sin una palabra.
Una discrepancia no es `FAIL` —actualizar refuto es legítimo y el certificado sigue siendo
válido— pero tampoco `PASS`: es `INCONCLUSIVE`, y se cierra volviendo a anclar.

**Declaración.** Un `policy_digest` que no se pudo determinar se escribía `""` dentro de la carga
que firma el quórum. Un campo vacío no dice «no se pudo»: no dice nada. Ahora dice
`irresoluble`, que es la palabra que el resto del sistema ya usaba para este mismo dato.
"""

from __future__ import annotations

import json
import shutil
import tempfile
import threading
import time
import unittest
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

from core import concordia as C
from core.evidence import append_event, verificar_cadena
from core.model import INCONCLUSIVE, NOT_EXECUTABLE, PASS
from core.trust import digest_motor
from tests.fixtures.ed25519_firma import ConcordiaFalso, membresia_sintetica

EXPORT, SECRETOS = membresia_sintetica(n=4, red="presupuesto")
PIN = EXPORT["membership_digest"]
MOTOR = digest_motor()


def _espacio(eventos: int = 5) -> Path:
    ws = Path(tempfile.mkdtemp(prefix="ancla-presupuesto-")).resolve()
    (ws / ".harness" / "evidence").mkdir(parents=True)
    for i in range(eventos):
        append_event(ws, {"kind": "policy/decision", "outcome": "deny", "n": i})
    return ws


class _Base(unittest.TestCase):
    def setUp(self):
        self.ws = _espacio()

    def tearDown(self):
        shutil.rmtree(self.ws, ignore_errors=True)

    def _anclar(self, cfg: dict, *, engine_digest: str = MOTOR, policy_digest: str = "p" * 64) -> dict:
        return C.anclar(self.ws, cfg, run_id="ver_p", engine_digest=engine_digest,
                        policy_digest=policy_digest, manifest={"anchoring": cfg}, pin=PIN,
                        cadena=verificar_cadena(self.ws))


# ═══════════════════════════════════════════════════════════════════════════════════════
class TestPresupuesto(_Base):
    """El plazo declarado tiene que acotar la operación ENTERA, no cada petición por separado."""

    PLAZO = 1.0
    #: Holgura generosa: lo que se afirma es que la duración es del ORDEN del plazo, no que sea
    #: exacta. Sin el presupuesto esto se iba a decenas de segundos, así que el margen no puede
    #: ocultar la regresión que vigila.
    TECHO = 5 * PLAZO + 2.0

    def _con_goteo(self, replicas: int) -> tuple:
        """`replicas` réplicas que gotean `/v1/log`. Devuelve `(estado, duración)`."""
        primero = ConcordiaFalso(EXPORT, SECRETOS, modo="goteo", pausa=0.2)
        with primero as a:
            otras = [ConcordiaFalso(EXPORT, SECRETOS, modo="goteo", pausa=0.2, comparte_log_con=primero)
                     for _ in range(replicas - 1)]
            abiertas = [o.__enter__() for o in otras]
            try:
                cfg = {"provider": "concordia", "endpoints": [a.url] + [o.url for o in abiertas],
                       "membership_digest": PIN, "timeout_s": self.PLAZO}
                inicio = time.monotonic()
                r = self._anclar(cfg)
                return r, time.monotonic() - inicio
            finally:
                for o in otras:
                    o.__exit__(None, None, None)

    def test_una_replica_que_gotea_no_alarga_el_plazo(self):
        r, duracion = self._con_goteo(1)
        self.assertEqual(NOT_EXECUTABLE, r["estado"], r["motivo"])
        self.assertLess(duracion, self.TECHO,
                        f"el plazo declarado es {self.PLAZO} s y el anclaje tardó {duracion:.1f} s: "
                        f"`timeout_s` no está acotando la operación")

    def test_cuatro_replicas_que_gotean_tampoco(self):
        """El peor caso que se midió: el coste NO puede multiplicarse por el número de réplicas."""
        r, duracion = self._con_goteo(4)
        self.assertEqual(NOT_EXECUTABLE, r["estado"], r["motivo"])
        self.assertLess(duracion, self.TECHO,
                        f"cuatro réplicas lentas y {duracion:.1f} s con un plazo de {self.PLAZO} s: "
                        f"el presupuesto se está gastando una vez por réplica")

    def test_el_presupuesto_agotado_es_no_disponible_y_no_abre_mas_peticiones(self):
        plazo = C.Plazo(0.2)
        time.sleep(0.25)
        self.assertTrue(plazo.agotado())
        with self.assertRaises(C.NoDisponible):
            plazo.para_peticion()

    def test_el_plazo_nunca_es_cero_ni_negativo(self):
        """Un `timeout_s` absurdo no puede convertirse en `urlopen(timeout=0)`, que no espera nada
        y volvería indistinguible «no contestó» de «no se preguntó»."""
        for absurdo in (0, -5, 0.0001):
            self.assertGreaterEqual(C.Plazo(absurdo).total, 0.1, absurdo)

    def test_una_respuesta_gigante_es_no_disponible_y_no_se_carga_en_memoria(self):
        """Una réplica que empieza a servir más de lo que cabe es tan indisponible como una caída.
        Antes `resp.read()` sin límite se lo tragaba entero."""
        exceso = C.LIMITE_RESPUESTA + 1

        class H(BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def do_GET(self):
                self.send_response(200)
                self.send_header("content-type", "application/json")
                self.send_header("content-length", str(exceso))
                self.end_headers()
                try:
                    self.wfile.write(b"\x20" * exceso)
                except OSError:
                    pass

        srv = HTTPServer(("127.0.0.1", 0), H)
        hilo = threading.Thread(target=srv.serve_forever, daemon=True)
        hilo.start()
        try:
            with self.assertRaises(C.NoDisponible) as caja:
                C._http(f"http://127.0.0.1:{srv.server_address[1]}/v1/log", plazo=C.Plazo(5))
            self.assertIn("pasa de", str(caja.exception))
        finally:
            srv.shutdown()
            srv.server_close()


# ═══════════════════════════════════════════════════════════════════════════════════════
class TestAtribucion(_Base):
    """El ancla dice qué motor produjo el veredicto; releerla con otro motor no puede ser PASS."""

    def setUp(self):
        super().setUp()
        with ConcordiaFalso(EXPORT, SECRETOS) as srv:
            self.cfg = {"provider": "concordia", "endpoints": [srv.url], "membership_digest": PIN}
            self.r = self._anclar(self.cfg)
        self.assertEqual(PASS, self.r["estado"], self.r["motivo"])
        self.manifest = {"anchoring": self.cfg}

    def test_el_mismo_motor_sigue_siendo_pass(self):
        s = C.estado_del_anclaje(self.ws, self.manifest, engine_digest=MOTOR)
        self.assertEqual(PASS, s["estado"], s["motivo"])
        self.assertTrue(s["detalle"]["motor"]["coincide"])

    def test_sin_decir_el_motor_se_usa_el_de_este_proceso(self):
        """Fail-closed: omitir el parámetro NO desactiva la comprobación. Si la desactivara, todo
        llamador que se olvidara de pasarlo perdería el control sin enterarse."""
        s = C.estado_del_anclaje(self.ws, self.manifest)
        self.assertEqual(PASS, s["estado"], s["motivo"])
        self.assertEqual(MOTOR, s["detalle"]["motor"]["vigente"])

    def test_otro_motor_no_es_pass_y_dice_por_que(self):
        s = C.estado_del_anclaje(self.ws, self.manifest, engine_digest="f" * 64)
        self.assertEqual(INCONCLUSIVE, s["estado"])
        self.assertIn("no se puede atribuir al motor vigente", s["motivo"])
        self.assertFalse(s["detalle"]["motor"]["coincide"])
        self.assertEqual(MOTOR, s["detalle"]["motor"]["del_ancla"])

    def test_la_discrepancia_de_motor_no_se_confunde_con_un_hecho_en_contra(self):
        """`INCONCLUSIVE`, no `FAIL`: el certificado es válido y el diario contiene el checkpoint.
        Lo que no se puede establecer es a quién atribuir el veredicto anclado."""
        s = C.estado_del_anclaje(self.ws, self.manifest, engine_digest="f" * 64)
        self.assertEqual(INCONCLUSIVE, s["estado"])
        self.assertTrue(s["detalle"]["cadena"]["ok"], "la cadena sigue cerrando")
        self.assertEqual(3, len(s["detalle"]["signers"]), "el quórum sigue verificando")

    def test_un_ancla_que_no_declara_motor_tampoco_aprueba(self):
        """Se ancló sin poder determinar el motor: el campo va vacío y no coincide con ninguno.
        No aprueba por estar en blanco, que es justo lo que hacía antes de esta comprobación."""
        ws2 = _espacio()
        try:
            with ConcordiaFalso(EXPORT, SECRETOS) as srv:
                cfg = {"provider": "concordia", "endpoints": [srv.url], "membership_digest": PIN}
                r = C.anclar(ws2, cfg, run_id="ver_q", engine_digest="", policy_digest="p" * 64,
                             manifest={"anchoring": cfg}, pin=PIN, cadena=verificar_cadena(ws2))
            self.assertEqual(PASS, r["estado"], r["motivo"])
            v = C.verificar_ancla(ws2, r["ancla"], pin=PIN, engine_digest=MOTOR)
            self.assertEqual(INCONCLUSIVE, v["estado"])
            self.assertEqual("", v["motor"]["del_ancla"])
        finally:
            shutil.rmtree(ws2, ignore_errors=True)

    def test_tocar_el_checkpoint_para_esquivar_la_comprobacion_es_fail(self):
        """Quitarle el `engine_digest` al ancla guardada no la vuelve «antigua»: el checkpoint
        declarado deja de ser la carga que firmó el quórum, y eso es un hecho en contra."""
        from core.model import FAIL
        doc = json.loads(Path(self.r["path"]).read_text(encoding="utf-8"))
        del doc["checkpoint"]["engine_digest"]
        v = C.verificar_ancla(self.ws, doc, pin=PIN, engine_digest=MOTOR)
        self.assertEqual(FAIL, v["estado"])
        self.assertIn("no es la carga certificada", v["motivo"])


# ═══════════════════════════════════════════════════════════════════════════════════════
class TestPolicyDigestDeclarado(unittest.TestCase):
    """Lo que no se pudo determinar se dice; no se escribe en blanco."""

    def setUp(self):
        self.ws = Path(tempfile.mkdtemp(prefix="ancla-politica-")).resolve()
        (self.ws / ".harness" / "evidence").mkdir(parents=True)

    def tearDown(self):
        shutil.rmtree(self.ws, ignore_errors=True)

    def test_sin_politica_el_checkpoint_lo_declara(self):
        import refuto
        self.assertEqual(refuto.POLITICA_AUSENTE, refuto._digest_politica(self.ws))

    def test_una_politica_que_no_resuelve_se_llama_distinto_de_no_tenerla(self):
        """Dos hechos distintos, dos palabras distintas. Fundirlos en `""` era la pérdida de
        información que hacía que un ancla sin política atada aprobara sin decirlo."""
        import refuto
        (self.ws / ".harness" / "policy.json").write_text("{ esto no es json", encoding="utf-8")
        self.assertEqual(refuto.POLITICA_IRRESOLUBLE, refuto._digest_politica(self.ws))
        self.assertNotEqual(refuto.POLITICA_AUSENTE, refuto.POLITICA_IRRESOLUBLE)

    def test_ninguno_de_los_dos_es_una_cadena_vacia(self):
        """La regresión concreta que se cierra: si alguno volviera a ser `""`, el campo dejaría
        de decir nada dentro de la carga que firma el quórum."""
        import refuto
        self.assertTrue(refuto.POLITICA_AUSENTE and refuto.POLITICA_IRRESOLUBLE)
        self.assertTrue(refuto._digest_politica(self.ws))

    def test_con_politica_valida_es_el_digest_efectivo(self):
        """Y cuando sí hay política, el valor es su identidad efectiva: la palabra sólo aparece
        cuando no hay digest que poner."""
        import refuto
        from core.policy import Policy
        ruta = self.ws / ".harness" / "policy.json"
        # La política REAL de este repositorio: una inventada aquí se quedaría vieja en cuanto el
        # esquema cambiara, y la prueba pasaría a medir «irresoluble» creyendo medir un digest.
        ruta.write_text(Path(".harness/policy.json").read_text(encoding="utf-8"), encoding="utf-8")
        valor = refuto._digest_politica(self.ws)
        self.assertNotIn(valor, (refuto.POLITICA_AUSENTE, refuto.POLITICA_IRRESOLUBLE))
        self.assertEqual(Policy.load(ruta).identidad_efectiva.efectivo, valor)


if __name__ == "__main__":
    unittest.main()
