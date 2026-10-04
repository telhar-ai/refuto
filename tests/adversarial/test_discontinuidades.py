# -*- coding: utf-8 -*-
"""Discontinuidades declaradas: reconocer una rotura concreta sin abrir una puerta.

Por qué existen (medido el 2026-09-28 en un espacio real)
--------------------------------------------------------
Un diario de 13.063 eventos con **dos** roturas, las dos del 2026-09-24 y las dos con la misma
firma: dos eventos con el mismo `prev` y milisegundos de diferencia — la carrera de concurrencia
del guardián que se cerró el 2026-09-25 (`7eb0945`). Ninguna huella alterada: los cuatro eventos
implicados reproducen su propio digest. Y aun así el espacio quedaba `NO INTEGRABLE` **para
siempre**, por un defecto que ya no existe.

Eso tiene dos salidas malas y una buena. Las malas: convivir con una alarma permanente hasta
aprender a ignorarla, o borrar el diario —la manipulación más simple que existe—. La buena:
declarar la rotura, con su causa y quién la reconoce, y seguir exigiendo todo lo demás.

Este fichero mide lo segundo: que una declaración sirva para **esa** rotura y para nada más.
Cada prueba es un intento de usarla para tapar algo, y todos tienen que fallar.
"""

from __future__ import annotations

import json
import shutil
import tempfile
import unittest
from pathlib import Path

from core.evidence import (CICATRIZADA, INTEGRA, ROTA, SCHEMA_DISCONTINUIDADES, append_event,
                           ledger_path, ruta_discontinuidades, verificar_cadena)


class _ConDiario(unittest.TestCase):
    """Un diario auténtico de 6 eventos, y una rotura real provocada como la provocaba la carrera."""

    def setUp(self):
        self.ws = Path(tempfile.mkdtemp(prefix="cicatriz-")).resolve()
        (self.ws / ".harness" / "evidence").mkdir(parents=True)
        for i in range(6):
            append_event(self.ws, {"kind": "policy/decision", "outcome": "allow", "n": i})
        self.lineas = ledger_path(self.ws).read_text(encoding="utf-8").splitlines()

    def tearDown(self):
        shutil.rmtree(self.ws, ignore_errors=True)

    def _escribir(self, lineas: list) -> None:
        ledger_path(self.ws).write_text("\n".join(lineas) + "\n", encoding="utf-8", newline="\n")

    def romper_como_la_carrera(self) -> dict:
        """Duplica el `prev` de la línea 4 en la 5, que es exactamente lo que hacían dos
        escritores leyendo la misma cabeza. Devuelve los datos para declararla."""
        ls = list(self.lineas)
        cuarta, quinta = json.loads(ls[3]), json.loads(ls[4])
        # La quinta se rehace encadenando a lo MISMO que la cuarta, con su huella coherente.
        from core.evidence import _eslabon
        quinta["prev"] = cuarta["prev"]
        quinta.pop("h", None)
        quinta["h"] = _eslabon(cuarta["prev"], quinta)
        ls[4] = json.dumps(quinta, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
        # Y la sexta encadena a la quinta rehecha, como ocurrió en el diario real.
        sexta = json.loads(ls[5]); sexta["prev"] = quinta["h"]; sexta.pop("h", None)
        sexta["h"] = _eslabon(quinta["prev"] and quinta["h"], sexta)
        ls[5] = json.dumps(sexta, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
        self._escribir(ls)
        return {"line": 5, "found_prev": quinta["prev"], "expected_head": cuarta["h"]}

    def declarar(self, **kw) -> None:
        d = {"line": 5, "found_prev": "", "expected_head": "", "cause": "carrera del guardián",
             "declared_by": "prueba", "declared_at": "2026-09-28"}
        d.update(kw)
        p = ruta_discontinuidades(self.ws)
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(json.dumps({"schema": SCHEMA_DISCONTINUIDADES, "entries": [d]}),
                     encoding="utf-8", newline="\n")


# ═══════════════════════════════════════════════════════════════════════════════════════
class TestLoQueUnaDeclaracionHace(_ConDiario):

    def test_sin_declaracion_sigue_rota(self):
        """La regresión de base: nada cambia para quien no declara nada."""
        self.romper_como_la_carrera()
        self.assertEqual(ROTA, verificar_cadena(self.ws)["estado"])

    def test_declarada_exactamente_queda_cicatrizada(self):
        datos = self.romper_como_la_carrera()
        self.declarar(**datos)
        r = verificar_cadena(self.ws)
        self.assertEqual(CICATRIZADA, r["estado"])
        self.assertTrue(r["ok"])
        self.assertEqual(1, len(r["cicatrices"]))
        self.assertEqual(5, r["cicatrices"][0]["line"])

    def test_cicatrizada_no_es_integra(self):
        """Quien exige integridad total tiene que poder distinguirlas sin leer una lista: el
        tramo anterior a una cicatriz no está atado al posterior."""
        datos = self.romper_como_la_carrera()
        self.declarar(**datos)
        self.assertNotEqual(INTEGRA, verificar_cadena(self.ws)["estado"])

    def test_un_diario_sano_no_cambia_por_tener_declaraciones(self):
        """Declarar de más no puede alterar la lectura de una cadena que cierra."""
        self.declarar(line=99, found_prev="a" * 64, expected_head="b" * 64)
        r = verificar_cadena(self.ws)
        self.assertEqual(INTEGRA, r["estado"])
        self.assertEqual([], r["cicatrices"])

    def test_la_cadena_sigue_verificandose_despues_de_la_cicatriz(self):
        """Lo que se acepta es el salto, no el resto: si algo posterior no cuadra, sale ROTA."""
        datos = self.romper_como_la_carrera()
        self.declarar(**datos)
        ls = ledger_path(self.ws).read_text(encoding="utf-8").splitlines()
        ultimo = json.loads(ls[-1]); ultimo["outcome"] = "deny"          # editado después
        ls[-1] = json.dumps(ultimo, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
        self._escribir(ls)
        r = verificar_cadena(self.ws)
        self.assertEqual(ROTA, r["estado"])
        self.assertIn("se editó", r["motivo"])


# ═══════════════════════════════════════════════════════════════════════════════════════
class TestLoQueUnaDeclaracionNoPuedeTapar(_ConDiario):
    """Cada prueba intenta usar la declaración para esconder algo. Todas tienen que fallar."""

    def test_no_sirve_para_otra_linea(self):
        datos = self.romper_como_la_carrera()
        self.declarar(**{**datos, "line": datos["line"] + 1})
        self.assertEqual(ROTA, verificar_cadena(self.ws)["estado"])

    def test_no_sirve_con_otro_prev_encontrado(self):
        datos = self.romper_como_la_carrera()
        self.declarar(**{**datos, "found_prev": "f" * 64})
        self.assertEqual(ROTA, verificar_cadena(self.ws)["estado"])

    def test_no_sirve_con_otra_cabeza_esperada(self):
        datos = self.romper_como_la_carrera()
        self.declarar(**{**datos, "expected_head": "f" * 64})
        self.assertEqual(ROTA, verificar_cadena(self.ws)["estado"])

    def test_no_autoriza_editar_el_evento_de_la_propia_cicatriz(self):
        """El ataque directo: declarar el salto y aprovechar para cambiar el contenido de ese
        evento. La huella se sigue exigiendo con el `prev` que el evento declara."""
        datos = self.romper_como_la_carrera()
        self.declarar(**datos)
        ls = ledger_path(self.ws).read_text(encoding="utf-8").splitlines()
        quinta = json.loads(ls[4]); quinta["outcome"] = "deny"          # sin recalcular `h`
        ls[4] = json.dumps(quinta, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
        self._escribir(ls)
        r = verificar_cadena(self.ws)
        self.assertEqual(ROTA, r["estado"])
        self.assertIn("se editó", r["motivo"])

    def test_no_autoriza_borrar_un_evento(self):
        """Borrar desplaza las líneas: la declaración deja de casar y vuelve a ROTA."""
        datos = self.romper_como_la_carrera()
        self.declarar(**datos)
        self.assertEqual(CICATRIZADA, verificar_cadena(self.ws)["estado"])
        ls = ledger_path(self.ws).read_text(encoding="utf-8").splitlines()
        del ls[1]
        self._escribir(ls)
        self.assertEqual(ROTA, verificar_cadena(self.ws)["estado"])

    def test_no_autoriza_insertar_un_evento(self):
        datos = self.romper_como_la_carrera()
        self.declarar(**datos)
        ls = ledger_path(self.ws).read_text(encoding="utf-8").splitlines()
        ls.insert(1, json.dumps({"kind": "policy/decision", "outcome": "allow",
                                 "prev": "0" * 64, "h": "1" * 64}))
        self._escribir(ls)
        self.assertEqual(ROTA, verificar_cadena(self.ws)["estado"])

    def test_no_autoriza_truncar_la_cola(self):
        """Truncar no rompe la cadena —por eso hace falta el ancla— y una declaración tampoco
        puede hacer que un ancla publicada aparezca en un diario que ya no la contiene."""
        from core.evidence import DESALINEADA
        cabeza = verificar_cadena(self.ws)["cabeza"]
        datos = self.romper_como_la_carrera()
        self.declarar(**datos)
        ls = ledger_path(self.ws).read_text(encoding="utf-8").splitlines()
        self._escribir(ls[:-1])
        r = verificar_cadena(self.ws, esperado=cabeza)
        self.assertEqual(DESALINEADA, r["estado"])
        self.assertFalse(r["ok"])

    def test_una_declaracion_no_vale_para_dos_roturas(self):
        """Cada rotura necesita la suya: una sola no amnistía todo lo que venga después."""
        from core.evidence import _eslabon
        datos = self.romper_como_la_carrera()
        self.declarar(**datos)
        ls = ledger_path(self.ws).read_text(encoding="utf-8").splitlines()
        sexta = json.loads(ls[5]); sexta["prev"] = "e" * 64; sexta.pop("h", None)
        sexta["h"] = _eslabon("e" * 64, sexta)
        ls[5] = json.dumps(sexta, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
        self._escribir(ls)
        self.assertEqual(ROTA, verificar_cadena(self.ws)["estado"])


# ═══════════════════════════════════════════════════════════════════════════════════════
class TestDeclaracionesMalFormadas(_ConDiario):
    """«No pude leer las declaraciones» no puede parecerse a «no hay ninguna rotura»."""

    def _crudo(self, texto: str) -> None:
        p = ruta_discontinuidades(self.ws)
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(texto, encoding="utf-8", newline="\n")

    def test_fichero_ilegible_no_amnistia_nada_y_se_declara(self):
        self.romper_como_la_carrera()
        self._crudo("{ esto no es json")
        r = verificar_cadena(self.ws)
        self.assertEqual(ROTA, r["estado"])

    def test_el_problema_de_la_declaracion_se_ve_aunque_la_cadena_cierre(self):
        """Un diario sano con declaraciones ilegibles sigue INTEGRA, pero lo dice."""
        self._crudo("{ esto no es json")
        r = verificar_cadena(self.ws)
        self.assertEqual(INTEGRA, r["estado"])
        self.assertIn("ilegible", r["motivo"])

    def test_otro_esquema_no_se_interpreta(self):
        datos = self.romper_como_la_carrera()
        self._crudo(json.dumps({"schema": "otra.cosa/v1", "entries": [
            {**{"cause": "x", "declared_by": "y", "declared_at": "z"}, **datos}]}))
        self.assertEqual(ROTA, verificar_cadena(self.ws)["estado"])

    def test_una_entrada_incompleta_no_cuenta(self):
        """Sin la causa o sin quién la declara no hay nada que contrastar ni a quién preguntar."""
        datos = self.romper_como_la_carrera()
        self._crudo(json.dumps({"schema": SCHEMA_DISCONTINUIDADES,
                                "entries": [{"line": datos["line"],
                                             "found_prev": datos["found_prev"],
                                             "expected_head": datos["expected_head"]}]}))
        r = verificar_cadena(self.ws)
        self.assertEqual(ROTA, r["estado"])

    def test_una_linea_que_no_es_numero_no_cuenta(self):
        datos = self.romper_como_la_carrera()
        self._crudo(json.dumps({"schema": SCHEMA_DISCONTINUIDADES, "entries": [
            {**datos, "line": "5", "cause": "x", "declared_by": "y", "declared_at": "z"}]}))
        self.assertEqual(ROTA, verificar_cadena(self.ws)["estado"])

    def test_un_booleano_no_es_una_linea(self):
        datos = self.romper_como_la_carrera()
        self._crudo(json.dumps({"schema": SCHEMA_DISCONTINUIDADES, "entries": [
            {**datos, "line": True, "cause": "x", "declared_by": "y", "declared_at": "z"}]}))
        self.assertEqual(ROTA, verificar_cadena(self.ws)["estado"])


# ═══════════════════════════════════════════════════════════════════════════════════════
class TestQuienExigeIntegridadTotal(_ConDiario):
    """El ancla afirma «el diario medía n y su cabeza era h». Con un salto en medio, eso es
    más de lo que la cadena sostiene."""

    def test_no_se_ancla_una_cadena_cicatrizada(self):
        from core import concordia as C
        from core.model import BLOCKED
        datos = self.romper_como_la_carrera()
        self.declarar(**datos)
        cad = verificar_cadena(self.ws)
        self.assertEqual(CICATRIZADA, cad["estado"])
        r = C.anclar(self.ws, {"provider": "concordia", "endpoints": ["http://127.0.0.1:9"],
                               "membership_digest": "0" * 64},
                     run_id="x", engine_digest="e" * 64, policy_digest="p" * 64,
                     manifest=None, pin="0" * 64, cadena=cad)
        self.assertEqual(BLOCKED, r["estado"])
        self.assertIn("discontinuidad", r["motivo"])

    def test_y_se_niega_ANTES_de_hablar_con_el_cluster(self):
        """El endpoint es el puerto discard: si intentara la red, el motivo sería otro."""
        from core import concordia as C
        datos = self.romper_como_la_carrera()
        self.declarar(**datos)
        r = C.anclar(self.ws, {"provider": "concordia", "endpoints": ["http://127.0.0.1:9"],
                               "membership_digest": "0" * 64},
                     run_id="x", engine_digest="e" * 64, policy_digest="p" * 64,
                     manifest=None, pin="0" * 64, cadena=verificar_cadena(self.ws))
        self.assertNotIn("réplica", r["motivo"])
        self.assertIsNone(r["ancla"])


if __name__ == "__main__":
    unittest.main()
