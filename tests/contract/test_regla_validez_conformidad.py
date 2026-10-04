# -*- coding: utf-8 -*-
"""Conformidad de `core.regla_validez` con el binario real de concordia (`CERTIFICATE-SPEC §11`).

Dos implementaciones independientes tienen que decidir lo mismo, y cuando no lo hagan, tienen que
poder decir EN QUÉ. Eso no se demuestra con el artefacto que uno de los dos escribió a mano: se
demuestra ejecutando el otro verificador. Si `HICON_BIN` apunta a `hicon`, aquí se ejecuta; si no,
esta mitad queda `NOT_RUN` —un `skip` con motivo— y nunca aprobada por omisión, igual que el
diferencial de `test_concordia_vectores.py`.

La divergencia conocida se DECLARA en `DIVERGENCIAS_CONOCIDAS` en vez de esperarse un veredicto
fijo. Así el test sirve para las tres cosas que pueden pasar:

- sigue divergiendo sólo en lo conocido → pasa, y la nota queda a la vista;
- concordia o refuto se alinean y deja de divergir → pasa;
- aparece una divergencia NUEVA → falla, que es lo único que hay que mirar.

Esperar `REGLA_DIVERGENTE` a secas haría lo contrario: convertiría el arreglo del defecto en un
fallo de la suite, que es cómo se enseña a no arreglarlo.
"""

from __future__ import annotations

import json
import os
import subprocess  # nosec B404 — ejecutar el verificador de referencia ES la medición
import unittest

from core import regla_validez as R
from core.model import BLOCKED, FAIL, INCONCLUSIVE, PASS
from core.proc import TEXT_IO

HICON = os.environ.get("HICON_BIN", "")

#: Sondas en las que se sabe que los dos verificadores discrepan, y por qué. Medido el 2026-09-30
#: contra `hicon 2a35611`: una clave cuya `y` codifica `2^255-1 > p` no es canónica; refuto la
#: rechaza al admitirla (`K`) y dalek la decodifica, la admite y falla luego en la firma (`S`).
#: refuto rechaza MÁS, que es la dirección segura, pero sigue siendo otra regla.
DIVERGENCIAS_CONOCIDAS = {"05-noncanonical-y-encoding-admitted"}


def _identidad_del_binario() -> dict | None:
    """`hicon validity-rule --probes`, o `None` si ese binario no conoce el subcomando.

    Un `hicon` anterior al mecanismo imprime el texto de uso y **sale con 0** (medido en
    `4e06e5b`). Comprobar sólo el código de salida daría por buena una salida que no es el
    artefacto: se exige que sea JSON con la forma esperada, y si no, no se pudo medir.
    """
    try:
        p = subprocess.run([HICON, "validity-rule", "--probes"],  # nosec B603
                           capture_output=True, timeout=60, check=False, **TEXT_IO)
    except (OSError, subprocess.SubprocessError):
        return None
    try:
        doc = json.loads(p.stdout)
    except ValueError:
        return None
    return doc if isinstance(doc, dict) and "identity" in doc and "probes" in doc else None


@unittest.skipUnless(HICON, "NOT_RUN: HICON_BIN no apunta a `hicon`; el diferencial de la regla "
                            "de validez con Rust no se ejecutó")
class TestConformidadDeLaRegla(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.doc = _identidad_del_binario()
        if cls.doc is None:
            raise unittest.SkipTest(
                f"NOT_RUN: {HICON} no publica `validity-rule --probes` (¿anterior al mecanismo?); "
                f"la identidad de regla no se pudo leer. Ausencia de la capacidad no es conformidad")

    def test_el_binario_sondea_lo_mismo_que_refuto(self):
        """Sin esto, comparar veredictos no significaría nada: serían dos instrumentos distintos."""
        self.assertEqual(self.doc["identity"]["probe_set_digest"], R.PROBE_SET_DIGEST)

    def test_las_sondas_coinciden_byte_a_byte(self):
        """`probe_set_digest` ya lo implica, pero si difiere hay que poder decir EN QUÉ sonda."""
        mias = [(i, pk, m, s) for i, pk, m, s in R.SONDAS]
        suyas = [(p["id"], p["public_key_hex"], p["message_hex"], p["signature_hex"])
                 for p in self.doc["probes"]]
        self.assertEqual(len(mias), len(suyas))
        for a, b in zip(mias, suyas, strict=True):
            self.assertEqual(a, b, f"la sonda {a[0]} no es la misma en los dos lados")

    def test_la_forma_canonica_reproduce_el_digest_del_binario(self):
        """La prueba de que un consumidor de biblioteca estándar puede CALCULAR el digest en vez
        de sólo compararlo — que es lo que hace la identidad verificable y no una etiqueta."""
        import hashlib
        decl = self.doc["identity"]
        canon = R.forma_canonica(decl["verdicts"])
        self.assertEqual(hashlib.sha256(canon).hexdigest(), decl["digest"])

    def test_consumir_la_identidad_real_da_una_resolucion_declarada(self):
        r = R.consumir(self.doc["identity"])
        self.assertIn(r["resolucion"], R.ESTADO_DE)
        self.assertEqual(r["estado"], R.ESTADO_DE[r["resolucion"]])
        self.assertTrue(r["motivo"])
        self.assertNotIn(r["estado"], (None, ""))

    def test_no_hay_divergencias_nuevas(self):
        """Lo único que hay que mirar. Las conocidas están declaradas y fechadas arriba."""
        r = R.consumir(self.doc["identity"])
        if r["resolucion"] == R.CONCUERDA:
            return                                   # se alinearon: también es un resultado válido
        self.assertEqual(r["resolucion"], R.REGLA_DIVERGENTE, r["motivo"])
        vistas = {d["sonda"] for d in r["divergentes"]}
        nuevas = vistas - DIVERGENCIAS_CONOCIDAS
        self.assertEqual(set(), nuevas,
                         f"divergencia NUEVA con concordia en {sorted(nuevas)}: mídela y "
                         f"declárala en DIVERGENCIAS_CONOCIDAS, no la absorbas")

    def test_una_divergencia_conocida_que_desaparece_se_nota(self):
        """Si `DIVERGENCIAS_CONOCIDAS` se queda con entradas que ya no ocurren, deja de describir
        el estado real y el día que aparezca otra nadie la creerá. No es un fallo: es un aviso."""
        r = R.consumir(self.doc["identity"])
        vistas = {d["sonda"] for d in r.get("divergentes", [])}
        obsoletas = DIVERGENCIAS_CONOCIDAS - vistas
        if obsoletas:
            self.skipTest(f"NOT_APPLICABLE: ya no divergen {sorted(obsoletas)}; quítelas de "
                          f"DIVERGENCIAS_CONOCIDAS y actualice la nota de `core.regla_validez`")

    def test_el_estado_no_es_pass_por_omision(self):
        """Ninguna de las resoluciones que no son `CONCUERDA` puede aprobar."""
        for res, estado in R.ESTADO_DE.items():
            if res != R.CONCUERDA:
                self.assertIn(estado, (FAIL, INCONCLUSIVE, BLOCKED), res)
            else:
                self.assertEqual(estado, PASS)


if __name__ == "__main__":
    unittest.main()
