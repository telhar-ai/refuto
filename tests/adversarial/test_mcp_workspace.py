# -*- coding: utf-8 -*-
"""El `workspace` lo aporta el modelo, y `refuto_verify` escribe. Eso hay que acotarlo.

El defecto que estas pruebas fijan, medido el 2026-09-25
--------------------------------------------------------
`core/mcp_server.py` valida el `workspace` comprobando que sea un directorio existente, y nada
más. `refuto_verify` ESCRIBE —emite evidencia en `.harness/evidence/`, que es su función—, así
que un agente podía nombrar cualquier directorio de la máquina y sembrarlo. Medido sobre uno
recién creado, fuera de todo espacio gobernado:

    .harness/evidence/ledger.jsonl · sbom.json · ver_edb734a4c5f14c66.json

No es destrucción ni exfiltración. Es escritura **no solicitada fuera del espacio**, y la
doctrina del producto sobre eso ya estaba escrita en otro sitio: `external_write_allow` existe
precisamente para que fuera del espacio sólo se escriba en raíces DECLARADAS, «porque la
diferencia entre una excepción nombrada y un agujero es que la excepción se puede leer y
discutir». Esta superficie rodeaba esa doctrina por no preguntarse cuál es el espacio.

El encabezado del módulo declara tres reglas que «no negocia», y la segunda es «no escribe lo
que gobierna». Decía *qué* no escribe y no decía *dónde*.
"""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from core.mcp_server import HERRAMIENTAS, _argv_de

RAIZ = Path(__file__).resolve().parents[2]


class TestElWorkspaceTieneQueSerUnEspacio(unittest.TestCase):
    def test_un_directorio_cualquiera_se_rechaza(self):
        with tempfile.TemporaryDirectory() as tmp:
            ajeno = Path(tmp) / "un-directorio-cualquiera"
            ajeno.mkdir()
            with self.assertRaises(ValueError) as ctx:
                _argv_de("refuto_verify", {"workspace": str(ajeno)}, raiz=RAIZ)
            self.assertIn(".harness", str(ctx.exception),
                          "el rechazo tiene que decir qué falta, o manda a adivinar")

    def test_y_no_se_escribio_nada_en_el(self):
        """La propiedad que de verdad importa: rechazar ANTES de tocar el disco."""
        with tempfile.TemporaryDirectory() as tmp:
            ajeno = Path(tmp) / "otro"
            ajeno.mkdir()
            with self.assertRaises(ValueError):
                _argv_de("refuto_verify", {"workspace": str(ajeno)}, raiz=RAIZ)
            self.assertEqual([], list(ajeno.iterdir()),
                             "se escribió algo en un destino que se iba a rechazar")

    def test_un_espacio_gobernado_se_acepta(self):
        """El otro lado. Si todo se rechazara, la herramienta no serviría para nada."""
        with tempfile.TemporaryDirectory() as tmp:
            espacio = Path(tmp) / "espacio"
            (espacio / ".harness").mkdir(parents=True)
            argv = _argv_de("refuto_verify", {"workspace": str(espacio)}, raiz=RAIZ)
            self.assertIn("--workspace", argv)
            self.assertIn(str(espacio.resolve()), argv)

    def test_sin_workspace_se_usa_la_raiz_del_servidor(self):
        """El caso por omisión: el directorio desde el que lo arrancó la propia persona."""
        argv = _argv_de("refuto_status", {}, raiz=RAIZ)
        self.assertIn(str(RAIZ.resolve()), argv)

    def test_la_raiz_del_servidor_vale_aunque_no_tuviera_harness(self):
        """No se castiga al espacio propio: lo eligió una persona al lanzar el servidor, no el
        modelo en una llamada."""
        with tempfile.TemporaryDirectory() as tmp:
            propia = Path(tmp) / "propia"
            propia.mkdir()
            argv = _argv_de("refuto_doctor", {"workspace": str(propia)}, raiz=propia)
            self.assertIn(str(propia.resolve()), argv)

    def test_la_regla_vale_para_TODAS_las_herramientas(self):
        """Se comprueba en `_argv_de`, que es por donde pasan las siete.

        Acotar sólo `refuto_verify` habría dejado la regla dependiendo de que nadie añada mañana
        otra herramienta que escriba — y la tabla está hecha para que añadir sea una línea.
        """
        with tempfile.TemporaryDirectory() as tmp:
            ajeno = Path(tmp) / "ajeno"
            ajeno.mkdir()
            for h in HERRAMIENTAS:
                with self.subTest(herramienta=h["name"]):
                    with self.assertRaises(ValueError):
                        _argv_de(h["name"], {"workspace": str(ajeno)}, raiz=RAIZ)


class TestLoQueEstaSuperficieSiguePrometiendo(unittest.TestCase):
    """Las tres reglas que el módulo dice no negociar, fijadas como pruebas."""

    def test_ninguna_herramienta_lleva_una_bandera_de_escritura(self):
        prohibidas = {"--apply", "--force", "--deep", "--execute", "unwire", "wire", "install",
                      "init", "chat", "run"}
        for h in HERRAMIENTAS:
            with self.subTest(herramienta=h["name"]):
                self.assertEqual(set(), prohibidas.intersection(h["argv"]))

    def test_el_argv_sale_de_la_tabla_y_no_de_una_cadena_del_modelo(self):
        """Los extras del modelo son booleanos y un `gate` con forma `G-NOMBRE`; nada más."""
        with self.assertRaises(ValueError):
            _argv_de("refuto_verify", {"gate": "G-POLICY; rm -rf /"}, raiz=RAIZ)
        with self.assertRaises(ValueError):
            _argv_de("refuto_verify", {"inventado": True}, raiz=RAIZ)


if __name__ == "__main__":
    unittest.main()
