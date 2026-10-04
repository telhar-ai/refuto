# -*- coding: utf-8 -*-
"""La suite no puede depender de la máquina donde se ejecuta.

El fixture `Workspace` ya declaraba la regla: «una prueba que necesita los repositorios de
quien la escribió para pasar no es una prueba, es una demostración». Este módulo la convierte
en algo comprobable, porque estaba siendo incumplida sin que nada lo dijera.

Falsación del 2026-09-22
------------------------
Un informe externo afirmó 472/480. En esta máquina daba 480/480, así que la afirmación no
reproducía — y la tentación era cerrarla como error del informe. Se probó al revés: fabricar
el entorno que la haría cierta. Con un `$HOME` cuyo `~/.claude/settings.json` no se puede
leer, **7 pruebas de G-MCP** pasan de su veredicto esperado a `NOT_EXECUTABLE`, en espacios
temporales que ni contienen ese fichero ni pueden arreglarlo.

Lo que fallaba no era el producto: era el instrumento. La suite medía «el código es correcto
Y el `$HOME` de quien la corre es benigno», y reportaba sólo lo primero. En la máquina donde
se escribieron las pruebas, el segundo término era verdadero por casualidad.

Lo que aquí se fija NO es que el home se ignore —un servidor MCP declarado a nivel de usuario
existe de verdad, y una puerta que no lo mirara aprobaría por no haber mirado, que es el
fallo que G-MCP existe para impedir—. Se fija que el home que ve una prueba sea el que la
prueba declara, y no el de quien la ejecuta.
"""

from __future__ import annotations

import json
import os
import shutil
import tempfile
import unittest
from pathlib import Path

from core.mcp import load_mcp_config
from core.model import NOT_EXECUTABLE
from gates.base import run_gate
from tests.fixtures import Workspace

#: JSON inválido, no un fichero sin permisos. `chmod 000` no aísla nada cuando la suite corre
#: como root —root lee igual— y CI a veces lo hace: la prueba pasaría por no haber reproducido
#: la condición, que es el mismo falso verde que se está persiguiendo.
BASURA = "{{{ esto no es json"


class TestElHomeDeLaSuiteEsDeclarado(unittest.TestCase):

    def test_workspace_aisla_el_home_y_lo_devuelve_al_salir(self):
        previo = os.environ.get("HOME")
        with Workspace("herm-home") as ws:
            self.assertEqual(os.environ["HOME"], str(ws.home))
            self.assertNotEqual(os.environ["HOME"], previo, "el home no se aisló")
            self.assertEqual(Path.home(), ws.home, "`Path.home()` no siguió a $HOME")
        self.assertEqual(os.environ.get("HOME"), previo, "el home no se restauró al salir")

    def test_un_home_hostil_no_cambia_el_veredicto_de_un_espacio_limpio(self):
        """La falsación, fijada.

        Sin el aislamiento esta prueba da `NOT_EXECUTABLE`: la puerta declara que no puede
        afirmar nada sobre un espacio temporal por culpa de un fichero que está en el home de
        quien audita. Es exactamente el acoplamiento que tumbaba las 7.
        """
        hostil = Path(tempfile.mkdtemp(prefix="home-hostil-"))
        previo = os.environ.get("HOME")
        try:
            (hostil / ".claude").mkdir(parents=True)
            (hostil / ".claude" / "settings.json").write_text(BASURA, encoding="utf-8")
            os.environ["HOME"] = str(hostil)          # así arranca la sesión de quien audita
            with Workspace("herm-mcp") as ws:
                ws.manifest()
                r = run_gate("G-MCP", ws.context(offline=True))
            self.assertNotEqual(NOT_EXECUTABLE, r.status,
                                f"el home de quien ejecuta la suite decidió el veredicto de un "
                                f"espacio ajeno: {r.measure}")
        finally:
            os.environ["HOME"] = previo if previo is not None else ""
            if previo is None:
                os.environ.pop("HOME", None)
            shutil.rmtree(hostil, ignore_errors=True)


class TestElAmbitoDelFicheroSeDeclara(unittest.TestCase):
    """Leer el home sigue siendo correcto. Lo que hacía falta es decir de quién es el fichero."""

    def test_un_servidor_declarado_en_el_home_SI_se_ve(self):
        """Contra-prueba: el arreglo no debilita la puerta.

        Si esto dejara de pasar, `load_mcp_config` habría dejado de mirar el nivel de usuario
        y G-MCP aprobaría espacios cuyas referencias sólo resuelven ahí — por no haber mirado.
        """
        with Workspace("amb-ve") as ws:
            (ws.home / ".claude").mkdir(parents=True, exist_ok=True)
            (ws.home / ".claude" / "settings.json").write_text(json.dumps(
                {"mcpServers": {"figma": {"url": "https://mcp.figma.invalid/mcp",
                                          "type": "http"}}}), encoding="utf-8")
            servers, ilegibles = load_mcp_config(ws.root, home=ws.home)
            self.assertIn("figma", servers, "un servidor de nivel de usuario dejó de verse")
            self.assertEqual([], ilegibles)
            self.assertIn(str(ws.home), servers["figma"][0]["_source"])

    def test_un_fichero_ilegible_del_usuario_dice_que_es_del_usuario(self):
        """Un `NOT_EXECUTABLE` sin ámbito manda a buscar el problema al repositorio equivocado.

        El hallazgo llega a alguien que audita un espacio que no es suyo. «`settings.json`
        ilegible» le hace revisar el árbol; el fichero está en su propia carpeta personal.
        """
        with Workspace("amb-ileg") as ws:
            (ws.home / ".claude").mkdir(parents=True, exist_ok=True)
            (ws.home / ".claude" / "settings.json").write_text(BASURA, encoding="utf-8")
            _, ilegibles = load_mcp_config(ws.root, home=ws.home)
            self.assertEqual(1, len(ilegibles))
            self.assertEqual("usuario", ilegibles[0]["scope"])
            self.assertIn("USUARIO", ilegibles[0]["problem"])

    def test_un_fichero_ilegible_del_espacio_no_se_disculpa_como_ajeno(self):
        """La otra mitad: lo que SÍ está en el árbol no puede excusarse como «no es de aquí»."""
        with Workspace("amb-esp") as ws:
            ws.file(".mcp.json", BASURA)
            _, ilegibles = load_mcp_config(ws.root, home=ws.home)
            self.assertEqual(1, len(ilegibles))
            self.assertEqual("espacio", ilegibles[0]["scope"])
            self.assertNotIn("USUARIO", ilegibles[0]["problem"])

    def test_sigue_sin_aprobar_lo_que_no_pudo_leer(self):
        """Lo que NO se ha arreglado, a propósito.

        Un fichero ilegible sigue dando `NOT_EXECUTABLE`, venga de donde venga. No poder leerlo
        es no poder afirmar, y eso no es un aprobado. El arreglo era de hermeticidad, no de
        indulgencia: si esta prueba se cayera, la puerta habría empezado a perdonar.
        """
        with Workspace("amb-dur") as ws:
            ws.manifest()
            ws.file(".mcp.json", BASURA)
            r = run_gate("G-MCP", ws.context(offline=True))
            self.assertEqual(NOT_EXECUTABLE, r.status,
                             f"un fichero ilegible dejó de bloquear: {r.measure}")


if __name__ == "__main__":
    unittest.main()
