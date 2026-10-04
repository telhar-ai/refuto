# -*- coding: utf-8 -*-
"""A dónde habla el agente.

El hueco que estas pruebas cubren: la sonda llega a `FUNCTIONAL` con un handshake **local**, que
no toca la red. Por eso un agente correctamente instalado y mal enrutado sale en verde y muere
en el primer mensaje con `API Error: Invalid URL`. Todo lo demás parece correcto.
"""

from __future__ import annotations

import unittest

from core.provider import clean_env, how_to_find, inspect
from core.proc import TEXT_IO


class TestDeteccion(unittest.TestCase):
    def test_sin_variables_usa_la_suscripcion(self):
        r = inspect({"PATH": "/usr/bin", "HOME": "/tmp"})
        self.assertFalse(r.overridden)
        self.assertEqual(r.provider, "suscripción de Anthropic")
        self.assertEqual(r.problems, [])

    def test_reconoce_foundry(self):
        self.assertEqual(inspect({"ANTHROPIC_FOUNDRY_ENDPOINT": "x"}).provider,
                         "Microsoft Foundry")
        self.assertEqual(inspect({"CLAUDE_CODE_USE_FOUNDRY": "1"}).provider,
                         "Microsoft Foundry")

    def test_reconoce_bedrock_y_vertex(self):
        self.assertEqual(inspect({"CLAUDE_CODE_USE_BEDROCK": "1"}).provider, "AWS Bedrock")
        self.assertEqual(inspect({"CLAUDE_CODE_USE_VERTEX": "1"}).provider, "Google Vertex")

    def test_una_URL_invalida_se_declara_con_su_sintoma(self):
        r = inspect({"ANTHROPIC_BASE_URL": "/ruta/sin/esquema"})
        self.assertTrue(r.problems)
        self.assertIn("Invalid URL", r.problems[0])

    def test_una_URL_valida_no_es_un_problema(self):
        r = inspect({"ANTHROPIC_BASE_URL": "https://api.ejemplo.mx/v1"})
        self.assertEqual(r.problems, [])
        self.assertTrue(r.overridden)

    def test_una_redireccion_valida_avisa_pero_no_falla(self):
        r = inspect({"CLAUDE_CODE_USE_BEDROCK": "1"})
        self.assertEqual(r.problems, [])
        self.assertTrue(any("NO usará su suscripción" in w for w in r.warnings))

    def test_variables_vacias_no_cuentan(self):
        self.assertFalse(inspect({"ANTHROPIC_BASE_URL": ""}).overridden)


class TestSecretos(unittest.TestCase):
    def test_nunca_revela_un_token(self):
        """El diagnóstico dice qué variable está puesta, no lo que vale."""
        r = inspect({"ANTHROPIC_AUTH_TOKEN": "sk-ant-secretisimo-0123456789"})
        blob = str(r.to_dict())
        self.assertNotIn("secretisimo", blob)
        self.assertIn("presente", blob)

    def test_una_API_KEY_tampoco(self):
        r = inspect({"ANTHROPIC_API_KEY": "sk-ant-api03-xxxxxxxxxxxx"})
        self.assertNotIn("xxxxxxxxxxxx", str(r.to_dict()))

    def test_una_URL_si_se_muestra_porque_hace_falta_para_arreglarla(self):
        r = inspect({"ANTHROPIC_BASE_URL": "http://localhost:1234"})
        self.assertIn("localhost:1234", str(r.to_dict()))


class TestLimpieza(unittest.TestCase):
    def test_clean_env_quita_toda_redireccion(self):
        sucio = {"PATH": "/usr/bin", "ANTHROPIC_BASE_URL": "x",
                 "CLAUDE_CODE_USE_FOUNDRY": "1", "ANTHROPIC_FOUNDRY_KEY": "y",
                 "ANTHROPIC_MODEL": "z"}
        limpio = clean_env(sucio)
        self.assertEqual(limpio, {"PATH": "/usr/bin"})
        self.assertFalse(inspect(limpio).overridden)

    def test_no_toca_lo_que_no_es_de_proveedor(self):
        limpio = clean_env({"HOME": "/tmp", "LANG": "es_MX", "ANTHROPIC_API_KEY": "k"})
        self.assertEqual(sorted(limpio), ["HOME", "LANG"])


class TestAyuda(unittest.TestCase):
    def test_dice_donde_buscar_sin_leer_los_dotfiles(self):
        """Refuto no lee los archivos personales de nadie: dice dónde mirar."""
        orden = how_to_find(["ANTHROPIC_BASE_URL"])
        self.assertIn("grep", orden)
        self.assertIn("ANTHROPIC_BASE_URL", orden)

    def test_sin_variables_no_propone_nada(self):
        self.assertEqual(how_to_find([]), "")


class TestSesion(unittest.TestCase):
    def test_una_redireccion_rota_se_limpia_sola(self):
        """Dejar pasar una sesión que va a fallar en el primer mensaje no ayuda a nadie."""
        from core.session import plan
        from core.wire import wire_claude
        from tests.fixtures import Workspace
        import os
        from pathlib import Path
        with Workspace("prov") as ws:
            ws.policy()
            wire_claude(ws.root, harness_root=Path(__file__).resolve().parents[2])
            os.environ["ANTHROPIC_BASE_URL"] = "/ruta/rota"
            try:
                sp = plan(ws.root, runtime="claude")
                self.assertTrue(sp.clean_provider)
                self.assertTrue(any("Invalid URL" in w for w in sp.warnings))
            finally:
                os.environ.pop("ANTHROPIC_BASE_URL", None)

    def test_inherit_respeta_el_entorno_aunque_este_roto(self):
        from core.session import plan
        from core.wire import wire_claude
        from tests.fixtures import Workspace
        import os
        from pathlib import Path
        with Workspace("prov2") as ws:
            ws.policy()
            wire_claude(ws.root, harness_root=Path(__file__).resolve().parents[2])
            os.environ["ANTHROPIC_BASE_URL"] = "/ruta/rota"
            try:
                self.assertFalse(plan(ws.root, runtime="claude",
                                      provider="inherit").clean_provider)
            finally:
                os.environ.pop("ANTHROPIC_BASE_URL", None)


class TestDeclaracionDelEspacio(unittest.TestCase):
    """El espacio declara a qué proveedor debe hablar, y eso manda sobre el entorno.

    `auto` sólo limpiaba cuando la redirección estaba ROTA. Una redirección válida hacia un
    proveedor que la persona no usa pasaba sin más: la sesión abría, funcionaba, y facturaba en
    el sitio equivocado. Adivinar cuál de los dos casos era sería peor que dejarlo declarar.
    """

    def _ws(self, expect: str | None):
        from tests.fixtures import Workspace
        ws = Workspace("prov-decl")
        ws.__enter__()
        ws.policy()
        m = {"schema": "harness.manifest/v1", "harness": {"version": "0.2.0"},
             "agents": {}, "gates": ["G-AGENT"]}
        if expect:
            m["provider"] = {"expect": expect}
        ws.json(".harness/harness.manifest.json", m)
        return ws

    def test_lee_la_declaracion(self):
        from core.provider import expected
        ws = self._ws("subscription")
        try:
            self.assertEqual(expected(ws.root), "subscription")
        finally:
            ws.__exit__(None, None, None)

    def test_sin_declaracion_devuelve_vacio(self):
        from core.provider import expected
        ws = self._ws(None)
        try:
            self.assertEqual(expected(ws.root), "")
        finally:
            ws.__exit__(None, None, None)

    def test_una_declaracion_invalida_se_ignora(self):
        from core.provider import expected
        ws = self._ws("inventado")
        try:
            self.assertEqual(expected(ws.root), "")
        finally:
            ws.__exit__(None, None, None)

    def test_matches(self):
        from core.provider import matches
        self.assertTrue(matches("subscription", "suscripción de Anthropic"))
        self.assertFalse(matches("subscription", "Microsoft Foundry"))

    def test_una_redireccion_VALIDA_que_contradice_la_declaracion_se_limpia(self):
        import os
        from pathlib import Path
        from core.session import plan
        from core.wire import wire_claude
        ws = self._ws("subscription")
        try:
            wire_claude(ws.root, harness_root=Path(__file__).resolve().parents[2])
            os.environ["ANTHROPIC_BASE_URL"] = "https://foundry.ejemplo/v1"
            os.environ["ANTHROPIC_FOUNDRY_ENDPOINT"] = "https://foundry.ejemplo/v1"
            sp = plan(ws.root, runtime="claude")
            self.assertTrue(sp.clean_provider, sp.warnings)
            self.assertTrue(any("declara" in w for w in sp.warnings), sp.warnings)
        finally:
            for k in ("ANTHROPIC_BASE_URL", "ANTHROPIC_FOUNDRY_ENDPOINT"):
                os.environ.pop(k, None)
            ws.__exit__(None, None, None)

    def test_sin_declaracion_una_redireccion_valida_se_respeta(self):
        import os
        from pathlib import Path
        from core.session import plan
        from core.wire import wire_claude
        ws = self._ws(None)
        try:
            wire_claude(ws.root, harness_root=Path(__file__).resolve().parents[2])
            os.environ["ANTHROPIC_BASE_URL"] = "https://propio.ejemplo/v1"
            sp = plan(ws.root, runtime="claude")
            self.assertFalse(sp.clean_provider, sp.warnings)
        finally:
            os.environ.pop("ANTHROPIC_BASE_URL", None)
            ws.__exit__(None, None, None)


class TestRecursosDelInforme(unittest.TestCase):
    """El informe sólo puede prometer comandos que existan desde ESE directorio.

    Decía `python3 refuto.py verify`. En un espacio gobernado desde fuera ese archivo no
    existe: el agente lo intentó, no lo encontró, y gastó una vuelta averiguando qué ejecutar.
    """

    def test_no_promete_harness_py_si_no_esta_aqui(self):
        from core.session import build_brief
        from tests.fixtures import Workspace
        with Workspace("res1") as ws:
            ws.policy()
            texto, _, _ = build_brief(ws.root, runtime="claude")
            self.assertNotIn("\npython3 refuto.py", texto)
            self.assertIn("no en este directorio", texto)

    def test_enumera_el_verificador_del_espacio(self):
        from core.session import build_brief, resources
        from tests.fixtures import Workspace
        with Workspace("res2") as ws:
            ws.policy()
            ws.file("verificacion/verificar.py", "print(1)\n")
            self.assertEqual(resources(ws.root)["verificador"], "verificacion/verificar.py")
            self.assertIn("verificacion/verificar.py", build_brief(ws.root, runtime="claude")[0])

    def test_enumera_agentes_skills_y_herramientas_reales(self):
        from core.session import resources
        from tests.fixtures import Workspace
        with Workspace("res3") as ws:
            ws.policy()
            ws.json(".kiro/agents/a.json", {"name": "a"})
            ws.skill("frontend", "frontend")
            ws.file("herramientas/x.py", "x=1\n")
            r = resources(ws.root)
            self.assertIn(".kiro/agents/a.json", r["agentes"])
            self.assertIn("frontend", r["skills"])
            self.assertIn("herramientas/x.py", r["herramientas"])

    def test_todo_comando_prometido_apunta_a_algo_que_existe(self):
        from pathlib import Path
        from core.session import resources
        from tests.fixtures import Workspace
        with Workspace("res4") as ws:
            ws.policy()
            ws.file("verificacion/verificar.py", "print(1)\n")
            for cmd, _ in resources(ws.root)["comandos"]:
                objetivo = cmd.split()[1]
                p = Path(objetivo)
                existe = p.is_file() if p.is_absolute() else (ws.root / objetivo).is_file()
                self.assertTrue(existe, f"el informe promete «{cmd}» y {objetivo} no existe")


class TestDoctorNoRevienta(unittest.TestCase):
    """`refuto doctor` reventaba con AttributeError en cuanto había un agente roto.

    Una variable `r` servía para la sonda y para el enrutado a la vez, y el resumen accionable
    leía `r.problems` sobre un `ProbeReport`. Es decir: el diagnóstico se caía exactamente
    cuando había algo que diagnosticar.
    """

    def test_el_comando_termina_con_un_agente_roto(self):
        import subprocess
        import sys
        from pathlib import Path
        raiz = Path(__file__).resolve().parents[2]
        p = subprocess.run([sys.executable, str(raiz / "refuto.py"), "doctor"],
                           capture_output=True, **TEXT_IO, timeout=180,
                           cwd=str(raiz), env={"PATH": __import__("os").environ["PATH"],
                                               "HOME": __import__("os").environ["HOME"],
                                               "NO_COLOR": "1"})
        self.assertNotIn("Traceback", p.stdout + p.stderr)
        self.assertIn("Resumen accionable", p.stdout)
