# -*- coding: utf-8 -*-
"""Antigravity al mismo nivel que Claude: guardián, informe de sesión y cableado.

Las cargas siguen el contrato embebido en Antigravity 2.15.1 (`toolCall.name`,
`toolCall.args` en PascalCase, `workspacePaths`, `conversationId`). La prueba que da sentido
al resto es la primera: el guardián anterior, enganchado con el dialecto de otro runtime,
no encontraba la ruta en esta carga y APROBABA la escritura en la política.
"""

from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from core.proc import TEXT_IO

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))



def _guard(workspace: Path, payload, runtime: str = "antigravity") -> tuple[int, str, str]:
    raw = payload if isinstance(payload, str) else json.dumps(payload)
    p = subprocess.run([sys.executable, "-m", "core.guard", "--runtime", runtime, "--stdin",
                        "--workspace", str(workspace)], input=raw, capture_output=True,
                       cwd=ROOT, timeout=120, **TEXT_IO)
    return p.returncode, p.stdout.strip(), p.stderr.strip()


def _tool(ws: Path, name: str, **args) -> dict:
    return {"toolCall": {"name": name, "args": args}, "stepIdx": 3,
            "conversationId": "conv-prueba", "workspacePaths": [str(ws)], "modelName": "auto"}


def _decision(out: str) -> str:
    return json.loads(out.splitlines()[-1])["decision"]


class _Espacio(unittest.TestCase):
    def setUp(self):
        self.ws = Path(tempfile.mkdtemp(prefix="harness-ag-"))
        (self.ws / ".harness").mkdir()
        (self.ws / ".harness" / "policy.json").write_text("{}", encoding="utf-8")
        (self.ws / "README.md").write_text("# x\n", encoding="utf-8")


class TestGuardianAntigravity(_Espacio):
    def test_el_dialecto_ajeno_no_entiende_la_carga_y_ya_no_la_aprueba(self):
        """Control de por qué hace falta un dialecto propio: `kiro` y `gemini` no la reconocen.

        La propiedad que esta prueba demuestra no ha cambiado —la carga de Antigravity no trae
        ruta reconocible para otro dialecto, y por eso `_main_antigravity` existe—; lo que
        cambió es CÓMO falla. Afirmaba `rc == 0`, es decir que el dialecto ajeno «aprueba en
        silencio», y eso era el defecto medido el 2026-09-25: no reconocer una carga producía
        `allow`, así que bastaba un cambio de esquema en cualquier runtime para que el guardián
        dejara de gobernar sin que nadie lo notara.

        Ahora un dialecto que no entiende la carga responde `ask` (salida 2). Sigue sin
        gobernar —para eso está el dialecto propio— pero falla del lado seguro, que es lo único
        que esta prueba tenía derecho a dar por bueno.
        """
        carga = _tool(self.ws, "write_to_file", TargetFile=str(self.ws / ".harness/policy.json"),
                      CodeContent="{}")
        for ajeno in ("kiro", "gemini"):
            rc, out, err = _guard(self.ws, carga, runtime=ajeno)
            self.assertNotEqual(rc, 0, f"{ajeno}: el guardián ajeno aprueba en silencio ({err})")
            self.assertIn("no sabe leer", err,
                          f"{ajeno}: retiene sin decir que la causa es el mapeo de campos")

    def test_escribir_la_politica_se_deniega(self):
        rc, out, _ = _guard(self.ws, _tool(self.ws, "write_to_file",
                                           TargetFile=str(self.ws / ".harness/policy.json"),
                                           CodeContent="{}"))
        self.assertEqual(rc, 0, "la decisión viaja en stdout, no en el código de salida")
        self.assertEqual(_decision(out), "deny", out)

    def test_escribir_obra_normal_se_permite(self):
        rc, out, _ = _guard(self.ws, _tool(self.ws, "write_to_file",
                                           TargetFile=str(self.ws / "README.md"),
                                           CodeContent="# y\n"))
        self.assertEqual(_decision(out), "allow", out)

    def test_leer_la_politica_no_se_bloquea(self):
        rc, out, _ = _guard(self.ws, _tool(self.ws, "view_file",
                                           AbsolutePath=str(self.ws / ".harness/policy.json")))
        self.assertEqual(_decision(out), "allow", out)

    def test_herramienta_desconocida_con_ruta_se_juzga_como_escritura(self):
        rc, out, _ = _guard(self.ws, _tool(self.ws, "move",
                                           SourcePath=str(self.ws / "README.md"),
                                           DestinationPath=str(self.ws / ".harness/policy.json")))
        self.assertEqual(_decision(out), "deny", out)

    def test_reemplazo_multiple_hacia_la_politica_se_deniega(self):
        rc, out, _ = _guard(self.ws, _tool(
            self.ws, "multi_replace_file_content", TargetFile=str(self.ws / ".harness/policy.json"),
            ReplacementChunks=[{"TargetContent": "{}", "ReplacementContent": '{"x":1}'}]))
        self.assertEqual(_decision(out), "deny", out)

    def test_orden_de_shell_pasa_por_la_politica_de_ordenes(self):
        rc, out, _ = _guard(self.ws, _tool(self.ws, "run_command", CommandLine="sudo rm -rf /x",
                                           Cwd=str(self.ws)))
        self.assertIn(_decision(out), ("deny", "ask"), out)
        rc, out, _ = _guard(self.ws, _tool(self.ws, "run_command", CommandLine="ls -la",
                                           Cwd=str(self.ws)))
        self.assertEqual(_decision(out), "allow", out)

    def test_carga_ilegible_se_deniega_explicitamente(self):
        rc, out, _ = _guard(self.ws, "{ esto no es json")
        self.assertEqual(rc, 0)
        self.assertEqual(_decision(out), "deny", out)

    def test_cada_decision_deja_rastro(self):
        _guard(self.ws, _tool(self.ws, "write_to_file",
                              TargetFile=str(self.ws / ".harness/policy.json"), CodeContent="{}"))
        diario = self.ws / ".harness" / "evidence" / "ledger.jsonl"
        self.assertTrue(diario.is_file())
        self.assertIn('"runtime": "antigravity"', diario.read_text(encoding="utf-8")
                      .replace('":"', '": "'))


class TestInformeYSesiones(_Espacio):
    def test_primera_invocacion_recibe_el_informe_y_la_segunda_no(self):
        carga = {"invocationNum": 1, "initialNumSteps": 0, "conversationId": "conv-A",
                 "workspacePaths": [str(self.ws)]}
        rc, out, _ = _guard(self.ws, carga)
        doc = json.loads(out)
        self.assertTrue(doc.get("injectSteps"), out[:300])
        self.assertGreater(len(doc["injectSteps"][0]["ephemeralMessage"]), 200)
        rc, out2, _ = _guard(self.ws, dict(carga, invocationNum=2))
        self.assertEqual(json.loads(out2), {})

    def test_la_sesion_se_anuncia_sin_huella_de_proceso(self):
        _guard(self.ws, {"invocationNum": 1, "conversationId": "conv-B",
                         "workspacePaths": [str(self.ws)]})
        latidos = list((self.ws / ".harness" / "state" / "sesiones").glob("antigravity-*.json"))
        self.assertEqual(len(latidos), 1)
        self.assertEqual(json.loads(latidos[0].read_text())["sesion"], "conv-B")


class TestCableado(unittest.TestCase):
    def setUp(self):
        self.ws = Path(tempfile.mkdtemp(prefix="harness-agw-"))

    def test_engancha_audita_y_es_idempotente(self):
        from core import wire
        self.assertFalse(wire.audit_antigravity(self.ws)["wired"])
        r = wire.wire_antigravity(self.ws, harness_root=ROOT)
        self.assertEqual(r[0].action, "wired")
        self.assertTrue(wire.audit_antigravity(self.ws)["wired"])
        self.assertEqual(wire.wire_antigravity(self.ws, harness_root=ROOT)[0].action, "already")

    def test_preserva_los_ganchos_ajenos(self):
        from core import wire
        p = self.ws / ".agents" / "hooks.json"
        p.parent.mkdir(parents=True)
        ajeno = {"lint-checker": {"PostToolUse": [{"matcher": "run_command",
                                                   "hooks": [{"command": "./lint.sh"}]}]}}
        p.write_text(json.dumps(ajeno), encoding="utf-8")
        wire.wire_antigravity(self.ws, harness_root=ROOT)
        doc = json.loads(p.read_text(encoding="utf-8"))
        self.assertEqual(doc["lint-checker"], ajeno["lint-checker"])
        self.assertIn(wire.ANTIGRAVITY_HOOK, doc)

    def test_matcher_estrechado_o_gancho_desactivado_no_cuenta(self):
        from core import wire
        wire.wire_antigravity(self.ws, harness_root=ROOT)
        p = self.ws / ".agents" / "hooks.json"
        doc = json.loads(p.read_text(encoding="utf-8"))
        doc[wire.ANTIGRAVITY_HOOK]["PreToolUse"][0]["matcher"] = "run_command"
        p.write_text(json.dumps(doc), encoding="utf-8")
        self.assertFalse(wire.audit_antigravity(self.ws)["wired"])
        doc[wire.ANTIGRAVITY_HOOK]["PreToolUse"][0]["matcher"] = "*"
        doc[wire.ANTIGRAVITY_HOOK]["enabled"] = False
        p.write_text(json.dumps(doc), encoding="utf-8")
        self.assertFalse(wire.audit_antigravity(self.ws)["wired"])

    def test_el_informe_bloquea_si_antigravity_no_esta_enganchado(self):
        from core.session import build_brief
        _, _, bloqueos = build_brief(self.ws, runtime="antigravity")
        self.assertTrue(any("Antigravity" in b for b in bloqueos), bloqueos)


class TestInstalacion(unittest.TestCase):
    """`install` tiene que enganchar Antigravity como a cualquier otro runtime presente.

    Si no lo hace, el agente trabaja sin guardián pese a que el producto dice soportarlo — que
    es exactamente el fallo que motivó añadir este runtime.
    """

    def setUp(self):
        self.ws = Path(tempfile.mkdtemp(prefix="harness-agi-"))

    def test_la_huella_de_antigravity_lo_declara_presente(self):
        import importlib
        refuto = importlib.import_module("refuto")
        (self.ws / ".agents").mkdir()
        self.assertIn("antigravity", refuto._runtimes_presentes(self.ws))

    def test_install_engancha_antigravity_cuando_esta_presente(self):
        import importlib
        importlib.import_module("refuto")   # el efecto es la importación, no el nombre
        from core import wire
        (self.ws / ".agents").mkdir()
        subprocess.run(["git", "init", "-q", str(self.ws)], capture_output=True)
        p = subprocess.run([sys.executable, str(ROOT / "refuto.py"), "--workspace", str(self.ws),
                            "install"], capture_output=True, cwd=ROOT, timeout=300, **TEXT_IO)
        self.assertTrue(wire.audit_antigravity(self.ws)["wired"],
                        f"install no enganchó Antigravity: {p.stdout[-400:]}")


if __name__ == "__main__":
    unittest.main()
