# -*- coding: utf-8 -*-
"""Lanzador del guardián. Cada prueba fija un modo de invocación que rompía la versión anterior."""

from __future__ import annotations

import json
import os
import subprocess
import unittest
from pathlib import Path

from core import launcher
from core.proc import TEXT_IO, owns_by_uid
from core.wire import audit_claude, wire_claude, wire_kiro_agents
from tests.fixtures import Workspace

HARNESS = Path(__file__).resolve().parents[2]
PAYLOAD_DENY = json.dumps({"tool_name": "Write",
                           "tool_input": {"file_path": "verificacion/juez.py", "content": "x"}})
PAYLOAD_ALLOW = json.dumps({"tool_name": "Write",
                            "tool_input": {"file_path": "app/ui.js", "content": "const x = 1"}})


#: Un directorio que existe en cualquier sistema, para probar que el lanzador no depende del
#: directorio actual. `/` no existe como tal en Windows.
AJENO = "/" if os.name != "nt" else os.environ.get("SystemRoot", r"C:\Windows")


def run_launcher(ws: Workspace, payload: str, *, cwd: str | None = None,
                 env: dict | None = None):
    """Ejecuta el lanzador NATIVO de este sistema.

    Cuál es depende del sistema: en Windows, `guard` es un guion de `sh` que `CreateProcess` no
    sabe ejecutar. Probar siempre el de POSIX no comprobaba el lanzador: comprobaba que la
    máquina fuera macOS.
    """
    base = {"HARNESS_GUARD_RUNTIME": "claude", "HOME": os.environ.get("HOME", "/tmp")}
    if os.name == "nt":
        # cmd.exe necesita estas dos para arrancar; sin ellas no es un entorno mínimo, es uno
        # roto, y lo que se probaría es el arranque de cmd.exe y no el guardián.
        for clave in ("SystemRoot", "COMSPEC", "PATHEXT"):
            if os.environ.get(clave):
                base[clave] = os.environ[clave]
    return subprocess.run([str(launcher.launcher_path(ws.root))],
                          input=payload, capture_output=True, cwd=cwd or AJENO, **TEXT_IO,
                          env={**base, **(env or {})}, timeout=60)


class TestLanzador(unittest.TestCase):
    def setUp(self):
        self.ws = Workspace("lz")
        self.ws.__enter__()
        self.ws.policy()
        launcher.install(self.ws.root, harness_home=HARNESS, runtime="claude")

    def tearDown(self):
        self.ws.__exit__(None, None, None)

    def decision(self, proc) -> str:
        return json.loads(proc.stdout)["hookSpecificOutput"]["permissionDecision"]

    def test_se_instala_ejecutable(self):
        p = launcher.launcher_path(self.ws.root)
        self.assertTrue(p.is_file())
        self.assertTrue(os.access(p, os.X_OK))

    def test_bloquea_lo_protegido(self):
        self.assertEqual(self.decision(run_launcher(self.ws, PAYLOAD_DENY)), "deny")

    def test_permite_el_producto(self):
        self.assertEqual(self.decision(run_launcher(self.ws, PAYLOAD_ALLOW)), "allow")

    def test_no_depende_del_directorio_actual(self):
        """El gancho se ejecuta con el cwd que le toque, no con el del espacio."""
        for cwd in (AJENO, os.path.expanduser("~")):
            self.assertEqual(self.decision(run_launcher(self.ws, PAYLOAD_DENY, cwd=cwd)),
                             "deny", cwd)

    def test_funciona_sin_PATH(self):
        """Es la condición de una aplicación de escritorio: no hereda el entorno del shell."""
        proc = run_launcher(self.ws, PAYLOAD_DENY, env={"PATH": ""})
        self.assertEqual(self.decision(proc), "deny", proc.stderr)

    def test_funciona_con_el_entorno_vacio(self):
        # Así arranca un proceso lanzado desde una aplicación de escritorio. En Windows el
        # entorno «vacío» conserva lo que cmd.exe necesita para existir: quitarlo no probaría
        # el lanzador, probaría que cmd.exe no arranca sin SystemRoot, que ya se sabe.
        proc = run_launcher(self.ws, PAYLOAD_DENY, env={})
        self.assertEqual(self.decision(proc), "deny", proc.stderr)

    def test_si_el_harness_se_movio_BLOQUEA_en_vez_de_aprobar(self):
        """Un guardián que no se encuentra a sí mismo no aprueba."""
        p = launcher.launcher_path(self.ws.root)
        salto = "\r\n" if p.suffix == ".cmd" else "\n"
        p.write_text(p.read_text(encoding="utf-8").replace(str(HARNESS), "/ruta/que/no/existe"),
                     encoding="utf-8", newline=salto)
        proc = run_launcher(self.ws, PAYLOAD_ALLOW)
        self.assertNotEqual(proc.returncode, 0)
        self.assertIn("BLOQUEA", proc.stderr)

    def test_check_detecta_el_harness_movido(self):
        p = self.ws.root / launcher.BIN / "installed.json"
        doc = json.loads(p.read_text(encoding="utf-8"))
        doc["harness_home"] = "/ruta/que/no/existe"
        p.write_text(json.dumps(doc), encoding="utf-8")
        out = launcher.check(self.ws.root)
        self.assertFalse(out["ok"])
        self.assertIn("ya no está refuto", out["reason"])

    def test_check_sin_instalar(self):
        with Workspace("lz2") as ws:
            self.assertFalse(launcher.check(ws.root)["ok"])


class TestPropiedad(unittest.TestCase):
    def test_informa_de_archivos_ajenos(self):
        with Workspace("own") as ws:
            ws.policy()
            launcher.install(ws.root, harness_home=HARNESS)
            rep = launcher.ownership_report(ws.root)
            if not owns_by_uid():
                # Donde no hay `uid` la respuesta correcta es «no comprobado», y está probado
                # en tests/unit/test_portabilidad.py. Afirmar aquí «0 ajenos» sería declarar
                # limpio lo que nadie miró.
                self.assertFalse(rep["checked"])
                return
            self.assertTrue(rep["checked"])
            self.assertEqual(rep["count"], 0, rep["foreign"])

    def test_sin_harness_no_afirma_nada(self):
        with Workspace("own2") as ws:
            self.assertFalse(launcher.ownership_report(ws.root)["checked"])

    def test_fuera_de_sudo_no_toca_nada(self):
        with Workspace("own3") as ws:
            ws.policy()
            launcher.install(ws.root, harness_home=HARNESS)
            self.assertEqual(launcher.restore_ownership(ws.root), 0)


class TestActualizacionDeGanchos(unittest.TestCase):
    def test_un_gancho_antiguo_se_ACTUALIZA_no_se_da_por_bueno(self):
        """`already` tenía que distinguir «ya está» de «ya está, pero anticuado»."""
        with Workspace("up") as ws:
            ws.json(".kiro/agents/a.json", {
                "name": "a", "tools": ["read"],
                "hooks": {"preToolUse": [{"matcher": "fs_write",
                                          "command": "cd /viejo && python3 -m core.guard"}]}})
            r = wire_kiro_agents(ws.root, harness_root=HARNESS)
            self.assertEqual([x.action for x in r], ["upgraded"])
            doc = json.loads((ws.root / ".kiro/agents/a.json").read_text(encoding="utf-8"))
            cmds = [h["command"] for h in doc["hooks"]["preToolUse"]]
            self.assertEqual(len(cmds), 1, "quedó el antiguo además del nuevo")
            self.assertIn(".harness/bin/guard", cmds[0])

    def test_un_gancho_ya_con_lanzador_no_se_toca(self):
        with Workspace("up2") as ws:
            ws.json(".kiro/agents/a.json", {"name": "a", "tools": ["read"]})
            wire_kiro_agents(ws.root, harness_root=HARNESS)
            self.assertEqual([x.action for x in wire_kiro_agents(ws.root, harness_root=HARNESS)],
                             ["already"])

    def test_claude_tambien_se_actualiza(self):
        with Workspace("up3") as ws:
            ws.json(".claude/settings.local.json", {
                "hooks": {"PreToolUse": [{"matcher": "Write",
                                          "hooks": [{"type": "command",
                                                     "command": "cd /viejo && python3 -m core.guard"}]}]}})
            r = wire_claude(ws.root, harness_root=HARNESS)
            self.assertEqual([x.action for x in r], ["upgraded"])
            self.assertTrue(audit_claude(ws.root)["wired"])
            doc = json.loads((ws.root / ".claude/settings.local.json").read_text(encoding="utf-8"))
            cmds = [h["command"] for e in doc["hooks"]["PreToolUse"] for h in e["hooks"]]
            self.assertEqual(len(cmds), 1)
            self.assertIn(".harness/bin/guard", cmds[0])
