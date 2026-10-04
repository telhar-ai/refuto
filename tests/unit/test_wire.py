# -*- coding: utf-8 -*-
"""Enganche del guardián. H-03 vuelve en silencio si `audit` no ve lo que hay."""

from __future__ import annotations

import json
import unittest
from pathlib import Path

from core.wire import audit, unwire, wire_kiro_agents
from tests.fixtures import Workspace

HARNESS = Path(__file__).resolve().parents[2]


def kiro_agent(ws, name, hooks=None):
    doc = {"name": name, "tools": ["read", "write"], "allowedTools": ["read", "write"]}
    if hooks:
        doc["hooks"] = hooks
    return ws.json(f".kiro/agents/{name}.json", doc)


class TestEnganche(unittest.TestCase):
    def test_antes_de_enganchar_no_hay_guardian(self):
        with Workspace("wire-none") as ws:
            kiro_agent(ws, "a"); kiro_agent(ws, "b")
            rep = audit(ws.root)
            self.assertEqual((rep["agents"], rep["wired"]), (2, 0))

    def test_engancha_y_audit_lo_ve(self):
        """La regresión concreta: `audit` buscaba la marca en `command` y el comando real dice
        `python3 -m core.guard`, así que reportaba 0 enganchados recién después de engancharlos."""
        with Workspace("wire-ok") as ws:
            kiro_agent(ws, "a"); kiro_agent(ws, "b")
            wire_kiro_agents(ws.root, harness_root=HARNESS)
            rep = audit(ws.root)
            self.assertEqual((rep["agents"], rep["wired"]), (2, 2), rep["detail"])

    def test_es_idempotente(self):
        with Workspace("wire-twice") as ws:
            kiro_agent(ws, "a")
            wire_kiro_agents(ws.root, harness_root=HARNESS)
            # La lista creció el 2026-10-04: `wire_*` declara ahora también el LANZADOR
            # (`.harness/bin/guard`). Antes lo escribía y lo callaba — incluso en
            # `--dry-run`. Se afirma sobre el gancho por su RUTA y no por la posición en
            # la lista, que es lo que hacía frágil la aserción anterior.
            second = wire_kiro_agents(ws.root, harness_root=HARNESS)
            acciones = {r.path: r.action for r in second}
            self.assertEqual("already", acciones[".kiro/agents/a.json"])
            self.assertEqual("already", acciones[".harness/bin/guard"],
                             "el lanzador ya apuntaba bien: no debía reescribirse")
            doc = json.loads((ws.root / ".kiro/agents/a.json").read_text())
            self.assertEqual(len(doc["hooks"]["preToolUse"]), 1, "el gancho se duplicó")

    def test_preserva_los_ganchos_existentes(self):
        """No destruir lo que alguien escribió a mano es la mitad del contrato."""
        with Workspace("wire-keep") as ws:
            kiro_agent(ws, "a", hooks={"preToolUse": [
                {"matcher": "fs_write", "command": "python3 verificacion/vc_datos.py --desde-hook"}]})
            wire_kiro_agents(ws.root, harness_root=HARNESS)
            doc = json.loads((ws.root / ".kiro/agents/a.json").read_text())
            cmds = [h["command"] for h in doc["hooks"]["preToolUse"]]
            self.assertEqual(len(cmds), 2)
            self.assertTrue(any("vc_datos" in c for c in cmds), "se perdió el gancho original")

    def test_es_reversible(self):
        with Workspace("wire-undo") as ws:
            kiro_agent(ws, "a")
            original = (ws.root / ".kiro/agents/a.json").read_text()
            wire_kiro_agents(ws.root, harness_root=HARNESS)
            self.assertNotEqual(original, (ws.root / ".kiro/agents/a.json").read_text())
            unwire(ws.root)
            self.assertEqual(original, (ws.root / ".kiro/agents/a.json").read_text())

    def test_simulacion_no_escribe(self):
        with Workspace("wire-dry") as ws:
            kiro_agent(ws, "a")
            before = (ws.root / ".kiro/agents/a.json").read_text()
            wire_kiro_agents(ws.root, harness_root=HARNESS, dry_run=True)
            self.assertEqual(before, (ws.root / ".kiro/agents/a.json").read_text())

    def test_un_agente_ilegible_se_declara_no_se_salta(self):
        with Workspace("wire-bad") as ws:
            ws.file(".kiro/agents/roto.json", "{ no json")
            # La lista creció el 2026-10-04: `wire_*` declara ahora también el LANZADOR
            # (`.harness/bin/guard`). Antes lo escribía y lo callaba — incluso en
            # `--dry-run`. Se afirma sobre el gancho por su RUTA y no por la posición en
            # la lista, que es lo que hacía frágil la aserción anterior.
            results = wire_kiro_agents(ws.root, harness_root=HARNESS)
            # Se busca por sufijo y no por clave exacta: la rama `skipped` reporta la ruta
            # ABSOLUTA mientras el resto de `wire_*` reporta la relativa al espacio.
            # Inconsistencia preexistente del informe, no de la decisión; se deja anotada aquí
            # en vez de absorberla en silencio.
            ilegible = [r for r in results if r.path.endswith("roto.json")]
            self.assertEqual(1, len(ilegible), f"no se declaró el agente ilegible: {results}")
            self.assertEqual("skipped", ilegible[0].action)
            self.assertIn("ilegible", ilegible[0].detail)


class TestEngancheEnRepositorios(unittest.TestCase):
    """Un espacio que contiene repositorios tiene tantos puntos de entrada como repositorios.

    Claude Code resuelve sus ajustes a la raiz del repositorio git, no al directorio actual.
    Enganchar solo la raiz del espacio cubre UN punto. Medido en un espacio real: 215
    repositorios, 38 ficheros de ajustes, 2 con guardian.

    Lo que esto NO es: multiplicar el gobierno. Hay una politica, un guardian y N punteros
    inertes. El guardian deduce el espacio de SU PROPIA ubicacion, asi que los N punteros dan
    la misma decision y no pueden derivar entre si.
    """

    def _espacio(self, ws):
        ws.policy()
        (ws.root / ".harness" / "bin").mkdir(parents=True, exist_ok=True)
        (ws.root / ".harness" / "bin" / "guard").write_text("#!/bin/sh\n", encoding="utf-8")

    def _repo(self, ws, rel):
        (ws.root / rel / ".git").mkdir(parents=True, exist_ok=True)

    def test_engancha_cada_repositorio_al_MISMO_guardian(self):
        from core.wire import wire_claude_repos
        with Workspace("w-repos") as ws:
            self._espacio(ws)
            for r in ("uno", "dos", "grupo/tres"):
                self._repo(ws, r)

            wire_claude_repos(ws.root, harness_root=HARNESS)

            guardias = set()
            for rel in ("uno", "dos", "grupo/tres"):
                p = ws.root / rel / ".claude" / "settings.local.json"
                self.assertTrue(p.is_file(), f"{rel} sin enganchar")
                doc = json.loads(p.read_text(encoding="utf-8"))
                for e in doc["hooks"]["PreToolUse"]:
                    for h in e.get("hooks", []):
                        guardias.add(h["command"])
            self.assertEqual(1, len(guardias), "los punteros no apuntan al mismo guardián")
            self.assertIn(str(ws.root / ".harness" / "bin" / "guard"), guardias.pop())

    def test_cubre_directorios_con_claude_aunque_no_sean_repositorios(self):
        """Un sitio donde ya se abrió una sesión es un punto de entrada probado por el uso.

        En un espacio real eran 23 de 136, y recorrer sólo repositorios los dejaba fuera.
        """
        from core.wire import wire_claude_repos
        with Workspace("w-noRepo") as ws:
            self._espacio(ws)
            ws.json("carpeta/.claude/settings.local.json", {"permissions": {"allow": []}})

            wire_claude_repos(ws.root, harness_root=HARNESS)

            doc = json.loads((ws.root / "carpeta" / ".claude" / "settings.local.json")
                             .read_text(encoding="utf-8"))
            mandos = [h["command"] for e in doc["hooks"]["PreToolUse"] for h in e["hooks"]]
            self.assertTrue(any("guard" in m for m in mandos))

    def test_es_idempotente(self):
        """Reejecutar no duplica ganchos: un guardián enganchado dos veces decide dos veces."""
        from core.wire import wire_claude_repos
        with Workspace("w-idem") as ws:
            self._espacio(ws)
            self._repo(ws, "uno")
            wire_claude_repos(ws.root, harness_root=HARNESS)
            wire_claude_repos(ws.root, harness_root=HARNESS)
            doc = json.loads((ws.root / "uno" / ".claude" / "settings.local.json")
                             .read_text(encoding="utf-8"))
            ganchos = [h for e in doc["hooks"]["PreToolUse"] for h in e.get("hooks", [])
                       if "guard" in h.get("command", "")]
            self.assertEqual(1, len(ganchos))

    def test_no_pisa_lo_que_ya_habia_en_el_fichero(self):
        """Instalar un control rompiendo la configuración de alguien es empezar mal."""
        from core.wire import wire_claude_repos
        with Workspace("w-preserva") as ws:
            self._espacio(ws)
            self._repo(ws, "uno")
            ws.json("uno/.claude/settings.local.json",
                    {"permissions": {"allow": ["Bash(ls:*)", "Bash(cat:*)"]}, "model": "opus"})

            wire_claude_repos(ws.root, harness_root=HARNESS)

            doc = json.loads((ws.root / "uno" / ".claude" / "settings.local.json")
                             .read_text(encoding="utf-8"))
            self.assertEqual(2, len(doc["permissions"]["allow"]))
            self.assertEqual("opus", doc["model"])

    def test_un_fichero_ilegible_se_salta_y_se_dice(self):
        from core.wire import wire_claude_repos
        with Workspace("w-roto") as ws:
            self._espacio(ws)
            self._repo(ws, "uno")
            ws.file("uno/.claude/settings.local.json", "{ roto")
            res = wire_claude_repos(ws.root, harness_root=HARNESS)
            self.assertTrue(any(r.action == "skipped" and "ilegible" in (r.detail or "")
                                for r in res))


class TestElAvisoDeRootNoDependeDeNadie(unittest.TestCase):
    """El gancho `SessionStart` se escribe en el `.claude/settings.local.json` de CADA
    repositorio enganchado de CADA adoptante. Lo que diga tiene que ser verdad en cualquier
    máquina, no sólo en la de quien lo escribió.

    Antes de este arreglo la primera y la tercera fallan: el gancho preguntaba por
    una variable de un lanzador privado ajeno a este producto, y mandaba reabrir la sesión
    con un comando que no forma parte de este producto. Fuera de aquella máquina el aviso
    más importante del arranque terminaba en «command not found».
    """

    def test_no_nombra_ningun_lanzador_privado(self):
        from core.wire import ROOT_WARN_CMD
        for rastro in ("cc-tlr", "cc-pub", "cc-arn", "THLR", "thlr", "ccs "):
            self.assertNotIn(rastro, ROOT_WARN_CMD,
                             f"el aviso remite a «{rastro}», que no se publica con refuto")
        self.assertNotIn("cc-", ROOT_WARN_CMD)

    def test_sugiere_una_orden_que_este_producto_tiene(self):
        from core.wire import ROOT_WARN_CMD
        self.assertIn("refuto chat", ROOT_WARN_CMD)

    def test_la_marca_que_consulta_la_pone_el_propio_producto(self):
        """La variable no puede venir de fuera: la escribe quien de verdad va a reparar."""
        import inspect as _inspect

        from core import session
        from core.wire import SESSION_ENV, ROOT_WARN_CMD
        self.assertTrue(SESSION_ENV.startswith("HARNESS_"))
        self.assertIn(f"${SESSION_ENV}", ROOT_WARN_CMD)
        self.assertIn("wire_SESSION_ENV", _inspect.getsource(session.launch),
                      "`refuto chat` tiene que exportar la marca que el gancho consulta; si no, "
                      "el aviso duro sale SIEMPRE y se aprende a ignorarlo")

    def test_el_aviso_enganchado_es_exactamente_el_del_modulo(self):
        from core.wire import ROOT_WARN_CMD, wire_claude
        with Workspace("wire-root") as ws:
            wire_claude(ws.root, harness_root=HARNESS)
            doc = json.loads((ws.root / ".claude/settings.local.json").read_text(encoding="utf-8"))
            ses = [h["command"] for e in doc["hooks"]["SessionStart"] for h in e["hooks"]]
            self.assertEqual([ROOT_WARN_CMD], ses)

    def test_un_aviso_previo_sin_marca_no_se_duplica(self):
        """El caso real: una versión anterior escribió el aviso SIN `_generado`, así que la
        limpieza —que buscaba sólo la marca— no lo reconocía y añadía otro igual. Medido el
        2026-09-28 al cablear un espacio que ya lo tenía: dos avisos idénticos donde hay que ver
        uno. Un control que se imprime dos veces enseña a no leerlo.
        """
        from core.wire import ROOT_WARN_CMD, wire_claude
        with Workspace("wire-root-dup") as ws:
            path = ws.root / ".claude" / "settings.local.json"
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(json.dumps({"hooks": {"SessionStart": [
                {"hooks": [{"type": "command", "command": ROOT_WARN_CMD, "timeout": 10}]},
            ]}}), encoding="utf-8")
            wire_claude(ws.root, harness_root=HARNESS)
            doc = json.loads(path.read_text(encoding="utf-8"))
            ses = [h["command"] for e in doc["hooks"]["SessionStart"] for h in e["hooks"]]
            self.assertEqual([ROOT_WARN_CMD], ses, "el aviso quedó duplicado")

    def test_un_sessionstart_ajeno_no_se_toca(self):
        """La otra mitad: limpiar por el comando no puede llevarse por delante el gancho de
        otra persona. Es la razón por la que la comparación es exacta y no `in`."""
        from core.wire import ROOT_WARN_CMD, wire_claude
        ajeno = 'echo "aviso de alguien más"; exit 0'
        with Workspace("wire-root-ajeno") as ws:
            path = ws.root / ".claude" / "settings.local.json"
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(json.dumps({"hooks": {"SessionStart": [
                {"hooks": [{"type": "command", "command": ajeno}]},
            ]}}), encoding="utf-8")
            wire_claude(ws.root, harness_root=HARNESS)
            doc = json.loads(path.read_text(encoding="utf-8"))
            ses = [h["command"] for e in doc["hooks"]["SessionStart"] for h in e["hooks"]]
            self.assertIn(ajeno, ses)
            self.assertIn(ROOT_WARN_CMD, ses)
            self.assertEqual(2, len(ses))
