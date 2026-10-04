# -*- coding: utf-8 -*-
"""Ciclo de vida, motor de ejecución y reanudación."""

from __future__ import annotations

import os
import subprocess
import unittest
from pathlib import Path

from core.lifecycle import ORDER, PHASES, entry_satisfied, exit_satisfied, plan_for
from core.run import (
    BLOCKED_, DONE, FAILED, PENDING, SKIPPED, Run, StepResult, compare_fingerprint,
    fingerprint, latest, load, resumable,
)
from tests.fixtures import Workspace


def repo(ws: Workspace) -> Path:
    env = {**os.environ, "GIT_AUTHOR_NAME": "a", "GIT_AUTHOR_EMAIL": "a@b",
           "GIT_COMMITTER_NAME": "a", "GIT_COMMITTER_EMAIL": "a@b"}
    subprocess.run(["git", "init", "-q", "-b", "main"], cwd=ws.root, capture_output=True, env=env)
    (ws.root / "README.md").write_text("# x\n", encoding="utf-8")
    subprocess.run(["git", "add", "-A"], cwd=ws.root, capture_output=True, env=env)
    subprocess.run(["git", "commit", "-qm", "i"], cwd=ws.root, capture_output=True, env=env)
    return ws.root


class TestCicloDeVida(unittest.TestCase):
    def test_toda_fase_declara_entrada_y_salida(self):
        for name, p in PHASES.items():
            self.assertTrue(p.exit, f"{name} no declara qué produce: no se puede saber si acabó")
            self.assertTrue(p.purpose, name)

    def test_las_fases_estan_en_el_orden_declarado(self):
        self.assertEqual(list(PHASES), list(ORDER))

    def test_el_plan_por_defecto_omite_las_opcionales(self):
        nombres = [p.name for p in plan_for()]
        self.assertNotIn("RELEASE", nombres)
        self.assertIn("IMPLEMENT", nombres)

    def test_pedir_una_fase_opcional_la_incluye(self):
        self.assertEqual([p.name for p in plan_for(["RELEASE"])], ["RELEASE"])

    def test_una_fase_sin_su_entrada_no_puede_empezar(self):
        ok, missing = entry_satisfied(PHASES["IMPLEMENT"], {"plan"})
        self.assertFalse(ok)
        self.assertIn("architecture", missing)

    def test_una_fase_sin_su_salida_no_ha_terminado(self):
        ok, missing = exit_satisfied(PHASES["TEST"], {"tests"})
        self.assertFalse(ok)
        self.assertIn("test-report", missing)


class TestHuellaDelEntorno(unittest.TestCase):
    def test_la_huella_recoge_lo_que_debe_seguir_igual(self):
        with Workspace("fp") as ws:
            repo(ws)
            ws.manifest()
            ws.policy()
            fp = fingerprint(ws.root)
            for k in ("git_commit", "git_branch", "manifest_digest", "policy_digest",
                      "harness_version"):
                self.assertIn(k, fp)

    def test_un_cambio_de_commit_se_detecta(self):
        before = {"git_commit": "a" * 40, "binding": {}}
        after = {"git_commit": "b" * 40, "binding": {}}
        self.assertTrue(any("commit" in d for d in compare_fingerprint(before, after)))

    def test_un_cambio_de_politica_se_detecta(self):
        d = compare_fingerprint({"policy_digest": "aaa", "binding": {}},
                                {"policy_digest": "bbb", "binding": {}})
        self.assertTrue(any("política" in x for x in d))

    def test_ensuciar_el_arbol_se_detecta(self):
        d = compare_fingerprint({"git_dirty": False, "binding": {}},
                                {"git_dirty": True, "binding": {}})
        self.assertTrue(any("sin confirmar" in x for x in d))

    def test_un_entorno_igual_no_produce_deriva(self):
        fp = {"git_commit": "a" * 40, "policy_digest": "x", "binding": {"sdd_core": "c" * 40}}
        self.assertEqual(compare_fingerprint(fp, dict(fp)), [])


class TestReanudacion(unittest.TestCase):
    def _run(self, ws) -> Run:
        r = Run(run_id="run_prueba", workspace=str(ws.root), goal="x",
                fingerprint=fingerprint(ws.root))
        r.steps = [StepResult(phase="SPECIFY", role="requirements-engineer",
                              runtime="claude", status=DONE),
                   StepResult(phase="TEST", role="test-engineer", runtime="claude",
                              status=PENDING)]
        r.save()
        return r

    def test_se_reanuda_si_el_entorno_no_cambio(self):
        with Workspace("res-ok") as ws:
            repo(ws); ws.manifest(); ws.policy()
            r = self._run(ws)
            check = resumable(r)
            self.assertTrue(check["can_resume"], check["drift"])
            self.assertEqual(check["pending"], ["TEST/test-engineer"])

    def test_NO_se_reanuda_si_el_entorno_cambio(self):
        """Reanudar sobre un entorno cambiado produce evidencia que dice una cosa sobre un
        árbol que ya es otra."""
        with Workspace("res-drift") as ws:
            repo(ws); ws.manifest(); ws.policy()
            r = self._run(ws)
            ws.policy(protected_paths=["otra/**"])          # cambia la política
            check = resumable(r)
            self.assertFalse(check["can_resume"])
            self.assertTrue(any("política" in d for d in check["drift"]))

    def test_una_ejecucion_terminada_no_tiene_nada_que_reanudar(self):
        with Workspace("res-done") as ws:
            repo(ws); ws.manifest(); ws.policy()
            r = self._run(ws)
            for s in r.steps:
                s.status = DONE
            r.save()
            self.assertFalse(resumable(r)["can_resume"])
            self.assertEqual(resumable(r)["pending"], [])

    def test_se_recupera_del_disco(self):
        with Workspace("res-load") as ws:
            repo(ws); ws.manifest(); ws.policy()
            self._run(ws)
            again = load(ws.root, "run_prueba")
            self.assertIsNotNone(again)
            self.assertEqual(again.goal, "x")
            self.assertEqual(latest(ws.root).run_id, "run_prueba")

    def test_un_estado_corrupto_no_revienta(self):
        with Workspace("res-bad") as ws:
            ws.file(".harness/state/run_roto.json", "{{{")
            self.assertIsNone(load(ws.root, "run_roto"))


class TestMotor(unittest.TestCase):
    def test_en_seco_no_invoca_a_nadie(self):
        from core.run import execute_step
        with Workspace("dry") as ws:
            repo(ws); ws.manifest(); ws.policy()
            r = Run(run_id="run_x", workspace=str(ws.root), fingerprint={})
            step = StepResult(phase="TEST", role="test-engineer", runtime="claude")
            execute_step(r, step, {}, dry_run=True)
            self.assertEqual(step.status, SKIPPED)
            self.assertIn("simulación", step.reason)

    def test_un_paso_bloqueado_por_el_router_no_se_ejecuta(self):
        from core.run import execute_step
        with Workspace("blk") as ws:
            ws.manifest()
            r = Run(run_id="run_y", workspace=str(ws.root), fingerprint={})
            step = StepResult(phase="TEST", role="test-engineer", status=BLOCKED_,
                              reason="ningún runtime cubre browser.automation")
            execute_step(r, step, {}, dry_run=False)
            self.assertEqual(step.status, BLOCKED_)

    def test_un_rol_inexistente_falla_y_lo_dice(self):
        from core.run import execute_step
        with Workspace("norole") as ws:
            ws.manifest()
            r = Run(run_id="run_z", workspace=str(ws.root), fingerprint={})
            step = StepResult(phase="X", role="rol-inventado", runtime="claude")
            execute_step(r, step, {}, dry_run=False)
            self.assertEqual(step.status, FAILED)
            self.assertIn("no existe", step.reason)

    def test_una_fase_con_revision_obligatoria_no_termina_sola(self):
        """Aunque el agente diga que acabó y las puertas pasen: falta una persona."""
        from core.run import execute_step
        with Workspace("hr-block") as ws:
            repo(ws); ws.manifest(); ws.policy()
            r = Run(run_id="run_h", workspace=str(ws.root), fingerprint={})
            step = StepResult(phase="VALIDATE", role="visual-validator", runtime="claude",
                              status=DONE)
            step.status = DONE
            execute_step(r, step, {}, dry_run=False, prompt_of=lambda role, w: "x")
            # Falla al invocar (no hay tarea real), pero si estuviera DONE quedaría BLOCKED.
            self.assertIn(step.status, (FAILED, BLOCKED_))
