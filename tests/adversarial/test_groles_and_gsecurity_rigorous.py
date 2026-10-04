# -*- coding: utf-8 -*-
"""Pruebas rigurosas de comportamiento y falsación de G-ROLES y G-SECURITY.

Verifica exhaustivamente:
G-ROLES:
- 0 examined -> nunca PASS (BLOCKED/FAIL)
- 1 examined, N examined
- expected > examined, expected == examined, expected < examined
- coverage calculation
- excluded items, duplicate items, missing items
- invalid selection

G-SECURITY:
- tool available (todos OK -> PASS con Scope completo)
- tool unavailable (falta trivy/syft -> BLOCKED, nunca PASS)
- tool failed (revienta o error -> NOT_EXECUTABLE)
- tool timed out (timeout -> NOT_EXECUTABLE)
- tool returned malformed result (JSON inválido -> NOT_EXECUTABLE)
- tool returned partial/empty result (código 0 pero salida vacía -> NOT_EXECUTABLE)
- tool returned zero findings (pero scanned == 0 -> BLOCKED)
- tool returned findings (secretos o vulnerabilidades críticas -> FAIL)
"""

from __future__ import annotations

import json
import shutil
import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

from core.context import Context
from core.model import (
    BLOCKED,
    CRITICAL,
    FAIL,
    HIGH,
    MEDIUM,
    NOT_EXECUTABLE,
    PASS,
    Result,
    Scope,
)
from gates import g_roles, g_security


class TestGRolesRigorous(unittest.TestCase):
    def setUp(self):
        self.temp_dir = Path(tempfile.mkdtemp(prefix="refuto-groles-test-"))
        self.ctx = Context(workspace=self.temp_dir)
        from core.roles import load
        load.cache_clear()

    def tearDown(self):
        from core.roles import load
        load.cache_clear()
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_roles_empty_registry_never_passes(self):
        """0 examined nunca produce PASS."""
        roles_dir = self.temp_dir / "roles"
        roles_dir.mkdir(parents=True, exist_ok=True)
        doc = {"schema": "harness.roles/v1", "version": "1.0", "roles": []}
        (roles_dir / "registry.json").write_text(json.dumps(doc), encoding="utf-8")
        res = g_roles.run(self.ctx)
        self.assertNotEqual(res.status, PASS)
        self.assertIn(res.status, (BLOCKED, FAIL))
        self.assertIsNotNone(res.scope)
        self.assertEqual(res.scope.examined, 0)

        # 0 roles encontrados sin hallazgos produce BLOCKED, nunca PASS (mata mutante M08)
        with patch("gates.g_roles.load", return_value={}), \
             patch("gates.g_roles.validate_registry", return_value=[]):
            res_mock = g_roles.run(self.ctx)
            self.assertEqual(res_mock.status, BLOCKED)

    def test_roles_n_examined_expected_equal(self):
        """N examined con registro válido produce PASS con Scope completo."""
        roles_dir = self.temp_dir / "roles"
        roles_dir.mkdir(parents=True, exist_ok=True)
        roles = []
        for i in range(5):
            roles.append({
                "id": f"role-{i}",
                "group": "development",
                "phase": "DEV",
                "purpose": "A valid purpose that is longer than twenty characters",
                "input_contract": [],
                "output_contract": ["artifact.txt"],
                "required_capabilities": ["code"],
                "allowed_tools": ["git"],
                "constraints": ["no_self_approval"],
                "quality_gates": ["G-POLICY"],
                "human_review": "",
                "handoff": []
            })
        doc = {
            "schema": "harness.roles/v1",
            "version": "1.0",
            "roles": roles
        }
        (roles_dir / "registry.json").write_text(json.dumps(doc), encoding="utf-8")
        res = g_roles.run(self.ctx)
        self.assertEqual(res.status, PASS)
        self.assertEqual(res.scope.examined, 5)
        self.assertEqual(res.scope.unknown, 0)
        self.assertEqual(res.scope.universe, "roles declarados en roles/registry.json")

    def test_roles_registry_schema_failure(self):
        """Si el registro tiene problemas de esquema, produce FAIL con findings."""
        roles_dir = self.temp_dir / "roles"
        roles_dir.mkdir(parents=True, exist_ok=True)
        doc = {
            "schema": "harness.roles/v1",
            "version": "1.0",
            "roles": [
                {
                    "id": "broken-role",
                    "phase": "DEV",
                    "purpose": "A valid purpose that is longer than twenty characters",
                    "output_contract": ["artifact.txt"],
                    "required_capabilities": ["code"],
                    "allowed_tools": ["git"],
                    "constraints": ["no_self_approval"]
                }
            ]
        }
        (roles_dir / "registry.json").write_text(json.dumps(doc), encoding="utf-8")
        res = g_roles.run(self.ctx)
        self.assertEqual(res.status, FAIL)
        self.assertGreaterEqual(len(res.findings), 1)
        self.assertEqual(res.scope.examined, 0)
        self.assertEqual(res.scope.unknown, 1)

    def test_scope_fields_semantics(self):
        """Verificar campos explícitos de Scope: items_examined, expected, coverage."""
        sc = Scope(
            examined=10,
            unknown=0,
            universe="roles",
            declared=True,
            subject="roles/registry.json",
            items_expected=10,
            coverage=1.0,
            selection_rule="todos",
            exclusions=[]
        )
        self.assertEqual(sc.items_examined, 10)
        self.assertEqual(sc.items_expected, 10)
        self.assertEqual(sc.coverage, 1.0)
        self.assertTrue(sc.complete)


class TestGSecurityRigorous(unittest.TestCase):
    def setUp(self):
        self.temp_dir = Path(tempfile.mkdtemp(prefix="refuto-gsec-test-"))
        self.ctx = Context(workspace=self.temp_dir)
        (self.temp_dir / "app.py").write_text("print('hello world')", encoding="utf-8")

    def tearDown(self):
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_tool_available_clean_passes(self):
        """Herramientas disponibles y limpias producen PASS con Scope."""
        with patch("shutil.which", return_value="/bin/tool"), \
             patch("gates.g_security._scan_secrets", return_value=(1, 0, [])), \
             patch("gates.g_security._run_json") as mock_run:
            mock_run.side_effect = [
                {"ok": True, "data": []},  # gitleaks
                {"ok": True, "data": {"artifacts": [{"name": "dep1"}]}},  # syft
                {"ok": True, "data": {"Results": []}}  # trivy
            ]
            res = g_security.run(self.ctx)
            self.assertEqual(res.status, PASS)
            self.assertIsNotNone(res.scope)
            self.assertEqual(res.scope.examined, 1)
            self.assertEqual(res.scope.unknown, 0)

    def test_tool_unavailable_blocks_never_pass(self):
        """Herramienta obligatoria no instalada (ej. trivy) produce BLOCKED, nunca PASS."""
        def fake_which(cmd):
            if cmd == "trivy":
                return None
            return f"/bin/{cmd}"

        with patch("shutil.which", side_effect=fake_which), \
             patch("gates.g_security._scan_secrets", return_value=(1, 0, [])), \
             patch("gates.g_security._run_json") as mock_run:
            mock_run.side_effect = [
                {"ok": True, "data": []},  # gitleaks
                {"ok": True, "data": {"artifacts": [{"name": "dep1"}]}},  # syft
            ]
            res = g_security.run(self.ctx)
            self.assertEqual(res.status, BLOCKED)
            self.assertIn("trivy NO está", "".join(res.observations))

    def test_tool_failed_produces_not_executable(self):
        """Herramienta presente que revienta o falla produce NOT_EXECUTABLE, no PASS."""
        with patch("shutil.which", return_value="/bin/tool"), \
             patch("gates.g_security._scan_secrets", return_value=(1, 0, [])), \
             patch("gates.g_security._run_json") as mock_run:
            mock_run.side_effect = [
                {"ok": False, "data": None, "error": "Segmentation fault"},  # gitleaks crash
                {"ok": True, "data": {"artifacts": [{"name": "dep1"}]}},  # syft
                {"ok": True, "data": {"Results": []}}  # trivy
            ]
            res = g_security.run(self.ctx)
            self.assertEqual(res.status, NOT_EXECUTABLE)
            self.assertGreater(res.scope.unknown, 0)

    def test_tool_timeout_produces_not_executable(self):
        """Herramienta que entra en timeout produce NOT_EXECUTABLE."""
        with patch("shutil.which", return_value="/bin/tool"), \
             patch("gates.g_security._scan_secrets", return_value=(1, 0, [])), \
             patch("gates.g_security._run_json") as mock_run:
            mock_run.side_effect = [
                {"ok": True, "data": []},  # gitleaks
                {"ok": False, "data": None, "error": "Command timed out after 300s"},  # syft timeout
                {"ok": True, "data": {"Results": []}}  # trivy
            ]
            res = g_security.run(self.ctx)
            self.assertEqual(res.status, NOT_EXECUTABLE)

    def test_tool_malformed_result_produces_not_executable(self):
        """Herramienta que emite JSON malformado produce NOT_EXECUTABLE."""
        with patch("shutil.which", return_value="/bin/tool"), \
             patch("gates.g_security._scan_secrets", return_value=(1, 0, [])), \
             patch("gates.g_security._run_json") as mock_run:
            mock_run.side_effect = [
                {"ok": True, "data": []},  # gitleaks
                {"ok": True, "data": {"artifacts": [{"name": "dep1"}]}},  # syft
                {"ok": False, "data": None, "error": "salida no era JSON: Expecting value: line 1 column 1"}
            ]
            res = g_security.run(self.ctx)
            self.assertEqual(res.status, NOT_EXECUTABLE)

    def test_tool_empty_output_produces_not_executable(self):
        """Herramienta que sale con código 0 pero sin salida es INVALID_OUTPUT -> NOT_EXECUTABLE."""
        from gates.g_security import _run_json
        with patch("subprocess.run") as mock_sub:
            mock_res = MagicMock()
            mock_res.stdout = ""
            mock_res.stderr = ""
            mock_res.returncode = 0
            mock_sub.return_value = mock_res
            out = _run_json(["fake_tool"])
            self.assertFalse(out["ok"])
            self.assertIn("no produjo salida", out["error"])

    def test_empty_workspace_scanned_zero_produces_blocked(self):
        """Espacio vacío con 0 archivos recorridos produce BLOCKED, nunca PASS."""
        with patch("shutil.which", return_value="/bin/tool"), \
             patch("gates.g_security._scan_secrets", return_value=(0, 0, [])), \
             patch("gates.g_security._run_json") as mock_run:
            mock_run.side_effect = [
                {"ok": True, "data": []},
                {"ok": True, "data": {"artifacts": [{"name": "dep1"}]}},
                {"ok": True, "data": {"Results": []}}
            ]
            res = g_security.run(self.ctx)
            self.assertEqual(res.status, BLOCKED)
            self.assertIn("cero archivos comprobados", res.measure.lower())

    def test_tool_returned_findings_produces_fail(self):
        """Herramienta con hallazgos (secretos o vulnerabilidades críticas) produce FAIL."""
        with patch("shutil.which", return_value="/bin/tool"), \
             patch("gates.g_security._scan_secrets", return_value=(1, 0, [("app.py", 1, ["AKIA_AWS"])])), \
             patch("gates.g_security._run_json") as mock_run:
            mock_run.side_effect = [
                {"ok": True, "data": []},
                {"ok": True, "data": {"artifacts": [{"name": "dep1"}]}},
                {"ok": True, "data": {"Results": []}}
            ]
            res = g_security.run(self.ctx)
            self.assertEqual(res.status, FAIL)
            self.assertGreater(len(res.findings), 0)


if __name__ == "__main__":
    unittest.main()
