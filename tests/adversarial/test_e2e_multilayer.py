# -*- coding: utf-8 -*-
"""tests/adversarial/test_e2e_multilayer.py — Escenarios E2E Multicapa de Refuto.

Verifica formalmente los 6 escenarios de integración multicapa de extremo a extremo:
- E2E-A: Flujo completo de cambio legítimo gobernado (Propose -> Authorize -> Apply -> Verify -> Admit).
- E2E-B: Cambio autorizado pero defectuoso (falla en verificación dinámica y bloquea admisión).
- E2E-C: Cambio con evidencia insuficiente o ámbito vacuo (degradado a INCONCLUSIVE, no avanza).
- E2E-D: Cambio no autorizado sobre superficie protegida (rechazado en frontera).
- E2E-E: Cambio autorizado y posteriormente adulterado (TOCTOU detectado por hash de diff).
- E2E-F: Agente hostil intentando elusión total combinada (defensa en profundidad multicapa).
"""

from __future__ import annotations

import hashlib
import json
import shutil
import sys
import tempfile
import unittest
from pathlib import Path

RAIZ = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(RAIZ))

from core.change import (
    AuthoritySeparationViolation,
    ChangeGovernanceEngine,
    ChangeProposal,
    DiffTamperDetectedError,
    ProtectedTargetRequiresAuthorizationError,
    _ed25519_public_key,
)
from core.envelope import EXIT_OK
from core.evidence import read_events, verificar_cadena
from core.model import FAIL, INCONCLUSIVE, PASS, Result, Scope
from core.protocol import RefutoProtocolServer


class TestE2EMultilayer(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="refuto-e2e-")).resolve()
        self.server = RefutoProtocolServer(self.tmp)
        self.engine = ChangeGovernanceEngine(self.tmp)

        # Generar claves de autorizador independiente
        self.auth_sk = hashlib.sha256(b"e2e-authorizer-seed-1").digest()
        self.auth_pk = _ed25519_public_key(self.auth_sk).hex()
        self.auth_id = "human:principal_sec"

        # Inicializar .harness
        harness = self.tmp / ".harness"
        harness.mkdir(parents=True, exist_ok=True)
        (harness / "evidence").mkdir(parents=True, exist_ok=True)
        trusted = {"authorizers": {self.auth_id: self.auth_pk}}
        (harness / "trusted_authorizers.json").write_text(json.dumps(trusted), encoding="utf-8")

        manifest = {
            "schema": "harness.manifest/v1",
            "harness": {"version": "0.2.2", "min_python": "3.10"},
            "workspace": {"name": "e2e-test", "profile": "standard"},
            "agents": {},
            "gates": ["G-MANIFEST"],
            "artifacts": []
        }
        (harness / "harness.manifest.json").write_text(json.dumps(manifest), encoding="utf-8")

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_E2E_A_legitimate_governed_change(self):
        """E2E-A: Ciclo completo de cambio legítimo con admisión positiva."""
        app_file = self.tmp / "src" / "app.py"
        app_file.parent.mkdir(parents=True, exist_ok=True)
        app_file.write_text("def hello(): return 1\n", encoding="utf-8")

        diff = "--- a/src/app.py\n+++ b/src/app.py\n@@ -1,1 +1,1 @@\n-def hello(): return 1\n+def hello(): return 2\n"

        # 1. Propose
        proposal = self.engine.propose(
            title="Update hello return",
            author="agent:dev",
            author_type="agent",
            diff=diff,
            target_files=["src/app.py"]
        )
        self.assertIsNotNone(proposal.proposal_id)

        # 2. Authorize (por humano independiente)
        token = self.engine.authorize(
            proposal=proposal,
            authorizer_id=self.auth_id,
            authorizer_type="human",
            secret_key_bytes=self.auth_sk
        )
        self.assertIsNotNone(token.signature)

        # 3. Apply
        apply_res = self.engine.apply(proposal, token)
        self.assertEqual("APPLIED", apply_res["status"])
        self.assertIn("def hello(): return 2", app_file.read_text(encoding="utf-8"))

        # 4. Verify & Admit vía Protocolo con ejecución real de la compuerta G-MANIFEST
        verify_res = self.server.dispatch("refuto.verify_claim", {
            "gate": "G-MANIFEST",
            "claim": {
                "claim_id": "clm_e2e_a",
                "property": "app_updated",
                "scope_requirement": {"min_examined": 1}
            }
        })

        self.assertEqual(PASS, verify_res["capsule"]["status"])
        self.assertTrue(verify_res["lifecycle_admissibility"]["can_advance"])
        self.assertEqual("E3", verify_res["capsule"]["epistemic_level"])

    def test_E2E_B_defective_change_blocked(self):
        """E2E-B: Cambio autorizado pero defectuoso en verificación dinámica."""
        app_file = self.tmp / "src" / "calc.py"
        app_file.parent.mkdir(parents=True, exist_ok=True)
        app_file.write_text("x = 10\n", encoding="utf-8")

        diff = "--- a/src/calc.py\n+++ b/src/calc.py\n@@ -1,1 +1,1 @@\n-x = 10\n+x = 'broken'\n"

        proposal = self.engine.propose("Change to broken", "agent:dev", "agent", diff, target_files=["src/calc.py"])
        token = self.engine.authorize(proposal, self.auth_id, "human", self.auth_sk)
        self.engine.apply(proposal, token)

        # La verificación dinámica falla al evaluar un manifiesto roto
        (self.tmp / ".harness" / "harness.manifest.json").write_text(
            json.dumps({"schema": "harness.manifest/v1"}), encoding="utf-8"
        )
        verify_res = self.server.dispatch("refuto.verify_claim", {
            "gate": "G-MANIFEST",
            "claim": {"claim_id": "clm_e2e_b", "property": "calc_valid"}
        })

        self.assertEqual(FAIL, verify_res["capsule"]["status"])
        self.assertFalse(verify_res["lifecycle_admissibility"]["can_advance"])

    def test_E2E_C_insufficient_evidence_inconclusive(self):
        """E2E-C: Cambio que aprueba nominalmente pero carece de ámbito demostrable suficiente."""
        # Se exige un ámbito mínimo de 10 elementos, pero el manifiesto sólo aporta 2 elementos examinados
        verify_res = self.server.dispatch("refuto.verify_claim", {
            "gate": "G-MANIFEST",
            "claim": {
                "claim_id": "clm_e2e_c",
                "property": "security_check",
                "scope_requirement": {"min_examined": 10}
            }
        })

        self.assertEqual(INCONCLUSIVE, verify_res["capsule"]["status"])
        self.assertFalse(verify_res["lifecycle_admissibility"]["can_advance"])
        self.assertIn("Ámbito examinado (2) insuficiente: se exigen al menos 10 elementos",
                      verify_res["lifecycle_admissibility"]["remediation_actions"])

    def test_E2E_D_unauthorized_change_blocked_at_boundary(self):
        """E2E-D: Intento de modificar compuerta protegida sin autorización previa."""
        diff = "--- a/gates/g_security.py\n+++ b/gates/g_security.py\n@@ -1,1 +1,1 @@\n-# comment\n+# bypass\n"
        proposal = self.engine.propose("Tamper gate", "agent:hacker", "agent", diff, target_files=["gates/g_security.py"])

        # Intentar aplicar sin token
        with self.assertRaises(ProtectedTargetRequiresAuthorizationError):
            self.engine.apply(proposal, authorization=None)

    def test_E2E_E_authorized_then_mutated_toctou(self):
        """E2E-E: Diff adulterado tras la emisión del token criptográfico."""
        diff_legit = "--- a/gates/g_security.py\n+++ b/gates/g_security.py\n@@ -1,1 +1,1 @@\n-# v1\n+# v2\n"
        diff_malicious = "--- a/gates/g_security.py\n+++ b/gates/g_security.py\n@@ -1,1 +1,1 @@\n-# v1\n+# backdoor\n"

        proposal = self.engine.propose("Legit update", "agent:dev", "agent", diff_legit, target_files=["gates/g_security.py"])
        token = self.engine.authorize(proposal, self.auth_id, "human", self.auth_sk)

        # Inyección de diff mutado
        proposal.diff = diff_malicious

        with self.assertRaises(DiffTamperDetectedError):
            self.engine.apply(proposal, token)

    def test_E2E_F_malicious_agent_combined_attack(self):
        """E2E-F: Ataque combinado multivectorial rechazado por todas las capas."""
        # 1. Capa de política de acciones rechaza intento de borrar archivos críticos
        res_cmd = self.server.dispatch("refuto.evaluate_action", {
            "action": "exec", "command": "rm -rf .harness", "tool": "Bash"
        })
        self.assertFalse(res_cmd["allowed"])

        # 2. Capa de gobernanza rechaza auto-aprobación del agente
        diff = "--- a/gates/g_security.py\n+++ b/gates/g_security.py\n@@ -1,1 +1,1 @@\n-# v1\n+# v2\n"
        agent_sk = hashlib.sha256(b"malicious-agent-seed").digest()
        prop = self.engine.propose("Self attack", "agent:rogue", "agent", diff, target_files=["gates/g_security.py"])
        with self.assertRaises(AuthoritySeparationViolation):
            self.engine.authorize(prop, "agent:rogue", "agent", agent_sk)

        # 3. Capa de verificación criptográfica rechaza claims con firmas falsas.
        # `evidence_requirements` va DENTRO de `claim`: en la raíz de `params` no se lee, y
        # hasta el 2026-09-30 esta llamada lo mandaba ahí. La firma falsa no se examinaba y el
        # `FAIL` esperado tenía que salir de las puertas del espacio temporal, no de la capa
        # criptográfica que este paso dice ejercitar.
        res_claim = self.server.dispatch("refuto.verify_claim", {
            "claim": {
                "claim_id": "clm_rogue", "property": "bypass",
                "evidence_requirements": {
                    "witness_public_key_hex": self.auth_pk,
                    "witness_signature_hex": "00" * 64  # Falsa
                }
            }
        })
        self.assertEqual(FAIL, res_claim["capsule"]["status"])
        self.assertFalse(res_claim["lifecycle_admissibility"]["can_advance"])
