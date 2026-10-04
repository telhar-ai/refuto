# -*- coding: utf-8 -*-
"""Batería de pruebas de vinculación criptográfica y detección de divergencia (drift).

Especificación: Sections 23 & 24 / Principia Veritas
Invariante: Una Cápsula de Decisión (Decision Capsule) debe estar criptográficamente vinculada
a su afirmación (Claim), sujeto (Subject), política (Policy), alcance (Scope), evidencia (Evidence),
testigo (Witness), entorno (Env) y herramienta (Tool). Cualquier mutación posterior debe ser
detectable y descalificar inmediatamente la admisibilidad de la decisión.
"""

from __future__ import annotations

import hashlib
import json
import tempfile
import unittest
from pathlib import Path

from core.model import FAIL, PASS
from core.protocol import (
    CAPSULE_SCHEMA,
    DecisionCapsule,
    RefutoProtocolServer,
    verify_capsule_binding,
)
from tests.fixtures.ed25519_firma import clave_publica, firmar


class TestCapsuleBindingAndDrift(unittest.TestCase):
    def setUp(self):
        self.tmp_dir = tempfile.TemporaryDirectory()
        self.workspace = Path(self.tmp_dir.name)
        (self.workspace / ".harness").mkdir(parents=True, exist_ok=True)
        (self.workspace / ".harness" / "policy.json").write_text(
            json.dumps({"version": "1.0", "rules": ["default_deny"]}), encoding="utf-8"
        )
        self.sk = hashlib.sha256(b"adversarial_test_secret_seed").digest()
        self.pk = clave_publica(self.sk)
        self.pk_hex = self.pk.hex()

    def tearDown(self):
        self.tmp_dir.cleanup()

    def _create_sample_capsule(self) -> DecisionCapsule:
        subject_dig = hashlib.sha256(b"codebase_commit_v1").hexdigest()
        policy_dig = hashlib.sha256(b"policy_v1").hexdigest()
        env_fp = hashlib.sha256(b"darwin:python3.14").hexdigest()
        tool_dig = hashlib.sha256(b"refuto:0.3.0").hexdigest()

        capsule = DecisionCapsule(
            schema=CAPSULE_SCHEMA,
            decision_id="cap_001test",
            claim_id="clm_001test",
            status=PASS,
            epistemic_level="E3",
            scope={"items_examined": 42, "unscoped_gates": [], "declared": True},
            verdict_rationale="42 items examinados satisfactoriamente",
            ledger_head="deadbeef" * 8,
            subject_digest=subject_dig,
            timestamp="2026-09-30T10:00:00Z",
            gates=[{"id": "G-UNIT", "status": PASS, "measure": "42 passed"}],
            policy_digest=policy_dig,
            env_fingerprint=env_fp,
            tool_digest=tool_dig,
            witness_public_key_hex=self.pk_hex,
        )
        digest = capsule.compute_digest()
        capsule.capsule_digest = digest
        capsule.witness_signature = firmar(self.sk, digest.encode("utf-8")).hex()
        return capsule

    def test_valid_capsule_passes_verification(self):
        """Una cápsula auténtica e intacta supera la verificación sin infracciones ni drift."""
        capsule = self._create_sample_capsule()
        result = verify_capsule_binding(
            capsule,
            expected_subject_digest=capsule.subject_digest,
            expected_policy_digest=capsule.policy_digest,
            expected_env_fingerprint=capsule.env_fingerprint,
            expected_tool_digest=capsule.tool_digest,
            witness_public_key_hex=self.pk_hex,
        )
        self.assertTrue(result["valid"])
        self.assertTrue(result["digest_verified"])
        self.assertFalse(result["subject_drift"])
        self.assertFalse(result["policy_drift"])
        self.assertFalse(result["env_drift"])
        self.assertFalse(result["tool_drift"])
        self.assertTrue(result["witness_verified"])
        self.assertEqual(len(result["violations"]), 0)

    def test_claim_mutation_invalidates_capsule_digest(self):
        """Mutar el claim_id o status corrompe el digest canónico y descalifica la cápsula."""
        capsule = self._create_sample_capsule()
        cap_dict = capsule.to_dict()
        # Ataque: agente malicioso intenta cambiar status de FAIL a PASS o alterar claim_id
        cap_dict["claim_id"] = "clm_hijacked_999"

        result = verify_capsule_binding(cap_dict)
        self.assertFalse(result["valid"])
        self.assertFalse(result["digest_verified"])
        self.assertTrue(any("Cápsula manipulada" in v for v in result["violations"]))

    def test_subject_drift_detected(self):
        """Si el sujeto sobre el que se decidió cambia (ej. commit o código posterior), se detecta drift."""
        capsule = self._create_sample_capsule()
        mutated_subject_digest = hashlib.sha256(b"codebase_mutated_v2").hexdigest()

        result = verify_capsule_binding(
            capsule,
            expected_subject_digest=mutated_subject_digest,
            expected_policy_digest=capsule.policy_digest,
        )
        self.assertFalse(result["valid"])
        self.assertTrue(result["subject_drift"])
        self.assertTrue(any("subject drift" in v for v in result["violations"]))

    def test_policy_drift_detected(self):
        """Si la política de gobierno cambia después de emitir la decisión, se detecta policy drift."""
        capsule = self._create_sample_capsule()
        altered_policy_digest = hashlib.sha256(b"policy_v2_altered").hexdigest()

        result = verify_capsule_binding(
            capsule,
            expected_subject_digest=capsule.subject_digest,
            expected_policy_digest=altered_policy_digest,
        )
        self.assertFalse(result["valid"])
        self.assertTrue(result["policy_drift"])
        self.assertTrue(any("policy drift" in v for v in result["violations"]))

    def test_scope_vacuity_violation(self):
        """Una cápsula que afirme PASS con items_examined == 0 viola la no-vacuidad."""
        capsule = self._create_sample_capsule()
        capsule.scope = {"items_examined": 0, "declared": False}
        capsule.capsule_digest = capsule.compute_digest()  # Recomputa para aislar la regla de scope

        result = verify_capsule_binding(capsule)
        self.assertFalse(result["valid"])
        self.assertTrue(any("no-vacuidad" in v for v in result["violations"]))

    def test_witness_signature_forgery_detected(self):
        """Una firma forjada o alterada es rechazada criptográficamente."""
        capsule = self._create_sample_capsule()
        # Modificar bytes de la firma
        sig_bytes = bytearray(bytes.fromhex(capsule.witness_signature))
        sig_bytes[0] ^= 0xFF
        capsule.witness_signature = sig_bytes.hex()

        result = verify_capsule_binding(capsule, witness_public_key_hex=self.pk_hex)
        self.assertFalse(result["valid"])
        self.assertFalse(result["witness_verified"])
        self.assertTrue(any("inválida o forjada" in v for v in result["violations"]))

    def test_environment_drift_detected(self):
        """Divergencia en el entorno de ejecución (ej. SO o versión de runtime distinta)."""
        capsule = self._create_sample_capsule()
        another_env = hashlib.sha256(b"linux-x86_64:python3.11").hexdigest()

        result = verify_capsule_binding(capsule, expected_env_fingerprint=another_env)
        self.assertFalse(result["valid"])
        self.assertTrue(result["env_drift"])
        self.assertTrue(any("env drift" in v for v in result["violations"]))

    def test_tool_drift_detected(self):
        """Divergencia en la versión o huella de la herramienta certificadora."""
        capsule = self._create_sample_capsule()
        another_tool = hashlib.sha256(b"refuto:0.9.9-untrusted").hexdigest()

        result = verify_capsule_binding(capsule, expected_tool_digest=another_tool)
        self.assertFalse(result["valid"])
        self.assertTrue(result["tool_drift"])
        self.assertTrue(any("tool drift" in v for v in result["violations"]))

    def test_protocol_server_verify_claim_generates_bound_capsule(self):
        """El servidor JSON-RPC emite cápsulas con vinculación criptográfica verificable."""
        server = RefutoProtocolServer(self.workspace)
        server.dispatch("refuto.initialize", {})

        req = {
            "claim": {
                "claim_id": "clm_binding_test",
                "property": "correctness",
                "subject": {"workspace": str(self.workspace)},
            }
        }
        res = server.dispatch("refuto.verify_claim", req)
        capsule_dict = res["capsule"]

        self.assertIn("capsule_digest", capsule_dict)
        self.assertIsNotNone(capsule_dict["capsule_digest"])
        self.assertIn("env_fingerprint", capsule_dict)

        # Verificar vinculación de la cápsula producida
        verification = verify_capsule_binding(capsule_dict)
        self.assertTrue(verification["digest_verified"])


if __name__ == "__main__":
    unittest.main()
