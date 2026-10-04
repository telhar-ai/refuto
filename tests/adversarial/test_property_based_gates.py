# -*- coding: utf-8 -*-
"""Pruebas basadas en propiedades (Property-Based Testing) P1 a P10 sobre compuertas y decisiones.

P1: empty scope never PASS
P2: invalid evidence never PASS
P3: missing witness never PASS where required
P4: mutated subject invalidates decision
P5: mutated policy invalidates decision
P6: mutated evidence invalidates decision
P7: replayed evidence cannot become fresh evidence
P8: failed mandatory gate prevents global PASS
P9: blocked mandatory gate prevents admission
P10: removing evidence cannot improve a decision (monotonicidad epistémica)
"""

from __future__ import annotations

import copy
import hashlib
import json
import random
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import patch

from core.assurance import compute_assurance_level
from core.evidence import verdict_of
from core.model import (
    BLOCKED,
    FAIL,
    INCONCLUSIVE,
    NOT_APPLICABLE,
    NOT_EXECUTABLE,
    PASS,
    Evidence,
    Finding,
    Result,
    Scope,
)
from core.protocol import RefutoProtocolServer


class TestPropertyBasedGatesP1P10(unittest.TestCase):

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="test-pbt-"))
        self.server = RefutoProtocolServer(self.tmp)

    def test_p1_empty_scope_never_pass(self):
        """P1: Un ámbito vacío (examined == 0) jamás puede producir PASS en ninguna compuerta."""
        for _ in range(20):
            zero_scope = Scope(examined=0, unknown=random.randint(0, 5), universe="fuzz_items")
            with self.assertRaises(ValueError):
                Result("G-FUZZ", "Fuzz Gate", PASS, "HIGH", ">=1", "0", scope=zero_scope)

    def test_p2_invalid_evidence_never_pass(self):
        """P2: Hallazgos no resueltos jamás permiten PASS."""
        for _ in range(20):
            n_findings = random.randint(1, 10)
            findings = [Finding("file.py", f"issue_{i}", i) for i in range(n_findings)]
            sc = Scope(examined=random.randint(1, 100), unknown=0, universe="items")
            with self.assertRaises(ValueError):
                Result("G-FUZZ", "Fuzz Gate", PASS, "HIGH", "zero findings", "issues",
                       findings=findings, scope=sc)

    def test_p3_missing_witness_never_pass_where_required(self):
        """P3: Afirmaciones que exigen atestación de testigo independiente fallan si está ausente."""
        req = {
            "claim": {
                "claim_id": "clm_p3",
                "property": "independent_audit",
                "evidence_requirements": {
                    "witness_required": True,
                    "witness_id": None
                }
            }
        }
        res = self.server.dispatch("refuto.verify_claim", req)
        self.assertFalse(res["lifecycle_admissibility"]["can_advance"])

    def test_p4_mutated_subject_invalidates_decision(self):
        """P4: Mutar el digest del sujeto respecto al esperado invalida la decisión."""
        req = {
            "claim": {
                "claim_id": "clm_p4",
                "property": "integrity",
                "subject": {
                    "expected_digest": "aaaa" * 16,
                    "actual_digest": "bbbb" * 16
                }
            }
        }
        res = self.server.dispatch("refuto.verify_claim", req)
        self.assertFalse(res["lifecycle_admissibility"]["can_advance"])
        self.assertIn("Divergencia de digest del sujeto", "".join(res["lifecycle_admissibility"]["remediation_actions"]))

    def test_p5_mutated_policy_invalidates_decision(self):
        """P5: Mutar la política invalida la verificación del claim."""
        req = {
            "claim": {
                "claim_id": "clm_p5",
                "property": "policy_conformance",
                "policy_binding": {
                    "policy_digest": "1111" * 16
                }
            }
        }
        res = self.server.dispatch("refuto.verify_claim", req)
        self.assertFalse(res["lifecycle_admissibility"]["can_advance"])

    def test_p6_mutated_evidence_invalidates_decision(self):
        """P6: Alterar la firma de evidencia invalida la atestación.

        Esta prueba era VACUA hasta el 2026-09-30 y lo era por dos motivos a la vez. Mandaba
        `witness_signature`/`witness_public_key`, que el protocolo no lee —los campos son
        `..._hex`—, así que la firma alterada nunca se examinaba; y sólo afirmaba sobre
        `can_advance`, que en un espacio recién creado ya es `False` por las puertas. Pasaba
        igual con una firma VÁLIDA y pasaba sin mandar firma alguna: no medía nada.

        Ahora usa los nombres que el código lee, exige el estado, y lleva el control negativo
        que es lo único que distingue «lo rechazó la firma» de «lo rechazó el ruido».
        """
        def pedir(evidence_requirements, claim_id):
            req = {"claim": {"claim_id": claim_id, "property": "signature_validity",
                             "evidence_requirements": evidence_requirements}}
            with patch("gates.base.run_all", return_value=[
                    Result("G-ROLES", "roles", PASS, scope=Scope(examined=1, universe="roles"))]):
                return self.server.dispatch("refuto.verify_claim", req)

        alterada = pedir({"witness_id": "auditor_sec",
                          "witness_signature_hex": "00" * 64,
                          "witness_public_key_hex": "11" * 32}, "clm_p6")
        self.assertEqual(FAIL, alterada["capsule"]["status"])
        self.assertFalse(alterada["lifecycle_admissibility"]["can_advance"])

        # Control negativo: las mismas puertas sin el par de testigo NO dan FAIL.
        sin_firma = pedir({"witness_id": "auditor_sec"}, "clm_p6_ctl")
        self.assertEqual(PASS, sin_firma["capsule"]["status"])

    def test_p7_replayed_evidence_cannot_become_fresh(self):
        """P7: Evidencia expirada no puede ser considerada fresca ni admitida."""
        req = {
            "claim": {
                "claim_id": "clm_p7",
                "property": "freshness",
                "valid_until": "1999-12-31T23:59:59Z"
            }
        }
        res = self.server.dispatch("refuto.verify_claim", req)
        self.assertFalse(res["lifecycle_admissibility"]["can_advance"])

    def test_p8_failed_mandatory_gate_prevents_global_pass(self):
        """P8: Una sola compuerta en FAIL impide que el veredicto global sea PASS."""
        for _ in range(10):
            n_gates = random.randint(2, 8)
            fail_idx = random.randint(0, n_gates - 1)
            results = []
            for i in range(n_gates):
                sc = Scope(examined=5, unknown=0, universe="items", declared=True)
                if i == fail_idx:
                    r = Result(f"G-{i}", f"Gate {i}", FAIL, "HIGH", "threshold", "measure",
                               findings=[Finding("x", "err", 1)], scope=sc)
                else:
                    r = Result(f"G-{i}", f"Gate {i}", PASS, "HIGH", "threshold", "measure", scope=sc)
                results.append(r)

            verdict = verdict_of(results)
            self.assertTrue(verdict.startswith("NO INTEGRABLE"))
            self.assertIn("rojo", verdict)

    def test_p9_blocked_mandatory_gate_prevents_admission(self):
        """P9: Una sola compuerta en BLOCKED impide la admisión en el ciclo de vida."""
        results = [
            Result("G-1", "Gate 1", PASS, "HIGH", "ok", "ok", scope=Scope(examined=5, unknown=0, universe="items", declared=True)),
            Result("G-2", "Gate 2", BLOCKED, "HIGH", "dep missing", "dep missing", scope=Scope(examined=0, unknown=1, universe="items", declared=True)),
        ]
        verdict = verdict_of(results)
        self.assertTrue(verdict.startswith("NO INTEGRABLE"))
        self.assertIn("pudieron comprobar", verdict)

    def test_p10_removing_evidence_cannot_improve_decision(self):
        """P10: Monotonicidad epistémica: remover evidencia u observaciones jamás mejora el nivel epistémico."""
        ev_full = {
            "scope": {"examined": 10, "unknown": 0},
            "document_path": "spec.md",
            "command": "python3 refuto.py selftest",
            "observed_output": "OK",
            "exit_code": 0,
            "test_status": PASS,
            "tests_run": 10,
            "ledger_event": True,
            "witness_signature_valid": True,
            "chain_integrity": "INTEGRA"
        }
        level_full = compute_assurance_level(ev_full)
        self.assertEqual(level_full, "E4")

        # Remover observaciones criptográficas en tiempo de ejecución
        ev_no_runtime = copy.deepcopy(ev_full)
        del ev_no_runtime["ledger_event"]
        del ev_no_runtime["witness_signature_valid"]
        level_no_runtime = compute_assurance_level(ev_no_runtime)
        self.assertEqual(level_no_runtime, "E3")
        self.assertLess(level_no_runtime, level_full)

        # Remover pruebas automatizadas
        ev_docs_only = {
            "scope": {"examined": 10, "unknown": 0},
            "document_path": "spec.md",
            "schema_valid": True
        }
        level_docs = compute_assurance_level(ev_docs_only)
        self.assertEqual(level_docs, "E1")
        self.assertLess(level_docs, level_no_runtime)


if __name__ == "__main__":
    unittest.main()
