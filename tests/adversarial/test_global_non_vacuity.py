# -*- coding: utf-8 -*-
"""Prueba parametrizada del Teorema Global de No-Vacuidad para todas las compuertas (G01–G13).

Propiedad:
    ∀ gate ∈ GATES:
        (scope is None ∨ scope.examined == 0 ∨ scope.unknown > 0 ∨ evidence == absent ∨ evidence == stale)
        ⟹ CANNOT produce (status == PASS ∧ can_advance == True)
"""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from core.model import (
    BLOCKED,
    FAIL,
    INCONCLUSIVE,
    NOT_APPLICABLE,
    PASS,
    Result,
    Scope,
)
from core.protocol import RefutoProtocolServer
from gates.base import GATES


class TestGlobalNonVacuityTheorem(unittest.TestCase):

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="test-non-vacuity-"))
        (self.tmp / ".harness").mkdir(parents=True)
        # Manifiesto mínimo
        (self.tmp / ".harness" / "harness.manifest.json").write_text(
            '{"schema": "harness.manifest/v1", "harness": {"version": "0.1.0"}, "workspace": {"name": "test"}, "gates": []}',
            encoding="utf-8"
        )
        self.server = RefutoProtocolServer(self.tmp)

    def test_todas_las_compuertas_con_scope_nulo_o_cero_son_inadmisibles(self):
        """Demuestra que NINGUNA de las 13 compuertas puede otorgar can_advance=True con scope vacío."""
        for gate_id in GATES:
            with self.subTest(gate=gate_id):
                req = {
                    "claim": {
                        "claim_id": f"clm_test_{gate_id.lower()}",
                        "property": f"prop_{gate_id.lower()}",
                        "subject": {"type": "workspace", "workspace": str(self.tmp)},
                    },
                    "gate": gate_id,
                }
                res = self.server._handle_verify_claim(req)
                capsule = res["capsule"]
                admissibility = res["lifecycle_admissibility"]

                # INVARIANTE FUNDAMENTAL:
                # Si no hubo examen de elementos (> 0) o scope fue None, no puede avanzar.
                if admissibility["can_advance"]:
                    self.assertIsNotNone(capsule["scope"])
                    self.assertGreater(capsule["scope"]["items_examined"], 0)
                    self.assertEqual(PASS, capsule["status"])
                else:
                    self.assertFalse(admissibility["can_advance"])
                    self.assertIn(capsule["status"], (INCONCLUSIVE, BLOCKED, FAIL, NOT_APPLICABLE))

    def test_mock_result_con_status_pass_y_scope_cero_revienta_en_constructor(self):
        """Demuestra que Result.__post_init__ impide físicamente construir PASS con examined=0."""
        for examined_count in (0,):
            with self.subTest(examined=examined_count):
                with self.assertRaises(ValueError):
                    Result(
                        id="G-MOCK",
                        name="Mock Gate",
                        status=PASS,
                        severity="HIGH",
                        threshold="must pass",
                        measure="0 items",
                        scope=Scope(examined=examined_count, universe="items"),
                    )

    def test_claim_con_ttl_expirado_no_puede_avanzar(self):
        req = {
            "claim": {
                "claim_id": "clm_expired",
                "valid_until": "2020-01-01T00:00:00Z",
                "property": "integrity",
            }
        }
        res = self.server._handle_verify_claim(req)
        self.assertFalse(res["lifecycle_admissibility"]["can_advance"])
        self.assertIn(res["capsule"]["status"], (INCONCLUSIVE, FAIL, BLOCKED))

    def test_claim_con_testigo_circular_no_puede_avanzar(self):
        req = {
            "claim": {
                "claim_id": "clm_circular",
                "subject": {"agent_id": "agent-alpha"},
                "evidence_requirements": {"witness_id": "agent-alpha"},
            }
        }
        res = self.server._handle_verify_claim(req)
        self.assertFalse(res["lifecycle_admissibility"]["can_advance"])
        self.assertIn(res["capsule"]["status"], (INCONCLUSIVE, FAIL, BLOCKED))
