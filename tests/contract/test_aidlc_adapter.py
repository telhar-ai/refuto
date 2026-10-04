# -*- coding: utf-8 -*-
"""Pruebas de contrato para el adapter de AWS AI-DLC.

Especificación: docs/21-adapter-model.md
Esquema: refuto.protocol/v1
"""

from __future__ import annotations

import json
import unittest
from pathlib import Path

from adapters.aidlc import SPEC, AidlcAdapter
from adapters.registry import get as get_adapter
from core.policy import Policy
from core.protocol import CAPSULE_SCHEMA

RAIZ = Path(__file__).resolve().parents[2]


class TestAidlcAdapterContract(unittest.TestCase):

    def setUp(self):
        self.adapter: AidlcAdapter = get_adapter("aidlc")

    def test_spec_registration(self):
        self.assertEqual("aidlc", self.adapter.name)
        self.assertEqual("ai-dlc", self.adapter.binary)
        self.assertIn("stages", self.adapter.native_extensions)

    def test_compile_policy_generates_conductor_bridge(self):
        pol = Policy(schema="harness.policy/v1", version="1")
        compiled = self.adapter.compile_policy(pol)

        self.assertTrue(compiled.get("supported"))
        self.assertIn(".aidlc/verification-bridge.json", compiled.get("artifacts", {}))

        bridge_cfg = json.loads(compiled["artifacts"][".aidlc/verification-bridge.json"])
        self.assertEqual("refuto", bridge_cfg.get("verification_engine"))
        self.assertEqual("refuto.protocol/v1", bridge_cfg.get("protocol"))
        self.assertIn("Plan", bridge_cfg.get("stages", {}))
        self.assertIn("Deploy", bridge_cfg.get("stages", {}))

    def test_verify_stage_transition_returns_decision_capsule(self):
        res = self.adapter.verify_stage_transition("Plan", RAIZ)
        self.assertIn("admitted", res)
        self.assertIn("decision_capsule", res)

        capsule = res["decision_capsule"]
        self.assertEqual(CAPSULE_SCHEMA, capsule.get("schema"))
        self.assertEqual("clm_aidlc_plan", capsule.get("claim_id"))

    def test_normalize_event(self):
        raw = {"type": "stage_transition", "from": "Plan", "to": "Code", "agent": "Claude"}
        norm = self.adapter.normalize_event(raw)

        self.assertIsNotNone(norm)
        self.assertEqual("aidlc", norm.get("source"))
        self.assertEqual("lifecycle", norm.get("family"))
        self.assertEqual("aidlc/stage_transition", norm.get("kind"))
        self.assertEqual(raw, norm.get("payload"))


if __name__ == "__main__":
    unittest.main()
