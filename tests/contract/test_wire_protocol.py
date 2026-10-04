# -*- coding: utf-8 -*-
"""Contrato de interoperabilidad del servidor Refuto Wire Protocol v1.

Especificación: docs/11-protocol.md
Esquema: refuto.protocol/v1
"""

from __future__ import annotations

import json
import unittest
from pathlib import Path

from core.model import INCONCLUSIVE, PASS, VERSION
from core.protocol import (CAPSULE_SCHEMA, INVALID_PARAMS, METHOD_NOT_FOUND, PARSE_ERROR,
                           PROTOCOL_VERSION, RefutoProtocolServer)

RAIZ = Path(__file__).resolve().parents[2]


class TestRefutoWireProtocolContract(unittest.TestCase):
    def setUp(self):
        self.server = RefutoProtocolServer(RAIZ)

    def test_initialize_handshake(self):
        req = {
            "jsonrpc": "2.0",
            "method": "refuto.initialize",
            "params": {"client": "ai-dlc-conductor/v2.10.0"},
            "id": 1
        }
        res_text = self.server.handle_request_text(json.dumps(req))
        self.assertIsNotNone(res_text)
        res = json.loads(res_text)

        self.assertEqual("2.0", res.get("jsonrpc"))
        self.assertEqual(1, res.get("id"))
        result = res.get("result", {})
        self.assertEqual(PROTOCOL_VERSION, result.get("protocol_version"))
        self.assertEqual(VERSION, result.get("server_info", {}).get("version"))
        self.assertIn("refuto.verify_claim", result.get("capabilities", []))

    def test_query_status(self):
        req = {
            "jsonrpc": "2.0",
            "method": "refuto.query_status",
            "params": {},
            "id": 2
        }
        res = json.loads(self.server.handle_request_text(json.dumps(req)))
        self.assertEqual(2, res.get("id"))
        result = res.get("result", {})
        self.assertIn("ledger", result)
        self.assertIn("chain_status", result["ledger"])

    def test_verify_claim_emits_decision_capsule(self):
        req = {
            "jsonrpc": "2.0",
            "method": "refuto.verify_claim",
            "params": {
                "claim": {
                    "schema": "refuto.claim/v1",
                    "claim_id": "clm_test_roles_001",
                    "property": "roles.validity",
                    "scope_requirement": {
                        "min_examined": 1
                    }
                },
                "gate": "G-ROLES"
            },
            "id": 3
        }
        res = json.loads(self.server.handle_request_text(json.dumps(req)))
        self.assertEqual(3, res.get("id"))
        result = res.get("result", {})

        self.assertIn("capsule", result)
        capsule = result["capsule"]
        self.assertEqual(CAPSULE_SCHEMA, capsule.get("schema"))
        self.assertEqual("clm_test_roles_001", capsule.get("claim_id"))

        # G-ROLES ahora declara Scope estructurado, por lo tanto la cápsula emite PASS
        self.assertEqual(PASS, capsule.get("status"))
        self.assertEqual(22, capsule.get("scope", {}).get("items_examined"))
        self.assertTrue(capsule.get("scope", {}).get("declared"))

        # La admisibilidad permite el avance ya que la compuerta cuenta con ámbito completo
        admissibility = result.get("lifecycle_admissibility", {})
        self.assertTrue(admissibility.get("can_advance"))
        self.assertEqual(0, len(admissibility.get("remediation_actions", [])))

    def test_verify_claim_rejects_advance_on_insufficient_scope(self):
        """Verifica que una compuerta con ámbito insuficiente o no cumplido emite INCONCLUSIVE."""
        req = {
            "jsonrpc": "2.0",
            "method": "refuto.verify_claim",
            "params": {
                "claim": {
                    "schema": "refuto.claim/v1",
                    "claim_id": "clm_test_insufficient_scope",
                    "property": "roles.validity",
                    "scope_requirement": {
                        "min_examined": 100  # Requiere 100 pero el registro sólo tiene 22
                    }
                },
                "gate": "G-ROLES"
            },
            "id": 99
        }
        res = json.loads(self.server.handle_request_text(json.dumps(req)))
        result = res.get("result", {})
        capsule = result["capsule"]
        self.assertEqual(INCONCLUSIVE, capsule.get("status"))
        admissibility = result.get("lifecycle_admissibility", {})
        self.assertFalse(admissibility.get("can_advance"))
        self.assertTrue(len(admissibility.get("remediation_actions", [])) >= 1)

    def test_method_not_found(self):
        req = {
            "jsonrpc": "2.0",
            "method": "refuto.inexistente",
            "params": {},
            "id": 99
        }
        res = json.loads(self.server.handle_request_text(json.dumps(req)))
        self.assertIn("error", res)
        self.assertEqual(METHOD_NOT_FOUND, res["error"]["code"])

    def test_parse_error(self):
        res = json.loads(self.server.handle_request_text("{ esto no es json"))
        self.assertIn("error", res)
        self.assertEqual(PARSE_ERROR, res["error"]["code"])


if __name__ == "__main__":
    unittest.main()
