# -*- coding: utf-8 -*-
"""Pruebas unitarias para el modelo normativo E0–E4 y agregador de estado del sistema."""

from __future__ import annotations

import unittest

from core.assurance import (
    E0,
    E1,
    E2,
    E3,
    E4,
    aggregate_system_state,
    compute_assurance_level,
)
from core.model import (
    BLOCKED,
    FAIL,
    INCONCLUSIVE,
    NOT_APPLICABLE,
    NOT_EXECUTABLE,
    PASS,
    Scope,
)


class TestAssuranceEvaluatorE0E4(unittest.TestCase):

    def test_evidencia_vacia_evalua_e0(self):
        self.assertEqual(E0, compute_assurance_level({}))
        self.assertEqual(E0, compute_assurance_level(None))

    def test_afirmacion_con_contradiccion_evalua_e0(self):
        ev = {"contradiction": True, "command": "echo ok", "observed_output": "ok", "exit_code": 0}
        self.assertEqual(E0, compute_assurance_level(ev))

    def test_documento_estatico_evalua_e1(self):
        ev = {"document_path": "docs/11-protocol.md", "schema_valid": True}
        self.assertEqual(E1, compute_assurance_level(ev))

    def test_scope_vacio_degrada_e3_o_e4_a_e1(self):
        # Atestación con test PASS pero sin scope (examined=0)
        ev = {
            "test_status": PASS,
            "suite_passed": True,
            "tests_run": 10,
            "scope": {"examined": 0},
            "document_path": "test.py",
        }
        self.assertEqual(E1, compute_assurance_level(ev))

    def test_testigo_circular_degrada_a_e1(self):
        ev = {
            "test_status": PASS,
            "suite_passed": True,
            "tests_run": 10,
            "is_circular": True,
            "document_path": "test.py",
            "scope": {"examined": 10},
        }
        self.assertEqual(E1, compute_assurance_level(ev))

    def test_comando_reproducible_evalua_e2(self):
        ev = {
            "command": "python3 scripts/check_schemas.py",
            "observed_output": "4/4 valid schemas",
            "exit_code": 0,
            "scope": Scope(examined=4, universe="schemas"),
        }
        self.assertEqual(E2, compute_assurance_level(ev))

    def test_suite_automatizada_pass_con_scope_evalua_e3(self):
        ev = {
            "test_status": PASS,
            "suite_passed": True,
            "tests_run": 535,
            "mutations_killed": True,
            "scope": Scope(examined=535, universe="unit tests"),
        }
        self.assertEqual(E3, compute_assurance_level(ev))

    def test_ejecucion_atestiguada_criptograficamente_evalua_e4(self):
        ev = {
            "ledger_event": True,
            "ledger_head": "0123456789abcdef",
            "chain_integrity": "INTEGRA",
            "witness_signature_valid": True,
            "anchor_verified": True,
            "scope": Scope(examined=100, universe="runtime sessions"),
        }
        self.assertEqual(E4, compute_assurance_level(ev))

    def test_ledger_sin_testigo_criptografico_no_alcanza_e4(self):
        """Un evento en ledger sin firma ni ancla criptográfica NO puede alcanzar E4."""
        ev = {
            "ledger_event": True,
            "ledger_head": "0123456789abcdef",
            "chain_integrity": "INTEGRA",
            "witness_signature_valid": False,
            "anchor_verified": False,
            "scope": Scope(examined=100, universe="runtime sessions"),
        }
        self.assertNotEqual(E4, compute_assurance_level(ev))


class TestSystemStateAggregator(unittest.TestCase):

    def test_fallo_critico_determina_system_fail(self):
        comps = {
            "unit": {"status": PASS, "epistemic_level": E3},
            "security": {"status": FAIL, "epistemic_level": E0, "is_critical": True},
        }
        rep = aggregate_system_state(comps)
        self.assertEqual(FAIL, rep.status)
        self.assertFalse(rep.can_advance)
        self.assertEqual(E0, rep.epistemic_level)
        self.assertIn("Componente crítico 'security' en fallo: FAIL", rep.blocking_reasons)

    def test_bloqueo_p0_determina_system_blocked(self):
        comps = {
            "unit": {"status": PASS, "epistemic_level": E3},
            "contract": {"status": PASS, "epistemic_level": E3},
            "p0_authority": {
                "status": BLOCKED,
                "epistemic_level": E1,
                "is_critical": True,
                "blocking_reason": "P0-2: Separación de autoridad requiere intervención del operador humano",
            },
        }
        rep = aggregate_system_state(comps)
        self.assertEqual(BLOCKED, rep.status)
        self.assertFalse(rep.can_advance)
        self.assertIn("P0-2: Separación de autoridad", rep.blocking_reasons[0])

    def test_evidencia_inconclusa_determina_system_inconclusive(self):
        comps = {
            "unit": {"status": PASS, "epistemic_level": E3},
            "adversarial": {"status": INCONCLUSIVE, "epistemic_level": E1, "is_critical": True},
        }
        rep = aggregate_system_state(comps)
        self.assertEqual(INCONCLUSIVE, rep.status)
        self.assertFalse(rep.can_advance)

    def test_todos_pass_con_e3_determina_system_pass(self):
        comps = {
            "unit": {"status": PASS, "epistemic_level": E3},
            "contract": {"status": PASS, "epistemic_level": E3},
            "selftest": {"status": PASS, "epistemic_level": E3},
            "adversarial": {"status": PASS, "epistemic_level": E3},
        }
        rep = aggregate_system_state(comps)
        self.assertEqual(PASS, rep.status)
        self.assertTrue(rep.can_advance)
        self.assertEqual(E3, rep.epistemic_level)
        self.assertEqual([], rep.blocking_reasons)

    def test_todos_pass_con_e4_determina_system_pass_e4(self):
        comps = {
            "ledger": {"status": PASS, "epistemic_level": E4},
            "concordia": {"status": PASS, "epistemic_level": E4},
        }
        rep = aggregate_system_state(comps)
        self.assertEqual(PASS, rep.status)
        self.assertTrue(rep.can_advance)
        self.assertEqual(E4, rep.epistemic_level)
