# -*- coding: utf-8 -*-
"""Prueba adversarial del invariante ADR-0023 y FORMAL-MODEL §3.3:
Una compuerta que aprueba sin declarar ámbito (scope=None) JAMÁS puede producir
un veredicto INTEGRABLE ni admisión positiva en el protocolo.

Falsación activa del vector T04 (Vacuous Truth / Empty Scope Exploitation).
"""

from __future__ import annotations

import json
import subprocess
import sys
import unittest
from pathlib import Path

from core.envelope import EXIT_OK
from core.evidence import verdict_of
from core.model import INCONCLUSIVE, PASS, Result, Scope
from core.proc import TEXT_IO
from core.protocol import RefutoProtocolServer

RAIZ = Path(__file__).resolve().parents[2]


from unittest.mock import patch

class TestInconclusiveScopeAdversarial(unittest.TestCase):
    def test_puerta_pass_sin_scope_produce_no_integrable_y_bloquea_protocolo(self):
        """Verifica que una puerta sin scope resulte en
        veredicto NO INTEGRABLE y can_advance=False en el protocolo de verificación."""
        # 1. En verdict_of, una compuerta que aprueba sin scope resulta en NO INTEGRABLE
        unscoped_result = [Result(id="G-UNSCOPED", name="unscoped", status=PASS, scope=None)]
        verdict = verdict_of(unscoped_result)
        self.assertIn("NO INTEGRABLE", verdict)
        self.assertIn("G-UNSCOPED", verdict)
        self.assertIn("sin declarar qué observaron", verdict)

        # 2. En el Protocolo Universal (Wire Protocol), el claim es degradado a INCONCLUSIVE y can_advance=False
        server = RefutoProtocolServer(RAIZ)
        with patch("gates.base.run_all", return_value=unscoped_result):
            res = server._handle_verify_claim({
                "claim": {"claim_id": "clm_t04_scope", "property": "roles_valid"},
                "gate": "G-UNSCOPED"
            })
        self.assertEqual(INCONCLUSIVE, res["capsule"]["status"])
        self.assertFalse(res["lifecycle_admissibility"]["can_advance"])
        self.assertIn("Declarar scope estructurado en todas las compuertas aprobadas",
                      res["lifecycle_admissibility"]["remediation_actions"])
