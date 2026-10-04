# -*- coding: utf-8 -*-
"""Descubrimiento automático y verificación del Invariante Global de No-Vacuidad.

Invariante del Sistema:
    ∀ gate ∈ gates/*:
        PASS ⟹ (scope is not None ∧ scope.examined > 0 ∧ scope.unknown == 0 ∧ len(findings) == 0)

Detecta automáticamente cualquier compuerta que viole este invariante o que intente
aprobar ante un sujeto vacío o inexistente.
"""

from __future__ import annotations

import importlib
import pkgutil
import tempfile
import unittest
from pathlib import Path

import gates
from core.context import Context
from core.model import (
    BLOCKED,
    FAIL,
    INCONCLUSIVE,
    NOT_APPLICABLE,
    NOT_EXECUTABLE,
    PASS,
    Result,
    Scope,
)


class TestSystemNonVacuityInvariant(unittest.TestCase):

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="test-vacuity-invariant-"))
        self.ctx = Context(workspace=self.tmp)

    def test_dynamic_gate_discovery_non_vacuity(self):
        """Descubre automáticamente todos los módulos g_*.py y comprueba el invariante de no-vacuidad."""
        discovered_gates = []
        gates_pkg = gates

        for _, modname, _ in pkgutil.iter_modules(gates_pkg.__path__):
            if modname.startswith("g_"):
                mod = importlib.import_module(f"gates.{modname}")
                if hasattr(mod, "run"):
                    discovered_gates.append((modname, mod))

        self.assertGreaterEqual(len(discovered_gates), 10, "Deben descubrirse al menos 10 compuertas activas")

        violating_gates = []
        for name, mod in discovered_gates:
            try:
                res = mod.run(self.ctx)
                if isinstance(res, Result):
                    # Si emite PASS sobre un directorio vacío, VIOLA el invariante
                    if res.status == PASS:
                        if res.scope is None or res.scope.examined == 0 or res.scope.unknown > 0:
                            violating_gates.append(
                                f"{name} devolvió PASS con scope inválido (examined={getattr(res.scope, 'examined', None)})"
                            )
            except ValueError:
                # Result.__post_init__ lanzó ValueError ante intento de PASS sin cobertura (esperado)
                pass
            except Exception:
                # Errores esperados en espacios vacíos (ej. falta manifiesto)
                pass

        self.assertEqual(
            [], violating_gates,
            f"Compuertas que violan el Teorema Global de No-Vacuidad: {violating_gates}"
        )

    def test_invariante_post_init_result_inviolable(self):
        """Result jamás permite construir PASS si examined == 0 o unknown > 0."""
        # Caso 1: examined = 0
        with self.assertRaises(ValueError):
            Result(
                id="G-INVARIANT",
                name="Test",
                status=PASS,
                severity="HIGH",
                threshold="no vacuity",
                measure="0",
                scope=Scope(examined=0, unknown=0, universe="items", declared=True)
            )

        # Caso 2: unknown > 0
        with self.assertRaises(ValueError):
            Result(
                id="G-INVARIANT",
                name="Test",
                status=PASS,
                severity="HIGH",
                threshold="no vacuity",
                measure="1 unknown",
                scope=Scope(examined=10, unknown=1, universe="items", declared=True)
            )

        # Caso 3: findings presentes con PASS
        from core.model import Finding
        with self.assertRaises(ValueError):
            Result(
                id="G-INVARIANT",
                name="Test",
                status=PASS,
                severity="HIGH",
                threshold="no findings",
                measure="1 finding",
                findings=[Finding("file.py", "issue", 1)],
                scope=Scope(examined=10, unknown=0, universe="items", declared=True)
            )


if __name__ == "__main__":
    unittest.main()
