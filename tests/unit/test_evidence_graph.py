# -*- coding: utf-8 -*-
"""Pruebas unitarias para el Grafo de Evidencia de Refuto (ADR-0010).

Verifica:
1. Invariante DAG (Acyclic Directed Graph).
2. Prevención y detección inmediata de ciclos.
3. Ordenamiento topológico determinista.
4. Cascada de impacto e invalidación transitiva.
5. Trazabilidad de procedencia y linaje upstream.
6. Serialización / Deserialización completa (round-trip).
7. Exportación a diagrama Mermaid.
"""

from __future__ import annotations

import unittest

from core.evidence_graph import (
    CycleDetectedError,
    EvidenceGraph,
    NODE_ANCHOR,
    NODE_CAPSULE,
    NODE_CLAIM,
    NODE_GATE,
    NODE_OBSERVATION,
    NODE_POLICY,
    NODE_SUBJECT,
    NODE_TOOL,
    REL_ANCHORED_BY,
    REL_DERIVED_FROM,
    REL_VERIFIED_BY,
    REL_WITNESSED_BY,
    STATUS_INVALIDATED,
    STATUS_VALID,
)


class TestEvidenceGraph(unittest.TestCase):
    def setUp(self):
        self.graph = EvidenceGraph()

    def test_node_type_validation(self):
        """Rechaza tipos de nodo no conformes con la ontología formal."""
        with self.assertRaises(ValueError):
            self.graph.add_node("bad_node", "UNKNOWN_TYPE", digest="abc")

        node = self.graph.add_node("sub_01", NODE_SUBJECT, digest="d01")
        self.assertEqual(node.type, NODE_SUBJECT)
        self.assertEqual(node.status, STATUS_VALID)

    def test_dag_dependency_and_acyclicity(self):
        """Construye un DAG de verificación y verifica que is_acyclic() sea True."""
        g = self.graph
        g.add_node("subj_1", NODE_SUBJECT, digest="sub_hash")
        g.add_node("pol_1", NODE_POLICY, digest="pol_hash")
        g.add_node("gate_1", NODE_GATE, digest="gate_hash")
        g.add_node("cap_1", NODE_CAPSULE, digest="cap_hash")

        g.add_dependency(child_id="gate_1", parent_id="subj_1", relation=REL_DERIVED_FROM)
        g.add_dependency(child_id="gate_1", parent_id="pol_1", relation=REL_VERIFIED_BY)
        g.add_dependency(child_id="cap_1", parent_id="gate_1", relation=REL_DERIVED_FROM)

        self.assertTrue(g.is_acyclic())
        order = g.topological_order()
        self.assertIn("subj_1", order)
        self.assertIn("gate_1", order)
        self.assertIn("cap_1", order)
        # subj_1 and pol_1 must precede gate_1, which must precede cap_1
        self.assertLess(order.index("subj_1"), order.index("gate_1"))
        self.assertLess(order.index("pol_1"), order.index("gate_1"))
        self.assertLess(order.index("gate_1"), order.index("cap_1"))

    def test_cycle_detection_rejection(self):
        """Intento de insertar una dependencia circular levanta CycleDetectedError y no altera el grafo."""
        g = self.graph
        g.add_node("A", NODE_CLAIM, digest="hA")
        g.add_node("B", NODE_OBSERVATION, digest="hB")
        g.add_node("C", NODE_GATE, digest="hC")

        g.add_dependency(child_id="B", parent_id="A", relation=REL_DERIVED_FROM)
        g.add_dependency(child_id="C", parent_id="B", relation=REL_DERIVED_FROM)

        # Intentar cerrar el ciclo: A depende de C (C -> A)
        with self.assertRaises(CycleDetectedError):
            g.add_dependency(child_id="A", parent_id="C", relation=REL_DERIVED_FROM)

        # El grafo sigue siendo acíclico y conserva su estado anterior
        self.assertTrue(g.is_acyclic())
        self.assertNotIn("A", g.adj["C"])

    def test_invalidation_impact_cascade(self):
        """Invalidar una dependencia raíz (ej. el sujeto o la política) invalida en cascada todos los dependientes."""
        g = self.graph
        # Rama 1: Depende de subject_A
        g.add_node("subj_A", NODE_SUBJECT, digest="subA")
        g.add_node("gate_unit", NODE_GATE, digest="g_unit")
        g.add_node("capsule_A", NODE_CAPSULE, digest="capA")

        g.add_dependency(child_id="gate_unit", parent_id="subj_A", relation=REL_DERIVED_FROM)
        g.add_dependency(child_id="capsule_A", parent_id="gate_unit", relation=REL_DERIVED_FROM)

        # Rama 2: Independiente de subject_A (depende de policy_B)
        g.add_node("pol_B", NODE_POLICY, digest="polB")
        g.add_node("gate_sec", NODE_GATE, digest="g_sec")

        g.add_dependency(child_id="gate_sec", parent_id="pol_B", relation=REL_VERIFIED_BY)

        # Calcular impacto de mutar subj_A
        impacted = g.compute_impact("subj_A")
        self.assertEqual(impacted, {"gate_unit", "capsule_A"})

        # Ejecutar invalidación
        invalidated_all = g.invalidate("subj_A", reason="Código fuente mutado")
        self.assertEqual(invalidated_all, {"subj_A", "gate_unit", "capsule_A"})

        self.assertEqual(g.nodes["subj_A"].status, STATUS_INVALIDATED)
        self.assertEqual(g.nodes["gate_unit"].status, STATUS_INVALIDATED)
        self.assertEqual(g.nodes["capsule_A"].status, STATUS_INVALIDATED)
        self.assertIn("Código fuente mutado", g.nodes["capsule_A"].invalidation_reason)

        # Rama 2 NO debe ser afectada
        self.assertEqual(g.nodes["pol_B"].status, STATUS_VALID)
        self.assertEqual(g.nodes["gate_sec"].status, STATUS_VALID)

    def test_trace_lineage(self):
        """Rastrear el linaje de una cápsula devuelve exactamente sus ancestros causales."""
        g = self.graph
        g.add_node("tool_1", NODE_TOOL, digest="t1")
        g.add_node("obs_1", NODE_OBSERVATION, digest="o1")
        g.add_node("gate_1", NODE_GATE, digest="g1")
        g.add_node("cap_1", NODE_CAPSULE, digest="c1")

        g.add_dependency(child_id="obs_1", parent_id="tool_1", relation=REL_DERIVED_FROM)
        g.add_dependency(child_id="gate_1", parent_id="obs_1", relation=REL_VERIFIED_BY)
        g.add_dependency(child_id="cap_1", parent_id="gate_1", relation=REL_DERIVED_FROM)

        lineage = g.trace_lineage("cap_1")
        self.assertEqual(lineage, {"gate_1", "obs_1", "tool_1"})

    def test_serialization_roundtrip(self):
        """Exportar a diccionario y reconstruir el grafo preserva toda la estructura y estado."""
        g = self.graph
        g.add_node("n1", NODE_CLAIM, digest="d1")
        g.add_node("n2", NODE_GATE, digest="d2")
        g.add_dependency("n2", "n1", REL_VERIFIED_BY)
        g.invalidate("n1", "Violación de aserción")

        serialized = g.to_dict()
        reconstructed = EvidenceGraph.from_dict(serialized)

        self.assertEqual(len(reconstructed.nodes), 2)
        self.assertEqual(len(reconstructed.edges), 1)
        self.assertEqual(reconstructed.nodes["n1"].status, STATUS_INVALIDATED)
        self.assertEqual(reconstructed.nodes["n2"].status, STATUS_INVALIDATED)
        self.assertTrue(reconstructed.is_acyclic())

    def test_mermaid_export(self):
        """Verifica que el diagrama Mermaid contenga los nodos y estilos correctos."""
        g = self.graph
        g.add_node("clm", NODE_CLAIM, digest="dclm")
        g.add_node("cap", NODE_CAPSULE, digest="dcap")
        g.add_dependency("cap", "clm", REL_DERIVED_FROM)

        mermaid = g.export_mermaid()
        self.assertTrue(mermaid.startswith("flowchart TD"))
        self.assertIn("clm", mermaid)
        self.assertIn("cap", mermaid)
        self.assertIn("-->|DERIVED_FROM|", mermaid)


if __name__ == "__main__":
    unittest.main()
