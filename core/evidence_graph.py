# -*- coding: utf-8 -*-
"""Grafo de Evidencia y Linaje Criptográfico (Evidence Graph v1).

Especificación: docs/decisions/ADR-0010-evidence-graph-and-evaluation-plane.md
Esquema: refuto.evidence-graph/v1
Axioma: Toda afirmación, artefacto, ejecución, puerta y cápsula forma un DAG
inmutable con trazabilidad estricta de procedencia y cascada determinista de invalidación.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any, Dict, List, Optional, Set

from core.model import now

# Tipos de Nodo normativos
NODE_CLAIM = "CLAIM"
NODE_SUBJECT = "SUBJECT"
NODE_POLICY = "POLICY"
NODE_TOOL = "TOOL"
NODE_ENVIRONMENT = "ENVIRONMENT"
NODE_GATE = "GATE"
NODE_OBSERVATION = "OBSERVATION"
NODE_WITNESS = "WITNESS"
NODE_ANCHOR = "ANCHOR"
NODE_CAPSULE = "CAPSULE"

NODE_TYPES = (
    NODE_CLAIM,
    NODE_SUBJECT,
    NODE_POLICY,
    NODE_TOOL,
    NODE_ENVIRONMENT,
    NODE_GATE,
    NODE_OBSERVATION,
    NODE_WITNESS,
    NODE_ANCHOR,
    NODE_CAPSULE,
)

# Relaciones normativas de aristas
REL_VERIFIED_BY = "VERIFIED_BY"
REL_DERIVED_FROM = "DERIVED_FROM"
REL_REFUTES = "REFUTES"
REL_BLOCKED_BY = "BLOCKED_BY"
REL_WITNESSED_BY = "WITNESSED_BY"
REL_ANCHORED_BY = "ANCHORED_BY"

RELATIONS = (
    REL_VERIFIED_BY,
    REL_DERIVED_FROM,
    REL_REFUTES,
    REL_BLOCKED_BY,
    REL_WITNESSED_BY,
    REL_ANCHORED_BY,
)

# Estados de nodo
STATUS_VALID = "VALID"
STATUS_INVALIDATED = "INVALIDATED"


class CycleDetectedError(Exception):
    """Se detectó un ciclo en el grafo de evidencia, violando la propiedad DAG."""


@dataclass
class EvidenceNode:
    id: str
    type: str
    digest: str
    status: str = STATUS_VALID
    metadata: Dict[str, Any] = field(default_factory=dict)
    invalidation_reason: Optional[str] = None
    created_at: str = field(default_factory=now)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class EvidenceEdge:
    source: str  # Productor / Dependencia upstream
    target: str  # Consumidor / Dependiente downstream
    relation: str

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


class EvidenceGraph:
    """Implementación formal del Grafo de Evidencia de Refuto (ADR-0010)."""

    def __init__(self):
        self.nodes: Dict[str, EvidenceNode] = {}
        # Aristas forward: parent -> list[children] (para propagar impacto)
        self.adj: Dict[str, List[str]] = {}
        # Aristas backward: child -> list[parents] (para rastrear linaje)
        self.rev_adj: Dict[str, List[str]] = {}
        self.edges: List[EvidenceEdge] = []

    def add_node(
        self,
        node_id: str,
        node_type: str,
        digest: str,
        status: str = STATUS_VALID,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> EvidenceNode:
        if node_type not in NODE_TYPES:
            raise ValueError(f"Tipo de nodo desconocido: {node_type}; permitidos: {NODE_TYPES}")

        node = EvidenceNode(
            id=node_id,
            type=node_type,
            digest=digest,
            status=status,
            metadata=metadata or {},
            created_at=now(),
        )
        self.nodes[node_id] = node
        if node_id not in self.adj:
            self.adj[node_id] = []
        if node_id not in self.rev_adj:
            self.rev_adj[node_id] = []
        return node

    def add_dependency(self, child_id: str, parent_id: str, relation: str = REL_DERIVED_FROM):
        """Declara que child_id depende de parent_id.

        Arista dirigida: parent_id -> child_id.
        Si la inserción introduce un ciclo, se revierte y levanta CycleDetectedError.
        """
        if child_id not in self.nodes:
            raise KeyError(f"Nodo dependiente '{child_id}' no existe en el grafo")
        if parent_id not in self.nodes:
            raise KeyError(f"Nodo dependencia '{parent_id}' no existe en el grafo")
        if relation not in RELATIONS:
            raise ValueError(f"Relación desconocida: {relation}; permitidas: {RELATIONS}")

        # Evitar duplicados
        if child_id in self.adj[parent_id]:
            return

        self.adj[parent_id].append(child_id)
        self.rev_adj[child_id].append(parent_id)
        edge = EvidenceEdge(source=parent_id, target=child_id, relation=relation)
        self.edges.append(edge)

        if not self.is_acyclic():
            # Revertir
            self.adj[parent_id].remove(child_id)
            self.rev_adj[child_id].remove(parent_id)
            self.edges.remove(edge)
            raise CycleDetectedError(f"Agregar dependencia {parent_id} -> {child_id} crearía un ciclo en el DAG")

    def is_acyclic(self) -> bool:
        """Determina si el grafo actual es acíclico mediante algoritmo DFS de 3 colores."""
        # 0: no visitado (blanco), 1: en progreso (gris), 2: completado (negro)
        color: Dict[str, int] = {nid: 0 for nid in self.nodes}

        def dfs(u: str) -> bool:
            color[u] = 1
            for v in self.adj.get(u, []):
                if color.get(v, 0) == 1:
                    return False  # Ciclo encontrado
                if color.get(v, 0) == 0:
                    if not dfs(v):
                        return False
            color[u] = 2
            return True

        for nid in self.nodes:
            if color[nid] == 0:
                if not dfs(nid):
                    return False
        return True

    def topological_order(self) -> List[str]:
        """Devuelve el orden topológico de los nodos (primero las dependencias raíz)."""
        if not self.is_acyclic():
            raise CycleDetectedError("No se puede ordenar topológicamente un grafo con ciclos")

        visited: Set[str] = set()
        order: List[str] = []

        def dfs(u: str):
            visited.add(u)
            for v in self.adj.get(u, []):
                if v not in visited:
                    dfs(v)
            order.append(u)

        for nid in self.nodes:
            if nid not in visited:
                dfs(nid)

        order.reverse()
        return order

    def compute_impact(self, node_id: str) -> Set[str]:
        """Calcula el conjunto de todos los nodos descendientes afectados por una invalidación."""
        if node_id not in self.nodes:
            raise KeyError(f"Nodo '{node_id}' no encontrado en el grafo")

        impacted: Set[str] = set()
        queue = [node_id]

        while queue:
            curr = queue.pop(0)
            for child in self.adj.get(curr, []):
                if child not in impacted:
                    impacted.add(child)
                    queue.append(child)

        return impacted

    def invalidate(self, node_id: str, reason: str) -> Set[str]:
        """Invalida un nodo y propaga la cascada a todos sus descendientes dependientes."""
        if node_id not in self.nodes:
            raise KeyError(f"Nodo '{node_id}' no encontrado en el grafo")

        impacted = self.compute_impact(node_id)
        all_to_invalidate = {node_id} | impacted

        for nid in all_to_invalidate:
            node = self.nodes[nid]
            node.status = STATUS_INVALIDATED
            if nid == node_id:
                node.invalidation_reason = f"Causa raíz: {reason}"
            else:
                node.invalidation_reason = f"Invalidado por cascada desde dependencia '{node_id}': {reason}"

        return all_to_invalidate

    def trace_lineage(self, node_id: str) -> Set[str]:
        """Calcula todos los ancestros de procedencia (upstream dependencies) de un nodo."""
        if node_id not in self.nodes:
            raise KeyError(f"Nodo '{node_id}' no encontrado en el grafo")

        lineage: Set[str] = set()
        queue = [node_id]

        while queue:
            curr = queue.pop(0)
            for parent in self.rev_adj.get(curr, []):
                if parent not in lineage:
                    lineage.add(parent)
                    queue.append(parent)

        return lineage

    def to_dict(self) -> Dict[str, Any]:
        return {
            "schema": "refuto.evidence-graph/v1",
            "nodes": {nid: n.to_dict() for nid, n in self.nodes.items()},
            "edges": [e.to_dict() for e in self.edges],
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> EvidenceGraph:
        graph = cls()
        nodes_dict = data.get("nodes", {})
        for nid, nd in nodes_dict.items():
            graph.add_node(
                node_id=nd["id"],
                node_type=nd["type"],
                digest=nd["digest"],
                status=nd.get("status", STATUS_VALID),
                metadata=nd.get("metadata", {}),
            )
            node = graph.nodes[nid]
            node.invalidation_reason = nd.get("invalidation_reason")
            node.created_at = nd.get("created_at", now())

        for ed in data.get("edges", []):
            graph.add_dependency(
                child_id=ed["target"],
                parent_id=ed["source"],
                relation=ed["relation"],
            )
        return graph

    def export_mermaid(self) -> str:
        """Exporta el grafo de evidencia a sintaxis Mermaid con codificación de estados."""
        lines = ["flowchart TD"]
        for nid, node in self.nodes.items():
            lbl = f"{node.type}: {nid[:16]}"
            if node.status == STATUS_INVALIDATED:
                lines.append(f'    {nid}["{lbl} (INVALIDATED)"]:::invalidated')
            else:
                lines.append(f'    {nid}["{lbl}"]:::valid')

        for edge in self.edges:
            lines.append(f"    {edge.source} -->|{edge.relation}| {edge.target}")

        lines.append("    classDef valid fill:#e1f5fe,stroke:#0288d1,stroke-width:2px;")
        lines.append("    classDef invalidated fill:#ffebee,stroke:#d32f2f,stroke-width:2px,stroke-dasharray: 5 5;")
        return "\n".join(lines)
