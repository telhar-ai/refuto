# -*- coding: utf-8 -*-
"""Roles de ingeniería. Un rol NO es un agente.

    ROL     una unidad de trabajo con contrato: qué consume, qué produce, qué puede tocar
    AGENTE  un runtime capaz de ejecutar roles: claude, kiro, gemini, opencode…

Separarlos es lo que permite cambiar de agente sin tocar el proceso, y añadir un rol sin tocar
ningún adapter. El router los empareja **por capacidad**, nunca por nombre (`core/routing.py`).

El contrato de un rol declara, y todo es exigible:

    input_contract          qué artefactos necesita para poder empezar
    output_contract         qué artefactos deja; sin ellos la fase no terminó
    required_capabilities   qué tiene que saber hacer el runtime
    allowed_tools           el privilegio mínimo, declarado y revisable
    constraints             lo que NO puede hacer, aunque la herramienta se lo permita
    quality_gates           qué puertas se ejecutan al terminar
    human_review            qué revisión humana es obligatoria
    handoff                 a quién entrega
"""

from __future__ import annotations

import functools
import json
from dataclasses import dataclass
from pathlib import Path

from core.schema import load_schema, validate

REGISTRY = Path(__file__).resolve().parents[1] / "roles" / "registry.json"

#: El TEXTO de cada restricción, para el informe de sesión. Es un diccionario de prosa y nada
#: más — quién las APLICA es `core/capabilities.py`, y esa distinción costó un defecto:
#: `validate_registry` comprobaba contra esta tabla y su mensaje decía «restricción que refuto
#: no sabe aplicar», de modo que «saber aplicar» significaba «tener una frase en español».
#: Ahora se valida contra `capabilities.CONOCIDAS` y esta tabla sólo responde de que el agente
#: pueda LEER por qué no puede hacer algo.
KNOWN_CONSTRAINTS = {
    "no_write_code":                "no puede escribir en el producto",
    "no_shell":                     "no puede ejecutar órdenes",
    "no_modify_verifier":           "no puede tocar lo que lo evalúa",
    "no_modify_evidence":           "no puede tocar la evidencia",
    "no_modify_product":            "observa; no repara",
    "no_secret_access":             "no puede leer rutas de credencial",
    "no_self_approval":             "no puede aprobar lo que él mismo produjo",
    "no_fix_what_it_reviews":       "no puede arreglar lo que critica",
    "read_only_infrastructure":     "sólo verbos de lectura contra infraestructura",
    "destructive_requires_approval":"toda operación destructiva pasa por una persona",
}


@dataclass(frozen=True)
class Role:
    id: str
    group: str
    phase: str
    purpose: str
    input_contract: tuple
    output_contract: tuple
    required_capabilities: tuple
    allowed_tools: tuple
    constraints: tuple
    quality_gates: tuple
    human_review: str
    handoff: tuple
    notes: str

    @classmethod
    def from_dict(cls, d: dict) -> "Role":
        return cls(
            id=d["id"], group=d["group"], phase=d["phase"], purpose=d["purpose"],
            input_contract=tuple(d.get("input_contract") or ()),
            output_contract=tuple(d["output_contract"]),
            required_capabilities=tuple(d.get("required_capabilities") or ()),
            allowed_tools=tuple(d.get("allowed_tools") or ()),
            constraints=tuple(d.get("constraints") or ()),
            quality_gates=tuple(d.get("quality_gates") or ()),
            human_review=d.get("human_review", ""),
            handoff=tuple(d.get("handoff") or ()),
            notes=d.get("notes", ""))

    def to_dict(self) -> dict:
        return {
            "id": self.id, "group": self.group, "phase": self.phase, "purpose": self.purpose,
            "input_contract": list(self.input_contract),
            "output_contract": list(self.output_contract),
            "required_capabilities": list(self.required_capabilities),
            "allowed_tools": list(self.allowed_tools),
            "constraints": list(self.constraints),
            "quality_gates": list(self.quality_gates),
            "human_review": self.human_review,
            "handoff": list(self.handoff), "notes": self.notes,
        }


@functools.lru_cache(maxsize=1)
def load(path: str = "") -> dict:
    doc = json.loads(Path(path or REGISTRY).read_text(encoding="utf-8"))
    return {r["id"]: Role.from_dict(r) for r in doc["roles"]}


def validate_registry(path: str = "") -> list:
    """Comprueba el registro entero. Devuelve los problemas; vacío significa correcto.

    Se comprueban tres cosas que el esquema no puede: que las restricciones existan, que los
    traspasos apunten a roles reales, y que las puertas citadas estén implementadas.
    """
    p = Path(path or REGISTRY)
    try:
        doc = json.loads(p.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        return [f"{p.name}: ilegible — {exc}"]

    from core.capabilities import CONOCIDAS

    problems = [f"{p.name}: {e}" for e in validate(doc, load_schema("roles.schema.json"))]
    ids = {r["id"] for r in doc.get("roles", [])}
    from gates.base import GATES

    seen: set = set()
    for r in doc.get("roles", []):
        rid = r.get("id", "?")
        if rid in seen:
            problems.append(f"{rid}: declarado dos veces")
        seen.add(rid)
        for c in r.get("constraints", []):
            # Contra `core.capabilities.CONOCIDAS`, no contra `KNOWN_CONSTRAINTS`.
            #
            # El defecto que esto cierra, medido el 2026-09-25: esta comprobación miraba
            # `KNOWN_CONSTRAINTS`, que es el **diccionario de prosa** con el que se redacta el
            # informe de sesión (`core/session.py:753`). Es decir, «refuto no sabe aplicar»
            # significaba «no tengo una frase en español para describirla». El umbral de
            # `G-ROLES` dice «restricciones APLICABLES» y el mensaje de error dice «una
            # restricción que no se aplica es peor que no declararla» — y lo que se verificaba
            # era que estuviera descrita. La puerta decía lo correcto y medía lo de al lado, y
            # aprobaba sobre 22 roles y 10 restricciones aplicadas por cero líneas de código.
            #
            # `CONOCIDAS` = las que el guardián APLICA ∪ las declaradas NO OBSERVABLES con su
            # motivo escrito. Una tercera categoría —descrita y en ningún sitio— es la que
            # existía, y ahora no se puede expresar sin poner esto en rojo.
            if c not in CONOCIDAS:
                problems.append(f"{rid}: restricción «{c}» que el guardián no aplica y que "
                                f"tampoco está declarada no observable en "
                                f"`core.capabilities.NO_OBSERVABLES`. Una restricción que sólo "
                                f"se imprime en el informe de sesión es una petición al modelo, "
                                f"no un control: se cita en las revisiones como si protegiera.")
            elif c not in KNOWN_CONSTRAINTS:
                problems.append(f"{rid}: restricción «{c}» sin texto en `KNOWN_CONSTRAINTS`. El "
                                f"guardián la aplica y el informe de sesión no la puede "
                                f"explicar, así que el agente la incumplirá sin saber por qué.")
        for h in r.get("handoff", []):
            if h not in ids:
                problems.append(f"{rid}: entrega a «{h}», que no es un rol")
        for g in r.get("quality_gates", []):
            if g not in GATES:
                problems.append(f"{rid}: cita la puerta «{g}», que no existe")
    return problems


def by_phase(phase: str) -> list:
    return [r for r in load().values() if r.phase == phase]


def chain_from(role_id: str, *, max_depth: int = 12) -> list:
    """Cadena de traspaso a partir de un rol. Detecta ciclos en vez de colgarse."""
    roles = load()
    out, seen, frontier = [], set(), [role_id]
    depth = 0
    while frontier and depth < max_depth:
        nxt = []
        for rid in frontier:
            if rid in seen or rid not in roles:
                continue
            seen.add(rid)
            out.append(roles[rid])
            nxt.extend(roles[rid].handoff)
        frontier = nxt
        depth += 1
    return out
