# -*- coding: utf-8 -*-
"""Enrutado por capacidad. Se elige un runtime por lo que sabe hacer, nunca por su nombre.

La diferencia, y es la que separa una plataforma de una colección de scripts
----------------------------------------------------------------------------
    por nombre      «esta fase la hace Kiro»          → cambiar de agente reescribe el proceso
    por capacidad   «esta fase necesita navegador,
                     salida estructurada y headless»  → cambiar de agente no cambia nada

Toda decisión de este módulo es **auditable**: devuelve por qué eligió ese runtime, por qué
descartó los demás, y qué restricciones quedan sin aplicar. Un router que no explica es un
router que nadie puede revisar, y entonces sus decisiones no son decisiones: son casualidades.

Sobre el fallback
-----------------
Cambiar de agente cuando el elegido falla es útil y es peligroso. Se permite **sólo hacia
capacidades iguales o menores**: nunca se cae a un runtime con más privilegio del que la tarea
pedía. Y si el sustituto no cubre alguna restricción declarada, se pide confirmación humana en
vez de sustituir en silencio.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field

from core.capability import AVAILABLE, BLOCKED, FUNCTIONAL, at_least
from core.roles import Role, load as load_roles

#: Privilegio implícito de cada herramienta. Se usa para no caer nunca «hacia arriba».
TOOL_PRIVILEGE = {
    "read": 1, "grep": 1, "glob": 1, "thinking": 1,
    "write": 3, "browser": 3,
    "shell": 5, "aws": 5, "kubectl": 5,
}


@dataclass
class Decision:
    role: str
    chosen: str = ""
    fallbacks: list = field(default_factory=list)
    rejected: dict = field(default_factory=dict)
    required_capabilities: list = field(default_factory=list)
    missing_capabilities: list = field(default_factory=list)
    allowed_tools: list = field(default_factory=list)
    constraints: list = field(default_factory=list)
    unenforceable: list = field(default_factory=list)
    gates: list = field(default_factory=list)
    human_review: str = ""
    rationale: list = field(default_factory=list)
    status: str = "READY"        # READY | DEGRADED | BLOCKED
    needs_confirmation: str = ""

    def to_dict(self) -> dict:
        return asdict(self)

    def explain(self) -> str:
        lines = [f"rol {self.role} → {self.chosen or '(ninguno)'}  [{self.status}]"]
        lines += [f"    · {r}" for r in self.rationale]
        if self.rejected:
            for name, why in sorted(self.rejected.items()):
                lines.append(f"    ✗ {name}: {why}")
        if self.unenforceable:
            for u in self.unenforceable:
                lines.append(f"    ! sin aplicar: {u}")
        if self.needs_confirmation:
            lines.append(f"    ? {self.needs_confirmation}")
        return "\n".join(lines)


def _privilege(tools: list) -> int:
    return max((TOOL_PRIVILEGE.get(t, 2) for t in tools), default=0)


def route(role: Role | str, graph, specs: dict, *, prefer: list | None = None,
          policy=None, exclude: list | None = None) -> Decision:
    """Elige un runtime para un rol. Explica la elección y todos los descartes."""
    if isinstance(role, str):
        roles = load_roles()
        if role not in roles:
            d = Decision(role=role, status="BLOCKED")
            d.rationale.append(f"«{role}» no está en el registro de roles")
            return d
        role = roles[role]

    d = Decision(role=role.id,
                 required_capabilities=list(role.required_capabilities),
                 allowed_tools=list(role.allowed_tools),
                 constraints=list(role.constraints),
                 gates=list(role.quality_gates),
                 human_review=role.human_review)

    # 1 · ¿Cubre el ENTORNO lo que el rol necesita? Si no, no hay agente que lo arregle.
    env_caps = [c for c in role.required_capabilities if not c.startswith("agent.")]
    ok_env, missing_env = graph.satisfies(env_caps, minimum=AVAILABLE)
    if not ok_env:
        d.status = "BLOCKED"
        d.missing_capabilities = missing_env
        d.rationale.append(f"el entorno no ofrece {', '.join(missing_env)}; ningún agente "
                           f"puede suplirlo")
        return d
    if env_caps:
        d.rationale.append(f"entorno cubre {', '.join(env_caps)}")

    # 2 · Candidatos que cubren las capacidades de AGENTE.
    agent_caps = [c for c in role.required_capabilities if c.startswith("agent.")]
    candidates, rejected = [], {}
    excluded = set(exclude or ())
    for name, caps in graph.by_provider.items():
        if name not in specs:
            continue
        if name in excluded:
            # `prefer` NO basta para descartar: el criterio de orden pone la aplicabilidad de
            # la política por delante de la preferencia, así que el que acaba de fallar volvía
            # a salir elegido. Excluir es excluir.
            rejected[name] = "excluido de esta selección"
            continue
        faltan = [c for c in agent_caps
                  if not at_least((caps.get(c).state if caps.get(c) else "MISSING"), FUNCTIONAL)]
        bloqueadas = [c for c, cap in caps.items() if cap.state == BLOCKED]
        if bloqueadas and any(c in agent_caps for c in bloqueadas):
            rejected[name] = f"capacidad bloqueada: {', '.join(sorted(set(bloqueadas) & set(agent_caps)))}"
            continue
        if faltan:
            rejected[name] = f"no ofrece {', '.join(faltan)}"
            continue
        candidates.append(name)

    if not candidates:
        d.status = "BLOCKED"
        d.rejected = rejected
        d.missing_capabilities = agent_caps
        d.rationale.append(f"ningún runtime cubre {', '.join(agent_caps)}")
        return d

    # 3 · Ordenar. **La aplicabilidad de la política manda sobre todo lo demás.**
    #
    #     La primera versión ordenaba por «menor superficie», medida como «menos capacidades
    #     registradas». Eso eligió sistemáticamente el único runtime donde la política NO se
    #     aplica — exactamente al revés de lo que hay que hacer. Un router que prefiere el
    #     entorno menos controlado no es un router: es un agujero con explicación.
    prefer = prefer or []
    gaps: dict = {}
    if policy is not None:
        from core.policy import compile_for
        for name in candidates:
            spec = specs.get(name)
            out = compile_for(policy, spec) if spec is not None else {}
            gaps[name] = ([] if out.get("supported") else ["el adapter no compila política"]) + \
                list(out.get("unenforceable") or [])

    def key(name: str):
        sin_aplicar = len(gaps.get(name, []))
        pref = prefer.index(name) if name in prefer else len(prefer)
        return (sin_aplicar, pref, name)

    ordered = sorted(candidates, key=key)
    d.chosen = ordered[0]
    d.fallbacks = ordered[1:]
    d.unenforceable = list(gaps.get(d.chosen, []))

    cubre = ", ".join(agent_caps) or "lo básico"
    if d.unenforceable:
        d.status = "DEGRADED"
        mejor = min((len(gaps.get(n, [])) for n in ordered), default=0)
        d.rationale.append(
            f"«{d.chosen}» cubre {cubre}, y es el que MENOS restricciones deja sin aplicar "
            f"({len(d.unenforceable)}) entre {len(ordered)} que cumplen"
            if mejor == len(d.unenforceable) else
            f"«{d.chosen}» cubre {cubre}")
    else:
        d.rationale.append(
            f"«{d.chosen}» cubre {cubre} y aplica la política entera"
            + (" (estaba en la preferencia declarada)" if d.chosen in prefer else
               f"; entre {len(ordered)} que cumplen, es el único sin huecos de política"
               if sum(1 for n in ordered if not gaps.get(n)) == 1 else ""))
    d.rejected = rejected

    privilegio = _privilege(role.allowed_tools)
    d.rationale.append(f"privilegio máximo del rol: {privilegio} "
                       f"({', '.join(role.allowed_tools) or 'sin herramientas'})")
    return d


def fallback(decision: Decision, graph, specs: dict, *, failed: str, policy=None) -> Decision:
    """Sustituye el runtime elegido tras un fallo. **Nunca hacia más privilegio.**

    Si el sustituto deja sin aplicar restricciones que el original sí aplicaba, no se cambia en
    silencio: se marca `needs_confirmation` y decide una persona.
    """
    remaining = [f for f in decision.fallbacks if f != failed]
    if not remaining:
        out = Decision(**{**decision.to_dict(), "chosen": "", "fallbacks": [],
                          "status": "BLOCKED"})
        out.rationale = list(decision.rationale) + [
            f"«{failed}» falló y no queda ningún runtime que cubra {decision.required_capabilities}"]
        return out

    roles = load_roles()
    role = roles.get(decision.role)
    nxt = route(role, graph, specs, prefer=remaining, policy=policy, exclude=[failed])
    nxt.rationale.insert(0, f"«{failed}» falló; se sustituye")

    antes = set(decision.unenforceable)
    ahora = set(nxt.unenforceable)
    nxt.rejected = {**decision.rejected, failed: "falló durante la ejecución"}
    nuevas = sorted(ahora - antes)
    if nuevas:
        nxt.status = "DEGRADED"
        nxt.needs_confirmation = (
            f"«{nxt.chosen}» deja sin aplicar restricciones que «{failed}» sí aplicaba: "
            f"{'; '.join(nuevas)[:200]}. Cambiar de agente aquí baja el nivel de control: "
            f"lo confirma una persona.")
    return nxt


def plan_phase(phase: str, graph, specs: dict, *, prefer: list | None = None,
               policy=None) -> list:
    """Enruta todos los roles de una fase."""
    from core.roles import by_phase
    return [route(r, graph, specs, prefer=prefer, policy=policy) for r in by_phase(phase)]
