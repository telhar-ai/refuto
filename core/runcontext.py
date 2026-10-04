# -*- coding: utf-8 -*-
"""Contexto de ejecución. Lo que refuto cree que está haciendo, y por qué.

La pregunta que este módulo tiene que poder responder
-----------------------------------------------------
> «¿Qué cree refuto que está pasando, y en qué se basa?»

Si no se puede responder mirando un archivo, el sistema es opaco — y un sistema opaco que toma
decisiones sobre tu repositorio no es una plataforma, es una caja negra con buena documentación.

El contexto se **construye**, no se acumula
-------------------------------------------
Se genera de cero en cada ejecución, a partir del descubrimiento, la sonda y el manifiesto. No
se hereda del anterior. Un contexto heredado envejece sin avisar, que es exactamente el fallo
que `refuto resume` tiene que detectar antes de continuar.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

from core.model import KIND_CONTEXT, new_id, now, provenance, write_json

DIR = ".harness/context"

FILES = {
    "environment":  "environment.json",
    "repository":   "repository.json",
    "sdd_core":     "sdd-core.json",
    "agents":       "agents.json",
    "capabilities": "capabilities.json",
    "tools":        "tools.json",
    "roles":        "roles.json",
    "policies":     "policies.json",
    "constraints":  "constraints.json",
}


@dataclass
class RunContext:
    workspace: Path
    run_id: str = ""
    parts: dict = field(default_factory=dict)

    def path(self, key: str) -> Path:
        return self.workspace / DIR / FILES[key]

    def write(self) -> list:
        written = []
        for key, doc in self.parts.items():
            if key in FILES:
                p = self.path(key)
                write_json(p, doc)
                written.append(p)
        write_json(self.workspace / DIR / "context.json", self.summary())
        written.append(self.workspace / DIR / "context.json")
        return written

    def summary(self) -> dict:
        env = self.parts.get("environment") or {}
        repo = (self.parts.get("repository") or {}).get("chosen") or {}
        core = (self.parts.get("sdd_core") or {}).get("chosen") or {}
        caps = self.parts.get("capabilities") or {}
        agents = self.parts.get("agents") or []
        tools = self.parts.get("tools") or {}
        return {
            "schema": "harness.context/v1",
            "run_id": self.run_id,
            "generated_at": now(),
            "provenance": provenance(self.workspace),
            "sdd_core": {"path": core.get("subject", ""), "name": core.get("name", ""),
                         "version": core.get("version", ""), "commit": core.get("commit", ""),
                         "integrity": core.get("integrity", ""),
                         "confidence": core.get("confidence", ""),
                         "resolved": (self.parts.get("sdd_core") or {}).get("outcome", "")},
            "repository": {"path": repo.get("subject", ""), "remote": repo.get("remote", ""),
                           "branch": repo.get("branch", ""), "commit": repo.get("commit", ""),
                           "dirty": repo.get("dirty"), "stack": repo.get("ecosystems", []),
                           "confidence": repo.get("confidence", ""),
                           "resolved": (self.parts.get("repository") or {}).get("outcome", "")},
            "agents": [{"name": a.get("agent"), "level": a.get("level"),
                        "version": a.get("version"),
                        "protocol": (a.get("protocol") or {}).get("family", ""),
                        "why_stopped": a.get("stopped_because", "")} for a in agents],
            "capabilities": caps.get("summary", {}),
            "tools": tools.get("summary", {}),
            "blockers": tools.get("blockers", []),
            "platform": env.get("os", {}),
            "ci": env.get("ci", {}),
        }


def build(workspace: Path, *, roots: list | None = None, deep: bool = False,
          phases: list | None = None, prefer: list | None = None) -> RunContext:
    """Construye el contexto completo. No modifica nada fuera de `.harness/context/`."""
    from adapters.registry import ADAPTERS, all_specs
    from core.capability import build as build_caps
    from core.discovery import discover
    from core.policy import Policy
    from core.probe import probe_all
    from core.roles import load as load_roles, validate_registry
    from core.toolplan import plan as tool_plan

    ctx = RunContext(workspace=workspace, run_id=new_id(KIND_CONTEXT))
    disc = discover(workspace, roots=roots, deep=deep)
    ctx.parts["environment"] = disc["environment"]
    ctx.parts["repository"] = disc["repository"]
    ctx.parts["sdd_core"] = disc["sdd_core"]

    probes = probe_all(all_specs(), workspace=workspace)
    ctx.parts["agents"] = [p.to_dict() for p in probes]

    # Se reutilizan las herramientas ya descubiertas: volver a escanearlas costaría 30
    # subprocesos por nada.
    from core.discovery import ToolFact
    known = set(ToolFact.__dataclass_fields__)                  # noqa: SLF001
    tool_facts = [ToolFact(**{k: v for k, v in t.items() if k in known})
                  for t in disc["environment"]["tools"]]

    graph = build_caps(probes, ADAPTERS, tool_facts)
    ctx.parts["capabilities"] = graph.to_dict()

    repo = (disc["repository"].get("chosen") or {})
    ecosystems = repo.get("ecosystems") or []
    ctx.parts["tools"] = tool_plan(ecosystems=ecosystems,
                                   phases=phases or ["IMPLEMENT", "TEST", "SECURE"],
                                   tool_facts=tool_facts)

    roles = load_roles()
    ctx.parts["roles"] = {
        "schema": "harness.roles-context/v1",
        "problems": validate_registry(),
        "roles": {rid: r.to_dict() for rid, r in sorted(roles.items())},
    }

    policy_file = workspace / ".harness" / "policy.json"
    policy = Policy.load(policy_file) if policy_file.is_file() else Policy.default()
    ctx.parts["policies"] = policy.to_dict()

    from core.routing import route
    decisions = {rid: route(r, graph, ADAPTERS, prefer=prefer, policy=policy).to_dict()
                 for rid, r in sorted(roles.items())}
    ctx.parts["constraints"] = {
        "schema": "harness.routing/v1",
        "decisions": decisions,
        "blocked_roles": sorted(r for r, d in decisions.items() if d["status"] == "BLOCKED"),
        "degraded_roles": sorted(r for r, d in decisions.items() if d["status"] == "DEGRADED"),
    }
    return ctx


def report(ctx: RunContext) -> str:
    """El informe humano. Se DERIVA del contexto estructurado, nunca al revés."""
    s = ctx.summary()
    core, repo = s["sdd_core"], s["repository"]
    routing = ctx.parts.get("constraints") or {}
    tools = ctx.parts.get("tools") or {}
    caps = ctx.parts.get("capabilities") or {}

    L = [
        "# Reporte de contexto",
        "",
        f"**Ejecución** `{s['run_id']}` · {s['generated_at']}",
        "",
        "> Este documento responde a una sola pregunta: *¿qué cree refuto que está "
        "pasando, y en qué se basa?* Se genera del contexto estructurado; si algo no está "
        "aquí, es que refuto no lo sabe.",
        "",
        "## Dónde",
        "",
        "| | Valor | Confianza |",
        "|---|---|---|",
        f"| Núcleo SDD | `{core['path'] or '—'}` {core['name']} {core['version']} | "
        f"{core['confidence'] or '—'} ({core['resolved']}) |",
        f"| Integridad del núcleo | {core['integrity'] or 'no comprobada'} | |",
        f"| Repositorio | `{repo['path'] or '—'}` | {repo['confidence'] or '—'} ({repo['resolved']}) |",
        f"| Rama · commit | `{repo['branch'] or '?'}` · `{(repo['commit'] or '')[:12] or '?'}`"
        f"{' · **con cambios sin confirmar**' if repo.get('dirty') else ''} | |",
        f"| Stack | {', '.join(repo['stack']) or 'no detectado'} | |",
        "",
        "## Agentes",
        "",
        "| Agente | Peldaño | Versión | Protocolo | Nota |",
        "|---|---|---|---|---|",
    ]
    for a in s["agents"]:
        L.append(f"| {a['name']} | `{a['level']}` | {a['version'] or '?'} | "
                 f"{a['protocol'] or '—'} | {(a['why_stopped'] or '')[:70]} |")

    L += ["", "## Capacidades", "",
          " · ".join(f"**{k}** {v}" for k, v in sorted(s["capabilities"].items())) or "—", ""]

    blockers = tools.get("blockers") or []
    L += ["## Herramientas", "",
          f"{tools.get('summary', {}).get('satisfied', 0)} satisfechas · "
          f"{tools.get('summary', {}).get('required_missing', 0)} requeridas ausentes · "
          f"{tools.get('summary', {}).get('recommended_missing', 0)} recomendadas ausentes", ""]
    if blockers:
        L += [f"**Bloquean:** {', '.join(blockers)}", ""]
    for t in (tools.get("tools") or []):
        if not t["present"] and t["need"] in ("REQUIRED", "RECOMMENDED"):
            L.append(f"- `{t['name']}` ({t['need']}) — {'; '.join(t['reasons'])}. "
                     f"→ {t['install_hint']}")
    L.append("")

    L += ["## Quién hará cada cosa", "",
          "El runtime de cada rol se elige **por capacidad**, no por nombre. "
          "Entre los que cumplen, gana el que deja menos restricciones sin aplicar.", "",
          "| Rol | Fase | Runtime | Estado | Revisión humana |", "|---|---|---|---|---|"]
    roles_doc = (ctx.parts.get("roles") or {}).get("roles", {})
    for rid, d in sorted((routing.get("decisions") or {}).items()):
        role = roles_doc.get(rid, {})
        L.append(f"| {rid} | {role.get('phase','')} | {d['chosen'] or '—'} | "
                 f"`{d['status']}` | {d['human_review'] or '—'} |")

    if routing.get("blocked_roles"):
        L += ["", f"**Roles bloqueados:** {', '.join(routing['blocked_roles'])}"]
    if routing.get("degraded_roles"):
        L += ["", f"**Roles degradados** (alguna restricción no se aplica): "
                  f"{', '.join(routing['degraded_roles'])}"]

    L += ["", "## Lo que refuto NO sabe", ""]
    unknown = []
    if core["resolved"] != "AUTO":
        unknown.append("cuál es el núcleo SDD: hay ambigüedad y hace falta decidir")
    if repo["resolved"] != "AUTO":
        unknown.append("cuál es el repositorio de trabajo")
    if not core.get("integrity"):
        unknown.append("si el núcleo está íntegro")
    blocked_caps = [k for k, v in (caps.get("capabilities") or {}).items()
                    if v.get("state") == "BLOCKED"]
    if blocked_caps:
        unknown.append(f"nada sobre {', '.join(sorted({c.split('.')[0] for c in blocked_caps}))} "
                       f"en los runtimes bloqueados")
    L += [f"- {u}" for u in unknown] or ["- nada relevante: todo lo necesario está resuelto"]
    L.append("")
    return "\n".join(L)
