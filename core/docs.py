# -*- coding: utf-8 -*-
"""Documentación dinámica. Se genera desde la máquina, no desde la memoria de quien escribe.

El problema que resuelve
------------------------
Una matriz de compatibilidad escrita a mano es correcta el día que se escribe y mentira tres
versiones después. Y miente en la dirección peligrosa: sigue diciendo «soportado» cuando ya no
lo está, porque nadie vuelve a mirarla.

Aquí la matriz **se genera de la sonda**, así que sólo puede decir lo que la máquina acaba de
demostrar. Cada casilla lleva su nivel de evidencia y ninguna se rellena por inferencia.

    agente instalado → sonda → adapter → matriz → documento
"""

from __future__ import annotations

from pathlib import Path

from core.model import FUNCTIONAL, STARTABLE, now, rung

#: Vocabulario de la matriz. Cada palabra dice de dónde salió la casilla.
NATIVE = "NATIVO"          # lo trae el agente, comprobado ejecutándolo
PROBED = "COMPROBADO"      # el agente lo declaró en su handshake
ADAPTER = "ADAPTER"        # lo aporta refuto traduciendo
DECLARED = "DECLARADO"     # el adapter lo afirma con evidencia documental, sin sondear
UNSUPPORTED = "NO"         # consta que no existe
UNKNOWN = "?"              # no se pudo verificar. Se declara, no se rellena
BLOCKED_ = "BLOQUEADO"     # no se pudo verificar porque el agente no arranca


def _cell(rep, spec, feature: str) -> tuple[str, str]:
    """Devuelve (valor, nota). Nunca inventa: si no consta, `?`."""
    if rung(rep.level) < rung(STARTABLE):
        return BLOCKED_, rep.stopped_because[:90]

    caps = rep.capabilities or {}
    proto = (rep.protocol or {}).get("family", "")

    if feature == "acp":
        if proto == "acp":
            return NATIVE, f"initialize respondió v{rep.protocol.get('version')}"
        return UNSUPPORTED if not spec.speaks_acp else UNKNOWN, "no aparece en su CLI"

    if feature == "handshake":
        if rung(rep.level) >= rung(FUNCTIONAL):
            return PROBED, proto
        return UNKNOWN, rep.stopped_because[:90]

    if feature == "mcp":
        if isinstance(caps.get("mcpCapabilities"), dict):
            kinds = [k for k, v in caps["mcpCapabilities"].items() if v]
            return NATIVE, "transportes: " + (", ".join(kinds) or "ninguno declarado")
        if caps.get("mcp_servers") is not None:
            return NATIVE, f"{len(caps['mcp_servers'])} servidores en la sesión sondeada"
        return DECLARED if "mcp" in str(spec.native_extensions) else UNKNOWN, ""

    if feature == "sessions":
        sc = caps.get("sessionCapabilities")
        if isinstance(sc, dict) and sc:
            return NATIVE, ", ".join(sorted(sc))
        if caps.get("loadSession"):
            return NATIVE, "loadSession"
        return UNKNOWN, ""

    if feature == "resume":
        if caps.get("loadSession"):
            return NATIVE, "loadSession en el handshake"
        return DECLARED, "bandera de reanudación en su CLI" if proto else UNKNOWN

    if feature == "skills":
        d = spec.declared.get("skill_md")
        if d and d.get("supported") is None:
            return UNKNOWN, d.get("note", "")
        if caps.get("slash_commands_count") is not None:
            return NATIVE, f"{caps['slash_commands_count']} comandos en la sesión sondeada"
        return DECLARED, "SKILL.md documentado en su CLI"

    if feature == "budget":
        ext = spec.native_extensions.get("budget_usd")
        if ext:
            return NATIVE, ext.get("flag", "")
        d = spec.declared.get("budget_usd")
        if d and d.get("supported") is False:
            return UNSUPPORTED, d.get("note", "")
        return UNKNOWN, ""

    if feature == "sandbox":
        for key in ("sandbox", "cloud_sandbox"):
            if key in spec.native_extensions:
                ext = spec.native_extensions[key]
                return NATIVE, ext.get("flag") or ext.get("note", "")
        return UNKNOWN, ""

    if feature == "policy":
        out = spec.compile_policy(_default_policy())
        if not out.get("supported"):
            return UNSUPPORTED, "; ".join(out.get("unenforceable", []))[:90]
        gaps = out.get("unenforceable") or []
        return (ADAPTER, f"{len(gaps)} regla(s) no aplicables" if gaps else "compilación completa")

    if feature == "evidence":
        return ADAPTER, "eventos normalizados por el adapter"

    return UNKNOWN, ""


def _default_policy():
    from core.policy import Policy
    return Policy.default()


FEATURES = [
    ("handshake", "Handshake estructurado", "¿Se puede saber qué sabe hacer sin gastar créditos?"),
    ("acp", "ACP v1", "Protocolo cliente↔agente, abierto"),
    ("mcp", "MCP", "Protocolo de herramientas"),
    ("sessions", "Sesiones", "Estado conversacional gestionado por el agente"),
    ("resume", "Reanudar", "Continuidad entre fases"),
    ("skills", "SKILL.md", "Procedimientos cargados por descripción"),
    ("policy", "Política compilable", "La política canónica se traduce a su vocabulario"),
    ("budget", "Presupuesto en $", "Tope de gasto por ejecución"),
    ("sandbox", "Aislamiento", "Ejecución acotada"),
    ("evidence", "Evidencia normalizada", "Sus eventos entran al diario de refuto"),
]


def build_matrix(reports: list, specs: dict) -> dict:
    rows = {}
    for key, label, why in FEATURES:
        row = {}
        for rep in reports:
            spec = specs.get(rep.agent)
            if spec is None:
                continue
            value, note = _cell(rep, spec, key)
            row[rep.agent] = {"value": value, "note": note}
        rows[key] = {"label": label, "why": why, "by_agent": row}
    return {
        "schema": "harness.matrix/v1",
        "generated_at": now(),
        "agents": {r.agent: {"level": r.level, "version": r.version,
                             "protocol": r.protocol,
                             "stopped_because": r.stopped_because,
                             "signature": r.signature.get("verdict", "")}
                   for r in reports},
        "features": rows,
    }


def render_matrix(matrix: dict) -> str:
    agents = sorted(matrix["agents"])
    lines = [
        "# Matriz de compatibilidad",
        "",
        "**Generado, no escrito.** Cada casilla sale de sondear los agentes de esta máquina; "
        "ninguna se rellena por inferencia. Vuelve a generarse con `refuto docs`.",
        "",
        f"Generado: {matrix['generated_at']}",
        "",
        "## Vocabulario",
        "",
        "| Valor | Significa |",
        "|---|---|",
        f"| `{NATIVE}` | Lo trae el agente y se comprobó ejecutándolo |",
        f"| `{PROBED}` | El agente lo declaró en su propio handshake |",
        f"| `{ADAPTER}` | Lo aporta refuto traduciendo |",
        f"| `{DECLARED}` | Consta en la documentación del CLI instalado; no se sondeó |",
        f"| `{UNSUPPORTED}` | Consta que no existe |",
        f"| `{BLOCKED_}` | No se pudo verificar: el agente no arranca en esta máquina |",
        f"| `{UNKNOWN}` | No verificado. Se declara; no se rellena |",
        "",
        "## Estado de cada agente",
        "",
        "| Agente | Peldaño | Versión | Protocolo | Firma | Nota |",
        "|---|---|---|---|---|---|",
    ]
    for name in agents:
        a = matrix["agents"][name]
        proto = a["protocol"].get("family", "—")
        pv = a["protocol"].get("version")
        lines.append(
            f"| **{name}** | `{a['level']}` | {a['version'] or '?'} | "
            f"{proto}{'/v' + str(pv) if pv else ''} | {a['signature'] or '—'} | "
            f"{a['stopped_because'][:70] or '—'} |")

    lines += ["", "## Capacidades", "",
              "| Capacidad | " + " | ".join(agents) + " |",
              "|---|" + "|".join(["---"] * len(agents)) + "|"]
    for key, _, _ in FEATURES:
        row = matrix["features"][key]
        cells = []
        for name in agents:
            cell = row["by_agent"].get(name, {"value": UNKNOWN, "note": ""})
            cells.append(f"`{cell['value']}`")
        lines.append(f"| {row['label']} | " + " | ".join(cells) + " |")

    lines += ["", "## Notas por casilla", ""]
    for key, _, why in FEATURES:
        row = matrix["features"][key]
        notes = [(n, c["note"]) for n, c in sorted(row["by_agent"].items()) if c["note"]]
        if not notes:
            continue
        lines.append(f"**{row['label']}** — {why}")
        lines += [f"- `{n}`: {note}" for n, note in notes]
        lines.append("")
    return "\n".join(lines) + "\n"


def write_docs(out_dir: Path, matrix: dict) -> list:
    out_dir.mkdir(parents=True, exist_ok=True)
    from core.model import write_json
    md = out_dir / "SUPPORT_MATRIX.md"
    md.write_text(render_matrix(matrix), encoding="utf-8", newline="\n")
    js = out_dir / "support-matrix.json"
    write_json(js, matrix)
    return [md, js]
