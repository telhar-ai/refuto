# -*- coding: utf-8 -*-
"""Inventario mecánico del conjunto de repositorios. Legible por máquina, y por eso comparable
entre corridas.

Lo que busca, y por qué cada cosa
---------------------------------
    agentes / skills / hooks / comandos   qué hay, y cuántas copias del mismo nombre
    duplicados con huella distinta        la deriva medida, no supuesta   (H-07)
    rutas absolutas en configuración      lo que rompe al mover el espacio (H-05)
    rutas rotas                           lo que ya está roto y nadie ve   (H-04)
    fuentes de verdad múltiples           el mismo nombre en dos sitios

Una carpeta con 113 archivos de agente para 70 nombres no es un problema hasta que se cuenta.
Contarlo es la mitad del trabajo.
"""

from __future__ import annotations

import json
import os
import re
from collections import defaultdict
from pathlib import Path

from core.digest import sha256_file

SKIP_DIRS = {".git", "node_modules", "__pycache__", ".venv", "venv", "dist", "build",
             ".next", "target", ".nucleo", ".DS_Store"}

#: Cada patrón es una forma conocida de que una configuración deje de funcionar al moverla.
ABS_PATH = re.compile(r'"(?:/Users/|/home/|/Volumes/|[A-Za-z]:\\\\)[^"]{3,}"')


def _walk_configs(root: Path, depth: int):
    """Localiza los directorios de configuración de agente hasta `depth` niveles."""
    found = []
    root = root.resolve()
    base_depth = len(root.parts)
    for dirpath, dirnames, _ in os.walk(root):
        here = Path(dirpath)
        if len(here.parts) - base_depth > depth:
            dirnames[:] = []
            continue
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
        for marker in (".claude", ".kiro", ".gemini", ".codex", ".opencode"):
            if marker in dirnames:
                found.append(here / marker)
    return found


def _frontmatter_name(path: Path) -> str:
    try:
        head = path.read_text(encoding="utf-8", errors="ignore")[:800]
    except OSError:
        return ""
    m = re.search(r"^name:\s*(.+)$", head, re.M)
    return m.group(1).strip() if m else ""


def build(root: Path, *, depth: int = 3) -> dict:
    root = root.resolve()
    workspaces: list = []
    names: dict = {"agent": defaultdict(list), "skill": defaultdict(list)}
    absolute_paths: list = []
    broken_refs: list = []

    for cfg in sorted(_walk_configs(root, depth)):
        ws = cfg.parent
        runtime = cfg.name.lstrip(".")
        entry = {
            "workspace": str(ws.relative_to(root)) if ws != root else ".",
            "runtime": runtime,
            "config_dir": str(cfg.relative_to(root)),
            "agents": [], "skills": [], "hooks": [], "commands": [], "mcp_servers": [],
        }

        for pattern, kind in ((("agents/*.md", "agents/*.json"), "agent"),
                              (("skills/*/SKILL.md", "skills/*/*/SKILL.md"), "skill")):
            for glob in pattern:
                for path in sorted(cfg.glob(glob)):
                    declared = _frontmatter_name(path) if path.suffix == ".md" else _json_name(path)
                    ident = declared or (path.parent.name if kind == "skill" else path.stem)
                    rec = {"id": ident, "declared_name": declared,
                           "path": str(path.relative_to(root)),
                           "sha256": sha256_file(path)[:16]}
                    entry[kind + "s"].append(rec)
                    names[kind][ident].append(rec)

        for glob in ("hooks/*", "hooks/*.json"):
            for path in sorted(cfg.glob(glob)):
                if path.is_file():
                    entry["hooks"].append(str(path.relative_to(root)))
        entry["hooks"] = sorted(set(entry["hooks"]))
        for path in sorted(cfg.glob("commands/*.md")):
            entry["commands"].append(str(path.relative_to(root)))

        for mcp in list(cfg.glob("settings/mcp.json")) + list(cfg.glob("mcp.json")) + \
                   [ws / ".mcp.json"]:
            if not mcp.is_file():
                continue
            try:
                doc = json.loads(mcp.read_text(encoding="utf-8"))
            except (OSError, ValueError):
                broken_refs.append({"path": str(mcp.relative_to(root)),
                                    "problem": "JSON ilegible"})
                continue
            for name in (doc.get("mcpServers") or {}):
                entry["mcp_servers"].append({"name": name,
                                             "source": str(mcp.relative_to(root))})

        # Rutas absolutas y rutas rotas en la configuración.
        for path in sorted(cfg.rglob("*.json")):
            if not path.is_file() or path.stat().st_size > 512_000:
                continue
            try:
                text = path.read_text(encoding="utf-8", errors="ignore")
            except OSError:
                continue
            for hit in ABS_PATH.findall(text):
                target = hit.strip('"')
                exists = Path(target.split("://")[-1]).exists()
                absolute_paths.append({"path": str(path.relative_to(root)),
                                       "value": target[:160], "target_exists": exists})
                if not exists:
                    broken_refs.append({"path": str(path.relative_to(root)),
                                        "problem": f"ruta absoluta rota: {target[:120]}"})
        workspaces.append(entry)

    duplicates = {}
    for kind in ("agent", "skill"):
        dupes = {}
        for ident, recs in names[kind].items():
            if len(recs) < 2:
                continue
            digests = {r["sha256"] for r in recs}
            dupes[ident] = {
                "copies": len(recs),
                "distinct_contents": len(digests),
                "drifted": len(digests) > 1,
                "where": [r["path"] for r in recs],
            }
        duplicates[kind] = dict(sorted(dupes.items(), key=lambda kv: -kv[1]["copies"]))

    totals = {
        "workspaces": len(workspaces),
        "agent_files": sum(len(w["agents"]) for w in workspaces),
        "agent_names": len(names["agent"]),
        "skill_files": sum(len(w["skills"]) for w in workspaces),
        "skill_names": len(names["skill"]),
        "hook_files": sum(len(w["hooks"]) for w in workspaces),
        "command_files": sum(len(w["commands"]) for w in workspaces),
        "mcp_declarations": sum(len(w["mcp_servers"]) for w in workspaces),
        "duplicated_agents": len(duplicates["agent"]),
        "drifted_agents": sum(1 for v in duplicates["agent"].values() if v["drifted"]),
        "duplicated_skills": len(duplicates["skill"]),
        "drifted_skills": sum(1 for v in duplicates["skill"].values() if v["drifted"]),
        "absolute_paths": len(absolute_paths),
        "broken_refs": len(broken_refs),
    }
    from core.model import provenance
    return {
        "schema": "harness.inventory/v1",
        "root": str(root),
        "provenance": provenance(root),
        "totals": totals,
        "workspaces": workspaces,
        "duplicates": duplicates,
        "absolute_paths": absolute_paths[:200],
        "broken_refs": broken_refs[:200],
    }


def _json_name(path: Path) -> str:
    try:
        return str(json.loads(path.read_text(encoding="utf-8")).get("name", ""))
    except (OSError, ValueError):
        return ""


def render_text(inv: dict, *, markdown: bool = False) -> str:
    t = inv["totals"]
    b = (lambda s: f"**{s}**") if markdown else (lambda s: s)
    lines = []
    if markdown:
        lines += ["# Inventario del conjunto de repositorios", "",
                  f"Raíz: `{inv['root']}` · generado {inv['provenance']['generated_at']}", ""]
    lines.append(f"\n  {b('Totales')}")
    for key in ("workspaces", "agent_files", "agent_names", "skill_files", "skill_names",
                "hook_files", "command_files", "mcp_declarations",
                "duplicated_agents", "drifted_agents", "duplicated_skills", "drifted_skills",
                "absolute_paths", "broken_refs"):
        lines.append(f"    {key:<20} {t[key]}")
    if t["agent_files"] and t["agent_files"] != t["agent_names"]:
        lines.append(f"\n    {t['agent_files']} archivos de agente para {t['agent_names']} "
                     f"nombres distintos: {t['agent_files'] - t['agent_names']} copias.")
    lines.append(f"\n  {b('Duplicados con contenido divergente')}")
    any_drift = False
    for kind in ("agent", "skill"):
        for ident, info in inv["duplicates"][kind].items():
            if not info["drifted"]:
                continue
            any_drift = True
            lines.append(f"    {kind:6} {ident:<26} {info['copies']} copias · "
                         f"{info['distinct_contents']} contenidos distintos")
    if not any_drift:
        lines.append("    ninguno")
    if inv["broken_refs"]:
        lines.append(f"\n  {b('Referencias rotas')}")
        for r in inv["broken_refs"][:12]:
            lines.append(f"    {r['path']}: {r['problem']}")
    lines.append("")
    return "\n".join(lines)
