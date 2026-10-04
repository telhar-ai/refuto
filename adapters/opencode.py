# -*- coding: utf-8 -*-
"""Adapter de OpenCode. Verificado contra 1.2.27 el 2026-08-27.

Habla ACP (`opencode acp`, handshake comprobado) y es el único de los cinco con **servidor
persistente y API HTTP** (`opencode serve`), lo que lo hace el candidato natural para
ejecución orquestada desde fuera del proceso. También exporta e importa sesiones como JSON
(`opencode export|import`), que es una capacidad de evidencia que ningún otro ofrece.
"""

from __future__ import annotations

import json
from pathlib import Path

from adapters.base import AgentSpec


class OpenCodeAdapter(AgentSpec):
    def compile_policy(self, policy) -> dict:
        """OpenCode configura permisos en `opencode.json`. La cobertura exacta de patrones no
        se pudo verificar en esta máquina, así que se genera el artefacto y se declara
        explícitamente qué NO consta comprobado. No se afirma aplicación sin evidencia.
        """
        doc = {
            "$schema": "https://opencode.ai/config.json",
            "_generado": "refuto policy compile — no editar; se sobrescribe",
            "permission": {
                "bash": {p: "deny" for p in policy.command_deny}
                        | {p: "ask" for p in policy.command_ask},
                "edit": "ask",
            },
        }
        return {
            "supported": True,
            "artifacts": {"opencode.harness.json":
                          json.dumps(doc, ensure_ascii=False, indent=2) + "\n"},
            "unenforceable": [
                "guardia de contenido antes de escribir: no consta un mecanismo de hook "
                "PreToolUse en 1.2.27 (NO VERIFICADO); mientras no se verifique, la política de "
                "contenido en OpenCode se considera NO aplicada",
            ],
            "notes": ["El artefacto se genera aparte de `opencode.json` para no pisar "
                      "configuración escrita a mano; hay que fusionarlo a conciencia."],
        }

    def run_argv(self, *, prompt_file: Path, allow_tools: list, effort: str,
                 headless: bool = True, resume: bool = False,
                 require_mcp: bool = False, budget_usd: float | None = None) -> list:
        argv = [self.binary, "run"]
        if resume:
            argv += ["--continue"]
        return argv

    def normalize_event(self, raw: dict) -> dict | None:
        method = raw.get("method") or raw.get("type") or ""
        return {"source": "opencode", "family": "acp", "kind": method, "payload": raw} if method else None


SPEC = OpenCodeAdapter(
    name="opencode",
    binary="opencode",
    version_args=("--version",),
    start_args=("--help",),
    speaks_acp=True,
    acp_args=("acp",),
    workspace_config=("opencode.json", "AGENTS.md", ".opencode"),
    home_config=("~/.config/opencode", "~/.local/share/opencode"),
    native_extensions={
        "http_server": {"command": "opencode serve", "evidence": "D",
                        "note": "único con API HTTP persistente; permite orquestar sin CLI"},
        "session_export": {"command": "opencode export|import", "evidence": "D",
                           "note": "sesión como JSON: evidencia portátil"},
        "cost_stats": {"command": "opencode stats", "evidence": "D"},
        "github_agent": {"command": "opencode github", "evidence": "D"},
        "acp_server": {"command": "opencode acp", "evidence": "E"},
    },
    declared={"skill_md": {"supported": None, "evidence": "?",
                           "note": "no verificado en esta máquina"}},
)
