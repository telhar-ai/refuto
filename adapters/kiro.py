# -*- coding: utf-8 -*-
"""Adapter de Kiro CLI. Verificado contra kiro-cli 2.20.0 el 2026-08-27.

Kiro habla ACP (`kiro-cli acp`) y su `--output-format stream-json` está documentado en el
propio `--help` como «the run's ACP events as JSON Lines». Es el agente cuyo modelo de fases
originó refuto, y el que más capacidades declarativas tiene: `allowedTools` por agente,
`--require-mcp-startup` con código de salida 3, y `knowledgeBase` indexada.
"""

from __future__ import annotations

import json
from pathlib import Path

from adapters.base import AgentSpec

#: Rutas que el propio agente protege. Vocabulario de herramienta de Kiro CLI (motor v2).
KIRO_WRITE_TOOLS = ("fs_write",)


class KiroAdapter(AgentSpec):
    def compile_policy(self, policy) -> dict:
        """Kiro expresa permiso en `allowedTools`/`excludedTools` del agente, y guardias en
        `hooks.preToolUse`. Se compila a un gancho único que invoca al guardián canónico.

        H-03 se resuelve aquí: la guardia deja de escribirse a mano en dos vocabularios
        (`.kiro/hooks/*.json` para el IDE, `hooks{}` del agente para el CLI) y pasa a
        generarse de una sola fuente para los dos.
        """
        guard = "python3 -m core.guard --runtime kiro --stdin"
        cli_hook = {
            "preToolUse": [{"matcher": "|".join(KIRO_WRITE_TOOLS), "command": guard}],
        }
        ide_hook = {
            "version": "v1",
            "_generado": "refuto policy compile — no editar; se sobrescribe",
            "hooks": [{
                "name": "harness-guard",
                "trigger": "PreToolUse",
                "matcher": "(fsWrite|fsReplace|strReplace|fsAppend)",
                "action": {"type": "command", "command": guard},
                "timeout": 30, "enabled": True, "confirm": False,
            }],
        }
        unenforceable = []
        if policy.network_rules:
            unenforceable.append(
                "reglas de red: Kiro CLI 2.20.0 no expone allowlist de dominios; se controla "
                "por el servidor MCP, no por el agente")
        return {
            "supported": True,
            "artifacts": {
                ".kiro/hooks/harness-guard.json": json.dumps(ide_hook, ensure_ascii=False, indent=2) + "\n",
            },
            "agent_patch": {"hooks": cli_hook},
            "unenforceable": unenforceable,
            "notes": ["El permiso efectivo vive en `allowedTools` del agente; el gancho es el "
                      "control preventivo sobre rutas y contenido."],
        }

    def run_argv(self, *, prompt_file: Path, allow_tools: list, effort: str,
                 headless: bool = True, resume: bool = False,
                 require_mcp: bool = False, budget_usd: float | None = None) -> list:
        argv = [self.binary, "chat", "--agent-engine", "v2", "--effort", effort]
        if headless:
            argv += ["--no-interactive", "--output-format", "stream-json"]
        if resume:
            argv += ["--resume"]
        if require_mcp:
            argv += ["--require-mcp-startup"]
        # budget_usd no existe en Kiro 2.20.0: se ignora a propósito y el core lo sabe.
        return argv

    def normalize_event(self, raw: dict) -> dict | None:
        # El flujo de Kiro son eventos ACP; se pasan casi tal cual, etiquetados.
        method = raw.get("method") or raw.get("type") or ""
        if not method:
            return None
        return {"source": "kiro", "family": "acp", "kind": method, "payload": raw}


SPEC = KiroAdapter(
    name="kiro",
    binary="kiro-cli",
    version_args=("--version",),
    start_args=("--help",),
    speaks_acp=True,
    acp_args=("acp",),
    workspace_config=(".kiro/agents", ".kiro/settings/mcp.json", ".kiro/settings/cli.json",
                      ".kiro/hooks", ".kiro/skills", ".kiro/steering", ".kiro/specs"),
    home_config=("~/.kiro/agents", "~/.kiro/settings/cli.json"),
    native_extensions={
        "require_mcp_startup": {"flag": "--require-mcp-startup", "exit_code": 3,
                                "evidence": "D", "note": "sólo cubre servidores HABILITADOS; "
                                "un servidor no declarado no se comprueba (H-02)"},
        "agent_engine": {"flag": "--agent-engine", "values": ["v1", "v2", "v3"], "evidence": "D"},
        "knowledge_base": {"where": "agent.resources[].type=knowledgeBase", "evidence": "L"},
        "cloud_sandbox": {"flag": "--cloud", "note": "V3/KAS", "evidence": "D"},
        "acp_server": {"command": "kiro-cli acp", "evidence": "E"},
    },
    declared={
        "budget_usd": {"supported": False, "evidence": "D",
                       "note": "no hay bandera de presupuesto en 2.20.0"},
        "structured_output_schema": {"supported": False, "evidence": "D"},
    },
)
