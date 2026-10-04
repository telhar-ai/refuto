# -*- coding: utf-8 -*-
"""Adapter de Gemini CLI. Verificado contra 0.55.1 el 2026-08-27.

Habla ACP (`gemini --acp`, handshake comprobado). Tres particularidades que NO deben aplanarse:

1. **Confianza de carpeta.** Gemini se niega a cargar agentes y hooks del proyecto si el
   directorio no está confiado — comprobado: «Skipping project agents due to untrusted
   folder». Ni Kiro ni Claude imponen esto igual. Es una propiedad de seguridad, no un detalle
   de configuración, y refuto la reporta en vez de sortearla.
2. **Policy Engine propio** (`--policy`, `--admin-policy`), con `--allowed-tools` ya marcado
   DEPRECATED en el propio `--help`. Es el único de los cinco con política administrativa
   separada de la del usuario.
3. **`gemini hooks migrate`** importa hooks de Claude Code — evidencia de convergencia del
   ecosistema hacia los formatos de Claude.
"""

from __future__ import annotations

import json
from pathlib import Path

from adapters.base import AgentSpec


class GeminiAdapter(AgentSpec):
    def compile_policy(self, policy) -> dict:
        """Se compila al Policy Engine de Gemini. `--allowed-tools` está deprecado y no se usa."""
        rules = []
        for pattern in policy.command_deny:
            rules.append({"toolName": "run_shell_command", "argsPattern": pattern,
                          "decision": "deny"})
        for pattern in policy.command_ask:
            rules.append({"toolName": "run_shell_command", "argsPattern": pattern,
                          "decision": "ask_user"})
        doc = {
            "_generado": "refuto policy compile — no editar; se sobrescribe",
            "rules": rules,
            "defaultDecision": "ask_user",
        }
        unenforceable = [
            "guardia de contenido (secretos, datos personales) sobre la escritura: el Policy "
            "Engine decide por herramienta y patrón de argumentos, no por el contenido escrito; "
            "esa parte se cubre con hooks de Gemini, que se generan aparte",
        ]
        guard = "python3 -m core.guard --runtime gemini --stdin"
        hooks = {
            "_generado": "refuto policy compile — no editar; se sobrescribe",
            "hooks": [{"event": "PreToolUse", "matcher": "write_file|replace|edit",
                       "command": guard, "timeout": 30}],
        }
        return {
            "supported": True,
            "artifacts": {
                ".gemini/policies/harness.json": json.dumps(doc, ensure_ascii=False, indent=2) + "\n",
                ".gemini/hooks/harness-guard.json": json.dumps(hooks, ensure_ascii=False, indent=2) + "\n",
            },
            "unenforceable": unenforceable,
            "notes": ["Requiere que la carpeta esté confiada; si no, Gemini ignora hooks y "
                      "agentes del proyecto y la política NO se aplica. Refuto lo comprueba."],
        }

    def run_argv(self, *, prompt_file: Path, allow_tools: list, effort: str,
                 headless: bool = True, resume: bool = False,
                 require_mcp: bool = False, budget_usd: float | None = None) -> list:
        argv = [self.binary]
        if headless:
            argv += ["-p", "-o", "stream-json"]
        argv += ["--approval-mode", "default"]
        argv += ["--policy", ".gemini/policies/harness.json"]
        if resume:
            argv += ["--resume", "latest"]
        return argv

    def normalize_event(self, raw: dict) -> dict | None:
        method = raw.get("method") or raw.get("type") or ""
        return {"source": "gemini", "family": "acp", "kind": method, "payload": raw} if method else None


SPEC = GeminiAdapter(
    name="gemini",
    binary="gemini",
    version_args=("--version",),
    start_args=("--help",),
    speaks_acp=True,
    acp_args=("--acp",),
    workspace_config=(".gemini/settings.json", ".gemini/policies", ".gemini/hooks",
                      "GEMINI.md", ".gemini/skills"),
    home_config=("~/.gemini/settings.json", "~/.gemini/trustedFolders.json"),
    native_extensions={
        "policy_engine": {"flags": ["--policy", "--admin-policy"], "evidence": "D",
                          "note": "único con política administrativa separada de la del usuario"},
        "folder_trust": {"where": "~/.gemini/trustedFolders.json", "evidence": "E",
                         "note": "sin confianza, agentes y hooks del proyecto NO se cargan"},
        "skills_from_git": {"command": "gemini skills install <git-url>", "evidence": "D"},
        "extensions": {"command": "gemini extensions install|link|validate", "evidence": "D"},
        "hooks_migrate": {"command": "gemini hooks migrate", "evidence": "D",
                          "note": "importa hooks de Claude Code"},
        "sandbox": {"flag": "--sandbox", "evidence": "D"},
        "acp_server": {"command": "gemini --acp", "evidence": "E"},
    },
    declared={"budget_usd": {"supported": False, "evidence": "D"}},
)
