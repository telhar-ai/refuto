# -*- coding: utf-8 -*-
"""Adapter de Claude Code. Verificado contra 2.1.247 el 2026-08-27.

Claude Code **no** expone ACP en su CLI (comprobado en `claude --help`, 2.1.247). Su handshake
estructurado equivalente es el primer evento del flujo `--print --output-format stream-json`:
un `system/init` que declara versión, modelo, modo de permisos, servidores MCP, herramientas,
agentes y comandos. Ese evento es el handshake, y se puede obtener con una tarea trivial.

Para NO gastar créditos en el peldaño FUNCTIONAL se usa `--tools ""` (sin herramientas) con un
prompt de una palabra: el flujo emite `system/init` completo antes de llamar al modelo.
"""

from __future__ import annotations

import json
import subprocess
from pathlib import Path

from adapters.base import AgentSpec
from core.digest import excerpt
from core.proc import TEXT_IO, spawn_kwargs
from core.wire import CLAUDE_MATCHER

_PERMISSION_MODES = ("acceptEdits", "auto", "bypassPermissions", "manual", "dontAsk", "plan")


class ClaudeAdapter(AgentSpec):
    def native_handshake(self, path: str, workspace: Path | None) -> dict:
        """Arranca un flujo `stream-json` y lee sólo `system/init`. Sin herramientas.

        Se corta en cuanto llega el primer evento: no se deja terminar el turno, así que el
        coste es el de abrir la sesión, no el de resolverla.
        """
        import os
        import threading

        argv = [path, "-p", "hi", "--output-format", "stream-json", "--verbose",
                "--tools", "", "--permission-mode", "plan", "--max-budget-usd", "0.05"]
        env = dict(os.environ)
        env.setdefault("CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC", "1")
        try:
            proc = subprocess.Popen(argv, cwd=str(workspace) if workspace else None, env=env,
                                    **TEXT_IO, bufsize=1, stdin=subprocess.DEVNULL,
                                    stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                    **spawn_kwargs())
        except (OSError, ValueError) as exc:
            return {"ok": False, "family": "claude-stream-json",
                    "detail": f"no se pudo lanzar: {exc}"}

        box: dict = {"init": None, "err": []}

        def read_out():
            try:
                for line in proc.stdout:                    # type: ignore[union-attr]
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        ev = json.loads(line)
                    except json.JSONDecodeError:
                        continue
                    if ev.get("type") == "system" and ev.get("subtype") == "init":
                        box["init"] = ev
                        return
            except (OSError, ValueError):
                pass

        def read_err():
            try:
                for line in proc.stderr:                    # type: ignore[union-attr]
                    if len(box["err"]) < 200:
                        box["err"].append(line)
            except (OSError, ValueError):
                pass

        t_o = threading.Thread(target=read_out, daemon=True)
        t_e = threading.Thread(target=read_err, daemon=True)
        t_o.start(); t_e.start()
        t_o.join(self.timeout)
        from core.acp import terminate
        terminate(proc)
        t_e.join(1.0)

        init = box["init"]
        if not init:
            return {"ok": False, "family": "claude-stream-json",
                    "detail": f"sin evento system/init en {self.timeout:g} s · "
                              f"stderr: {excerpt(''.join(box['err']), 200)}"}
        caps = {
            "tools": init.get("tools", []),
            "mcp_servers": [s.get("name") for s in (init.get("mcp_servers") or [])],
            "agents": init.get("agents", []),
            "slash_commands_count": len(init.get("slash_commands") or []),
            "plugins": [p if isinstance(p, str) else p.get("name") for p in (init.get("plugins") or [])],
            "permission_mode": init.get("permissionMode"),
            "model": init.get("model"),
            "protocol_capabilities": init.get("capabilities", []),
        }
        return {"ok": True, "family": "claude-stream-json",
                "version": init.get("claude_code_version"),
                "detail": f"system/init recibido · modelo {init.get('model')} · "
                          f"{len(caps['tools'])} herramientas · "
                          f"{len(caps['mcp_servers'])} servidores MCP",
                "capabilities": caps}

    def verify_task(self, path: str, workspace: Path | None) -> dict:
        """Tarea mínima real: leer un archivo del workspace y devolver un dato verificable.

        Se acota con `--max-budget-usd` y una sola herramienta. Si el resultado no contiene lo
        esperado, NO se marca verificado: una respuesta bonita no es una respuesta correcta.
        """
        import os
        import tempfile

        # La sonda NO escribe en el repositorio de nadie. La primera versión dejaba
        # `.harness-probe.txt` en el espacio de trabajo: ensuciaba el árbol, aparecía en
        # `git status`, y fallaba con «Permission denied» en cuanto el directorio no era
        # escribible. Se usa un directorio temporal propio, que se borra siempre.
        marker = "HARNESS-PROBE-OK"
        env = dict(os.environ)
        env.setdefault("CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC", "1")
        try:
            with tempfile.TemporaryDirectory(prefix="harness-probe-") as tmp:
                (Path(tmp) / "dato.txt").write_text(marker + "\n", encoding="utf-8", newline="\n")
                argv = [path, "-p",
                        "Lee el archivo dato.txt y responde EXACTAMENTE su contenido, "
                        "sin ninguna otra palabra.",
                        "--output-format", "json", "--tools", "Read",
                        "--permission-mode", "dontAsk", "--max-budget-usd", "0.25",
                        "--add-dir", tmp]
                proc = subprocess.run(argv, cwd=tmp, env=env, capture_output=True, **TEXT_IO,
                                      timeout=180, **spawn_kwargs())
        except (OSError, subprocess.SubprocessError) as exc:
            return {"ok": False, "detail": f"la tarea no se pudo ejecutar: {exc}"}

        try:
            payload = json.loads(proc.stdout or "{}")
        except json.JSONDecodeError:
            return {"ok": False, "detail": "la salida no era JSON",
                    "excerpt": excerpt(proc.stdout, 200)}
        answer = str(payload.get("result", ""))
        ok = marker in answer and not payload.get("is_error")
        return {"ok": ok,
                "detail": ("respuesta correcta y verificada contra el archivo"
                           if ok else f"respuesta inesperada: {excerpt(answer, 120)!r}"),
                "cost_usd": payload.get("total_cost_usd"),
                "duration_ms": payload.get("duration_ms")}

    def compile_policy(self, policy) -> dict:
        """Claude expresa política en `.claude/settings.json` (`permissions.allow/ask/deny`) y
        en `hooks.PreToolUse`. Las dos se generan de la política canónica.
        """
        deny = [f"Read({p})" for p in policy.secret_read_deny]
        deny += [f"Bash({c})" for c in policy.command_deny]
        ask = [f"Bash({c})" for c in policy.command_ask]
        guard = "python3 -m core.guard --runtime claude --stdin"
        settings = {
            "$schema": "https://json.schemastore.org/claude-code-settings.json",
            "_generado": "refuto policy compile — no editar; se sobrescribe",
            "permissions": {
                "defaultMode": policy.default_mode_for("claude"),
                "deny": sorted(set(deny)),
                "ask": sorted(set(ask)),
            },
            "hooks": {
                "PreToolUse": [{
                    "matcher": CLAUDE_MATCHER,
                    "hooks": [{"type": "command", "command": guard, "timeout": 30}],
                }],
            },
        }
        return {
            "supported": True,
            "artifacts": {".claude/settings.harness.json":
                          json.dumps(settings, ensure_ascii=False, indent=2) + "\n"},
            "unenforceable": [],
            "notes": ["Claude aplica deny sobre patrones de ruta y de orden; el gancho cubre "
                      "el contenido, que el patrón no ve."],
        }

    def run_argv(self, *, prompt_file: Path, allow_tools: list, effort: str,
                 headless: bool = True, resume: bool = False,
                 require_mcp: bool = False, budget_usd: float | None = None) -> list:
        argv = [self.binary, "--effort", effort]
        if headless:
            argv += ["-p", "--output-format", "stream-json", "--verbose"]
        if allow_tools:
            argv += ["--tools", ",".join(allow_tools)]
        if resume:
            argv += ["--continue"]
        if require_mcp:
            argv += ["--strict-mcp-config"]
        if budget_usd is not None:
            argv += ["--max-budget-usd", str(budget_usd)]
        return argv

    def normalize_event(self, raw: dict) -> dict | None:
        kind = raw.get("type")
        if kind == "system" and raw.get("subtype") == "init":
            return {"source": "claude", "family": "claude-stream-json", "kind": "session/start",
                    "payload": {"model": raw.get("model"), "tools": raw.get("tools"),
                                "version": raw.get("claude_code_version")}}
        if kind == "assistant":
            for block in (raw.get("message") or {}).get("content", []):
                if block.get("type") == "tool_use":
                    return {"source": "claude", "family": "claude-stream-json",
                            "kind": "tool/call",
                            "payload": {"tool": block.get("name"), "id": block.get("id")}}
            return None
        if kind == "result":
            return {"source": "claude", "family": "claude-stream-json", "kind": "session/end",
                    "payload": {"is_error": raw.get("is_error"),
                                "stop_reason": raw.get("stop_reason"),
                                "cost_usd": raw.get("total_cost_usd"),
                                "duration_ms": raw.get("duration_ms"),
                                "turns": raw.get("num_turns"),
                                "permission_denials": raw.get("permission_denials")}}
        return None


SPEC = ClaudeAdapter(
    name="claude",
    binary="claude",
    version_args=("--version",),
    start_args=("--help",),
    speaks_acp=False,
    timeout=90.0,
    workspace_config=(".claude/settings.json", ".claude/settings.local.json", ".claude/agents",
                      ".claude/skills", ".claude/hooks", ".claude/commands", ".mcp.json",
                      "CLAUDE.md"),
    home_config=("~/.claude/settings.json", "~/.claude/agents", "~/.claude/skills",
                 "~/.claude/CLAUDE.md"),
    native_extensions={
        "budget_usd": {"flag": "--max-budget-usd", "evidence": "E",
                       "note": "control de coste por ejecución; ningún otro agente lo tiene"},
        "structured_output_schema": {"flag": "--json-schema", "evidence": "D"},
        "strict_mcp_config": {"flag": "--strict-mcp-config", "evidence": "D"},
        "safe_mode": {"flag": "--safe-mode", "evidence": "D",
                      "note": "desactiva TODA personalización; útil para aislar un fallo"},
        "worktree": {"flag": "--worktree", "evidence": "D"},
        "import_from": {"command": "claude import codex|gemini", "evidence": "D"},
        "hook_events_in_stream": {"flag": "--include-hook-events", "evidence": "D"},
    },
    declared={"acp": {"supported": False, "evidence": "D",
                      "note": "no aparece en claude --help 2.1.247"}},
)
