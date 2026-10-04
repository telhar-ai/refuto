# -*- coding: utf-8 -*-
"""Adapter de OpenAI Codex. Verificado contra `codex-cli 0.151.0` el 2026-08-30.

Historia de este archivo, porque explica su forma
--------------------------------------------------
La versión anterior devolvía `ok: False` **codificado a mano**, con el texto «el binario no
arranca en esta máquina (H-01)». Era cierto: `@openai/codex@0.103.0` tenía el certificado de
firma revocado y macOS le mandaba SIGKILL. Y su propio docstring dejó escrita la instrucción
para este momento:

    «Cuando se reinstale, la sonda subirá sola de peldaño y este docstring habrá que corregirlo
     con evidencia, no con optimismo.»

Se reinstaló (0.103.0 → 0.151.0, `Developer ID Application: OpenAI OpCo, LLC (2DC432GLL2)`,
`codesign --verify` → válido) y la sonda subió sola a `STARTABLE`. Pero la constante impedía
llegar a `FUNCTIONAL` para siempre: el adapter se negaba a intentarlo. **Una afirmación fija
donde debía haber una medida es el mismo defecto que refuto existe para no aceptar**, sólo
que en la dirección que sub-declara en vez de sobre-declarar.

El handshake, y por qué es gratis
----------------------------------
`codex mcp-server` arranca Codex como servidor MCP sobre stdio. Un `initialize` de MCP devuelve
un documento de capacidades **sin llamar a ningún modelo y sin gastar créditos**, igual que
`initialize` de ACP para quien lo habla. Medido:

    {"protocolVersion":"2026-07-28",
     "capabilities":{"tools":{"listChanged":true}},
     "serverInfo":{"name":"codex-mcp-server","version":"0.151.0"}}

**Distinción que no se debe borrar:** eso prueba que Codex **expone** MCP, no que lo
**consuma**. El lado cliente se mide aparte con `codex mcp list`, que existe y responde con
cero servidores configurados. Aplanar las dos cosas en una casilla «MCP: sí» diría algo falso.
"""

from __future__ import annotations

import json
import subprocess
import threading
from pathlib import Path

from adapters.base import AgentSpec, npm_package_version
from core.proc import TEXT_IO, spawn_kwargs, terminate

#: Versión de protocolo que se ofrece en el `initialize`. Coincide con la que declara el
#: manifiesto del espacio; si divergieran, el servidor lo diría en su respuesta.
MCP_PROTOCOL = "2026-07-28"


class CodexAdapter(AgentSpec):
    def native_handshake(self, path: str, workspace: Path | None) -> dict:
        """`initialize` de MCP sobre `codex mcp-server`. Sin créditos, sin modelo.

        Se lee UNA línea y se mata el proceso: el servidor responde el `initialize` antes de
        hacer nada más, así que esperar más sería pagar por información que ya está.
        """
        argv = [path, "mcp-server"]
        try:
            proc = subprocess.Popen(
                argv, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                bufsize=1, cwd=str(workspace) if workspace else None,
                **TEXT_IO, **spawn_kwargs())
        except (OSError, subprocess.SubprocessError) as exc:
            return {"ok": False, "family": "codex-mcp-server",
                    "detail": f"no se pudo lanzar `codex mcp-server`: {exc}"}

        peticion = {"jsonrpc": "2.0", "id": 1, "method": "initialize",
                    "params": {"protocolVersion": MCP_PROTOCOL, "capabilities": {},
                               "clientInfo": {"name": "harness-probe", "version": "0.2.0"}}}
        recogido: dict = {}

        def leer() -> None:
            try:
                recogido["linea"] = proc.stdout.readline()
            except (OSError, ValueError) as exc:
                recogido["error"] = str(exc)

        hilo = threading.Thread(target=leer, daemon=True)
        try:
            proc.stdin.write(json.dumps(peticion) + "\n")
            proc.stdin.flush()
            hilo.start()
            hilo.join(self.timeout)
        except (OSError, ValueError) as exc:
            return {"ok": False, "family": "codex-mcp-server",
                    "detail": f"el servidor no aceptó el initialize: {exc}"}
        finally:
            # El grupo entero, no sólo la raíz: `codex` es un lanzador de Node que puede dejar
            # vivo al binario nativo si sólo se mata al padre (core/proc.py:terminate).
            terminate(proc, grace=1.0)

        linea = (recogido.get("linea") or "").strip()
        if not linea:
            return {"ok": False, "family": "codex-mcp-server",
                    "detail": f"sin respuesta a initialize en {self.timeout:g} s"}
        try:
            doc = json.loads(linea)
        except ValueError:
            return {"ok": False, "family": "codex-mcp-server",
                    "detail": f"respuesta no es JSON-RPC: {linea[:120]}"}
        if "error" in doc:
            return {"ok": False, "family": "codex-mcp-server",
                    "detail": f"initialize devolvió error: {str(doc['error'])[:140]}"}

        r = doc.get("result") or {}
        info = r.get("serverInfo") or {}
        # `mcp_servers` es lo que `core.capability.from_probe` sabe leer para derivar
        # `agent.mcp`. Se rellena con el lado CLIENTE —lo que Codex consume—, no con el
        # servidor que él mismo expone, que sería contar el espejo como si fuera la sala.
        return {
            "ok": True,
            "family": "codex-mcp-server",
            "version": info.get("version", ""),
            "detail": f"initialize de MCP respondido · {info.get('name', 'codex')} "
                      f"{info.get('version', '?')} · protocolo {r.get('protocolVersion', '?')}",
            "capabilities": {
                "mcp_servers": _servidores_mcp_consumidos(path),
                "expone_mcp": r.get("capabilities", {}),
                "protocolVersion": r.get("protocolVersion", ""),
            },
        }

    def fallback_version(self, path: str) -> str:
        return npm_package_version(path)

    def compile_policy(self, policy) -> dict:
        """Codex expresa control en el sandbox de seatbelt y en la política de aprobación.

        Lo que SÍ aplica: `--sandbox` acota la escritura al espacio de trabajo, y
        `--ask-for-approval` obliga a confirmar antes de ejecutar una orden. Las dos se
        comprobaron en `codex --help --all` de 0.151.0.

        Lo que NO aplica, y se declara: Codex 0.151 **tiene** un sistema de ganchos —consta
        `--dangerously-bypass-hook-trust`, que sólo tiene sentido si hay ganchos con confianza
        persistida— pero **el formato de su configuración no está documentado en el CLI y no se
        ha verificado**. Mientras no se verifique, la guardia de contenido en Codex se considera
        NO aplicada. Declararla aplicada porque «probablemente hay hooks» sería exactamente el
        verde falso que refuto rechaza.
        """
        modo = "workspace-write" if policy.protected_paths else "read-only"
        doc = {
            "_generado": "refuto policy compile — no editar; se sobrescribe",
            "sandbox_mode": modo,
            "approval_policy": "on-request" if policy.command_ask else "never",
            "_ordenes_denegadas": list(policy.command_deny),
            "_nota": ("Codex no expresa una lista de denegación de órdenes: el control es el "
                      "sandbox más la aprobación. Las órdenes de `command_deny` se listan aquí "
                      "para el operador; NO las aplica el agente."),
        }
        unenforceable = [
            "guardia de contenido (secretos, datos personales) antes de escribir: Codex 0.151 "
            "tiene ganchos (consta --dangerously-bypass-hook-trust) pero el formato de su "
            "configuración NO está documentado ni verificado; mientras no se verifique, se "
            "considera NO aplicada",
            "protección por ruta DENTRO del espacio de trabajo: el sandbox `workspace-write` "
            "concede el espacio entero; no hay lista de rutas protegidas que compilar",
            f"denegación de órdenes ({len(policy.command_deny)} patrones): se cubre con "
            f"aprobación humana, no con una regla que el agente aplique solo",
        ]
        return {
            "supported": True,
            "artifacts": {
                ".codex/harness-policy.json":
                    json.dumps(doc, ensure_ascii=False, indent=2) + "\n",
            },
            "unenforceable": unenforceable,
            "notes": [
                "Se aplica en la invocación (`--sandbox`, `--ask-for-approval`), no en un "
                "archivo que el agente lea: es lo que el CLI de 0.151.0 admite de verdad.",
                "La capa que Codex NO puede saltarse sigue siendo la rama protegida y el CI.",
            ],
        }

    def run_argv(self, *, prompt_file: Path, allow_tools: list, effort: str,
                 stream: bool = True, resume: bool = False, budget_usd=None,
                 strict_mcp: bool = False, schema: Path | None = None) -> list:
        """`codex exec` es la superficie no interactiva. `--json` emite JSONL de eventos."""
        argv = [self.binary, "exec", "--sandbox", "workspace-write",
                "--ask-for-approval", "on-request"]
        if stream:
            argv += ["--json"]
        if schema is not None:
            argv += ["--output-schema", str(schema)]
        if resume:
            argv += ["resume", "--last"]
        return argv

    def normalize_event(self, raw: dict) -> dict | None:
        """Los eventos de `codex exec --json` entran al diario con el vocabulario común."""
        tipo = raw.get("type") or raw.get("msg", {}).get("type") or ""
        if not tipo:
            return None
        familia = {
            "session.created": "session/start",
            "task_started": "task/start",
            "agent_message": "message",
            "exec_command_begin": "tool/start",
            "exec_command_end": "tool/end",
            "task_complete": "task/end",
            "error": "error",
        }.get(tipo, "otro")
        return {"source": "codex", "family": "codex-exec-json", "kind": familia, "raw_type": tipo}


def _servidores_mcp_consumidos(path: str) -> list:
    """Qué servidores MCP consume Codex. Distinto de los que expone.

    Un fallo aquí NO invalida el handshake: devuelve lista vacía y la casilla lo dirá. Confundir
    «no pude preguntarlo» con «no hay ninguno» es el error que esta función existe para no
    cometer, así que ante un fallo se devuelve vacío y el detalle lo aporta la propia sonda.
    """
    try:
        p = subprocess.run([path, "mcp", "list", "--json"], capture_output=True, timeout=20,
                           **TEXT_IO)
        if p.returncode == 0 and p.stdout.strip().startswith(("[", "{")):
            d = json.loads(p.stdout)
            return d if isinstance(d, list) else list(d.get("servers") or [])
        p = subprocess.run([path, "mcp", "list"], capture_output=True, timeout=20, **TEXT_IO)
        if p.returncode == 0 and "No MCP servers configured" in (p.stdout + p.stderr):
            return []
    except (OSError, ValueError, subprocess.SubprocessError):
        return []
    return []


SPEC = CodexAdapter(
    name="codex",
    binary="codex",
    version_args=("--version",),
    start_args=("--help",),
    speaks_acp=False,
    timeout=25.0,
    workspace_config=("AGENTS.md",),
    home_config=("~/.codex/config.toml", "~/.codex/auth.json"),
    native_extensions={
        "sandbox": {"flag": "--sandbox (seatbelt) · `codex sandbox` ejecuta órdenes acotadas",
                    "verificado": "codex sandbox --help, 0.151.0"},
        "structured_output_schema": {
            "flag": "--output-schema <FILE>",
            "note": "esquema JSON para la respuesta final; verificado en `codex exec --help`"},
        "approval_policy": {"flag": "--ask-for-approval <on-request|never|…>"},
        "mcp_server_mode": {"flag": "codex mcp-server",
                            "note": "expone Codex como servidor MCP sobre stdio"},
    },
    declared={
        "acp": {"supported": False, "evidence": "D",
                "note": "no aparece en `codex --help` 0.151.0; habla MCP, no ACP"},
        "budget_usd": {"supported": False, "evidence": "D",
                       "note": "no hay bandera de presupuesto en 0.151.0"},
        "skill_md": {"supported": None, "evidence": "?",
                     "note": "no verificado en esta máquina en 0.151.0"},
    },
)
