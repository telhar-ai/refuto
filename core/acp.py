# -*- coding: utf-8 -*-
"""Cliente mínimo de Agent Client Protocol (ACP) sobre stdio. Sólo biblioteca estándar.

Por qué ACP y no un protocolo propio
------------------------------------
Se comprobó por ejecución (2026-08-27) que kiro-cli 2.20.0, Gemini CLI 0.55.1 y OpenCode
1.2.27 responden `initialize` de ACP v1 sobre stdio y devuelven un documento estructurado de
capacidades — **sin gastar un crédito y sin llamar a ningún modelo**. Es descubrimiento de
capacidades declarado por el propio agente, no inferido por nosotros. Ver ADR-0001 y
`docs/research/acp.md`.

Dos lecciones que costaron un cuelgue cada una
----------------------------------------------
1. **Nunca `stderr.read()` sobre un proceso que puede seguir vivo.** Bloquea hasta EOF, y un
   agente ACP no cierra stderr mientras espera órdenes. Aquí stderr se drena desde el
   principio en su propio hilo, a un búfer acotado.
2. **Matar el proceso no basta: hay que matar el grupo.** Gemini y OpenCode son lanzadores de
   Node que crean hijos; el hijo hereda el descriptor y lo mantiene abierto aunque el padre ya
   esté muerto. Se lanza en su propio grupo (`core.proc.spawn_kwargs`) y se termina el grupo
   entero — que en Windows no es `setsid` ni `killpg`, y por eso la decisión no vive aquí.

Qué NO hace este módulo
-----------------------
No implementa ACP completo: implementa `initialize`, que es lo que hace falta para sondear.
Conducir una sesión (`session/new`, `session/prompt`) se hace hoy por el CLI nativo de cada
agente a través de su adapter. Ver riesgo residual RR-03 en `docs/remediation/hallazgos.md`.
"""

from __future__ import annotations

import json
import os
import subprocess
import threading
from dataclasses import dataclass, field

from core.proc import TEXT_IO, spawn_kwargs, terminate as _terminate_tree

#: Versión de ACP que este cliente habla. Entero, según la especificación (v1).
PROTOCOL_VERSION = 1

#: Capacidades que este cliente declara. `fs` y `terminal` van en falso a propósito: una sonda
#: que presta el sistema de archivos al agente ya no es una sonda, es una sesión.
PROBE_CLIENT_CAPABILITIES = {
    "fs": {"readTextFile": False, "writeTextFile": False},
    "terminal": False,
}

_STDERR_CAP = 64 * 1024


@dataclass
class AcpHandshake:
    ok: bool
    protocol_version: int | None = None
    agent_info: dict = field(default_factory=dict)
    agent_capabilities: dict = field(default_factory=dict)
    auth_methods: list = field(default_factory=list)
    error: str = ""
    stderr_excerpt: str = ""
    exit_signal: int | None = None
    raw: dict = field(default_factory=dict)


def initialize(argv: list[str], *, cwd: str | None = None, timeout: float = 15.0,
               env: dict | None = None) -> AcpHandshake:
    """Lanza `argv` como agente ACP y le pide `initialize`. No gasta créditos.

    Devuelve siempre un `AcpHandshake`; nunca lanza por culpa del agente. Un agente que se
    porta mal es un dato, no una excepción.
    """
    from core.digest import excerpt

    request = {
        "jsonrpc": "2.0", "id": 1, "method": "initialize",
        "params": {
            "protocolVersion": PROTOCOL_VERSION,
            "clientCapabilities": PROBE_CLIENT_CAPABILITIES,
            "clientInfo": {"name": "harness-probe", "version": "0.1.0"},
        },
    }
    full_env = dict(os.environ if env is None else env)
    # Una sonda no debe aparecer en el panel de uso de nadie como si fuera trabajo.
    full_env.setdefault("KIRO_TELEMETRY_OPT_OUT", "1")
    full_env.setdefault("CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC", "1")

    try:
        proc = subprocess.Popen(
            argv, cwd=cwd, env=full_env, bufsize=1,
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            **TEXT_IO, **spawn_kwargs(),
        )
    except FileNotFoundError:
        return AcpHandshake(False, error="ejecutable no encontrado")
    except (OSError, ValueError) as exc:
        return AcpHandshake(False, error=f"no se pudo lanzar: {exc}")

    box: dict = {"msg": None, "err": []}

    def read_stdout() -> None:
        try:
            for line in proc.stdout:                       # type: ignore[union-attr]
                line = line.strip()
                if not line:
                    continue
                try:
                    msg = json.loads(line)
                except json.JSONDecodeError:
                    continue                                # ruido de arranque, no error
                if msg.get("id") == 1:
                    box["msg"] = msg
                    return
        except (OSError, ValueError):
            pass

    def read_stderr() -> None:
        size = 0
        try:
            for line in proc.stderr:                        # type: ignore[union-attr]
                if size < _STDERR_CAP:
                    box["err"].append(line)
                    size += len(line)
        except (OSError, ValueError):
            pass

    t_out = threading.Thread(target=read_stdout, daemon=True)
    t_err = threading.Thread(target=read_stderr, daemon=True)
    t_out.start()
    t_err.start()

    write_error = ""
    try:
        proc.stdin.write(json.dumps(request) + "\n")        # type: ignore[union-attr]
        proc.stdin.flush()                                   # type: ignore[union-attr]
    except (BrokenPipeError, OSError) as exc:
        write_error = f"el agente cerró la entrada: {exc}"

    if not write_error:
        t_out.join(timeout)

    terminate(proc)
    t_err.join(1.0)

    sig = _signal_of(proc)
    err_text = excerpt("".join(box["err"]), 400)
    msg = box["msg"]

    if write_error:
        return AcpHandshake(False, error=write_error, stderr_excerpt=err_text, exit_signal=sig)
    if msg is None:
        return AcpHandshake(False, error=f"sin respuesta a initialize en {timeout:g} s",
                            stderr_excerpt=err_text, exit_signal=sig)
    if "error" in msg:
        return AcpHandshake(False, error=f"initialize devolvió error: {msg['error']}",
                            stderr_excerpt=err_text, exit_signal=sig, raw=msg)

    result = msg.get("result") or {}
    return AcpHandshake(
        True,
        protocol_version=result.get("protocolVersion"),
        agent_info=result.get("agentInfo") or {},
        agent_capabilities=result.get("agentCapabilities") or {},
        auth_methods=result.get("authMethods") or [],
        stderr_excerpt=err_text,
        raw=result,
    )


def terminate(proc: subprocess.Popen) -> None:
    """Termina el proceso y su grupo. Cortés primero, contundente después.

    Sin matar el grupo, un lanzador de Node deja hijos vivos que mantienen abiertos los
    descriptores y cuelgan a quien esté leyéndolos. Cómo se mata un grupo depende del sistema,
    y eso vive en `core/proc.py`: aquí sólo se declara la intención.
    """
    _terminate_tree(proc)


def _signal_of(proc: subprocess.Popen) -> int | None:
    """Si el proceso murió por señal, cuál. Distingue «no responde» de «lo mataron».

    Es lo que convierte el hallazgo H-01 —un binario con el certificado revocado al que macOS
    manda SIGKILL— de misterio en dato.
    """
    code = proc.poll()
    return -code if code is not None and code < 0 else None
