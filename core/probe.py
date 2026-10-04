# -*- coding: utf-8 -*-
"""H-01 · Escalera de ejecutabilidad. `which` no es prueba de nada.

El hallazgo que motiva este módulo
----------------------------------
En la máquina auditada, `@openai/codex@0.103.0` está en el PATH, tiene versión declarada en su
`package.json` y **no arranca**: macOS le manda SIGKILL porque el certificado de firma está
revocado (`codesign -v` → `CSSMERR_TP_CERT_REVOKED`). Un `command -v codex` dice que sí. La
realidad dice que no. Todo harness que comprueba presencia en el PATH cree lo primero.

La escalera, y qué prueba cada peldaño
--------------------------------------
    NOT_INSTALLED  no se resuelve en el PATH
    INSTALLED      se resuelve            ← lo máximo que puede afirmar `which`
    STARTABLE      el proceso arranca y no muere por señal
    FUNCTIONAL     responde un handshake estructurado (ACP initialize, o el nativo del CLI)
    VERIFIED       completa una tarea mínima real con salida verificable  ← gasta créditos

Cada peldaño implica los anteriores. La sonda se detiene en el primero que falla y **declara
dónde se detuvo**: un agente parado en INSTALLED no es un agente soportado.

Sólo `VERIFIED` cuesta dinero, y por eso es opt-in (`--deep`). Los otros cuatro son gratis y se
corren siempre.
"""

from __future__ import annotations

import concurrent.futures as futures
import os
import platform
import shutil
import subprocess
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path

from core import acp
from core.digest import excerpt
from core.model import (
    AGENT_VERIFIED, FUNCTIONAL, INSTALLED, NOT_INSTALLED, STARTABLE, rung,
)
from core.proc import TEXT_IO, spawn_kwargs


@dataclass
class ProbeReport:
    agent: str
    level: str = NOT_INSTALLED
    executable: str = ""
    version: str = ""
    #: Por qué se detuvo en este peldaño. Vacío sólo si llegó al final pedido.
    stopped_because: str = ""
    signature: dict = field(default_factory=dict)
    protocol: dict = field(default_factory=dict)
    capabilities: dict = field(default_factory=dict)
    auth_methods: list = field(default_factory=list)
    steps: list = field(default_factory=list)
    duration_ms: int = 0

    def to_dict(self) -> dict:
        return asdict(self)


def _step(name: str, ok: bool, detail: str = "", **extra) -> dict:
    return {"step": name, "ok": ok, "detail": detail, **extra}


# ── peldaño 1 · INSTALLED ────────────────────────────────────────────────────────────
def _resolve(binary: str) -> str:
    return shutil.which(binary) or ""


# ── firma de código ──────────────────────────────────────────────────────────────────
def check_signature(path: str, command: str = "") -> dict:
    """Comprueba la firma del ejecutable donde el sistema lo permite.

    En macOS es la comprobación que convierte «no arranca y no sé por qué» en «el certificado
    está revocado». No es un extra de seguridad: es diagnóstico.

    Se sigue el enlace simbólico y, para lanzadores de Node que delegan en un binario nativo,
    se comprueba el binario nativo si se puede localizar — es el que la firma protege.
    """
    if platform.system() != "Darwin":
        return {"checked": False, "reason": "verificación de firma sólo implementada en macOS"}
    target = os.path.realpath(path)
    native = _native_behind_launcher(target, command) or target
    try:
        proc = subprocess.run(["codesign", "-v", "--verbose=2", native],
                              capture_output=True, timeout=30, **TEXT_IO)
    except (OSError, subprocess.SubprocessError) as exc:
        return {"checked": False, "reason": f"no se pudo ejecutar codesign: {exc}"}
    out = (proc.stderr or "") + (proc.stdout or "")
    revoked = "CSSMERR_TP_CERT_REVOKED" in out
    # «no está firmado» NO es «la firma es inválida». Un guion de Node nunca lleva firma, y
    # tratarlo como fallo produce ruido en cuatro de cinco agentes — que es la forma en que
    # una comprobación de seguridad se aprende a ignorar.
    unsigned = "not signed at all" in out or "code object is not signed" in out
    verdict = ("REVOKED" if revoked else
               "UNSIGNED" if unsigned else
               "VALID" if proc.returncode == 0 else "INVALID")
    return {
        "checked": True,
        "subject": native,
        "verdict": verdict,
        "valid": verdict in ("VALID", "UNSIGNED"),
        "revoked": revoked,
        "exit_code": proc.returncode,
        "detail": excerpt(out, 240),
    }


def _native_behind_launcher(path: str, command: str = "") -> str:
    """Localiza el binario nativo detrás de un lanzador `*.js` de npm, si lo hay.

    Firmar el lanzador de JavaScript no dice nada: lo que macOS mata es el nativo.

    El primer intento de esto eligió `vendor/.../path/rg` —el ripgrep que Codex empaqueta— en
    vez del propio `codex`, y declaró la firma válida. Comprobar la firma del binario
    equivocado es peor que no comprobarla: da un verde falso sobre seguridad. Ahora se
    prefiere el que se llama como la orden, y sólo si no lo hay, el mayor.
    """
    if not path.endswith(".js"):
        return ""
    pkg_root = Path(path).parent.parent
    vendor = pkg_root / "node_modules"
    if not vendor.is_dir():
        return ""
    candidates = [c for c in vendor.rglob("vendor/*/*/*")
                  if c.is_file() and os.access(c, os.X_OK) and c.stat().st_size > 1_000_000]
    if not candidates:
        return ""
    want = command or Path(path).stem
    named = [c for c in candidates if c.name == want]
    if named:
        return str(max(named, key=lambda c: c.stat().st_size))
    return str(max(candidates, key=lambda c: c.stat().st_size))


# ── peldaño 2 · STARTABLE ────────────────────────────────────────────────────────────
def _startable(argv: list[str], timeout: float = 30.0) -> dict:
    """¿Arranca el proceso sin que el sistema lo mate?

    Un código de salida distinto de cero es aceptable: muchos CLIs devuelven != 0 en `--help`.
    Lo que NO es aceptable es morir por señal: eso es el sistema operativo negándose a
    ejecutarlo, y ningún reintento lo arregla.
    """
    try:
        proc = subprocess.run(argv, capture_output=True, timeout=timeout,
                              env=_probe_env(), **TEXT_IO, **spawn_kwargs())
    except FileNotFoundError:
        return {"ok": False, "reason": "ejecutable no encontrado", "signal": None}
    except subprocess.TimeoutExpired:
        return {"ok": False, "reason": f"colgado más de {timeout:g} s", "signal": None}
    except (OSError, subprocess.SubprocessError) as exc:
        return {"ok": False, "reason": f"no se pudo lanzar: {exc}", "signal": None}

    sig = -proc.returncode if proc.returncode < 0 else None
    if sig is not None:
        return {"ok": False, "reason": f"muerto por señal {sig}", "signal": sig,
                "stderr": excerpt(proc.stderr, 240)}
    produced = bool((proc.stdout or "").strip() or (proc.stderr or "").strip())
    if not produced and proc.returncode != 0:
        return {"ok": False, "reason": f"salió con {proc.returncode} sin producir salida",
                "signal": None}
    return {"ok": True, "exit_code": proc.returncode, "signal": None,
            "stdout": excerpt(proc.stdout, 200)}


def _probe_env() -> dict:
    env = dict(os.environ)
    env.setdefault("KIRO_TELEMETRY_OPT_OUT", "1")
    env.setdefault("CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC", "1")
    env.setdefault("NO_COLOR", "1")
    return env


def _version_of(argv: list[str], timeout: float = 30.0) -> str:
    try:
        proc = subprocess.run(argv, capture_output=True, timeout=timeout,
                              env=_probe_env(), **TEXT_IO, **spawn_kwargs())
    except (OSError, subprocess.SubprocessError):
        return ""
    text = ((proc.stdout or "") + " " + (proc.stderr or "")).strip()
    import re
    m = re.search(r"\d+\.\d+\.\d+[\w.+-]*", text)
    return m.group(0) if m else ""


# ── orquestación de la sonda ─────────────────────────────────────────────────────────
def probe(spec, *, deep: bool = False, workspace: Path | None = None) -> ProbeReport:
    """Corre la escalera para un `AgentSpec` (ver `adapters/registry.py`)."""
    t0 = time.monotonic()
    rep = ProbeReport(agent=spec.name)

    # 1 · INSTALLED
    path = _resolve(spec.binary)
    rep.steps.append(_step("resolve_path", bool(path), path or f"{spec.binary} no está en el PATH"))
    if not path:
        rep.level = NOT_INSTALLED
        rep.stopped_because = f"{spec.binary} no se resuelve en el PATH"
        rep.duration_ms = int((time.monotonic() - t0) * 1000)
        return rep
    rep.executable = path
    rep.level = INSTALLED

    # 1b · firma. No mueve el peldaño por sí sola, pero explica el que viene.
    rep.signature = check_signature(path, spec.binary)
    if rep.signature.get("checked"):
        rep.steps.append(_step("code_signature", bool(rep.signature.get("valid")),
                               rep.signature.get("verdict", "") + " · " +
                               rep.signature.get("detail", "")[:120],
                               verdict=rep.signature.get("verdict"),
                               revoked=rep.signature.get("revoked", False)))

    # 2 · STARTABLE
    start = _startable([path, *spec.start_args], timeout=spec.timeout)
    rep.steps.append(_step("startable", start["ok"], start.get("reason", "arranca"),
                           signal=start.get("signal")))
    if not start["ok"]:
        rep.level = INSTALLED
        # La versión declarada se lee del manifiesto de instalación aunque el binario no
        # arranque: «qué versión es la que no arranca» es la mitad del diagnóstico.
        rep.version = spec.fallback_version(path)
        if rep.version:
            rep.steps.append(_step("version", True,
                                   f"{rep.version} (declarada en el manifiesto de instalación; "
                                   f"NO confirmada por el binario, que no arranca)"))
        why = start.get("reason", "no arranca")
        if rep.signature.get("revoked"):
            why += " — el certificado de firma del binario nativo está REVOCADO; reinstale"
        rep.stopped_because = why
        rep.duration_ms = int((time.monotonic() - t0) * 1000)
        return rep
    rep.level = STARTABLE
    rep.version = _version_of([path, *spec.version_args], timeout=spec.timeout) or spec.fallback_version(path)
    rep.steps.append(_step("version", bool(rep.version), rep.version or "no declarada"))

    # 3 · FUNCTIONAL — handshake estructurado, sin gastar créditos
    if spec.speaks_acp:
        hs = acp.initialize([path, *spec.acp_args],
                            cwd=str(workspace) if workspace else None, timeout=spec.timeout)
        rep.steps.append(_step("acp_initialize", hs.ok, hs.error or "handshake ACP correcto",
                               signal=hs.exit_signal))
        if hs.ok:
            rep.level = FUNCTIONAL
            rep.protocol = {"family": "acp", "version": hs.protocol_version}
            rep.capabilities = hs.agent_capabilities
            rep.auth_methods = [a.get("id", "") for a in hs.auth_methods]
            if hs.agent_info.get("version"):
                rep.version = hs.agent_info["version"]
        else:
            rep.stopped_because = f"habla ACP según su CLI pero el handshake falló: {hs.error}"
    else:
        native = spec.native_handshake(path, workspace)
        rep.steps.append(_step("native_handshake", native["ok"],
                               native.get("detail", ""), protocol=native.get("family", "")))
        if native["ok"]:
            rep.level = FUNCTIONAL
            rep.protocol = {"family": native.get("family", "native"),
                            "version": native.get("version")}
            rep.capabilities = native.get("capabilities", {})
        else:
            rep.stopped_because = native.get("detail", "el handshake nativo falló")

    if rung(rep.level) < rung(FUNCTIONAL):
        rep.duration_ms = int((time.monotonic() - t0) * 1000)
        return rep

    # 4 · VERIFIED — tarea mínima real. Gasta créditos, por eso es opt-in.
    if not deep:
        rep.stopped_because = "VERIFIED no se intentó: requiere --deep (gasta créditos)"
        rep.duration_ms = int((time.monotonic() - t0) * 1000)
        return rep

    task = spec.verify_task(path, workspace)
    rep.steps.append(_step("verify_task", task["ok"], task.get("detail", ""),
                           cost_usd=task.get("cost_usd"), duration_ms=task.get("duration_ms")))
    if task["ok"]:
        rep.level = AGENT_VERIFIED
        rep.stopped_because = ""
    else:
        rep.stopped_because = task.get("detail", "la tarea mínima no se completó")
    rep.duration_ms = int((time.monotonic() - t0) * 1000)
    return rep


def probe_all(specs, *, deep: bool = False, workspace: Path | None = None,
              max_workers: int = 6) -> list[ProbeReport]:
    """Sondea en paralelo. Cinco agentes tardan segundos, no minutos."""
    reports: list[ProbeReport] = []
    with futures.ThreadPoolExecutor(max_workers=max_workers) as pool:
        pending = {pool.submit(probe, s, deep=deep, workspace=workspace): s for s in specs}
        for fut in futures.as_completed(pending):
            spec = pending[fut]
            try:
                reports.append(fut.result())
            except Exception as exc:                                   # noqa: BLE001
                # Una sonda que revienta no deja al agente sin veredicto: lo deja en el
                # peldaño más bajo, que es la lectura honesta.
                rep = ProbeReport(agent=spec.name, level=NOT_INSTALLED,
                                  stopped_because=f"la sonda falló: {type(exc).__name__}: {exc}")
                reports.append(rep)
    return sorted(reports, key=lambda r: (-rung(r.level), r.agent))
