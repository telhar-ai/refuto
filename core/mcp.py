# -*- coding: utf-8 -*-
"""H-02 · Integridad referencial de MCP. Validar el esquema no basta.

El hallazgo que motiva este módulo
----------------------------------
El agente `sdd-verificacion-visual` declara `@navegador/*` en `allowedTools`. Ese servidor MCP
**no está declarado en ningún `mcp.json`** del espacio. Y `kiro-cli agent validate` devuelve
**0**: valida la FORMA del JSON, no que lo que nombra exista.

Peor: el orquestador pasa `--require-mcp-startup` a esa fase precisamente para que no corra sin
navegador. Pero la bandera exige que arranquen *los servidores habilitados* — y un servidor que
nadie declaró no está habilitado, así que no se comprueba. La fase corre, captura nada, y
«nada» se lee como «no hay diferencias».

La cadena que hay que comprobar, entera
---------------------------------------
    herramienta declarada  →  servidor requerido  →  configuración  →  arranque
                           →  capacidad anunciada →  herramienta concreta disponible

Un eslabón roto en cualquier punto es FAIL o BLOCKED. Nunca PASS. Y nunca:

    resultado vacío == aprobado

Descubrimiento de capacidades
-----------------------------
MCP 2026-07-28 hace obligatorio `server/discover`: una sola llamada devuelve versiones
soportadas, capacidades e identidad. Los servidores anteriores (≤2025-11-25) usan el handshake
`initialize`. Este módulo intenta `server/discover` primero y cae a `initialize`, y **registra
cuál de los dos respondió** — porque saber qué revisión habla realmente cada servidor es parte
del inventario.
"""

from __future__ import annotations

import json
import os
import re
import subprocess
import threading
from dataclasses import asdict, dataclass, field
from pathlib import Path

from core.digest import excerpt
from core.proc import TEXT_IO, spawn_kwargs, terminate as terminate_tree

#: Revisión que este cliente pide. Ver docs/research/mcp.md.
PROTOCOL_VERSION = "2026-07-28"
#: Revisión con handshake `initialize`, para servidores que aún no migraron.
LEGACY_PROTOCOL_VERSION = "2025-06-18"

_CLIENT_INFO = {"name": "harness-mcp-probe", "version": "0.1.0"}

#: `@servidor/herramienta` o `@servidor/*` o `@servidor`
TOOL_REF = re.compile(r"^@([A-Za-z0-9_.-]+)(?:/(\*|[A-Za-z0-9_.-]+))?$")


@dataclass
class ToolRef:
    raw: str
    server: str
    tool: str = "*"

    @property
    def wildcard(self) -> bool:
        return self.tool == "*"


@dataclass
class ServerReport:
    name: str
    declared_in: list = field(default_factory=list)
    configured: bool = False
    config_source: str = ""
    transport: str = ""
    disabled: bool = False
    reachable: bool = False
    discovery_method: str = ""          # server/discover | initialize | —
    protocol_versions: list = field(default_factory=list)
    server_info: dict = field(default_factory=dict)
    capabilities: dict = field(default_factory=dict)
    tools: list = field(default_factory=list)
    error: str = ""

    def to_dict(self) -> dict:
        return asdict(self)


def parse_tool_ref(raw: str) -> ToolRef | None:
    """`@figma/get_screenshot` → ToolRef(server='figma', tool='get_screenshot')."""
    m = TOOL_REF.match(raw.strip())
    if not m:
        return None
    return ToolRef(raw=raw, server=m.group(1), tool=m.group(2) or "*")


# ── cliente MCP stdio ────────────────────────────────────────────────────────────────
def _rpc_stdio(command: str, args: list, env_extra: dict, requests: list,
               *, cwd: str | None = None, timeout: float = 25.0) -> tuple[dict, str, int | None]:
    """Envía una lista de peticiones JSON-RPC a un servidor stdio y recoge sus respuestas.

    Devuelve `({id: respuesta}, stderr, señal)`. Igual que en ACP: se drena stderr desde el
    principio en su propio hilo y se mata el GRUPO, no el proceso — un servidor lanzado con
    `npx` deja hijos que mantienen los descriptores abiertos.
    """
    env = dict(os.environ)
    env.update(env_extra or {})
    try:
        proc = subprocess.Popen([command, *args], cwd=cwd, env=env, bufsize=1,
                                stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE, **TEXT_IO, **spawn_kwargs())
    except FileNotFoundError:
        return {}, f"orden no encontrada: {command}", None
    except (OSError, ValueError) as exc:
        return {}, f"no se pudo lanzar: {exc}", None

    want = {r["id"] for r in requests}
    got: dict = {}
    err: list = []

    def read_out():
        try:
            for line in proc.stdout:                         # type: ignore[union-attr]
                line = line.strip()
                if not line:
                    continue
                try:
                    msg = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if msg.get("id") in want:
                    got[msg["id"]] = msg
                    if len(got) == len(want):
                        return
        except (OSError, ValueError):
            pass

    def read_err():
        try:
            for line in proc.stderr:                         # type: ignore[union-attr]
                if len(err) < 200:
                    err.append(line)
        except (OSError, ValueError):
            pass

    t_o = threading.Thread(target=read_out, daemon=True)
    t_e = threading.Thread(target=read_err, daemon=True)
    t_o.start(); t_e.start()
    try:
        for req in requests:
            proc.stdin.write(json.dumps(req) + "\n")          # type: ignore[union-attr]
        proc.stdin.flush()                                     # type: ignore[union-attr]
    except (BrokenPipeError, OSError) as exc:
        err.append(f"stdin cerrado: {exc}\n")
    t_o.join(timeout)

    terminate_tree(proc, close_streams=False)
    t_e.join(1.0)
    code = proc.poll()
    sig = -code if code is not None and code < 0 else None
    for stream in (proc.stdin, proc.stdout, proc.stderr):
        try:
            if stream and not stream.closed:
                stream.close()
        except (OSError, ValueError):
            pass
    return got, excerpt("".join(err), 300), sig


def _meta(version: str) -> dict:
    return {
        "io.modelcontextprotocol/protocolVersion": version,
        "io.modelcontextprotocol/clientInfo": _CLIENT_INFO,
        "io.modelcontextprotocol/clientCapabilities": {},
    }


def interrogate_stdio(name: str, cfg: dict, *, cwd: str | None = None,
                      timeout: float = 25.0) -> ServerReport:
    """Arranca un servidor MCP stdio y le pregunta qué sabe hacer.

    Se prueba primero `server/discover` (obligatorio desde 2026-07-28) y, si el servidor no lo
    conoce, el handshake `initialize` de las revisiones anteriores. En los dos casos se pide
    `tools/list`, porque la lista concreta de herramientas es lo que hace falta para responder
    «¿existe `@figma/get_screenshot`?».
    """
    rep = ServerReport(name=name, configured=True, transport="stdio",
                       config_source=cfg.get("_source", ""))
    command = cfg.get("command", "")
    if not command:
        rep.error = "la configuración no declara `command`"
        return rep

    reqs = [
        {"jsonrpc": "2.0", "id": 1, "method": "server/discover",
         "params": {"_meta": _meta(PROTOCOL_VERSION)}},
        {"jsonrpc": "2.0", "id": 2, "method": "initialize",
         "params": {"protocolVersion": LEGACY_PROTOCOL_VERSION,
                    "capabilities": {}, "clientInfo": _CLIENT_INFO}},
        {"jsonrpc": "2.0", "id": 3, "method": "tools/list",
         "params": {"_meta": _meta(PROTOCOL_VERSION)}},
    ]
    got, err, sig = _rpc_stdio(command, cfg.get("args") or [], cfg.get("env") or {},
                               reqs, cwd=cwd, timeout=timeout)

    disc = got.get(1, {})
    if "result" in disc:
        res = disc["result"]
        rep.reachable = True
        rep.discovery_method = "server/discover"
        rep.protocol_versions = res.get("supportedVersions") or []
        rep.capabilities = res.get("capabilities") or {}
        rep.server_info = (res.get("_meta") or {}).get("io.modelcontextprotocol/serverInfo") or {}
    else:
        init = got.get(2, {})
        if "result" in init:
            res = init["result"]
            rep.reachable = True
            rep.discovery_method = "initialize"
            rep.protocol_versions = [res.get("protocolVersion")] if res.get("protocolVersion") else []
            rep.capabilities = res.get("capabilities") or {}
            rep.server_info = res.get("serverInfo") or {}

    listing = got.get(3, {})
    if "result" in listing:
        rep.tools = [t.get("name") for t in (listing["result"].get("tools") or []) if t.get("name")]

    if not rep.reachable:
        detail = err or "sin respuesta"
        if sig:
            detail = f"muerto por señal {sig} · {detail}"
        rep.error = f"el servidor no respondió a server/discover ni a initialize — {detail}"
    return rep


def interrogate_http(name: str, cfg: dict) -> ServerReport:
    """Servidores HTTP/SSE. No se intenta autenticar: sin credencial el resultado sería un 401
    disfrazado de «no disponible», y eso es exactamente el falso negativo que se quiere evitar.

    Se marca `reachable=False` con motivo explícito, lo que el core traduce a **BLOCKED**, no a
    FAIL. La diferencia importa: BLOCKED dice «no se pudo comprobar», que es la verdad.
    """
    return ServerReport(
        name=name, configured=True, transport=cfg.get("type", "http"),
        config_source=cfg.get("_source", ""),
        error="servidor HTTP: la interrogación requiere credencial de la sesión del agente; "
              "refuto no la tiene y no la pide. Comprobable sólo desde el propio agente.")


# ── lectura de configuración ─────────────────────────────────────────────────────────
#: Dónde puede estar declarado un servidor MCP, y **de quién es el fichero**.
#:
#: El ámbito no es decorativo. Un fichero del ESPACIO está en el árbol, se versiona, y lo
#: arregla quien audita. Uno del USUARIO que ejecuta la auditoría no está en el árbol, no
#: se versiona, y puede cambiar el veredicto sobre un espacio ajeno sin dejar rastro en él.
#: Los dos hay que leerlos —un servidor declarado a nivel de usuario existe de verdad, y una
#: puerta que sólo mirara el espacio aprobaría por no haber mirado—, pero cuando uno no se
#: puede leer, el hallazgo tiene que decir cuál de los dos es: si no, quien lo recibe busca
#: el problema en el repositorio equivocado.
_CANDIDATOS_ESPACIO = ((".kiro", "settings", "mcp.json"), (".mcp.json",),
                       (".vscode", "mcp.json"), (".gemini", "settings.json"),
                       ("opencode.json",))
_CANDIDATOS_USUARIO = ((".kiro", "settings", "mcp.json"), (".claude", "settings.json"))


def load_mcp_config(workspace: Path, home: Path | None = None) -> tuple[dict, list]:
    """Reúne los servidores MCP declarados en el espacio, digan lo que digan los agentes.

    Devuelve `(servidores, ilegibles)`. **La segunda lista no es opcional.**

    La primera versión de esta función hacía `except (OSError, ValueError): continue`. Un
    `mcp.json` corrupto desaparecía, la puerta no veía referencias, y devolvía PASS con el
    texto «nada que verificar» — el fallo silencioso exacto que esta puerta existe para
    impedir, cometido por la puerta. Lo encontró `TestGateMcp::test_entrada_corrupta`.

    `home` es un parámetro, y no un `Path.home()` enterrado en el cuerpo, por lo medido el
    2026-09-22: con `~/.claude/settings.json` ilegible, **siete** pruebas de G-MCP pasan de
    su veredicto esperado a `NOT_EXECUTABLE`, en espacios temporales que no contienen ese
    fichero ni pueden arreglarlo. La suite no medía «el código es correcto»: medía «el código
    es correcto Y el `$HOME` de quien la corre es benigno», y reportaba sólo lo primero. El
    fixture `Workspace` ya declaraba la regla que se estaba incumpliendo: «una prueba que
    necesita los repositorios de quien la escribió para pasar no es una prueba».

    En producción el valor por defecto es el de antes —el home real, que es lo correcto para
    auditar de verdad— y no se debilita nada: un fichero ilegible sigue dando NOT_EXECUTABLE,
    porque no poder leerlo es exactamente no poder afirmar.
    """
    servers: dict = {}
    unreadable: list = []
    base = Path.home() if home is None else Path(home)
    candidates = [(workspace.joinpath(*p), "espacio") for p in _CANDIDATOS_ESPACIO]
    candidates += [(base.joinpath(*p), "usuario") for p in _CANDIDATOS_USUARIO]
    for path, scope in candidates:
        if not path.is_file():
            continue
        try:
            doc = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError) as exc:
            nota = "" if scope == "espacio" else (
                " — OJO: este fichero es del USUARIO que ejecuta la auditoría, no del espacio "
                "auditado. No está en su árbol y no se arregla desde él.")
            unreadable.append({"path": str(path), "scope": scope,
                               "problem": f"{type(exc).__name__}: {exc}{nota}"})
            continue
        block = doc.get("mcpServers") or doc.get("mcp") or {}
        if not isinstance(block, dict):
            continue
        for name, cfg in block.items():
            if not isinstance(cfg, dict):
                continue
            entry = dict(cfg)
            entry["_source"] = str(path)
            servers.setdefault(name, []).append(entry)
    return servers, unreadable


def collect_required_refs(workspace: Path) -> tuple[dict, list]:
    """Qué herramientas MCP exige cada agente declarado en el espacio.

    Devuelve `({ '@servidor/herramienta': [archivos] }, ilegibles)`. Un agente que no se puede
    leer NO se salta: se declara. Si no se sabe qué exige, no se puede afirmar que se cumple.
    """
    required: dict = {}
    unreadable: list = []

    def note(ref_raw: str, where: Path) -> None:
        required.setdefault(ref_raw, []).append(str(where))

    for path in sorted((workspace / ".kiro" / "agents").glob("*.json")) if (workspace / ".kiro" / "agents").is_dir() else []:
        try:
            doc = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError) as exc:
            unreadable.append({"path": str(path), "problem": f"{type(exc).__name__}: {exc}"})
            continue
        for field_name in ("tools", "allowedTools", "excludedTools"):
            for item in doc.get(field_name) or []:
                if isinstance(item, str) and item.startswith("@"):
                    note(item, path)

    agents_dir = workspace / ".claude" / "agents"
    for path in sorted(agents_dir.glob("*.md")) if agents_dir.is_dir() else []:
        head = path.read_text(encoding="utf-8", errors="ignore")[:1500]
        for m in re.finditer(r"\bmcp__([A-Za-z0-9_-]+)__([A-Za-z0-9_-]+)", head):
            note(f"@{m.group(1)}/{m.group(2)}", path)
    return required, unreadable
