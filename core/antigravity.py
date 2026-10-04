# -*- coding: utf-8 -*-
"""Dialecto de Google Antigravity para el guardián y el informe de sesión.

Contrato verificado en la documentación que el propio binario lleva embebida
(`Antigravity.app/Contents/Resources/bin/language_server`, versión 2.15.1, leída el
2026-09-21 con `strings`): «Lifecycle Hooks (`hooks.json`)».

    ganchos       `<raíz abierta>/.agents/hooks.json` o `~/.gemini/config/hooks.json`
    cwd           el directorio que contiene `hooks.json`
    PreToolUse    stdin  {"toolCall": {"name", "args"}, "workspacePaths": [...], "conversationId"}
                  stdout {"decision": allow|deny|ask|force_ask, "reason"}
    PreInvocation stdin  {"invocationNum", "conversationId", "workspacePaths", ...}
                  stdout {"injectSteps": [{"ephemeralMessage": "..."}]}
    claves        camelCase en la carga; los ARGUMENTOS de la herramienta van en PascalCase
                  (`TargetFile`, `CodeContent`, `CommandLine`)

Lo que la documentación NO dice, y por eso aquí no se supone: qué hace Antigravity si el
gancho sale con código distinto de cero. Toda respuesta se da, por tanto, con la decisión
explícita en stdout y salida 0; nunca se confía en el código de salida para bloquear.

Por qué no basta una lista de herramientas de escritura
-------------------------------------------------------
El binario declara más de cien tipos de paso (`CORTEX_STEP_TYPE_*`): `move`,
`delete_directory`, `edit_notebook`, `write_blob`, `git_commit`, `shell_exec`... Una lista
cerrada de «herramientas que escriben» deja pasar la siguiente que se añada. Aquí se hace al
revés: las LECTURAS se enumeran, y toda otra herramienta que traiga una ruta se juzga como
escritura sobre cada ruta que traiga. Lo desconocido que toca ficheros no se aprueba por
desconocido.
"""

from __future__ import annotations

import json
import os
import time
from pathlib import Path

#: Herramientas que sólo leen. Enumeradas a mano desde el inventario del binario 2.15.1.
LECTURAS = frozenset({
    "view_file", "view_file_outline", "view_code_item", "view_content_chunk",
    "list_directory", "grep_search", "find", "find_all_references", "code_search",
    "codebase_search", "read_url_content", "read_terminal", "read_notebook", "read_resource",
    "list_resources", "search_web", "read_browser_page", "list_browser_pages",
    "command_status", "retrieve_memory", "retrieve_content", "trajectory_search",
    "internal_search", "tool_search", "conversation_history", "knowledge_artifacts",
    "capture_browser_screenshot", "capture_browser_console_logs", "browser_get_dom",
    "browser_list_network_requests", "browser_get_network_request",
})

#: Herramientas cuyo argumento es una orden de shell (o su entrada).
ORDENES = {
    "run_command": ("CommandLine", "Command", "command"),
    "shell_exec": ("CommandLine", "Command", "command"),
    "send_command_input": ("Input", "CommandLine", "input"),
}

#: Pistas de nombre de argumento que designan una ruta.
_PISTAS_RUTA = ("file", "path", "directory", "target", "source", "destination", "dest")
#: Argumentos que traen contenido a escribir (para las formas de credencial).
_CONTENIDO = ("CodeContent", "ReplacementContent", "Content", "content")


def _rutas(args: dict) -> list:
    """Todo argumento de texto cuyo nombre sugiere ruta y cuyo valor parece una."""
    salida = []
    for clave, valor in (args or {}).items():
        if not isinstance(valor, str) or not valor.strip():
            continue
        k = clave.lower()
        if any(p in k for p in _PISTAS_RUTA) and ("/" in valor or "." in valor):
            if "content" in k:          # `TargetContent` es texto a buscar, no una ruta
                continue
            salida.append(valor)
    return salida


def _contenido(args: dict) -> str:
    partes = [args.get(k) for k in _CONTENIDO if isinstance((args or {}).get(k), str)]
    for trozo in (args or {}).get("ReplacementChunks") or []:
        if isinstance(trozo, dict) and isinstance(trozo.get("ReplacementContent"), str):
            partes.append(trozo["ReplacementContent"])
    return "\n".join(p for p in partes if p)


def espacio(payload: dict) -> str:
    rutas = payload.get("workspacePaths") or []
    return rutas[0] if rutas and isinstance(rutas[0], str) else ""


def hechos(payload: dict) -> tuple[str, list]:
    """Carga de PreToolUse → (herramienta, lista de hechos canónicos a evaluar).

    Lista vacía = nada que decidir (lectura, o herramienta sin ruta ni orden).
    """
    llamada = payload.get("toolCall") or {}
    nombre = str(llamada.get("name") or "")
    args = llamada.get("args") or {}
    if isinstance(args, str):                       # por si llegara serializado
        try:
            args = json.loads(args)
        except ValueError:
            args = {}
    base = {"runtime": "antigravity", "tool": nombre, "path": "", "content": "",
            "command": "", "cwd": espacio(payload), "structured_reply": False}
    if nombre in LECTURAS:
        return nombre, []
    if nombre in ORDENES:
        orden = next((args[k] for k in ORDENES[nombre] if isinstance(args.get(k), str)), "")
        return nombre, ([dict(base, command=orden)] if orden else [])
    if nombre == "git_commit":
        return nombre, [dict(base, command="git commit")]
    contenido = _contenido(args)
    return nombre, [dict(base, path=r, content=contenido) for r in _rutas(args)]


def responder(decision: str, motivo: str) -> str:
    """Salida documentada de PreToolUse. `decision` ∈ {allow, deny, ask}."""
    return json.dumps({"decision": decision, "reason": motivo}, ensure_ascii=False)


# ─────────────────────────── sesiones y contexto ───────────────────────────

def registrar_sesion(workspace: Path, runtime: str, sesion: str) -> bool:
    """Latido de una sesión en `.harness/state/sesiones/`. Devuelve True si es NUEVA.

    Es la detección que no depende de la huella de proceso de un proveedor: la sesión se
    anuncia a sí misma a través del gancho, que es lo único que todos los runtimes tienen.
    """
    if not sesion:
        return False
    d = workspace / ".harness" / "state" / "sesiones"
    d.mkdir(parents=True, exist_ok=True)
    ruta = d / f"{runtime}-{''.join(c for c in sesion if c.isalnum() or c in '-_')[:64]}.json"
    ahora = time.time()
    nueva = not ruta.exists()
    doc = {"runtime": runtime, "sesion": sesion, "primer_latido": ahora, "ultimo_latido": ahora,
           "pid_padre": os.getppid()}
    if not nueva:
        try:
            previo = json.loads(ruta.read_text(encoding="utf-8"))
            doc["primer_latido"] = previo.get("primer_latido", ahora)
        except (OSError, ValueError):
            pass
    tmp = ruta.with_suffix(".tmp")
    tmp.write_text(json.dumps(doc, ensure_ascii=False), encoding="utf-8", newline="\n")
    os.replace(tmp, ruta)
    return nueva


def informe(workspace: Path) -> str:
    """El mismo informe de sesión que recibe Claude, construido para este runtime."""
    try:
        from core.session import build_brief
        texto, avisos, bloqueos = build_brief(workspace, runtime="antigravity")
        cabecera = ""
        if bloqueos:
            cabecera = ("BLOQUEOS DEL ARNÉS (resuélvelos antes de trabajar):\n- "
                        + "\n- ".join(bloqueos) + "\n\n")
        return cabecera + texto
    except Exception as exc:                                            # noqa: BLE001
        previo = workspace / ".harness" / "state" / "session-brief.md"
        if previo.is_file():
            return (f"[informe regenerado sin éxito ({type(exc).__name__}); se usa la última "
                    f"copia escrita]\n\n" + previo.read_text(encoding="utf-8"))
        return (f"AVISO DEL ARNÉS: no se pudo componer el informe de sesión "
                f"({type(exc).__name__}: {exc}). Trabaja como si todo `.harness/` estuviera "
                f"denegado y pide instrucciones a la persona.")


def pre_invocacion(workspace: Path, payload: dict) -> str:
    """PreInvocation: la primera vez que se ve una conversación, se le inyecta el informe.

    Lo estable (método, rutas denegadas, qué no se sella) vive además en `AGENTS.md`, que
    Antigravity carga siempre. El informe es lo dinámico: estado del espacio, memoria,
    bloqueos. Se inyecta una vez por conversación, no en cada llamada al modelo.
    """
    nueva = registrar_sesion(workspace, "antigravity", str(payload.get("conversationId") or ""))
    if not nueva:
        return json.dumps({})
    return json.dumps({"injectSteps": [{"ephemeralMessage": informe(workspace)}]},
                      ensure_ascii=False)


def es_pre_invocacion(payload: dict) -> bool:
    return "toolCall" not in payload and ("invocationNum" in payload
                                          or "initialNumSteps" in payload)
