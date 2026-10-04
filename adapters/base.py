# -*- coding: utf-8 -*-
"""Contrato de adapter. Lo único que el core sabe de un agente concreto.

Regla de reparto, y es la que decide si esta arquitectura envejece bien:

    CORE      lo que es verdad para cualquier agente   → manifiesto, lock, puertas, evidencia
    ADAPTER   cómo lo dice ESTE agente                 → banderas, formatos, vocabularios
    NATIVE    lo que sólo tiene ESTE agente            → se expone, no se aplana

El tercer punto es el que se suele romper. `--max-budget-usd` existe en Claude Code y no en
Kiro; `--require-mcp-startup` existe en Kiro y no en Claude. Un modelo agnóstico que borra las
dos para que la tabla quede simétrica ha empeorado los dos agentes. Aquí se declaran como
`native_extensions` y el core puede consultarlas sin depender de ellas.

Métodos obligatorios y opcionales
---------------------------------
Obligatorio: `name`, `binary`, `version_args`, `start_args`, y uno de {`speaks_acp`,
`native_handshake`}. Todo lo demás tiene una implementación por defecto que devuelve
«no soportado» de forma honesta — nunca un falso positivo.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path


@dataclass
class AgentSpec:
    """Declaración de un agente. Un adapter es una instancia de esto más sus métodos."""

    name: str
    binary: str
    #: Argumentos que producen la versión. Se parsea el primer semver que aparezca.
    version_args: tuple = ("--version",)
    #: Argumentos de un arranque inocuo. `--help` es el estándar de facto y no gasta nada.
    start_args: tuple = ("--help",)
    #: Si habla ACP, cómo se le pide que arranque en modo ACP.
    speaks_acp: bool = False
    acp_args: tuple = ()
    timeout: float = 30.0
    #: Rutas de configuración que este agente descubre, relativas al workspace y a $HOME.
    workspace_config: tuple = ()
    home_config: tuple = ()
    #: Lo que sólo tiene este agente. Se declara para no perderlo, no para homogeneizarlo.
    native_extensions: dict = field(default_factory=dict)
    #: Capacidades que el adapter afirma sin poder sondearlas. Cada una lleva su nivel de
    #: evidencia, y `doctor` las distingue de las que sí se comprobaron.
    declared: dict = field(default_factory=dict)

    # ── handshake ────────────────────────────────────────────────────────────────────
    def native_handshake(self, path: str, workspace: Path | None) -> dict:
        """Handshake estructurado para agentes que no hablan ACP.

        Debe devolver `{"ok": bool, "family": str, "detail": str, "capabilities": dict}` y
        **no debe gastar créditos**. Por defecto: no soportado, dicho sin rodeos.
        """
        return {"ok": False, "family": "", "detail":
                f"{self.name} no habla ACP y su adapter no implementa handshake nativo"}

    # ── tarea mínima verificable ─────────────────────────────────────────────────────
    def verify_task(self, path: str, workspace: Path | None) -> dict:
        """Tarea mínima real que demuestra que el agente TRABAJA. Gasta créditos.

        Debe devolver `{"ok": bool, "detail": str, "cost_usd": float|None,
        "duration_ms": int|None}`.
        """
        return {"ok": False, "detail":
                f"{self.name} no implementa tarea de verificación; no se puede llegar a VERIFIED"}

    # ── política ─────────────────────────────────────────────────────────────────────
    def compile_policy(self, policy) -> dict:
        """Traduce la política canónica al vocabulario de este agente.

        Devuelve `{"supported": bool, "artifacts": {ruta_relativa: contenido},
        "unenforceable": [str], "notes": [str]}`.

        `unenforceable` es obligatorio y no puede mentir: si una regla canónica no se puede
        expresar en este runtime, va en esa lista. Una política que se declara aplicada donde
        no se aplica es peor que no tener política.
        """
        return {"supported": False, "artifacts": {},
                "unenforceable": ["todas: el adapter no implementa compilación de política"],
                "notes": []}

    # ── ejecución ────────────────────────────────────────────────────────────────────
    def run_argv(self, *, prompt_file: Path, allow_tools: list, effort: str,
                 headless: bool = True, resume: bool = False,
                 require_mcp: bool = False, budget_usd: float | None = None) -> list:
        """Línea de órdenes para ejecutar una fase. Vacía = no soportado."""
        return []

    # ── eventos ──────────────────────────────────────────────────────────────────────
    def normalize_event(self, raw: dict) -> dict | None:
        """Traduce un evento del flujo nativo al evento canónico de refuto.

        Devuelve `None` para eventos que no interesan. El esquema canónico está en
        `schemas/event.schema.json`.
        """
        return None

    # ── auxiliares ───────────────────────────────────────────────────────────────────
    def fallback_version(self, path: str) -> str:
        """Versión cuando el propio binario no la sabe decir (p. ej. porque no arranca)."""
        return ""


def npm_package_version(executable_path: str) -> str:
    """Versión declarada en el `package.json` del paquete npm que instaló este ejecutable.

    Es la única forma de saber qué versión hay cuando el binario no arranca — que es
    exactamente el caso de Codex en la máquina auditada. Una versión leída del manifiesto no
    es una versión ejecutable, y quien la use debe saberlo.
    """
    import json
    import os
    real = Path(os.path.realpath(executable_path))
    for parent in list(real.parents)[:4]:
        pkg = parent / "package.json"
        if pkg.is_file():
            try:
                return json.loads(pkg.read_text(encoding="utf-8")).get("version", "")
            except (OSError, ValueError):
                return ""
    return ""
