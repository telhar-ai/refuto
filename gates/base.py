# -*- coding: utf-8 -*-
"""Registro de puertas de refuto.

Vive en un solo sitio, igual que el registro de verificaciones del núcleo SDD: con dos listas,
una puerta retirada sigue apareciendo en la que nadie actualizó y nadie se entera.
"""

from __future__ import annotations

import importlib
import time

from core.model import Result, not_executable

#: id → (módulo, nombre legible, severidad por defecto)
GATES: dict = {
    "G-AGENT":    ("gates.g_agent",    "Ejecutabilidad real de los agentes", "CRITICAL"),
    "G-MCP":      ("gates.g_mcp",      "Integridad referencial de MCP",      "CRITICAL"),
    "G-POLICY":   ("gates.g_policy",   "Política: fuente única y aplicada",  "HIGH"),
    "G-LOCK":     ("gates.g_lock",     "Lock criptográfico del origen",      "HIGH"),
    "G-FLEET":    ("gates.g_fleet",    "Deriva de la flota materializada",   "HIGH"),
    "G-SKILL":    ("gates.g_skill",    "Contrato de las skills",             "MEDIUM"),
    "G-MANIFEST": ("gates.g_manifest", "Manifiesto válido y completo",       "HIGH"),
    "G-SDD":      ("gates.g_sdd",      "Puertas heredadas del núcleo SDD",   "HIGH"),
    "G-TRACE":    ("gates.g_trace",    "Trazabilidad de la cadena",          "HIGH"),
    "G-SECURITY": ("gates.g_security", "Seguridad: secretos y dependencias", "CRITICAL"),
    "G-PR":       ("gates.g_pr",       "El cambio como unidad de revisión",  "HIGH"),
    "G-HUMAN":    ("gates.g_human",    "Revisión humana",                    "HIGH"),
    "G-ROLES":    ("gates.g_roles",    "Registro de roles válido",           "MEDIUM"),
}


def run_gate(gate_id: str, ctx) -> Result:
    """Corre una puerta. Una puerta que revienta no aprueba: se declara NOT_EXECUTABLE."""
    module_name, title, severity = GATES[gate_id]
    started = time.monotonic()
    try:
        module = importlib.import_module(module_name)
        result = module.run(ctx)
    except Exception as exc:                                          # noqa: BLE001
        result = not_executable(gate_id, title, "la puerta falló al ejecutarse", exc)
    result.duration_ms = int((time.monotonic() - started) * 1000)
    if not result.severity or result.severity == "MEDIUM":
        result.severity = severity if result.status != "PASS" else result.severity
    return result


def run_all(ctx, only: list | None = None) -> list:
    ids = [g for g in GATES if not only or g in only]
    return [run_gate(g, ctx) for g in ids]
