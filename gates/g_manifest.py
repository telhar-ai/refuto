# -*- coding: utf-8 -*-
"""G-MANIFEST · El manifiesto es válido, completo y coherente con lo que hay.

Umbral: **valida contra el esquema · no nombra nada que no exista · declara todo lo que se usa.**

Se comprueban las dos direcciones, porque fallan distinto:
    declarado y ausente  → el espacio promete algo que no tiene
    presente y no declarado → hay superficie que nadie revisa
"""

from __future__ import annotations

from adapters.registry import ADAPTERS
from core.model import BLOCKED, FAIL, Finding, HIGH, PASS, Result, Scope
from core.schema import load_schema, validate

GATE_ID = "G-MANIFEST"
TITLE = "Manifiesto válido y completo"
THRESHOLD = "valida contra el esquema · no nombra nada inexistente · declara lo que se usa"


def run(ctx) -> Result:
    if ctx.manifest is None:
        return Result(GATE_ID, TITLE, BLOCKED, severity=HIGH, threshold=THRESHOLD,
                      measure="no hay .harness/harness.manifest.json. Ejecute `refuto init`.")

    schema = load_schema("manifest.schema.json")
    errors = validate(ctx.manifest, schema)
    findings = [Finding("harness.manifest.json", e) for e in errors]
    observations = []

    for name in (ctx.manifest.get("agents") or {}):
        if name not in ADAPTERS:
            findings.append(Finding("harness.manifest.json",
                                    f"declara el agente «{name}» y no hay adapter para él"))

    for rel in (ctx.manifest.get("artifacts") or []):
        if not (ctx.workspace / rel).exists():
            findings.append(Finding(rel, "declarado en `artifacts` y ausente del árbol"))

    gates_declared = set(ctx.manifest.get("gates") or [])
    from gates.base import GATES
    unknown = gates_declared - set(GATES)
    for g in sorted(unknown):
        findings.append(Finding("harness.manifest.json", f"declara la puerta «{g}», que no existe"))
    missing = set(GATES) - gates_declared
    if missing:
        observations.append(
            f"puertas implementadas y NO declaradas en el manifiesto: {', '.join(sorted(missing))}. "
            f"No se ejecutan. Si es a propósito, decláralo con `enabled: false`.")

    items_count = 1 + len(ctx.manifest.get("agents") or {}) + len(ctx.manifest.get("artifacts") or []) + len(gates_declared)
    scope = Scope(examined=items_count, universe="manifest", subject="harness.manifest.json")
    return Result(GATE_ID, TITLE, PASS if not findings else FAIL, severity=HIGH,
                  threshold=THRESHOLD,
                  measure=f"{len(ctx.manifest.get('agents') or {})} agentes · "
                          f"{len(gates_declared)} puertas declaradas · {len(findings)} problemas",
                  findings=findings, observations=observations, scope=scope)
