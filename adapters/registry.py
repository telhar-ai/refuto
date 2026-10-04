# -*- coding: utf-8 -*-
"""Registro de adapters. Añadir un agente es añadir un módulo aquí y nada más.

El registro NO decide si un agente está soportado. Eso lo decide la sonda, contra la máquina
real. Estar en el registro sólo significa que existe un adapter escrito.
"""

from __future__ import annotations

from adapters import aidlc, claude, codex, gemini, kiro, opencode

ADAPTERS = {
    spec.name: spec
    for spec in (kiro.SPEC, claude.SPEC, gemini.SPEC, opencode.SPEC, codex.SPEC, aidlc.SPEC)
}


def get(name: str):
    if name not in ADAPTERS:
        raise KeyError(f"no hay adapter para {name!r}; hay: {sorted(ADAPTERS)}")
    return ADAPTERS[name]


def all_specs() -> list:
    return [ADAPTERS[k] for k in sorted(ADAPTERS)]
