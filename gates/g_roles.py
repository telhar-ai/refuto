# -*- coding: utf-8 -*-
"""G-ROLES · El registro de roles es válido y todo lo que cita existe.

Un rol que declara una restricción que refuto no sabe aplicar es una restricción que **no
existe**, y declararla es peor que no tenerla: se cita en las revisiones como si protegiera.
"""

from __future__ import annotations

from core.model import BLOCKED, FAIL, Finding, MEDIUM, PASS, Result, Scope
from core.roles import load, validate_registry

GATE_ID = "G-ROLES"
TITLE = "Registro de roles válido"
THRESHOLD = "esquema válido · restricciones aplicables · traspasos y puertas que existen"


def run(ctx) -> Result:
    from pathlib import Path
    reg_path = ""
    if ctx and getattr(ctx, "workspace", None):
        ws_reg = Path(ctx.workspace) / "roles" / "registry.json"
        if ws_reg.exists():
            reg_path = str(ws_reg)
    problems = validate_registry(reg_path)
    roles = {} if problems else load(reg_path)
    findings = [Finding("roles/registry.json", p) for p in problems]
    observations = []
    if roles:
        groups: dict = {}
        for r in roles.values():
            groups[r.group] = groups.get(r.group, 0) + 1
        observations.append("grupos: " + " · ".join(f"{g}({n})" for g, n in sorted(groups.items())))
        # El reparto de capacidades, publicado. «22 roles · 0 problemas» no permite
        # distinguir un registro cuyas restricciones se APLICAN de uno cuyas restricciones
        # sólo se describen, y ésa es justo la distincion que costo el defecto.
        from core.capabilities import APLICADAS, NO_OBSERVABLES
        usadas = {c for r in roles.values() for c in r.constraints}
        aplicadas = sorted(usadas & set(APLICADAS))
        declaradas = sorted(usadas & set(NO_OBSERVABLES))
        observations.append(
            f"capacidades: {len(aplicadas)} las aplica el guardian "
            f"({', '.join(aplicadas)}) · {len(declaradas)} declaradas NO observables en esta "
            f"frontera, con su motivo ({', '.join(declaradas)})")
        sin_gates = [r.id for r in roles.values() if not r.quality_gates]
        if sin_gates:
            observations.append(f"{len(sin_gates)} roles sin puerta declarada: "
                                f"{', '.join(sin_gates[:8])}. Su salida no la comprueba nadie.")
    # `Scope` es obligatorio para aprobar —`Result` lo exige y el veredicto lo comprueba— y
    # NINGUNA de las 13 puertas lo declaraba: medido el 2026-09-25, cero `scope=` en `gates/`.
    # Es la misma clase de defecto que este gate cierra: un campo que existe en el contrato y
    # que no usa nadie. `unknown=1` cuando el registro no se pudo cargar, porque no saber
    # cuantos roles hay no es haber comprobado cero.
    alcance = Scope(examined=len(roles), unknown=0 if roles else 1,
                    universe="roles declarados en roles/registry.json", declared=True)
    if not roles and not findings:
        status = BLOCKED
        measure = "0 roles encontrados en el registro · no hay sujetos que evaluar"
    else:
        status = PASS if not findings else FAIL
        measure = f"{len(roles)} roles · {len(findings)} problemas"
    return Result(GATE_ID, TITLE, status, severity=MEDIUM,
                  threshold=THRESHOLD,
                  measure=measure,
                  findings=findings, observations=observations, scope=alcance)
