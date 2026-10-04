# -*- coding: utf-8 -*-
"""G-HUMAN · Las revisiones humanas obligatorias existen, están decididas y las hizo otra persona.

Umbral: **toda revisión exigida por un rol ejecutado está APROBADA, con nombre, y por alguien
distinto de quien generó.**

La ausencia de una revisión obligatoria es `BLOCKED`. Nunca `PASS`.
"""

from __future__ import annotations

from core import humanreview as HR
from core.model import BLOCKED, Evidence, FAIL, Finding, HIGH, PASS, Result, Scope

GATE_ID = "G-HUMAN"
TITLE = "Revisión humana"
THRESHOLD = "toda revisión obligatoria decidida, con nombre, y por otra persona"


def run(ctx) -> Result:
    required, why = _required(ctx)
    if not required:
        return Result(GATE_ID, TITLE, BLOCKED, severity=HIGH, threshold=THRESHOLD,
                      scope=Scope(examined=0, universe="revisiones humanas exigidas por roles",
                                  declared=False, subject=".harness/human_review"),
                      measure=f"ningún rol ejecutado exige revisión humana ({why}); no hay "
                              f"nada que comprobar y por tanto nada que aprobar")

    out = HR.evaluate(ctx.workspace, required)
    pend = HR.pending(ctx.workspace)
    evidence = [Evidence(kind="file", summary=f"{r['kind']} · {r['decision']}",
                         source=r["subject"], excerpt=r.get("reviewer", ""))
                for r in out["reviews"]]

    # Falta ≠ rechazada. Lo primero bloquea; lo segundo es un no.
    #
    # Y lo que no cae en ninguno de los dos cubos es un FALLO, no un aprobado: la primera
    # versión clasificaba en dos listas y dejaba caer a PASS todo lo demás — una revisión
    # aprobada sin nombre pasaba. Aquí el resto va a `defectos`, que es donde debe ir.
    faltan = [p for p in out["problems"] if p.startswith("falta ") or "PENDIENTE" in p]
    defectos = [p for p in out["problems"] if p not in faltan]
    status = FAIL if defectos else (BLOCKED if faltan else PASS)
    # Sólo se adjuntan como hallazgos los defectos: los que faltan van a observaciones, porque
    # el contrato prohíbe PASS con hallazgos y BLOCKED no es un defecto del trabajo.
    findings = [Finding(".harness/" + HR.DIR, p) for p in defectos]
    observations = [f"pendiente: {p}" for p in faltan]
    scope = Scope(
        examined=len(required),
        unknown=len(defectos),
        universe=f"revisiones humanas exigidas ({', '.join(sorted(required))})",
        declared=True,
        subject=".harness/evidence/human-review"
    )

    return Result(GATE_ID, TITLE, status, severity=HIGH, threshold=THRESHOLD,
                  measure=f"{len(required)} revisiones exigidas · {len(out['reviews'])} "
                          f"registradas · {len(pend)} pendientes · {len(out['problems'])} problemas",
                  findings=findings, evidence=evidence, scope=scope,
                  observations=observations + [
                      f"exigidas por: {why}",
                      f"revisiones: {', '.join(sorted(required))}"])


def _required(ctx) -> tuple[list, str]:
    """Qué revisiones exigen los roles **realmente ejecutados**, y de dónde sale esa lista.

    Tres fuentes, por orden de precisión:
        1. el estado de la última ejecución — los roles que de verdad corrieron
        2. `roles` en el manifiesto — los que este espacio declara usar
        3. todos — sólo si no hay ninguna de las dos

    La primera versión usaba siempre la tercera, así que ejecutar una sola fase dejaba la
    puerta exigiendo las cinco revisiones del ciclo entero: siempre roja, y una puerta siempre
    roja se aprende a ignorar igual que una siempre verde.
    """
    from core.roles import load
    roles = load()

    from core.run import latest
    run = latest(ctx.workspace)
    if run is not None and run.steps:
        ejecutados = sorted({s.role for s in run.steps
                             if s.role and s.status in ("DONE", "BLOCKED", "FAILED")})
        if ejecutados:
            return (sorted({roles[r].human_review for r in ejecutados
                            if r in roles and roles[r].human_review}),
                    f"roles ejecutados en {run.run_id}: {', '.join(ejecutados)}")

    declared = (ctx.manifest or {}).get("roles") or []
    if declared:
        return (sorted({roles[r].human_review for r in declared
                        if r in roles and roles[r].human_review}),
                "roles declarados en el manifiesto")

    return (sorted({r.human_review for r in roles.values() if r.human_review}),
            "no consta qué roles se ejecutaron: se exigen TODAS las del ciclo")
