# -*- coding: utf-8 -*-
"""G-AGENT · ¿Los agentes que este espacio declara necesitar, funcionan de verdad? (H-01)

Umbral: **todo agente `required` del manifiesto debe llegar al menos a FUNCTIONAL.**

Por qué FUNCTIONAL y no VERIFIED: VERIFIED gasta créditos y no puede exigirse en cada corrida
ni en CI sin convertir la verificación en una factura. FUNCTIONAL —el agente responde un
handshake estructurado— es gratis, tarda segundos y descarta el 100 % de los fallos de
instalación, firma y arranque observados. VERIFIED se exige a mano, con `--deep`.
"""

from __future__ import annotations

from core.model import (
    BLOCKED, CRITICAL, Evidence, FAIL, Finding, HIGH, PASS,
    Result, FUNCTIONAL, rung, Scope,
)
from core.probe import probe_all
from adapters.registry import ADAPTERS, all_specs

GATE_ID = "G-AGENT"
TITLE = "Ejecutabilidad real de los agentes"
THRESHOLD = "todo agente requerido alcanza FUNCTIONAL · ninguno se declara por `which`"


def run(ctx) -> Result:
    manifest = ctx.manifest or {}
    declared = manifest.get("agents") or {}
    required = [name for name, cfg in declared.items() if cfg.get("required")]
    optional = [name for name, cfg in declared.items() if not cfg.get("required")]

    unknown = [n for n in declared if n not in ADAPTERS]
    if unknown:
        return Result(GATE_ID, TITLE, FAIL, severity=CRITICAL, threshold=THRESHOLD,
                      measure=f"el manifiesto exige agentes sin adapter: {', '.join(sorted(unknown))}",
                      findings=[Finding("harness.manifest.json", f"no hay adapter para {n!r}")
                                for n in sorted(unknown)])

    wanted = set(required) | set(optional)
    specs = [s for s in all_specs() if not wanted or s.name in wanted]
    reports = ctx.probes or probe_all(specs, deep=ctx.deep, workspace=ctx.workspace)
    ctx.probes = reports
    by_name = {r.agent: r for r in reports}

    findings, observations, evidence = [], [], []
    for name in sorted(required):
        rep = by_name.get(name)
        if rep is None:
            findings.append(Finding(name, "requerido por el manifiesto y no sondeado"))
            continue
        evidence.append(Evidence(
            kind="probe", summary=f"{name} → {rep.level}", command=f"refuto probe {name}",
            source=rep.executable, excerpt=rep.stopped_because))
        if rung(rep.level) < rung(FUNCTIONAL):
            detail = rep.stopped_because or "no alcanzó FUNCTIONAL"
            if rep.signature.get("verdict") == "REVOKED":
                detail += " · CERTIFICADO DE FIRMA REVOKED — reinstale el agente"
            findings.append(Finding(name, f"se detuvo en {rep.level}: {detail}"))

    for name in sorted(optional):
        rep = by_name.get(name)
        if rep and rung(rep.level) < rung(FUNCTIONAL):
            observations.append(
                f"{name} (opcional) se detuvo en {rep.level}: {rep.stopped_because}")

    # Firma: no bloquea por sí sola —un binario de Homebrew relocalizado sale INVALID y
    # funciona— pero se dice siempre. Callarlo sería tapar una señal de cadena de suministro.
    for rep in reports:
        verdict = rep.signature.get("verdict")
        if verdict in ("INVALID", "REVOKED"):
            observations.append(
                f"firma de {rep.agent}: {verdict} sobre {rep.signature.get('subject','?')} — "
                f"{rep.signature.get('detail','')[:120]}")

    reached = sum(1 for r in reports if rung(r.level) >= rung(FUNCTIONAL))
    measure = (f"{len(reports)} agentes sondeados · {reached} FUNCTIONAL o mejor · "
               f"{len(required)} requeridos · {len(findings)} incumplen")

    if not required:
        return Result(GATE_ID, TITLE, BLOCKED, severity=HIGH, threshold=THRESHOLD,
                      scope=Scope(examined=0, universe="agentes declarados en el manifiesto",
                                  declared=False, subject="harness.manifest.json:agents"),
                      measure="el manifiesto no declara ningún agente requerido: no hay nada "
                              "que exigir, y por tanto nada que aprobar",
                      observations=observations, evidence=evidence)

    scope = Scope(
        examined=len(reports), unknown=0,
        universe="agentes requeridos y opcionales sondeados en el entorno",
        declared=True, subject="harness.manifest.json:agents",
        items_expected=len(specs), coverage=len(reports) / len(specs) if specs else 1.0,
        evidence=[e.summary for e in evidence],
    )
    return Result(
        GATE_ID, TITLE, PASS if not findings else FAIL,
        severity=CRITICAL, threshold=THRESHOLD, measure=measure,
        findings=findings, observations=observations, evidence=evidence,
        scope=scope)
