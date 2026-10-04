# -*- coding: utf-8 -*-
"""G-TRACE · La cadena de trazabilidad está completa y no cita fantasmas.

Umbral: **cero citas a requisitos inexistentes · cero requisitos sin prueba que los nombre.**

La primera mitad detecta un defecto medido en un repositorio real: tres pruebas citaban
`REQ-022`, `REQ-023` y `REQ-024`, que no existen. Una prueba que cita un requisito fantasma
parece cobertura y no lo es — es peor que no citar nada, porque engaña al que cuenta.
"""

from __future__ import annotations

from core.model import BLOCKED, Evidence, FAIL, Finding, HIGH, PASS, Result, Scope
from core.trace import build

GATE_ID = "G-TRACE"
TITLE = "Trazabilidad de la cadena"
THRESHOLD = "cero citas a requisitos inexistentes · cero requisitos sin prueba"


def run(ctx) -> Result:
    g = build(ctx.workspace)
    if not g.requirements:
        return Result(GATE_ID, TITLE, BLOCKED, severity=HIGH, threshold=THRESHOLD,
                      scope=Scope(examined=0, universe="documentos de requisitos en el espacio",
                                  declared=False, subject="documentos de requisitos"),
                      measure="no se encontró ningún documento de requisitos: no hay cadena "
                              "que comprobar y por tanto nada que aprobar")

    doc = g.to_dict()
    findings = []
    for phantom in doc["phantom_citations"]:
        sites = [l for l in g.links if l.requirement == phantom][:4]
        for l in sites:
            findings.append(Finding(l.where, f"cita {phantom}, que no existe en ningún "
                                             f"documento de requisitos", l.line))
    for rid in doc["untested"]:
        findings.append(Finding("requisitos", f"{rid} no lo nombra ninguna prueba: "
                                              f"«está implementado» no se puede comprobar"))

    observations = []
    if doc["orphans"]:
        observations.append(f"{len(doc['orphans'])} requisitos sin código NI prueba: "
                            f"{', '.join(doc['orphans'][:8])}")
    observations.append(
        "Esta puerta comprueba que la CITA existe, no que la prueba compruebe lo correcto. "
        "Lo segundo lo mira la revisión humana.")

    evidence = [Evidence(kind="computation", summary="cadena de trazabilidad",
                         excerpt=f"{len(doc['coverage'])} requisitos indexados")]
    scope = Scope(
        examined=len(g.requirements) + len(g.links),
        unknown=0,
        universe="requisitos indexados y citas encontradas en código/pruebas",
        declared=True,
        subject="cadena de trazabilidad",
        items_expected=len(g.requirements),
        coverage=1.0 if not doc["untested"] else ((len(g.requirements) - len(doc["untested"])) / len(g.requirements)),
        evidence=[e.summary for e in evidence],
    )
    return Result(GATE_ID, TITLE, PASS if not findings else FAIL, severity=HIGH,
                  threshold=THRESHOLD,
                  measure=f"{len(g.requirements)} requisitos · {len(g.links)} citas · "
                          f"{len(doc['phantom_citations'])} fantasmas · "
                          f"{len(doc['untested'])} sin prueba",
                  findings=findings, observations=observations,
                  evidence=evidence, scope=scope)
