# -*- coding: utf-8 -*-
"""G-SDD · Puente a un verificador EXTERNO que el espacio declara. **No se reescribe: se envuelve.**

Por qué un puente y no una reimplementación
--------------------------------------------
Hay espacios que ya tienen su propio juez —un conjunto de puertas escrito antes que refuto, con
su vocabulario, su evidencia y sus casos negativos—. Reescribir eso para que hablara el
vocabulario de refuto tiraría el activo para ganar simetría. Esta puerta lo ejecuta y traduce su
veredicto, y nada más.

Por qué la integración es DECLARADA y no adivinada
--------------------------------------------------
Esta puerta nació cableada a un repositorio concreto: ejecutaba `verificacion/verificar.py`,
leía `evidencia/informe.json` y traducía cuatro palabras en español, porque así se llamaban en
el espacio donde se escribió. Ese núcleo no se publica, así que para cualquier otro espacio la
puerta era un puente a un componente inalcanzable — y peor: encontrar un fichero con ese nombre
en el árbol bastaba para que refuto lo **ejecutara**.

Ahora el contrato se declara en el manifiesto del espacio, y sin declaración no se ejecuta nada:

    "integrations": {
      "spec_core": {
        "runner":  "verificacion/verificar.py",   ← qué se ejecuta (relativo al espacio)
        "args":    ["--json"],                    ← opcional
        "report":  "evidencia/informe.json",      ← dónde deja su informe
        "gates_key": "puertas",                   ← opcional: la lista de puertas dentro del informe
        "status_map": {"cumple": "PASS", "no cumple": "FAIL",
                       "pendiente": "BLOCKED", "no ejecutable": "NOT_EXECUTABLE"}
      }
    }

`gates_key`, `args` y `status_map` tienen valores por omisión (los de abajo). `runner` y
`report` no: son lo que hace que el puente apunte a algo concreto.

Correspondencia por omisión, que es la que hacía el puente original:

    cumple          → PASS
    no cumple       → FAIL
    pendiente       → BLOCKED           (no era ni verde ni rojo, y sigue sin serlo)
    no ejecutable   → NOT_EXECUTABLE

Sin integración declarada: `NOT_APPLICABLE`, nunca `PASS`
---------------------------------------------------------
Un espacio que no declara verificador externo no tiene sujeto para esta puerta. Eso no es un
aprobado ni un bloqueo: es que la puerta no aplica aquí, y así se declara, con motivo. Antes se
devolvía `BLOCKED`, que se lee como «falta algo por hacer» y llenaba de amarillo cualquier
espacio normal.
"""

from __future__ import annotations

import json
import subprocess
import sys

from core.model import (
    BLOCKED, Evidence, FAIL, Finding, HIGH, INFO, NOT_APPLICABLE, NOT_EXECUTABLE, PASS, Result,
    Scope,
)
from core.proc import TEXT_IO

GATE_ID = "G-SDD"
TITLE = "Puertas heredadas de un verificador externo"
THRESHOLD = ("el verificador que el espacio declara · su veredicto se respeta tal cual · "
             "sin integración declarada, no aplica")

#: Clave del manifiesto donde vive la declaración. `spec_core` y `sdd_core` valen igual: la
#: segunda es el nombre con el que nació y sigue habiendo manifiestos que la usan.
INTEGRATION_KEYS = ("spec_core", "sdd_core")

DEFAULT_STATUS_MAP = {
    "cumple": PASS,
    "no cumple": FAIL,
    "pendiente": BLOCKED,
    "no ejecutable": NOT_EXECUTABLE,
    # Los mismos en inglés, para un verificador que no hable español.
    "pass": PASS,
    "fail": FAIL,
    "blocked": BLOCKED,
    "not_executable": NOT_EXECUTABLE,
}
DEFAULT_GATES_KEY = "puertas"
DEFAULT_ARGS = ("--json",)
#: Claves del informe externo que se copian como procedencia, si están.
PROVENANCE_KEYS = ("commit", "rama", "branch", "nucleo", "core", "version")


def _declaration(ctx) -> tuple[dict, str]:
    """La integración declarada en el manifiesto, o («», motivo de que no la haya)."""
    try:
        manifest = ctx.manifest or {}
    except ValueError as exc:
        return {}, f"el manifiesto del espacio no es JSON válido: {exc}"
    if not isinstance(manifest, dict):
        return {}, "el manifiesto del espacio no es un objeto JSON"
    integrations = manifest.get("integrations")
    if not isinstance(integrations, dict):
        return {}, ""
    for key in INTEGRATION_KEYS:
        decl = integrations.get(key)
        if isinstance(decl, dict) and decl:
            return decl, ""
    return {}, ""


def run(ctx) -> Result:
    decl, problema = _declaration(ctx)
    if problema:
        return Result(GATE_ID, TITLE, NOT_EXECUTABLE, severity=HIGH, threshold=THRESHOLD,
                      measure=problema)

    if not decl:
        # Se dice si hay algo con pinta de verificador, pero NO se ejecuta: un programa que
        # aparece en el árbol no es un programa que este espacio haya autorizado a correr.
        pistas = [c for c in ("verificacion/verificar.py", "verification/verify.py")
                  if (ctx.workspace / c).is_file()]
        cola = (f" Hay `{pistas[0]}` en el árbol, pero el manifiesto no lo declara y no se "
                f"ejecuta nada sin declarar." if pistas else "")
        return Result(
            GATE_ID, TITLE, NOT_APPLICABLE, severity=INFO, threshold=THRESHOLD,
            scope=Scope(examined=0, universe="verificador externo SDD declarado en manifiesto",
                        declared=False, subject="harness.manifest.json:integrations"),
            measure=f"este espacio no declara ningún verificador externo en "
                    f"`integrations.spec_core` del manifiesto: no hay puertas heredadas que "
                    f"ejecutar. No es un fallo ni un aprobado — es que la puerta no tiene "
                    f"sujeto aquí.{cola}")

    runner_rel = str(decl.get("runner") or "")
    report_rel = str(decl.get("report") or "")
    if not runner_rel or not report_rel:
        return Result(GATE_ID, TITLE, NOT_EXECUTABLE, severity=HIGH, threshold=THRESHOLD,
                      measure="la integración declarada está incompleta: hacen falta `runner` "
                              "(qué se ejecuta) y `report` (dónde deja su informe). Una "
                              "declaración a medias no se completa adivinando.")

    runner = ctx.workspace / runner_rel
    if not runner.is_file():
        return Result(GATE_ID, TITLE, BLOCKED, severity=HIGH, threshold=THRESHOLD,
                      measure=f"el manifiesto declara el verificador «{runner_rel}» y ese "
                              f"archivo no está en el espacio. Declarado y ausente sí es un "
                              f"bloqueo: alguien contaba con él.")

    args = [str(a) for a in (decl.get("args") or DEFAULT_ARGS)]
    status_map = dict(DEFAULT_STATUS_MAP)
    declarado = decl.get("status_map")
    if isinstance(declarado, dict):
        status_map.update({str(k): str(v) for k, v in declarado.items()})
    gates_key = str(decl.get("gates_key") or DEFAULT_GATES_KEY)

    try:
        proc = subprocess.run([sys.executable, runner_rel, *args],
                              cwd=str(ctx.workspace), capture_output=True, **TEXT_IO, timeout=900)
    except (OSError, subprocess.SubprocessError) as exc:
        return Result(GATE_ID, TITLE, NOT_EXECUTABLE, severity=HIGH, threshold=THRESHOLD,
                      measure=f"{runner_rel} no se pudo ejecutar: {exc}")

    report = ctx.workspace / report_rel
    if not report.is_file():
        return Result(GATE_ID, TITLE, NOT_EXECUTABLE, severity=HIGH, threshold=THRESHOLD,
                      measure=f"{runner_rel} salió con {proc.returncode} y no dejó "
                              f"{report_rel}")
    try:
        doc = json.loads(report.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        return Result(GATE_ID, TITLE, NOT_EXECUTABLE, severity=HIGH, threshold=THRESHOLD,
                      measure=f"{report_rel} ilegible: {exc}")

    findings, observations = [], []
    statuses = []
    for gate in doc.get(gates_key) or []:
        mapped = status_map.get(str(gate.get("estado", gate.get("status", ""))), NOT_EXECUTABLE)
        statuses.append(mapped)
        if mapped != PASS:
            label = {FAIL: "en rojo", BLOCKED: "pendiente",
                     NOT_EXECUTABLE: "no ejecutable"}.get(mapped, mapped)
            clave = gate.get("clave") or gate.get("id") or "?"
            nombre = gate.get("nombre") or gate.get("name") or ""
            findings.append(Finding(f"{clave}", f"{nombre} — {label}: "
                                                f"{gate.get('medida', gate.get('measure', ''))}"))
            for h in (gate.get("hallazgos") or gate.get("findings") or [])[:4]:
                findings.append(Finding(f"{clave}", str(h)))

    # El veredicto compuesto respeta la misma jerarquía que el verificador: no ejecutable manda.
    if NOT_EXECUTABLE in statuses:
        status = NOT_EXECUTABLE
    elif FAIL in statuses:
        status = FAIL
    elif BLOCKED in statuses:
        status = BLOCKED
    elif statuses:
        status = PASS
    else:
        # El verificador corrió y su informe no contiene ni una puerta. Ámbito vacío: no
        # aprueba. Que el puente funcione no dice nada sobre lo que había al otro lado.
        return Result(
            GATE_ID, TITLE, NOT_EXECUTABLE, severity=HIGH, threshold=THRESHOLD,
            measure=f"{runner_rel} corrió y su informe no declara ninguna puerta bajo "
                    f"«{gates_key}»: no hay veredicto que traducir, y un puente vacío no "
                    f"aprueba nada",
            evidence=[Evidence(kind="command", summary="corrida del verificador declarado",
                               command=f"python3 {runner_rel} {' '.join(args)}",
                               exit_code=proc.returncode, source=str(report))])

    observations.append(f"veredicto del verificador, literal: "
                        f"{doc.get('veredicto', doc.get('verdict', '?'))}")
    prov = {k: doc.get(k) for k in PROVENANCE_KEYS if doc.get(k)}

    scope = Scope(
        examined=len(statuses),
        unknown=0,
        universe=f"puertas externas declaradas en {runner_rel}",
        declared=True,
        subject=str(runner_rel),
        items_expected=len(statuses),
        coverage=1.0,
    )
    return Result(GATE_ID, TITLE, status, severity=HIGH, threshold=THRESHOLD,
                  measure=f"{len(statuses)} puertas externas · "
                          f"{statuses.count(PASS)} cumplen · {statuses.count(FAIL)} en rojo · "
                          f"{statuses.count(BLOCKED)} pendientes · "
                          f"{statuses.count(NOT_EXECUTABLE)} no ejecutables",
                  findings=findings, observations=observations, provenance=prov,
                  evidence=[Evidence(kind="command",
                                     summary="corrida real del verificador declarado",
                                     command=f"python3 {runner_rel} {' '.join(args)}",
                                     exit_code=proc.returncode,
                                     source=str(report))],
                  scope=scope)
