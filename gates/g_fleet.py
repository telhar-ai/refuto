# -*- coding: utf-8 -*-
"""G-FLEET · Deriva de lo materializado. (H-07)

El hallazgo que motiva esta puerta
----------------------------------
La flota de agentes se distribuye copiando carpetas a mano. Medido en un conjunto real de
cuatro proyectos que compartían la misma plantilla: **14 de 14** agentes compartidos habían
divergido, y **6 de 7** skills. Nadie lo sabía porque nadie lo miraba.

Qué comprueba
-------------
Que todo lo que el manifiesto declara materializado desde un origen siga coincidiendo con la
huella que el lock fijó — en las dos direcciones:

    declarado y ausente      se materializó y se borró
    presente y distinto      se materializó y se editó aquí
    presente y no declarado  hay algo del origen que el lock no cubre

La tercera es la que suele faltar en implementaciones caseras, y es la que deja entrar un
archivo que nadie revisó.
"""

from __future__ import annotations


from core.digest import sha256_file
from core.model import BLOCKED, FAIL, Finding, HIGH, PASS, Result, Scope

GATE_ID = "G-FLEET"
TITLE = "Deriva de la flota materializada"
THRESHOLD = "cero desviaciones en las tres direcciones · lo materializado no es fuente de verdad"


def run(ctx) -> Result:
    manifest = ctx.manifest or {}
    sources = manifest.get("sources") or {}
    if not sources:
        return Result(GATE_ID, TITLE, BLOCKED, severity=HIGH, threshold=THRESHOLD,
                      scope=Scope(examined=0, universe="orígenes materializados declarados en manifiesto",
                                  declared=False, subject="harness.manifest.json:sources"),
                      measure="el manifiesto no declara orígenes que materializar: nada que "
                              "comprobar, y por tanto nada que aprobar")
    lock = ctx.lock or {}
    locked = lock.get("sources") or {}

    findings, observations = [], []
    checked = 0

    for name, decl in sorted(sources.items()):
        entry = locked.get(name)
        if entry is None:
            findings.append(Finding("harness.lock.json",
                                    f"el manifiesto declara el origen «{name}» y el lock no lo "
                                    f"ancla: lo materializado no tiene huella conocida"))
            continue
        files = entry.get("files") or {}
        declared_dests = {m["to"] for m in (decl.get("materialize") or [])}

        for rel, expected in sorted(files.items()):
            checked += 1
            path = ctx.workspace / rel
            if not path.is_file():
                findings.append(Finding(rel, f"anclado por «{name}» y ausente del árbol"))
                continue
            if sha256_file(path) != expected:
                findings.append(Finding(
                    rel, f"editado en el espacio de trabajo: es una copia del origen «{name}» "
                         f"y no se modifica aquí. El cambio se propone al origen."))

        extra = declared_dests - set(files)
        for rel in sorted(extra):
            findings.append(Finding(
                rel, f"el manifiesto lo materializa desde «{name}» y el lock no lo ancla: "
                     f"entraría al árbol sin huella y sin revisión"))

        observations.append(f"«{name}»: {len(files)} archivos anclados en {entry.get('commit','?')[:12]}…")

    scope = Scope(
        examined=checked,
        unknown=0,
        universe="archivos materializados desde orígenes declarados en el manifiesto",
        declared=True,
        subject="harness.manifest.json:sources",
        items_expected=checked,
        coverage=1.0,
    )
    return Result(GATE_ID, TITLE, PASS if not findings else FAIL, severity=HIGH,
                  threshold=THRESHOLD,
                  measure=f"{len(sources)} orígenes · {checked} archivos comprobados · "
                          f"{len(findings)} desviaciones",
                  findings=findings, observations=observations, scope=scope)
