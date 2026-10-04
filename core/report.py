# -*- coding: utf-8 -*-
"""Presentación. Se genera DESDE la evidencia estructurada, nunca al revés."""

from __future__ import annotations

import os
import sys

from core.model import BLOCKED, FAIL, NOT_APPLICABLE, NOT_EXECUTABLE, PASS, SYMBOL

_TTY = sys.stdout.isatty() and os.environ.get("NO_COLOR") is None
#: `NOT_APPLICABLE` va en gris y NO en verde: no ha demostrado nada. Pintarlo como un aprobado
#: sería deshacer en la presentación lo que el estado existe para distinguir.
_C = {PASS: "32", FAIL: "31", BLOCKED: "33", NOT_EXECUTABLE: "31", NOT_APPLICABLE: "2"}


def paint(text: str, code: str) -> str:
    return f"\033[{code}m{text}\033[0m" if _TTY else text


def dim(text: str) -> str:
    return paint(text, "2")


def bold(text: str) -> str:
    return paint(text, "1")


def status_tag(status: str) -> str:
    return paint(f"{SYMBOL[status]} {status}", _C[status])


def render(results: list, verdict: str, *, verbose: bool = False) -> str:
    lines = [""]
    for r in results:
        lines.append(f"  {status_tag(r.status):22} {bold(r.id)} · {r.name}")
        if r.threshold:
            lines.append(dim(f"      umbral: {r.threshold}"))
        if r.measure:
            lines.append(f"      {r.measure}")
        for f in r.findings[: (200 if verbose else 6)]:
            lines.append(paint(f"      ✗ {f.as_text()}", _C[FAIL]))
        if len(r.findings) > 6 and not verbose:
            # La orden ENTERA, y no el nombre de la bandera. `--verbose` es global y va ANTES
            # del subcomando, así que quien leía «use --verbose» escribía `refuto verify
            # --verbose` —lo natural— y recibía `unrecognized arguments: --verbose` con salida
            # 64. Un `next` que no se puede pegar en la consola no es un `next`: es el mismo
            # defecto que `core.envelope.Siguiente` documenta para `do`, «una orden ejecutable,
            # no una descripción», aplicado al texto que sí lee una persona.
            lines.append(dim(f"      … y {len(r.findings) - 6} más "
                             f"(véalos con  refuto --verbose verify)"))
        for o in r.observations[: (200 if verbose else 4)]:
            lines.append(dim(f"      i {o}"))
        lines.append("")
    lines.append(f"  {bold('VEREDICTO:')} {verdict}")
    lines.append("")
    return "\n".join(lines)


def render_probes(reports: list) -> str:
    from core.model import FUNCTIONAL, rung
    lines = ["", f"  {bold('Agentes')}"]
    for r in reports:
        good = rung(r.level) >= rung(FUNCTIONAL)
        tag = paint(f"{'✓' if good else '✗'} {r.level:<12}", "32" if good else "31")
        lines.append(f"    {tag} {r.agent:<10} {r.version or '?':<10} "
                     f"{dim(r.protocol.get('family','') + ('/v' + str(r.protocol['version']) if r.protocol.get('version') else ''))}")
        if r.stopped_because:
            lines.append(dim(f"        ↳ {r.stopped_because}"))
        verdict = r.signature.get("verdict")
        if verdict in ("REVOKED", "INVALID"):
            lines.append(paint(f"        ↳ firma {verdict}: {r.signature.get('subject','')}",
                               "31" if verdict == "REVOKED" else "33"))
    lines.append("")
    return "\n".join(lines)
