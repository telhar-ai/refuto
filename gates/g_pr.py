# -*- coding: utf-8 -*-
"""G-PR · El cambio como unidad de revisión: rama, diff, trazabilidad y separación de funciones.

Umbral: **no se trabaja sobre la rama por defecto · el cambio cita el requisito que lo justifica
· quien aprueba no es quien produjo.**

Por qué la rama importa
-----------------------
Porque la única capa de control que el agente NO puede tocar es la rama protegida y CI. Trabajar
directamente sobre la rama por defecto elimina esa capa, y con ella la única garantía real: las
otras dos viven en el repositorio y el agente puede editarlas.
"""

from __future__ import annotations

import json
import shutil
import subprocess

from core.model import BLOCKED, Evidence, FAIL, Finding, HIGH, PASS, Result, Scope
from core.proc import TEXT_IO

GATE_ID = "G-PR"
TITLE = "El cambio como unidad de revisión"
THRESHOLD = "rama de trabajo distinta de la por defecto · cambio trazado · sin auto-aprobación"


def run(ctx) -> Result:
    ws = ctx.workspace
    if not (ws / ".git").exists():
        return Result(GATE_ID, TITLE, BLOCKED, severity=HIGH, threshold=THRESHOLD,
                      scope=Scope(examined=0, universe="repositorio git", declared=False, subject="repositorio"),
                      measure="este espacio no es un repositorio git: no hay cambio que revisar")

    findings, observations, evidence = [], [], []
    branch = _git(ws, "rev-parse", "--abbrev-ref", "HEAD")
    default = _default_branch(ws)
    observations.append(f"rama actual «{branch}» · por defecto «{default}»")

    if branch and default and branch == default:
        findings.append(Finding("git", f"se está trabajando directamente sobre «{default}». "
                                       f"La rama protegida es la única capa de control que el "
                                       f"agente no puede tocar; trabajar aquí la elimina."))

    base = f"{default}...HEAD" if default and branch != default else ""
    # Se cuentan las DOS cosas: lo confirmado respecto de la rama base y lo que hay en el
    # árbol sin confirmar. Contar sólo lo primero decía «0 archivos cambiados» con el trabajo
    # recién hecho delante, porque el agente escribe antes de que nadie confirme nada.
    committed = [l for l in _git(ws, "diff", "--name-only", base).splitlines() if l.strip()] \
        if base else []
    working = [l[3:].strip() for l in _git(ws, "status", "--porcelain").splitlines()
               if l.strip()]
    changed = sorted(set(committed) | set(working))
    observations.append(
        f"{len(changed)} archivos cambiados · {len(committed)} confirmados respecto de "
        f"«{default or 'HEAD'}» · {len(working)} sin confirmar en el árbol")
    if working and not committed:
        observations.append(
            "todo el cambio está SIN CONFIRMAR: no hay commit que citar, así que la pregunta "
            "«¿qué requisito justifica este cambio?» no la responde la historia todavía")

    if base:
        subjects = _git(ws, "log", "--format=%s", base).splitlines()
        from core.trace import ANY_ID
        cited = {m.group(0) for s in subjects for m in ANY_ID.finditer(s)}
        if subjects and not cited:
            findings.append(Finding("git", f"ninguno de los {len(subjects)} commits cita un "
                                           f"requisito. «¿Qué requisito justifica este cambio?» "
                                           f"no tiene respuesta."))
        elif cited:
            observations.append(f"requisitos citados en los commits: {', '.join(sorted(cited))}")
            evidence.append(Evidence(kind="command", summary="commits del cambio",
                                     command=f"git log --format=%s {base}",
                                     excerpt=", ".join(sorted(cited))))

    # Separación de funciones: quien generó no puede aprobar.
    from core import humanreview as HR
    hr = HR.evaluate(ws, [HR.PR])
    for problem in hr["problems"]:
        if "quien generó" in problem:
            findings.append(Finding(".harness/" + HR.DIR, problem))
        elif "falta" in problem or "PENDIENTE" in problem:
            observations.append(problem)

    # Estado en la forja, si se puede consultar. No se pide credencial ni se autentica aquí.
    forge = _forge_status(ws)
    if forge["available"]:
        observations.append(forge["summary"])
        evidence.append(Evidence(kind="command", summary="estado del PR",
                                 command="gh pr view --json ...", excerpt=forge["summary"]))
        if forge.get("failing_checks"):
            findings.append(Finding("PR", f"comprobaciones en rojo: "
                                          f"{', '.join(forge['failing_checks'][:6])}"))
    else:
        observations.append(forge["summary"])

    pending_pr = any("HUMAN_PR_REVIEW" in p for p in hr["problems"])
    status = FAIL if findings else (BLOCKED if pending_pr else PASS)
    scope = Scope(
        examined=max(len(changed), 1),
        unknown=0,
        universe="archivos modificados y estado de revisión de la rama de trabajo",
        declared=True,
        subject=f"git branch {branch}",
        items_expected=len(changed),
        coverage=1.0,
        evidence=[e.summary for e in evidence],
    )
    return Result(GATE_ID, TITLE, status, severity=HIGH, threshold=THRESHOLD,
                  measure=f"rama «{branch}» · {len(changed)} archivos · {len(findings)} problemas",
                  findings=findings, observations=observations, evidence=evidence, scope=scope)


def _git(ws, *args) -> str:
    try:
        p = subprocess.run(["git", "-C", str(ws), *[a for a in args if a]],
                           capture_output=True, **TEXT_IO, timeout=30)
        return p.stdout.strip() if p.returncode == 0 else ""
    except (OSError, subprocess.SubprocessError):
        return ""


def _default_branch(ws) -> str:
    ref = _git(ws, "symbolic-ref", "refs/remotes/origin/HEAD")
    if ref:
        return ref.rsplit("/", 1)[-1]
    for name in ("main", "master", "develop"):
        if _git(ws, "rev-parse", "--verify", name):
            return name
    return ""


def _forge_status(ws) -> dict:
    """Estado del PR, si `gh` está y ya hay sesión. **No autentica ni pide credencial.**"""
    if not shutil.which("gh"):
        return {"available": False,
                "summary": "gh no está: el estado del PR no se pudo consultar. No es un fallo "
                           "del cambio; es una comprobación que no se pudo hacer."}
    try:
        auth = subprocess.run(["gh", "auth", "status"], capture_output=True, **TEXT_IO, timeout=30)
        if auth.returncode != 0:
            return {"available": False,
                    "summary": "gh está y no hay sesión iniciada: `gh auth login`. El estado "
                               "del PR no se consultó."}
        p = subprocess.run(["gh", "pr", "view", "--json",
                            "number,title,isDraft,reviewDecision,statusCheckRollup"],
                           cwd=str(ws), capture_output=True, **TEXT_IO, timeout=60)
        if p.returncode != 0:
            return {"available": False,
                    "summary": "no hay PR abierto para esta rama todavía"}
        d = json.loads(p.stdout or "{}")
        checks = d.get("statusCheckRollup") or []
        failing = [c.get("name", "?") for c in checks
                   if str(c.get("conclusion", "")).upper() in ("FAILURE", "TIMED_OUT",
                                                               "CANCELLED", "ACTION_REQUIRED")]
        return {"available": True, "failing_checks": failing,
                "summary": (f"PR #{d.get('number')} · {d.get('reviewDecision') or 'sin revisión'}"
                            f" · {len(checks)} comprobaciones, {len(failing)} en rojo"
                            f"{' · BORRADOR' if d.get('isDraft') else ''}")}
    except (OSError, subprocess.SubprocessError, ValueError) as exc:
        return {"available": False, "summary": f"no se pudo consultar la forja: {exc}"}
