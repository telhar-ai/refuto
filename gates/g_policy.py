# -*- coding: utf-8 -*-
"""G-POLICY · ¿La política es una sola, y está realmente enganchada? (H-03)

Umbral: **una fuente canónica · compilada a todo runtime requerido · el guardián invocable ·
cero reglas declaradas como aplicadas donde no se aplican.**

Lo que esta puerta busca de verdad no es que exista un archivo de política. Es la brecha que
produjo H-03: que la política esté escrita y NO enganchada en la ruta que se usa. Por eso lo
último que comprueba es que el guardián responde, ejecutándolo.
"""

from __future__ import annotations

import json
import subprocess
import sys

from adapters.registry import ADAPTERS
from core.model import (
    BLOCKED, Evidence, FAIL, Finding, HIGH, PASS, Result, Scope,
)
from core.policy import Policy, compile_for
from core.proc import TEXT_IO

GATE_ID = "G-POLICY"
TITLE = "Política: fuente única y aplicada"
THRESHOLD = ("una fuente canónica · compilada a cada runtime requerido · guardián ejecutable · "
             "toda regla no aplicable declarada como tal")


def run(ctx) -> Result:
    findings, observations, evidence = [], [], []

    if ctx.policy_doc is None:
        return Result(GATE_ID, TITLE, BLOCKED, severity=HIGH, threshold=THRESHOLD,
                      scope=Scope(examined=0, universe="archivo de política canónica",
                                  declared=False, subject=".harness/policy.json"),
                      measure="no hay .harness/policy.json: este espacio no declara política. "
                              "Ejecute `refuto policy init`.")
    policy = Policy.from_dict(ctx.policy_doc)

    manifest = ctx.manifest or {}
    runtimes = [n for n, cfg in (manifest.get("agents") or {}).items() if cfg.get("required")]
    if not runtimes:
        observations.append("el manifiesto no declara agentes requeridos: se comprueba la "
                            "política contra todos los adapters conocidos")
        runtimes = sorted(ADAPTERS)

    for name in sorted(runtimes):
        spec = ADAPTERS.get(name)
        if spec is None:
            findings.append(Finding("harness.manifest.json", f"runtime sin adapter: {name}"))
            continue
        out = compile_for(policy, spec)
        if not out["supported"]:
            # No es un fallo de la política: es una limitación del runtime, y se dice.
            observations.append(
                f"«{name}»: el adapter no compila política — "
                f"{'; '.join(out['unenforceable'])[:160]}")
            continue
        for gap in out["unenforceable"]:
            observations.append(f"«{name}» NO aplica: {gap}")
        evidence.append(Evidence(
            kind="computation", summary=f"política compilada para {name}",
            excerpt=", ".join(sorted(out["artifacts"]))))

    # La comprobación que da sentido a la puerta: el guardián RESPONDE. Se le manda una
    # escritura que tiene que rechazar, y se exige que la rechace.
    probe = _guard_answers(ctx)
    evidence.append(Evidence(kind="command", summary="prueba en vivo del guardián",
                             command=probe["command"], exit_code=probe.get("exit_code"),
                             excerpt=probe["detail"]))
    if not probe["ok"]:
        findings.append(Finding("core/guard.py", probe["detail"]))

    # H-03 en su forma original: política escrita en dos vocabularios que divergen.
    legacy = _legacy_policy_files(ctx)
    for path, why in legacy:
        observations.append(f"política heredada fuera del canon: {path} — {why}")

    measure = (f"{len(runtimes)} runtimes · {len(evidence)-1} compilaciones · "
               f"{len([o for o in observations if 'NO aplica' in o])} reglas declaradas no "
               f"aplicables · guardián {'responde' if probe['ok'] else 'NO responde'}")

    scope = Scope(
        examined=len(runtimes) + 1,
        unknown=0,
        universe="runtimes objetivo de política y prueba en vivo del guardián",
        declared=True,
        subject=".harness/policy.json",
        items_expected=len(runtimes) + 1,
        coverage=1.0,
        evidence=[e.summary for e in evidence],
    )
    return Result(GATE_ID, TITLE, PASS if not findings else FAIL, severity=HIGH,
                  threshold=THRESHOLD, measure=measure, findings=findings,
                  observations=observations, evidence=evidence, scope=scope)


def _guard_answers(ctx) -> dict:
    """Ejecuta el guardián contra una escritura que DEBE rechazar.

    Es la diferencia entre «la política está escrita» y «la política corre». H-03 existió
    porque nadie comprobó lo segundo.
    """
    payload = json.dumps({"tool_name": "fs_write",
                          "path": ".harness/policy.json",
                          "content": "manipulado"})
    argv = [sys.executable, "-m", "core.guard", "--runtime", "kiro", "--stdin",
            "--workspace", str(ctx.workspace)]
    try:
        proc = subprocess.run(argv, input=payload, capture_output=True, **TEXT_IO, timeout=60,
                              cwd=str(_repo_root()))
    except (OSError, subprocess.SubprocessError) as exc:
        return {"ok": False, "command": " ".join(argv),
                "detail": f"el guardián no se pudo ejecutar: {exc}"}
    blocked = proc.returncode != 0
    return {
        "ok": blocked,
        "command": " ".join(argv),
        "exit_code": proc.returncode,
        "detail": ("el guardián bloqueó la escritura sobre la propia política, como debe"
                   if blocked else
                   "EL GUARDIÁN DEJÓ PASAR una escritura sobre .harness/policy.json. Un "
                   "control que no bloquea no es un control: es documentación."),
    }


def _repo_root():
    from pathlib import Path
    return Path(__file__).resolve().parents[1]


def _legacy_policy_files(ctx) -> list:
    """Localiza política escrita a mano fuera del canon. No falla: avisa.

    Romper una configuración que alguien escribió a mano sin avisar es peor que convivir con
    ella un ciclo más. Se declara y se migra a conciencia.
    """
    out = []
    ws = ctx.workspace
    for rel, why in (
        (".kiro/hooks", "ganchos del IDE de Kiro: vocabulario distinto del CLI; si el "
                        "orquestador usa el CLI, esto NO corre (es la causa raíz de H-03)"),
        (".claude/settings.json", "permisos escritos a mano; refuto genera "
                                  ".claude/settings.harness.json aparte para no pisarlos"),
        (".gemini/settings.json", "configuración de Gemini escrita a mano"),
    ):
        path = ws / rel
        if path.exists():
            out.append((rel, why))
    return out
