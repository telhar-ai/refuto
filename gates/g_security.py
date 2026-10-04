# -*- coding: utf-8 -*-
"""G-SECURITY · Inventario, secretos y dependencias, con las herramientas que HAY.

Umbral: **cero secretos en el árbol · inventario de dependencias generado · cero
vulnerabilidades críticas sin excepción declarada.**

La regla que ordena esta puerta
-------------------------------
Cuando falta la herramienta que haría una comprobación, el resultado es **`BLOCKED`**, no
`PASS`. Un pipeline de seguridad que sale en verde porque el escáner no estaba instalado es
peor que no tener pipeline: da una garantía falsa, y las garantías falsas se citan.

Lo que sí se hace siempre, aunque no haya nada instalado: el escaneo de secretos propio del
harness, que corre con biblioteca estándar y no depende de nadie.
"""

from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path

from core.digest import redact
from core.model import (BLOCKED, CRITICAL, Evidence, FAIL, Finding, HIGH, NOT_EXECUTABLE,
                        PASS, Result, Scope)
from core.proc import TEXT_IO

GATE_ID = "G-SECURITY"
TITLE = "Seguridad: secretos, dependencias e inventario"
THRESHOLD = ("cero secretos en el árbol · SBOM generado · cero críticas sin excepción · "
             "herramienta ausente O FALLIDA = no aprueba · cero archivos recorridos = no "
             "aprueba")

SKIP = {".git", "node_modules", "__pycache__", ".venv", "dist", "build", "target", ".harness"}
BINARY_EXT = {".png", ".jpg", ".jpeg", ".gif", ".pdf", ".zip", ".gz", ".woff", ".woff2",
              ".ico", ".mp4", ".pyc", ".so", ".dylib", ".jar", ".class"}
MAX_BYTES = 2_000_000


def run(ctx) -> Result:
    findings, observations, evidence = [], [], []
    blocked = False
    #: Herramientas que SE INTENTARON y no se pudieron correr. No es lo mismo que ausentes —
    #: una falta y la otra revienta— pero para el veredicto pesan igual: en los dos casos no
    #: se sabe qué había. Ver `core.model.OUTCOME_STATUS` y FORMAL-MODEL §3.4.
    inejecutables: list = []

    # 1 · Secretos. Siempre corre: no depende de nada instalado.
    scanned, ilegibles, hits = _scan_secrets(ctx.workspace)
    for rel, line_no, labels in hits:
        findings.append(Finding(rel, f"posible secreto ({', '.join(labels)}). "
                                     f"Lo que entra al árbol, sale: el control es que el dato "
                                     f"no esté, no que no se mande.", line_no))
    evidence.append(Evidence(kind="computation", summary="escaneo de secretos propio",
                             excerpt=f"{scanned} archivos recorridos · {len(hits)} hallazgos"))

    if shutil.which("gitleaks"):
        out = _run_json(["gitleaks", "detect", "--no-banner", "--report-format", "json",
                         "--report-path", "-", "-s", str(ctx.workspace)])
        if out["ok"]:
            n = len(out["data"] or [])
            observations.append(f"gitleaks: {n} hallazgos")
            for h in (out["data"] or [])[:10]:
                findings.append(Finding(h.get("File", "?"),
                                        f"gitleaks: {h.get('RuleID', 'regla desconocida')}",
                                        int(h.get("StartLine") or 0)))
        else:
            inejecutables.append("gitleaks")
            observations.append(
                f"gitleaks está instalado y NO se pudo ejecutar: {out['error'][:120]}. "
                f"→ NOT_EXECUTABLE. Un escáner que revienta es epistémicamente idéntico a "
                f"uno ausente: en los dos casos no se sabe qué había.")
    else:
        observations.append("gitleaks NO está: el escaneo profundo de secretos no se ejecutó. "
                            "Sólo consta el escaneo propio de refuto, que es más superficial.")

    # 2 · Inventario de dependencias (SBOM).
    sbom_path = ctx.workspace / ".harness" / "evidence" / "sbom.json"
    if shutil.which("syft"):
        out = _run_json(["syft", "scan", f"dir:{ctx.workspace}", "-o", "syft-json"])
        if out["ok"] and out["data"]:
            from core.model import write_json
            write_json(sbom_path, out["data"])
            n = len(out["data"].get("artifacts") or [])
            evidence.append(Evidence(kind="command", summary=f"SBOM con {n} componentes",
                                     command="syft scan dir:. -o syft-json",
                                     source=str(sbom_path)))
            observations.append(f"SBOM generado: {n} componentes")
        else:
            inejecutables.append("syft")
            observations.append(
                f"syft está instalado y NO se pudo ejecutar: {out['error'][:120]}. "
                f"→ NOT_EXECUTABLE. Un escáner que revienta es epistémicamente idéntico a "
                f"uno ausente: en los dos casos no se sabe qué había.")
    else:
        blocked = True
        observations.append(
            "syft NO está: no hay inventario de dependencias. Sin SBOM no se puede responder "
            "«¿qué contiene esto?» ante un CVE. → BLOCKED, no PASS. Instale con `brew install syft`.")

    # 3 · Vulnerabilidades.
    if shutil.which("trivy"):
        out = _run_json(["trivy", "fs", "--skip-db-update", "--quiet", "--format", "json", "--severity",
                         "CRITICAL,HIGH", str(ctx.workspace)])
        if out["ok"]:
            crit = high = 0
            for res in (out["data"] or {}).get("Results", []):
                for v in res.get("Vulnerabilities") or []:
                    if v.get("Severity") == "CRITICAL":
                        crit += 1
                        findings.append(Finding(res.get("Target", "?"),
                                                f"CRÍTICA {v.get('VulnerabilityID')} en "
                                                f"{v.get('PkgName')}"))
                    else:
                        high += 1
            observations.append(f"trivy: {crit} críticas · {high} altas")
        else:
            inejecutables.append("trivy")
            observations.append(
                f"trivy está instalado y NO se pudo ejecutar: {out['error'][:120]}. "
                f"→ NOT_EXECUTABLE. Medido el 2026-09-23: con la base de datos de trivy "
                f"rota, esta puerta salía PASS sin haber escaneado una sola vulnerabilidad.")
    else:
        blocked = True
        observations.append("trivy NO está: no se escanearon vulnerabilidades conocidas. "
                            "→ BLOCKED. Instale con `brew install trivy`.")

    herramientas = [t for t in ("gitleaks", "syft", "trivy") if shutil.which(t)]
    scope = Scope(examined=scanned, unknown=ilegibles + len(inejecutables),
                  universe="archivos recorridos", declared=True)
    measure = (f"{scanned} archivos recorridos · {len(findings)} hallazgos · "
               f"{ilegibles} ilegibles · herramientas: {', '.join(herramientas) or 'ninguna'}"
               + (f" · NO EJECUTABLES: {', '.join(inejecutables)}" if inejecutables else ""))

    if findings:
        return Result(GATE_ID, TITLE, FAIL, severity=CRITICAL, threshold=THRESHOLD,
                      scope=scope, measure=measure, findings=findings,
                      observations=observations, evidence=evidence)
    # Una herramienta que se intentó y reventó NO es un aprobado. Va antes que `blocked`
    # porque dice más: se llegó a intentar.
    if inejecutables:
        return Result(GATE_ID, TITLE, NOT_EXECUTABLE, severity=HIGH, threshold=THRESHOLD,
                      scope=scope, measure=measure, observations=observations,
                      evidence=evidence)
    if blocked:
        return Result(GATE_ID, TITLE, BLOCKED, severity=HIGH, threshold=THRESHOLD,
                      scope=scope, measure=measure, observations=observations,
                      evidence=evidence)
    # Ámbito vacío. `status = ... else PASS` no consultaba `scanned`, así que un espacio
    # cuyo contenido vive bajo `node_modules/`, `dist/` o `target/` —o que sólo tiene
    # binarios— aprobaba con «0 archivos recorridos» escrito en su propia medida. Medido el
    # 2026-09-23 con una credencial AKIA real dentro de `node_modules/`: PASS, 0 hallazgos.
    # `∀x ∈ ∅ : P(x)` es cierto y no es evidencia. Ver FORMAL-MODEL §3.3.
    if scanned == 0:
        return Result(GATE_ID, TITLE, BLOCKED, severity=HIGH, threshold=THRESHOLD,
                      scope=scope,
                      measure="no se intentó — el escaneo propio no recorrió NINGÚN archivo. "
                              "El árbol puede estar vacío, o todo su contenido puede vivir "
                              "bajo directorios excluidos (" + ", ".join(sorted(SKIP)) + ") "
                              "o ser binario. Cero archivos comprobados no es cero secretos.",
                      observations=observations, evidence=evidence)
    if ilegibles:
        return Result(GATE_ID, TITLE, NOT_EXECUTABLE, severity=HIGH, threshold=THRESHOLD,
                      scope=scope,
                      measure=measure + " — hay archivos que no se pudieron leer: no se sabe "
                                        "qué contienen, y no saber no es estar bien.",
                      observations=observations, evidence=evidence)
    return Result(GATE_ID, TITLE, PASS, severity=HIGH, threshold=THRESHOLD,
                  scope=scope, measure=measure, observations=observations, evidence=evidence)


def _scan_secrets(root: Path) -> tuple[int, int, list]:
    """`(recorridos, ilegibles, hallazgos)`.

    `ilegibles` se contaba como cero: el `except OSError: continue` descartaba el archivo y
    no dejaba rastro, así que un archivo que no se pudo leer era indistinguible de uno
    limpio. Ahora se cuenta, y `Scope.unknown` impide aprobar con él dentro.
    """
    import os
    scanned, ilegibles, hits = 0, 0, []
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in SKIP]
        for name in filenames:
            p = Path(dirpath) / name
            if p.suffix.lower() in BINARY_EXT:
                continue
            try:
                if p.stat().st_size > MAX_BYTES:
                    continue
                text = p.read_text(encoding="utf-8", errors="ignore")
            except OSError:
                ilegibles += 1
                continue
            scanned += 1
            for n, line in enumerate(text.splitlines(), 1):
                _, labels = redact(line)
                if labels:
                    hits.append((str(p.relative_to(root)), n, labels))
    return scanned, ilegibles, hits


def _run_json(argv: list, timeout: int = 300) -> dict:
    try:
        p = subprocess.run(argv, capture_output=True, **TEXT_IO, timeout=timeout)
    except (OSError, subprocess.SubprocessError) as exc:
        return {"ok": False, "data": None, "error": str(exc)}
    if not (p.stdout or "").strip():
        # Salida vacía con código 0 se daba por buena (`ok=True, data=None`), así que una
        # herramienta que no llegó a emitir nada era indistinguible de una que no encontró
        # nada. Son dos hechos distintos: INVALID_OUTPUT no es OK.
        return {"ok": False, "data": None,
                "error": (p.stderr or "")[:300] or
                         f"no produjo salida (código {p.returncode}): no se puede afirmar "
                         f"que no encontrara nada"}
    try:
        return {"ok": True, "data": json.loads(p.stdout), "error": ""}
    except json.JSONDecodeError as exc:
        return {"ok": False, "data": None, "error": f"salida no era JSON: {exc}"}
