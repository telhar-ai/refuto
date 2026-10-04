#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""E2E del ancla certificada contra un clúster REAL de concordia (4 procesos `hicon node`).

No es una prueba de la suite: exige el binario y un clúster levantado. Cada paso imprime `estado
esperado` y `estado real`, y el guion termina declarando UN estado del vocabulario de refuto:

    PASS             todos los pasos coincidieron                        → código 0
    FAIL             algún paso dio algo distinto de lo esperado         → código 1
    NOT_EXECUTABLE   no hay `hicon`, o el clúster no levantó             → código 2

`NOT_EXECUTABLE` es lo que sale en CI, donde `hicon` no existe (vive en otro repositorio, en
Rust). Ese estado **no es un aprobado**: dice que la comprobación no se pudo hacer, y sale con un
código que no es 0 para que nadie lo lea como verde. Hasta el 2026-09-28 el guion no estaba en
ningún flujo de CI y `scripts/check_wiring.py` lo denunciaba con razón —«una comprobación que
nadie corre no comprueba nada»—; ahora CI lo ejecuta y publica el estado que salga.

    HICON_BIN=…/target/release/hicon CLUSTER_DIR=…/cluster \
    python3 scripts/e2e_ancla_concordia.py --base-api 8400 --n 4

Qué demuestra: (1) el pin se fija FUERA DE BANDA desde la configuración, no desde el clúster, y
coincide con lo que el clúster sirve; (2) `evidence --anchor` deja un ancla que `hicon verify-entry`
(Rust) también acepta — diferencial sobre datos reales; (3) `status` la relee offline; (4) truncar
el diario → FAIL; (5) con una réplica caída (f=1) sigue anclando; (6) con dos caídas no hay
quórum → NOT_EXECUTABLE, no PASS; (7) tras reiniciar TODO el clúster, el ancla vieja sigue
verificando offline y la nueva empieza en seq 1 (durabilidad: declarada inexistente).
"""

from __future__ import annotations

import argparse
import json
import os
import signal
import subprocess  # nosec B404
import sys
import tempfile
import time
from pathlib import Path

RAIZ = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(RAIZ))

from core.envelope import exit_for  # noqa: E402
from core.evidence import append_event, ledger_path  # noqa: E402
from core.model import FAIL, NOT_EXECUTABLE, PASS  # noqa: E402
from core.proc import TEXT_IO  # noqa: E402

HICON = os.environ.get("HICON_BIN", "")
CLUSTER = Path(os.environ.get("CLUSTER_DIR", ""))


def _veredicto(estado: str, motivo: str = "") -> int:
    """Una sola línea final con el estado y su código, derivado por la tabla del protocolo."""
    print(f"\n  E2E ancla certificada · {estado}" + (f" · {motivo}" if motivo else ""))
    return exit_for(estado)


def cli(ws: Path, *args: str) -> tuple:
    p = subprocess.run([sys.executable, str(RAIZ / "refuto.py"), "--workspace", str(ws), *args, "--json"],
                       capture_output=True, timeout=180, **TEXT_IO)  # nosec B603
    try:
        doc = json.loads(p.stdout)
    except ValueError:
        doc = {"raw": p.stdout[-600:], "stderr": p.stderr[-600:]}
    return p.returncode, doc


def http(url: str) -> dict | None:
    import urllib.request
    try:
        with urllib.request.urlopen(url, timeout=3) as r:  # nosec B310
            return json.loads(r.read())
    except Exception:  # noqa: BLE001
        return None


def esperar(fn, plazo: float = 30.0):
    fin = time.monotonic() + plazo
    while time.monotonic() < fin:
        if fn():
            return True
        time.sleep(0.5)
    return False


class Nodos:
    def __init__(self, n: int, base_api: int):
        self.n, self.base_api = n, base_api
        self.procs: dict = {}

    def arrancar(self, i: int):
        env = dict(os.environ)
        for linea in (CLUSTER / f"node-{i:02d}.env").read_text().splitlines():
            if "=" in linea:
                k, v = linea.split("=", 1)
                env[k] = v
        log = open(CLUSTER / f"node-{i:02d}.e2e.log", "ab")  # noqa: SIM115
        self.procs[i] = subprocess.Popen([HICON, "node", str(CLUSTER / f"node-{i:02d}.toml")],
                                         env=env, stdout=log, stderr=subprocess.STDOUT)  # nosec B603

    def parar(self, i: int):
        p = self.procs.pop(i, None)
        if p is not None:
            p.send_signal(signal.SIGTERM)
            try:
                p.wait(timeout=10)
            except subprocess.TimeoutExpired:
                p.kill()

    def sanos(self, indices) -> bool:
        return all(http(f"http://127.0.0.1:{self.base_api + i}/health") for i in indices)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--base-api", type=int, default=8300)
    ap.add_argument("--n", type=int, default=4)
    ap.add_argument("--ya-arrancados", action="store_true",
                    help="los nodos ya corren fuera de este guion (no se podrán parar/reiniciar)")
    o = ap.parse_args()
    if not HICON or not CLUSTER.is_dir():
        # Falta la dependencia externa (el binario de concordia, que vive en otro repositorio).
        # No es un error de uso —64 diría que el invocador se equivocó— ni un aprobado: es
        # NOT_EXECUTABLE, «se intentó y no se pudo», y sale con código 2.
        return _veredicto(NOT_EXECUTABLE,
                          f"sin clúster con el que medir: HICON_BIN={HICON or '(vacío)'} "
                          f"CLUSTER_DIR={CLUSTER or '(vacío)'}")
    endpoints = [f"http://127.0.0.1:{o.base_api + i}" for i in range(o.n)]
    nodos = Nodos(o.n, o.base_api)
    resultados: list = []

    def paso(nombre: str, esperado, real, detalle: str = ""):
        ok = (real == esperado) if not isinstance(esperado, (set, tuple)) else (real in esperado)
        resultados.append((nombre, esperado, real, ok, detalle))
        print(f"  [{'ok' if ok else 'XX'}] {nombre:<58} esperado={esperado} real={real}" + (f"  · {detalle}" if detalle else ""))

    if not o.ya_arrancados:
        for i in range(o.n):
            nodos.arrancar(i)
    if not esperar(lambda: nodos.sanos(range(o.n))):
        return _veredicto(NOT_EXECUTABLE, "el clúster no levantó: no hay nada contra lo que medir")

    # 1 · el pin sale de la CONFIGURACIÓN (fuera de banda), no del clúster
    fuera_de_banda = subprocess.run([HICON, "membership", "--export", str(CLUSTER / "node-00.toml")],
                                    capture_output=True, timeout=30, **TEXT_IO)  # nosec B603
    export_oob = json.loads(fuera_de_banda.stdout)
    pin = export_oob["membership_digest"]
    servida = http(endpoints[0] + "/v1/membership")
    paso("1 pin fuera de banda == digest que sirve el clúster", True, servida == export_oob, pin[:16] + "…")

    ws = Path(tempfile.mkdtemp(prefix="e2e-ancla-")).resolve()
    (ws / ".harness" / "evidence").mkdir(parents=True)
    for i in range(7):
        append_event(ws, {"kind": "policy/decision", "outcome": "deny", "n": i})
    manifest = {"schema": "harness.manifest/v1", "harness": {"version": "0.1.0"}, "agents": {}, "gates": [],
                "workspace": {"name": "e2e-ancla"},
                "anchoring": {"provider": "concordia", "endpoints": endpoints, "membership_digest": pin,
                              "timeout_s": 8, "pinned_by": "e2e", "pinned_at": "2026-09-27"}}
    (ws / ".harness" / "harness.manifest.json").write_text(json.dumps(manifest, indent=2), newline="\n")

    # 2 · anclar contra el clúster real
    rc, d = cli(ws, "evidence", "--anchor")
    anc = (d.get("payload") or {}).get("anchor") or {}
    paso("2 evidence --anchor con 4 réplicas", "PASS", d.get("status"), f"seq={anc.get('seq')} firmantes={anc.get('signers')} rc={rc}")
    ruta_ancla = anc.get("path")

    # 3 · diferencial: hicon verify-entry acepta la entrada guardada bajo la membresía guardada
    if ruta_ancla and Path(ruta_ancla).is_file():
        doc = json.loads(Path(ruta_ancla).read_text())
        with tempfile.TemporaryDirectory() as td:
            Path(td, "m.json").write_text(doc["membership_raw"], newline="\n")
            Path(td, "e.json").write_text(doc["entry_raw"], newline="\n")
            h = subprocess.run([HICON, "verify-entry", "--membership", f"{td}/m.json", "--entry", f"{td}/e.json"],
                               capture_output=True, timeout=30, **TEXT_IO)  # nosec B603
        paso("3 hicon verify-entry sobre el ancla real (diferencial Rust)", 0, h.returncode, h.stdout.strip()[:100])
        paso("3b el ancla no contiene material de clave privada", False,
             any(s in Path(ruta_ancla).read_text() for s in ("CONCORDIA_SECRET_KEY_HEX", "secret", "PRIVATE")))
    else:
        paso("3 hicon verify-entry sobre el ancla real", 0, "sin ancla")

    # 4 · status relee offline; truncar la cola → FAIL; restaurar → PASS
    rc, d = cli(ws, "status")
    paso("4 status con ancla íntegra", "PASS", d.get("status"), f"rc={rc}")
    L = ledger_path(ws).read_text().splitlines()
    ledger_path(ws).write_text("\n".join(L[:4]) + "\n", newline="\n")
    rc, d = cli(ws, "status")
    paso("4b status tras truncar la cola del diario", "FAIL", d.get("status"), f"rc={rc}")
    ledger_path(ws).write_text("\n".join(L) + "\n", newline="\n")
    rc, d = cli(ws, "status")
    paso("4c status tras restaurar", "PASS", d.get("status"))
    rc, d = cli(ws, "evidence", "--anchor-check")
    paso("4d evidence --anchor-check (offline)", "PASS", d.get("status"))

    if o.ya_arrancados:
        print("  (nodos externos: se omiten 5–7, que exigen pararlos)")
    else:
        # 5 · una réplica caída (f = 1): sigue anclando
        nodos.parar(3)
        time.sleep(1)
        rc, d = cli(ws, "evidence", "--anchor")
        anc = (d.get("payload") or {}).get("anchor") or {}
        paso("5 anchor con 1 réplica caída (n=4, f=1)", "PASS", d.get("status"), f"seq={anc.get('seq')} firmantes={anc.get('signers')}")
        # 6 · dos caídas: sin quórum → no hay certificado → NOT_EXECUTABLE (nunca PASS)
        nodos.parar(2)
        time.sleep(1)
        rc, d = cli(ws, "evidence", "--anchor")
        paso("6 anchor con 2 réplicas caídas (sin quórum)", "NOT_EXECUTABLE", d.get("status"), f"rc={rc}")
        rc, d = cli(ws, "status")
        paso("6b status sigue PASS: el ancla anterior se relee offline", "PASS", d.get("status"))
        # 7 · reinicio TOTAL: el log se pierde; el ancla vieja sigue verificando; la nueva empieza en seq 1
        for i in (0, 1):
            nodos.parar(i)
        time.sleep(1)
        for i in range(o.n):
            nodos.arrancar(i)
        if not esperar(lambda: nodos.sanos(range(o.n))):
            paso("7 el clúster volvió a levantar", True, False)
        else:
            time.sleep(2)
            log = http(endpoints[0] + "/v1/log?from=1&limit=10") or {}
            paso("7 tras reiniciar todo, el log está vacío (sin durabilidad, SPEC §8.4)", 0, log.get("last_executed"))
            rc, d = cli(ws, "status")
            paso("7b status: el ancla vieja sigue verificando OFFLINE", "PASS", d.get("status"))
            rc, d = cli(ws, "evidence", "--anchor")
            anc = (d.get("payload") or {}).get("anchor") or {}
            paso("7c anchor nuevo tras reinicio: seq vuelve a 1", 1, anc.get("seq"), f"estado={d.get('status')}")
            rc, d = cli(ws, "status")
            paso("7d status tras re-anclar", "PASS", d.get("status"))
        for i in list(nodos.procs):
            nodos.parar(i)

    malos = [r for r in resultados if not r[3]]
    print(f"\n  {len(resultados) - len(malos)}/{len(resultados)} pasos como se esperaba · espacio {ws}")
    if not resultados:
        # Un ámbito vacío no aprueba: cero pasos ejecutados no es un E2E que haya pasado.
        return _veredicto(NOT_EXECUTABLE, "no se ejecutó ni un paso")
    return _veredicto(FAIL if malos else PASS,
                      f"{len(malos)} paso(s) discrepan: {[r[0] for r in malos]}" if malos else
                      f"{len(resultados)}/{len(resultados)}")


if __name__ == "__main__":
    sys.exit(main())
