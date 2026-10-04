#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Centinela del árbol: detecta que alguien más escribió, en vez de suponer que nadie lo hizo.

    python3 scripts/tree_sentinel.py snapshot --out /tmp/antes.json
    …trabajo…
    python3 scripts/tree_sentinel.py verify --against /tmp/antes.json --mine core/run.py

Por qué existe
--------------
El 2026-09-22, con dos IDE residentes sobre este mismo árbol, ocurrió esto:

  1. una sonda mutó `core/evidence.py`, lo restauró y **verificó el sha256 en proceso**;
  2. `git diff` mostró la mutación **después**;
  3. `scripts/mutate_probe.py` —creado en esa sesión— apareció modificado por un tercero.

Dos observaciones que sólo un escritor externo reconcilia. La reacción cómoda es exigir una
máquina en silencio. La reacción correcta es **medir**: un sistema de assurance que sólo
funciona cuando nadie más toca el disco no está asegurando nada, está pidiendo condiciones.

Qué garantiza y qué no
----------------------
Garantiza **detección**, no exclusión. No impide que otro proceso escriba; impide que esa
escritura pase inadvertida y contamine una conclusión. Es la diferencia entre «el árbol estaba
quieto» (que no se puede saber) y «si se movió, me enteré» (que sí).

    PASS   nada cambió fuera de lo declarado con --mine
    FAIL   alguien escribió algo que esta sesión no declaró
    BLOCKED  no se pudo leer parte del árbol → no se puede afirmar que no cambió

`BLOCKED` no es `PASS`: un fichero ilegible es un fichero del que no se sabe nada.
"""

from __future__ import annotations

import argparse
import fnmatch
import hashlib
import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCHEMA = "harness.sentinel/v1"

#: Se excluye lo que cambia por el mero hecho de trabajar y no dice nada de una interferencia.
#: `.harness/evidence/` entra aquí porque toda orden del guardián escribe en el diario: incluirlo
#: haría que el centinela se detectara a sí mismo y el aviso se volvería ruido.
EXCLUIR = (
    ".git/*", "*/__pycache__/*", "__pycache__/*", "*.pyc", ".DS_Store", "*/.DS_Store",
    ".harness/evidence/*", ".harness/state/*", ".harness/context/*",
)


def _excluido(rel: str) -> bool:
    return any(fnmatch.fnmatch(rel, p) for p in EXCLUIR)


def recorrer(root: Path) -> tuple[dict, list]:
    """(rel → sha256, ilegibles). La segunda lista no es opcional."""
    huellas: dict = {}
    ilegibles: list = []
    for base, dirs, files in os.walk(root):
        dirs[:] = [d for d in dirs if not _excluido(
            str(Path(base, d).relative_to(root)).replace(os.sep, "/") + "/x")]
        for f in files:
            p = Path(base, f)
            rel = str(p.relative_to(root)).replace(os.sep, "/")
            if _excluido(rel):
                continue
            try:
                huellas[rel] = hashlib.sha256(p.read_bytes()).hexdigest()
            except OSError as exc:
                ilegibles.append({"path": rel, "problem": f"{type(exc).__name__}: {exc}"})
    return huellas, ilegibles


def cmd_snapshot(o) -> int:
    huellas, ilegibles = recorrer(ROOT)
    doc = {
        "schema": SCHEMA,
        "taken_at": datetime.now(timezone.utc).astimezone().isoformat(timespec="milliseconds"),
        "root": str(ROOT),
        "pid": os.getpid(),
        "files": huellas,
        "unreadable": ilegibles,
    }
    # `newline="\n"` explícito: en Windows `write_text` escribiría CRLF y la huella del mismo
    # documento dejaría de coincidir — que es justo lo que este centinela existe para detectar.
    Path(o.out).write_text(json.dumps(doc, ensure_ascii=False, indent=2) + "\n",
                           encoding="utf-8", newline="\n")
    estado = "BLOCKED" if ilegibles else "PASS"
    print(f"  {len(huellas)} ficheros · {len(ilegibles)} ilegibles · {estado} → {o.out}")
    return 0


def cmd_verify(o) -> int:
    antes = json.loads(Path(o.against).read_text(encoding="utf-8"))
    if antes.get("schema") != SCHEMA:
        print(f"  esquema desconocido {antes.get('schema')!r}: no se puede comparar. BLOCKED",
              file=sys.stderr)
        return 2
    viejo = antes["files"]
    nuevo, ilegibles = recorrer(ROOT)
    mios = set(o.mine or [])

    cambiados = sorted(k for k in viejo.keys() & nuevo.keys() if viejo[k] != nuevo[k])
    nuevos = sorted(nuevo.keys() - viejo.keys())
    borrados = sorted(viejo.keys() - nuevo.keys())

    ajenos = {"modificado": [k for k in cambiados if k not in mios],
              "creado": [k for k in nuevos if k not in mios],
              "borrado": [k for k in borrados if k not in mios]}
    declarados = sum(len([k for k in lst if k in mios])
                     for lst in (cambiados, nuevos, borrados))
    total_ajeno = sum(len(v) for v in ajenos.values())

    if o.json:
        print(json.dumps({"schema": SCHEMA, "declarado": declarados, "ajeno": ajenos,
                          "unreadable": ilegibles}, ensure_ascii=False, indent=2))
    else:
        print(f"\n  declarado por esta sesión (--mine): {declarados} cambio(s)")
        if total_ajeno:
            print(f"  ✗ AJENO: {total_ajeno} cambio(s) que esta sesión NO declaró")
            for verbo, rutas in ajenos.items():
                for r in rutas:
                    print(f"      {verbo:<12} {r}")
        else:
            print("  ✓ ningún cambio ajeno")
        if ilegibles:
            print(f"  ⊘ {len(ilegibles)} ilegibles: de éstos no se puede afirmar que no cambiaron")
            for u in ilegibles[:5]:
                print(f"      {u['path']}: {u['problem']}")

    # Ilegible no aprueba: si no se pudo leer, no se sabe.
    if ilegibles:
        return 2
    return 1 if total_ajeno else 0


def main() -> int:
    ap = argparse.ArgumentParser(description="centinela de interferencia sobre el árbol")
    sub = ap.add_subparsers(dest="cmd", required=True)
    s = sub.add_parser("snapshot", help="huella sha256 de todo el árbol")
    s.add_argument("--out", required=True)
    s.set_defaults(fn=cmd_snapshot)
    v = sub.add_parser("verify", help="qué cambió, y quién no lo declaró")
    v.add_argument("--against", required=True)
    v.add_argument("--mine", action="append", help="ruta que ESTA sesión sí cambió a propósito")
    v.add_argument("--json", action="store_true")
    v.set_defaults(fn=cmd_verify)
    o = ap.parse_args()
    return o.fn(o)


if __name__ == "__main__":
    raise SystemExit(main())
