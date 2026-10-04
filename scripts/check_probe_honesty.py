#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""En un ejecutor sin agentes, la sonda debe decir NOT_INSTALLED — y decir por qué.

Lo que se comprueba aquí no es que los agentes existan: es que la sonda no miente cuando no
están. Un harness que marca «soportado» lo que no puede ejecutar es peor que no tener harness.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from core.proc import force_utf8_io  # noqa: E402

# Estos guiones imprimen ✓ y ✗ y los ejecuta CI en cualquier sistema. En una consola
# cp1252 ese carácter no afeaba la salida: abortaba la comprobación con un Traceback,
# y una comprobación que no llega a hablar no dice «pasa» ni «falla».
force_utf8_io()

VALID = {"NOT_INSTALLED", "INSTALLED", "STARTABLE", "FUNCTIONAL", "VERIFIED"}


USAGE = ("uso: check_probe_honesty.py <ruta-al-json-de-la-sonda>\n"
         "  el JSON es una lista de reportes con al menos {agent, level, stopped_because}.\n"
         "  genérelo con: refuto probe --json > sonda.json")


def main(argv) -> int:
    if len(argv) < 2:
        print(USAGE)
        return 2
    path = Path(argv[1])
    if not path.is_file():
        print(f"  ✗ no existe el archivo: {path}\n\n{USAGE}")
        return 2
    try:
        # `payload_of` acepta las dos formas: la lista suelta de antes del sobre y el
        # `harness.envelope/v1` de ahora. El puente vive en el contrato, no aquí.
        from core.envelope import payload_of
        reports = payload_of(json.loads(path.read_text(encoding="utf-8")))
    except ValueError as e:
        print(f"  ✗ no es JSON válido ({e})")
        return 2
    bad = 0
    for r in reports:
        level, why = r["level"], r.get("stopped_because", "")
        print(f"  {r['agent']:<10} {level:<14} {why[:80]}")
        if level not in VALID:
            print(f"    ✗ peldaño desconocido: {level}")
            bad += 1
        if level != "VERIFIED" and not why:
            print(f"    ✗ se detuvo en {level} y no dice por qué")
            bad += 1
    if not reports:
        print("  ✗ la sonda no devolvió nada")
        bad += 1
    return 1 if bad else 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
