#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Todo esquema del repositorio cae dentro del subconjunto que `core.schema` implementa.

Un esquema que usa `allOf` validaría de menos en silencio, que es un verde falso.
"""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from core.proc import force_utf8_io  # noqa: E402

# Estos guiones imprimen ✓ y ✗ y los ejecuta CI en cualquier sistema. En una consola
# cp1252 ese carácter no afeaba la salida: abortaba la comprobación con un Traceback,
# y una comprobación que no llega a hablar no dice «pasa» ni «falla».
force_utf8_io()
from core.schema import SCHEMA_DIR, UnsupportedSchema, assert_supported, load_schema  # noqa: E402


def main() -> int:
    bad = 0
    for path in sorted(SCHEMA_DIR.glob("*.schema.json")):
        try:
            assert_supported(load_schema(path.name))
            print(f"✓ {path.name}")
        except UnsupportedSchema as exc:
            print(f"✗ {path.name}: {exc}")
            bad += 1
        except ValueError as exc:
            print(f"✗ {path.name}: JSON inválido — {exc}")
            bad += 1
    return 1 if bad else 0


if __name__ == "__main__":
    raise SystemExit(main())
