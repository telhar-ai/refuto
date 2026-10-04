#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Comprueba que refuto no importa nada fuera de la biblioteca estándar.

Es una promesa del diseño (ADR-0002) y las promesas de diseño se erosionan con un `import`
distraído. Aquí se comprueba en vez de confiar.
"""
from __future__ import annotations

import ast
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from core.proc import force_utf8_io  # noqa: E402

# Estos guiones imprimen ✓ y ✗ y los ejecuta CI en cualquier sistema. En una consola
# cp1252 ese carácter no afeaba la salida: abortaba la comprobación con un Traceback,
# y una comprobación que no llega a hablar no dice «pasa» ni «falla».
force_utf8_io()

ROOT = Path(__file__).resolve().parents[1]
#: Paquetes y módulos del propio repositorio. `refuto` es el punto de entrada.
LOCAL = {"core", "adapters", "gates", "tests", "schemas", "refuto", "experimental"}


def top_level(node) -> set:
    out = set()
    if isinstance(node, ast.Import):
        out |= {a.name.split(".")[0] for a in node.names}
    elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
        out.add(node.module.split(".")[0])
    return out


def main() -> int:
    stdlib = set(sys.stdlib_module_names)
    offenders = []
    for path in sorted(ROOT.rglob("*.py")):
        if any(p in {".git", "__pycache__"} for p in path.parts):
            continue
        try:
            tree = ast.parse(path.read_text(encoding="utf-8"))
        except SyntaxError as exc:
            print(f"✗ {path.relative_to(ROOT)}: no compila — {exc}")
            return 1
        for node in ast.walk(tree):
            for name in top_level(node):
                if name in stdlib or name in LOCAL or name.startswith("_"):
                    continue
                offenders.append(f"{path.relative_to(ROOT)}: import {name}")
    if offenders:
        print("✗ dependencias fuera de la biblioteca estándar:")
        for o in offenders:
            print(f"    {o}")
        print("\n  Refuto debe poder diagnosticar una máquina donde aún no se instaló nada.")
        return 1
    print("✓ sólo biblioteca estándar")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
