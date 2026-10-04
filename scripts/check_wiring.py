#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Revisión integral de conexión: ¿está cada componente **enchufado**, no sólo escrito?

Un módulo que existe y que nadie invoca es peor que no tenerlo: aparece en el inventario, se
cita en las revisiones, y no hace nada. Este guion recorre el árbol y comprueba que cada pieza
tiene al menos un consumidor real.

Se ejecuta en CI. Si añade un módulo y no lo conecta, esto falla — que es lo que hace que la
plataforma no se degrade en una colección de archivos sueltos.
"""
from __future__ import annotations

import ast
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from core.proc import force_utf8_io  # noqa: E402

# Estos guiones imprimen ✓ y ✗ y los ejecuta CI en cualquier sistema. En una consola
# cp1252 ese carácter no afeaba la salida: abortaba la comprobación con un Traceback,
# y una comprobación que no llega a hablar no dice «pasa» ni «falla».
force_utf8_io()
from core.proc import TEXT_IO  # noqa: E402

ROOT = Path(__file__).resolve().parents[1]

#: Módulos que se invocan por otra vía y no por `import`. Cada excepción lleva su razón, y su
#: propia comprobación más abajo: quedar exento del chequeo de import NO es quedar exento.
ENTRYPOINTS = {
    "core/guard.py":   "lo invocan los ganchos por `python3 -m core.guard`",
    "refuto.py":      "es el punto de entrada de la CLI",
    "tests/runner.py": "lo invoca `refuto selftest`",
}


def imported_by(module: str) -> list:
    """Quién importa este módulo, buscando en el árbol."""
    name = module.replace("/", ".").removesuffix(".py")
    short = name.split(".")[-1]
    out = []
    for path in sorted(ROOT.rglob("*.py")):
        # `as_posix()`: el resto del guion compara con '/' y convierte la ruta a nombre de
        # modulo con replace('/', '.'). Con separadores de Windows no casaba NADA, y este
        # verificador declaraba desconectado el arbol entero — 81 falsos positivos que,
        # por ser tantos, se aprenden a ignorar.
        rel = path.relative_to(ROOT).as_posix()
        if rel == module or ".git" in rel or "__pycache__" in rel:
            continue
        try:
            tree = ast.parse(path.read_text(encoding="utf-8"))
        except (OSError, SyntaxError):
            continue
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                if any(a.name == name for a in node.names):
                    out.append(rel)
            elif isinstance(node, ast.ImportFrom):
                mod = node.module or ""
                if mod == name or (mod == name.rsplit(".", 1)[0] and
                                   any(a.name == short for a in node.names)):
                    out.append(rel)
    return sorted(set(out))


def check_modules() -> list:
    problemas = []
    for path in sorted(ROOT.rglob("*.py")):
        # `as_posix()`: el resto del guion compara con '/' y convierte la ruta a nombre de
        # modulo con replace('/', '.'). Con separadores de Windows no casaba NADA, y este
        # verificador declaraba desconectado el arbol entero — 81 falsos positivos que,
        # por ser tantos, se aprenden a ignorar.
        rel = path.relative_to(ROOT).as_posix()
        if ".git" in rel or "__pycache__" in rel or rel.startswith("tests/"):
            continue
        if rel in ENTRYPOINTS or rel.endswith("__init__.py"):
            continue
        # Las puertas se cargan por `importlib` desde el registro, y los guiones los invoca
        # CI. Ninguno se importa, y los dos están conectados: se comprueban aparte, contra su
        # registro y contra el flujo. Exigir un `import` aquí sería medir la conexión con la
        # regla equivocada.
        if rel.startswith("gates/g_") or rel.startswith("scripts/"):
            continue
        # `experimental/` es diseño DECLARADO como no conectado. La declaración no se acepta
        # por estar en una carpeta con ese nombre: el módulo tiene que constar en su README,
        # con su estado. Una excepción que no se comprueba es una puerta trasera.
        if rel.startswith("experimental/"):
            # La primera versión de esta excepción aceptaba que el nombre del fichero
            # apareciera EN CUALQUIER SITIO del README. Un módulo colado pasaba con citarlo
            # una vez (comprobado el 2026-09-22): la excepción era la puerta trasera que
            # decía evitar. Ahora se exige una FILA de la tabla, con su estado declarado.
            doc = ROOT / "experimental" / "README.md"
            lineas = doc.read_text(encoding="utf-8").splitlines() if doc.is_file() else []
            nombre = Path(rel).name
            fila = next((l for l in lineas
                         if l.strip().startswith("|") and f"`{nombre}`" in l), "")
            estados = ("NOT_RUN", "NOT_APPLICABLE", "INCONCLUSIVE", "BLOCKED", "E0", "E1")
            if not fila:
                problemas.append(f"{rel}: está en experimental/ y no tiene fila en "
                                 f"experimental/README.md. Un módulo no conectado y no "
                                 f"declarado es código muerto, no un diseño.")
            elif not any(e in fila for e in estados):
                problemas.append(f"{rel}: su fila en experimental/README.md no declara estado "
                                 f"(uno de {', '.join(estados)}). Sin estado, la declaración "
                                 f"no dice nada.")
            continue
        consumidores = imported_by(rel)
        if not consumidores:
            problemas.append(f"{rel}: nadie lo importa. Un módulo que nadie invoca no está "
                             f"conectado: aparece en el inventario y no hace nada.")
        elif all(c.startswith("tests/") for c in consumidores):
            problemas.append(f"{rel}: sólo lo importan las pruebas. Está probado y no "
                             f"conectado a la plataforma.")
    return problemas


def check_cli() -> list:
    """Todo comando de la CLI resuelve, y toda función `cmd_*` está registrada."""
    problemas = []
    src = (ROOT / "refuto.py").read_text(encoding="utf-8")
    tree = ast.parse(src)
    definidos = {n.name for n in ast.walk(tree)
                 if isinstance(n, ast.FunctionDef) and n.name.startswith("cmd_")}
    registrados = set()
    for node in ast.walk(tree):
        if (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
                and node.func.attr == "set_defaults"):
            for kw in node.keywords:
                if kw.arg == "func" and isinstance(kw.value, ast.Name):
                    registrados.add(kw.value.id)
    for huerfano in sorted(definidos - registrados):
        problemas.append(f"refuto.py: {huerfano}() existe y no está registrado en ningún "
                         f"subcomando: no se puede invocar.")
    for fantasma in sorted(registrados - definidos):
        problemas.append(f"refuto.py: un subcomando apunta a {fantasma}(), que no existe.")

    proc = subprocess.run([sys.executable, str(ROOT / "refuto.py"), "--help"],
                          capture_output=True, **TEXT_IO, timeout=60)
    if proc.returncode != 0:
        problemas.append(f"refuto.py --help falla: {(proc.stderr or '')[:120]}")
    return problemas


def check_scripts() -> list:
    """Todo guion de `scripts/` lo invoca CI. Uno que nadie ejecuta no comprueba nada."""
    wf = ROOT / ".github" / "workflows" / "refuto.yml"
    if not wf.is_file():
        return ["no hay .github/workflows/refuto.yml: los guiones de scripts/ no los corre nadie"]
    texto = wf.read_text(encoding="utf-8")
    problemas = []
    for p in sorted((ROOT / "scripts").glob("*.py")):
        if p.name not in texto:
            problemas.append(f"scripts/{p.name}: existe y CI no lo ejecuta. "
                             f"Una comprobación que nadie corre no comprueba nada.")
    return problemas


def check_gates() -> list:
    sys.path.insert(0, str(ROOT))
    from gates.base import GATES
    problemas = []
    for gate_id, (module, _, _) in GATES.items():
        p = ROOT / (module.replace(".", "/") + ".py")
        if not p.is_file():
            problemas.append(f"{gate_id}: apunta a {module}, que no existe")
            continue
        if "def run(" not in p.read_text(encoding="utf-8"):
            problemas.append(f"{gate_id}: {module} no expone run(ctx)")
    # Y al revés: una puerta escrita y no registrada no corre nunca.
    for p in sorted((ROOT / "gates").glob("g_*.py")):
        mod = f"gates.{p.stem}"
        if mod not in {m for m, _, _ in GATES.values()}:
            problemas.append(f"{p.name}: es una puerta y NO está en el registro: no se ejecuta.")
    return problemas


def check_roles() -> list:
    sys.path.insert(0, str(ROOT))
    from core.roles import validate_registry
    return [f"roles/registry.json: {p}" for p in validate_registry()]


def check_adapters() -> list:
    sys.path.insert(0, str(ROOT))
    from adapters.registry import ADAPTERS
    problemas = []
    for p in sorted((ROOT / "adapters").glob("*.py")):
        if p.stem in ("__init__", "base", "registry"):
            continue
        if p.stem not in ADAPTERS:
            problemas.append(f"adapters/{p.name}: existe y NO está en el registro: "
                             f"ningún runtime lo usará.")
    return problemas


def check_context_chain() -> list:
    """La cadena que hace que un agente abierto a secas sepa dónde está."""
    sys.path.insert(0, str(ROOT))
    from core import context_files
    problemas = []
    for runtime, t in context_files.TARGETS.items():
        if not t.get("file"):
            problemas.append(f"context_files: «{runtime}» no declara archivo de contexto")
    if not hasattr(context_files, "install") or not hasattr(context_files, "audit"):
        problemas.append("context_files: falta install() o audit()")
    src = (ROOT / "refuto.py").read_text(encoding="utf-8")
    if "context_files.install" not in src:
        problemas.append("refuto.py: nadie llama a context_files.install(): el contexto "
                         "persistente no se genera nunca, y `claude` a secas no sabrá dónde está.")
    if "launcher.install" not in (ROOT / "core" / "wire.py").read_text(encoding="utf-8"):
        problemas.append("core/wire.py: no instala el lanzador: los ganchos apuntarían a rutas "
                         "incrustadas otra vez.")
    return problemas


BLOQUES = (
    ("módulos conectados", check_modules),
    ("guiones en CI", check_scripts),
    ("comandos de la CLI", check_cli),
    ("puertas registradas", check_gates),
    ("registro de roles", check_roles),
    ("adapters registrados", check_adapters),
    ("cadena de contexto", check_context_chain),
)


def main() -> int:
    total = 0
    for nombre, fn in BLOQUES:
        try:
            problemas = fn()
        except Exception as exc:                                        # noqa: BLE001
            problemas = [f"la comprobación falló: {type(exc).__name__}: {exc}"]
        marca = "✓" if not problemas else "✗"
        print(f"{marca} {nombre}")
        for p in problemas:
            print(f"    {p}")
        total += len(problemas)
    print()
    print("todo conectado" if not total else f"{total} desconexiones")
    return 0 if not total else 1


if __name__ == "__main__":
    raise SystemExit(main())
