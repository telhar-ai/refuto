# -*- coding: utf-8 -*-
"""Contexto persistente. Lo que hace que un agente sepa dónde está **sin que nadie se lo diga**.

El fallo que este módulo corrige
---------------------------------
Refuto enganchaba el control —el guardián— pero no dejaba contexto. Resultado: abrir
`claude` a secas en un espacio gobernado producía un agente que se presentaba como asistente
genérico, ofrecía «explorar el repo» y no sabía que había un estándar exigible, unas puertas y
unas rutas que no podía tocar. El control estaba; la conciencia de estar gobernado, no.

Y eso importa más de lo que parece: un agente que descubre las restricciones chocando contra
ellas gasta una vuelta por cada choque. Un agente que las conoce al arrancar no choca.

Cómo se resuelve, y por qué así
--------------------------------
Cada runtime lee por su cuenta un archivo de contexto del proyecto:

    claude     CLAUDE.md
    opencode   AGENTS.md
    gemini     GEMINI.md
    kiro       .kiro/steering/*.md

Refuto escribe **un solo documento** —`.harness/CONTEXTO.md`— y en cada archivo de contexto
deja un **bloque delimitado** que lo importa. Delimitado y no reescrito entero: `CLAUDE.md` suele
estar escrito a mano, y pisar el trabajo de alguien para instalar contexto es empezar mal.

    <!-- harness:inicio -->   …generado, se sobrescribe…   <!-- harness:fin -->

Lo de fuera de los marcadores no se toca nunca.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path

#: Los marcadores conservan el prefijo `harness:` aunque el producto se llame refuto: están
#: escritos en el `AGENTS.md`, el `CLAUDE.md` y el `GEMINI.md` de todos los espacios ya
#: instalados, y son lo único que permite reemplazar el bloque sin pisar lo de alrededor.
#: Renombrarlos convertiría cada uno de esos ficheros en «no había bloque» y duplicaría el
#: contenido. Es la misma regla que `.harness/`, `HARNESS_*` y los esquemas `harness.*/v1`:
#: el nombre del producto cambia; el formato de datos compartido, no.
INICIO = "<!-- harness:inicio · generado por `refuto install`; no editar dentro -->"
FIN = "<!-- harness:fin -->"
BLOQUE = re.compile(re.escape(INICIO) + r".*?" + re.escape(FIN), re.S)

DOC = ".harness/CONTEXTO.md"

#: Dónde deja cada runtime su contexto de proyecto, y si admite importación por referencia.
TARGETS = {
    "claude":   {"file": "CLAUDE.md", "import": True},
    "opencode": {"file": "AGENTS.md", "import": False},
    "gemini":   {"file": "GEMINI.md", "import": False},
}


@dataclass
class Written:
    path: str
    action: str      # created | updated | unchanged
    detail: str = ""


def _block(workspace: Path, *, use_import: bool, body: str) -> str:
    if use_import:
        # Claude Code resuelve `@ruta` como importación. Así el contenido vive en un sitio y no
        # se duplica en cuatro archivos que después divergen.
        cuerpo = (f"@{DOC}\n\n"
                  f"_(El contenido vive en `{DOC}`. Se regenera con `refuto install`.)_")
    else:
        cuerpo = body
    return f"{INICIO}\n\n{cuerpo}\n\n{FIN}"


def build_context(workspace: Path, *, spec: str = "") -> str:
    """El documento único. Es el mismo que `refuto chat` inyecta como prompt de sistema."""
    from core.session import build_brief
    brief, _, _ = build_brief(workspace, runtime="claude", spec=spec)
    return brief.replace("# Sesión gobernada por refuto",
                         "# Este espacio está gobernado por un harness")


def upsert(path: Path, block: str) -> Written:
    """Inserta o actualiza el bloque delimitado. Lo de fuera no se toca."""
    rel = path.name
    if not path.exists():
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(block + "\n", encoding="utf-8", newline="\n")
        return Written(rel, "created")
    texto = path.read_text(encoding="utf-8")
    if BLOQUE.search(texto):
        nuevo = BLOQUE.sub(lambda _: block, texto)
        if nuevo == texto:
            return Written(rel, "unchanged")
        path.write_text(nuevo, encoding="utf-8", newline="\n")
        return Written(rel, "updated", "bloque de refuto reemplazado")
    # Se añade al final: lo que la persona escribió arriba manda, y se lee primero.
    sep = "" if texto.endswith("\n") else "\n"
    path.write_text(f"{texto}{sep}\n{block}\n", encoding="utf-8", newline="\n")
    return Written(rel, "updated", "bloque añadido al final; lo anterior intacto")


def remove(path: Path) -> Written:
    if not path.exists():
        return Written(path.name, "unchanged", "no existía")
    texto = path.read_text(encoding="utf-8")
    nuevo = BLOQUE.sub("", texto).strip()
    if nuevo == texto.strip():
        return Written(path.name, "unchanged", "no había bloque de refuto")
    if not nuevo:
        path.unlink()
        return Written(path.name, "updated", "quedó vacío; se borró")
    path.write_text(nuevo + "\n", encoding="utf-8", newline="\n")
    return Written(path.name, "updated", "bloque retirado")


def install(workspace: Path, *, runtimes: list | None = None, spec: str = "") -> list:
    """Escribe el contexto y lo enlaza desde los archivos que cada runtime lee solo."""
    body = build_context(workspace, spec=spec)
    doc = workspace / DOC
    doc.parent.mkdir(parents=True, exist_ok=True)
    doc.write_text(body, encoding="utf-8", newline="\n")

    out = [Written(DOC, "created" if not doc.exists() else "updated",
                   f"{len(body.splitlines())} líneas")]
    for name in (runtimes or list(TARGETS)):
        t = TARGETS.get(name)
        if t is None:
            continue
        out.append(upsert(workspace / t["file"],
                          _block(workspace, use_import=t["import"], body=body)))

    # Kiro lee `.kiro/steering/*.md` entero. Se escribe un archivo propio, con nombre que no
    # colisiona con lo materializado del núcleo — y que V7 no vigila porque no es del núcleo.
    steering = workspace / ".kiro" / "steering"
    if steering.is_dir():
        p = steering / "zz-harness.md"
        p.write_text(f"{INICIO}\n\n{body}\n\n{FIN}\n", encoding="utf-8", newline="\n")
        out.append(Written(".kiro/steering/zz-harness.md", "updated"))
    return out


def uninstall(workspace: Path) -> list:
    out = []
    for t in TARGETS.values():
        out.append(remove(workspace / t["file"]))
    p = workspace / ".kiro" / "steering" / "zz-harness.md"
    if p.exists():
        p.unlink()
        out.append(Written(".kiro/steering/zz-harness.md", "updated", "borrado"))
    doc = workspace / DOC
    if doc.exists():
        doc.unlink()
        out.append(Written(DOC, "updated", "borrado"))
    return out


def audit(workspace: Path) -> dict:
    """¿Está el contexto puesto y al día en todos los sitios que hacen falta?"""
    doc = workspace / DOC
    estado = {"context_doc": doc.is_file(), "targets": {}, "stale": []}
    if not doc.is_file():
        estado["reason"] = f"falta {DOC}: ningún agente abierto a secas sabrá que hay un harness"
        return estado
    vigente = build_context(workspace)
    actual = doc.read_text(encoding="utf-8")
    if actual.strip() != vigente.strip():
        estado["stale"].append(DOC)
    for name, t in TARGETS.items():
        p = workspace / t["file"]
        tiene = p.is_file() and bool(BLOQUE.search(p.read_text(encoding="utf-8",
                                                               errors="ignore")))
        estado["targets"][name] = {"file": t["file"], "wired": tiene}
    estado["ok"] = doc.is_file() and all(v["wired"] for v in estado["targets"].values())
    return estado
