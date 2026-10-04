# -*- coding: utf-8 -*-
"""Contexto de una corrida. Lo que toda puerta recibe y nada más.

Una puerta que va a buscar sus datos por su cuenta es una puerta que no se puede probar con
una entrada falsa. Todo entra por aquí, y por eso `tests/fixtures/` puede fabricar espacios de
trabajo completos sin tocar nada real.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from functools import cached_property
from pathlib import Path

#: Los nombres del directorio y de los ficheros del espacio NO llevan el nombre del producto.
#: `.harness/`, `harness.manifest.json`, `harness.lock.json` y los `$schema` `harness.*/v1` son
#: un FORMATO DE DATOS que ya existe en espacios instalados: renombrarlos al renombrar el
#: producto rompería todos ellos sin ganar nada. Lo mismo vale para las variables `HARNESS_*`.
MANIFEST_NAME = "harness.manifest.json"
LOCK_NAME = "harness.lock.json"
POLICY_NAME = "policy.json"

# ── convenciones declarables del espacio ─────────────────────────────────────────────
#: Dónde vive el documento de requisitos, por convención con nombre.
#:
#: Estaba cableado a UNA distribución concreta —la de un espacio multi-repo donde las specs
#: cuelgan de `sdd/espacios/<nombre>/especificacion/`— y por eso un espacio con otra
#: organización no encontraba ninguna. Ahora las convenciones tienen nombre, el espacio puede
#: elegir cuáles usa, y puede declarar las suyas.
SPEC_LAYOUTS: dict = {
    # Convención de Kiro: `.kiro/specs/<nombre>/requirements.md`.
    "kiro": (".kiro/specs/*/requirements.md",),
    # Plana: la spec en la raíz del repositorio o bajo `specs/`.
    "flat": ("specs/*/requirements.md", "requirements.md", "docs/requirements.md"),
    # SDD: `sdd/espacios/<nombre>/especificacion/requirements.md`. Se enumeran tres
    # profundidades y no se usa `rglob` a propósito: en un espacio de trabajo con cientos de
    # miles de archivos, recorrerlo entero para redactar un informe cuesta más que la sesión.
    # Medido en un espacio real de ~300 000 ficheros.
    "sdd": ("sdd/espacios/*/especificacion/requirements.md",
            "*/sdd/espacios/*/especificacion/requirements.md",
            "*/*/sdd/espacios/*/especificacion/requirements.md"),
}

#: Las que se usan si el espacio no declara nada. Son todas: buscar de más cuesta un `glob`;
#: buscar de menos deja al agente sin la única autoridad que tenía delante.
DEFAULT_SPEC_PROFILES = ("kiro", "flat", "sdd")

#: Directorios ocultos que CONTIENEN repositorios en vez de artefactos. `git worktree add` deja
#: los árboles bajo `.worktrees/` por convención, y ahí hay trabajo que no está en otro sitio.
#: Es una convención, no una ley: se puede declarar otra en el manifiesto.
DEFAULT_CONTAINER_DIRS = (".worktrees",)


def read_manifest(workspace: Path) -> dict:
    """El manifiesto del espacio, o `{}`. Nunca lanza: esto se llama para adornar informes."""
    p = Path(workspace) / ".harness" / MANIFEST_NAME
    try:
        doc = json.loads(p.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}
    return doc if isinstance(doc, dict) else {}


def spec_globs(workspace: Path) -> tuple:
    """Dónde buscar especificaciones en ESTE espacio.

    Se declara en el manifiesto, y hay dos formas porque resuelven dos problemas distintos:

        "specs": {"profiles": ["kiro"]}                  ← usa sólo esa convención conocida
        "specs": {"globs": ["proyectos/*/spec/req.md"]}  ← la distribución es propia

    `globs` manda sobre `profiles`. Cada patrón apunta al DOCUMENTO de requisitos; el
    directorio de la especificación se deriva de él (ver `core.session._spec_dir`).
    """
    cfg = read_manifest(workspace).get("specs")
    if isinstance(cfg, dict):
        globs = cfg.get("globs")
        if isinstance(globs, list) and globs:
            return tuple(str(g) for g in globs)
        profiles = cfg.get("profiles")
        if isinstance(profiles, list) and profiles:
            return tuple(g for p in profiles for g in SPEC_LAYOUTS.get(str(p), ()))
    return tuple(g for p in DEFAULT_SPEC_PROFILES for g in SPEC_LAYOUTS[p])


def container_dirs(workspace: Path) -> tuple:
    """Directorios ocultos que sí hay que recorrer, declarables en `workspace.containers`."""
    cfg = read_manifest(workspace).get("workspace")
    if isinstance(cfg, dict):
        dirs = cfg.get("containers")
        if isinstance(dirs, list) and dirs:
            return tuple(str(d) for d in dirs)
    return DEFAULT_CONTAINER_DIRS


@dataclass
class Context:
    workspace: Path
    run_id: str = ""
    #: Sondear agentes cuesta segundos; algunas puertas no lo necesitan. Se comparte el
    #: resultado entre puertas en vez de repetirlo.
    probes: list = field(default_factory=list)
    deep: bool = False
    offline: bool = False

    @cached_property
    def harness_dir(self) -> Path:
        return self.workspace / ".harness"

    @cached_property
    def manifest_path(self) -> Path:
        return self.harness_dir / MANIFEST_NAME

    @cached_property
    def lock_path(self) -> Path:
        return self.harness_dir / LOCK_NAME

    @cached_property
    def policy_path(self) -> Path:
        return self.harness_dir / POLICY_NAME

    @cached_property
    def evidence_dir(self) -> Path:
        return self.harness_dir / "evidence"

    def read_json(self, path: Path) -> dict | None:
        """Lee JSON o devuelve None. Distinguir «no está» de «está roto» es tarea de la puerta.

        Lanza `ValueError` cuando el archivo existe y no es JSON: eso NO es lo mismo que no
        tenerlo, y colapsarlo produciría un `PENDIENTE` donde hay un `FAIL`.
        """
        if not path.is_file():
            return None
        return json.loads(path.read_text(encoding="utf-8"))

    @cached_property
    def manifest(self) -> dict | None:
        return self.read_json(self.manifest_path)

    @cached_property
    def lock(self) -> dict | None:
        return self.read_json(self.lock_path)

    @cached_property
    def policy_doc(self) -> dict | None:
        return self.read_json(self.policy_path)
