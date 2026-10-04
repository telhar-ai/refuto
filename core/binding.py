# -*- coding: utf-8 -*-
"""Vínculo del espacio de trabajo: a qué núcleo y a qué repositorio queda atado.

Descubrir es barato y ambiguo; **vincular es la decisión**. El descubrimiento propone, y cuando
hay más de un candidato verificable —lo que pasa de verdad: en el conjunto auditado había dos
núcleos idénticos— la elección la toma una persona una vez, se escribe, y deja de preguntarse.

Qué se guarda, y por qué cada cosa
----------------------------------
    path      dónde está hoy. Puede cambiar al mover el espacio; se revalida.
    commit    con qué versión exacta se vinculó. **Es el ancla**: si el path cambia pero el
              commit coincide, no ha pasado nada. Si el commit cambia, sí.
    version   lo que declaraba. Sirve para leer el CHANGELOG antes de aceptar un cambio.
    digest    huella del manifiesto en el momento de vincular.

El vínculo NO se actualiza solo. Si el núcleo del disco ya no coincide con el vínculo, se
reporta como deriva y se pide confirmación. Un vínculo que se corrige solo no es un vínculo.
"""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass
from pathlib import Path

from core.digest import sha256_file
from core.model import now, write_json


@dataclass
class Binding:
    kind: str                 # sdd_core | repository
    path: str
    commit: str = ""
    version: str = ""
    remote: str = ""
    manifest_digest: str = ""
    bound_at: str = ""
    bound_by: str = ""

    def to_dict(self) -> dict:
        return asdict(self)


def bind_core(candidate: dict, *, by: str = "") -> Binding:
    manifest = candidate.get("manifest_path") or ""
    digest = sha256_file(Path(manifest))[:32] if manifest and Path(manifest).is_file() else ""
    return Binding(kind="sdd_core", path=candidate["subject"],
                   commit=candidate.get("commit", ""), version=candidate.get("version", ""),
                   remote=candidate.get("remote", ""), manifest_digest=digest,
                   bound_at=now(), bound_by=by)


def bind_repo(candidate: dict, *, by: str = "") -> Binding:
    return Binding(kind="repository", path=candidate["subject"],
                   commit=candidate.get("commit", ""), remote=candidate.get("remote", ""),
                   bound_at=now(), bound_by=by)


def write(workspace: Path, bindings: list) -> Path:
    p = workspace / ".harness" / "binding.json"
    write_json(p, {
        "schema": "harness.binding/v1",
        "_que_es": ("A que nucleo y a que repositorio esta atado este espacio. El ancla es el "
                    "COMMIT, no la ruta: mover el espacio de sitio no es un cambio; cambiar de "
                    "commit si. No se actualiza solo."),
        "bindings": {b.kind: b.to_dict() for b in bindings},
    })
    return p


def read(workspace: Path) -> dict:
    p = workspace / ".harness" / "binding.json"
    if not p.is_file():
        return {}
    try:
        return (json.loads(p.read_text(encoding="utf-8")).get("bindings") or {})
    except (OSError, ValueError):
        return {}


def verify(workspace: Path, discovery: dict) -> dict:
    """Comprueba que el vínculo sigue valiendo. Devuelve problemas, no los arregla."""
    bound = read(workspace)
    problems, notes = [], []
    if not bound:
        return {"bound": False, "problems": [], "notes": ["este espacio no está vinculado"]}

    for kind, block_key in (("sdd_core", "sdd_core"), ("repository", "repository")):
        b = bound.get(kind)
        if not b:
            continue
        path = Path(b["path"])
        if not path.is_dir():
            problems.append(f"{kind}: la ruta vinculada ya no existe ({b['path']}). "
                            f"Vuelva a vincular con `refuto bind`.")
            continue
        live = None
        for c in (discovery.get(block_key) or {}).get("candidates", []):
            if Path(c["subject"]).resolve() == path.resolve():
                live = c
                break
        if live is None:
            notes.append(f"{kind}: vinculado a {b['path']}, que existe pero no salió en el "
                         f"descubrimiento de esta ejecución")
            continue
        if b.get("commit") and live.get("commit") and b["commit"] != live["commit"]:
            problems.append(
                f"{kind}: se vinculó al commit {b['commit'][:12]} y ahora está en "
                f"{live['commit'][:12]}. **No se acepta solo**: revise el cambio y vuelva a "
                f"vincular a conciencia.")
        if b.get("version") and live.get("version") and b["version"] != live["version"]:
            problems.append(f"{kind}: versión vinculada {b['version']}, en disco "
                            f"{live['version']}. Lea el CHANGELOG antes de aceptarlo.")
        if kind == "sdd_core" and live.get("integrity", "").startswith(("íntegro",)) is False \
                and live.get("integrity"):
            problems.append(f"sdd_core: integridad — {live['integrity']}")
    return {"bound": True, "problems": problems, "notes": notes, "bindings": bound}


def decide(block: dict, *, choice: str = "", interactive: bool = False,
           what: str = "") -> tuple[dict | None, str]:
    """Resuelve un bloque de descubrimiento a un candidato concreto.

    Devuelve `(candidato, motivo)`. `None` significa que hace falta una persona, y el motivo lo
    explica. **Nunca elige un candidato ambiguo por su cuenta**, ni siquiera «el primero».
    """
    if choice:
        for c in block.get("candidates", []):
            if Path(c["subject"]).resolve() == Path(choice).expanduser().resolve():
                return c, f"elegido explícitamente: {choice}"
        return None, (f"«{choice}» no está entre los candidatos encontrados. "
                      f"Candidatos: {', '.join(c['subject'] for c in block.get('candidates', []))}")
    if block.get("outcome") == "AUTO":
        return block["chosen"], (block.get("note") or "único candidato con confianza suficiente")
    if block.get("outcome") == "NONE":
        return None, f"no se encontró {what}. Buscado en: " + \
                     ", ".join(block.get("searched", []))
    return None, block.get("question", f"hay que decidir cuál es {what}")
