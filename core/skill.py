# -*- coding: utf-8 -*-
"""H-08 · Contrato de skill. `SKILL.md` es el formato canónico, no uno propio.

Por qué no se inventa un formato
--------------------------------
Claude Code y Gemini CLI consumen los dos `SKILL.md` con frontmatter YAML `name` + `description`
(verificado: `gemini skills list --all` lista `.../builtin/skill-creator/SKILL.md`). Las 8
skills del espacio SDD ya están escritas así. Inventar un formato canónico propio obligaría a
compilar hacia el que ya es estándar de facto, para no ganar nada. Ver ADR-0003.

Lo que sí falta y este módulo añade, en un bloque `harness:` opcional dentro del mismo
frontmatter — invisible para los runtimes que no lo entienden:

    version            para poder fijarlo en un lock
    requires.tools     qué herramientas necesita para funcionar
    requires.mcp       qué servidores MCP necesita
    inputs / outputs   qué consume y qué deja
    compat             en qué runtimes se ha comprobado que carga

El defecto encontrado en la auditoría
--------------------------------------
`experiencia/SKILL.md` declara `name: experiencia-y-accesibilidad` y `revision/SKILL.md`
declara `name: revision-adversarial`. Claude Code exige que `name` coincida con el directorio.
Copiadas tal cual, dos de las ocho no cargan. Es un defecto de dos líneas que separa
«casi portable» de «portable», y sin una puerta que lo mire nadie se entera hasta que falla.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

NAME_RE = re.compile(r"^[a-z0-9]+(?:-[a-z0-9]+)*$")
MAX_NAME = 64
MAX_DESCRIPTION = 1024


@dataclass
class Skill:
    path: Path
    directory: str
    name: str = ""
    description: str = ""
    harness: dict = field(default_factory=dict)
    parse_error: str = ""
    body_chars: int = 0

    @property
    def version(self) -> str:
        return str(self.harness.get("version", ""))


def _parse_frontmatter(text: str) -> tuple[dict, str, str]:
    """Lee el frontmatter. Subconjunto de YAML: mapas anidados y listas de escalares.

    Por qué un parser propio y no PyYAML
    ------------------------------------
    Porque refuto declara correr sólo con biblioteca estándar (ADR-0002), y `SKILL.md` usa
    un subconjunto pequeño y estable. Lo que NO se hace es fingir que soporta YAML entero: una
    construcción fuera del subconjunto devuelve un error explícito, nunca un mapa a medias.

    La primera versión falló contra su propio ejemplo: al ver una clave sin valor creaba
    siempre un mapa, así que una lista anidada (`tools:` seguido de `- read`) devolvía «elemento
    de lista sin clave». Un contenedor no se decide al abrirlo: se decide al ver su primer hijo.

    Devuelve (mapa, cuerpo, error).
    """
    if not text.startswith("---"):
        return {}, text, "no empieza con frontmatter `---`"
    end = text.find("\n---", 3)
    if end == -1:
        return {}, text, "el frontmatter no se cierra con `---`"
    raw = text[3:end].strip("\n")
    body = text[end + 4:]

    root: dict = {}
    # Pila de contenedores abiertos: (sangrado, contenedor, mapa_padre, clave_en_el_padre).
    # Se guarda el padre y la clave para poder SUSTITUIR un mapa vacío por una lista cuando
    # el primer hijo resulta ser un elemento de lista.
    stack: list = [(-1, root, None, None)]

    for lineno, line in enumerate(raw.splitlines(), start=2):
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        indent = len(line) - len(line.lstrip(" "))
        stripped = line.strip()

        while len(stack) > 1 and indent <= stack[-1][0]:
            stack.pop()
        _, container, parent, key_in_parent = stack[-1]

        if stripped.startswith("- "):
            if isinstance(container, dict):
                if container:
                    return {}, body, f"línea {lineno}: lista mezclada con claves"
                if parent is None:
                    return {}, body, f"línea {lineno}: lista en la raíz del frontmatter"
                container = []
                parent[key_in_parent] = container
                stack[-1] = (stack[-1][0], container, parent, key_in_parent)
            container.append(_scalar(stripped[2:].strip()))
            continue

        if isinstance(container, list):
            return {}, body, f"línea {lineno}: clave dentro de una lista"
        if ":" not in stripped:
            return {}, body, f"línea {lineno}: se esperaba `clave: valor`"

        key, _, value = stripped.partition(":")
        key, value = key.strip(), value.strip()
        if not key:
            return {}, body, f"línea {lineno}: clave vacía"
        if value:
            container[key] = _scalar(value)
            continue
        # Clave sin valor: se abre un contenedor cuya forma decidirá su primer hijo.
        child: dict = {}
        container[key] = child
        stack.append((indent, child, container, key))

    return root, body, ""


def _scalar(value: str):
    v = value.strip().strip('"').strip("'")
    low = v.lower()
    if low in ("true", "yes"):
        return True
    if low in ("false", "no"):
        return False
    if re.fullmatch(r"-?\d+", v):
        return int(v)
    if v.startswith("[") and v.endswith("]"):
        inner = v[1:-1].strip()
        return [_scalar(p) for p in inner.split(",")] if inner else []
    return v


def load(path: Path) -> Skill:
    directory = path.parent.name
    try:
        text = path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError) as exc:
        return Skill(path=path, directory=directory, parse_error=f"no se pudo leer: {exc}")
    data, body, err = _parse_frontmatter(text)
    return Skill(path=path, directory=directory,
                 name=str(data.get("name", "")), description=str(data.get("description", "")),
                 harness=data.get("harness") if isinstance(data.get("harness"), dict) else {},
                 parse_error=err, body_chars=len(body))


def discover(roots: list) -> list:
    found: list = []
    for root in roots:
        base = Path(root)
        if not base.is_dir():
            continue
        found.extend(sorted(base.glob("*/SKILL.md")))
        found.extend(sorted(base.glob("*/*/SKILL.md")))
    seen, out = set(), []
    for p in found:
        rp = p.resolve()
        if rp in seen:
            continue
        seen.add(rp)
        out.append(load(p))
    return out


def check(skill: Skill, *, require_name_matches_directory: bool = True) -> list:
    """Devuelve la lista de incumplimientos del contrato. Vacía = conforme."""
    problems: list = []
    if skill.parse_error:
        return [f"frontmatter ilegible: {skill.parse_error}"]
    if not skill.name:
        problems.append("no declara `name`")
    else:
        if len(skill.name) > MAX_NAME:
            problems.append(f"`name` de {len(skill.name)} caracteres; el máximo es {MAX_NAME}")
        if not NAME_RE.match(skill.name):
            problems.append(f"`name` {skill.name!r} no es minúsculas-con-guiones")
        if require_name_matches_directory and skill.name != skill.directory:
            problems.append(
                f"`name: {skill.name}` no coincide con el directorio «{skill.directory}». "
                f"Claude Code exige que coincidan: esta skill NO cargaría allí.")
    if not skill.description:
        problems.append("no declara `description`; sin ella el agente no sabe cuándo usarla")
    elif len(skill.description) > MAX_DESCRIPTION:
        problems.append(f"`description` de {len(skill.description)} caracteres; máximo {MAX_DESCRIPTION}")
    if skill.body_chars < 80:
        problems.append("el cuerpo está prácticamente vacío")
    return problems
