# -*- coding: utf-8 -*-
"""Trazabilidad de extremo a extremo. La cadena, y las tres preguntas que tiene que responder.

    INTENCIÓN → REQUISITO → CRITERIO → TAREA → CÓDIGO → PRUEBA → DESPLIEGUE → EVIDENCIA

    1 · ¿Qué requisito justifica este cambio?
    2 · ¿Qué pruebas demuestran que ese requisito está implementado?
    3 · ¿Qué entrega contiene este cambio?

Cómo se ata cada eslabón, y por qué así
---------------------------------------
Por **identificador citado en el texto**, no por una base de datos aparte. `REQ-007` aparece en
`requirements.md`, en `tasks.md`, en el nombre de la prueba y en el mensaje del commit. El
vínculo vive donde vive el trabajo, así que no puede desincronizarse sin que se note.

Se paga un precio: exigir la cita hace las salidas menos deterministas. Se cambia determinismo
por verificabilidad, **y se declara que se está cambiando**.
"""

from __future__ import annotations

import re
import subprocess
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path

from core.proc import TEXT_IO

#: Identificadores. Se distinguen dos niveles porque son dos cosas:
#:   REQUISITO  exigible; sin prueba que lo cite, la puerta falla
#:   HISTORIA   nivel de negocio; se traza, pero no se exige prueba directa
#: Colapsarlos ponía en rojo cinco historias de usuario que sus requisitos derivados sí prueban.
REQ_ID = re.compile(r"\b(REQ|RF|RNF)-(\d{1,4})\b")
STORY_ID = re.compile(r"\b(HU|US)-(\d{1,4})\b")
ANY_ID = re.compile(r"\b(REQ|RF|RNF|HU|US)-(\d{1,4})\b")

TEXT_EXT = {".md", ".txt", ".rst", ".adoc"}
CODE_EXT = {".py", ".js", ".ts", ".tsx", ".jsx", ".java", ".kt", ".go", ".rs", ".rb",
            ".php", ".cs", ".swift", ".html", ".css", ".sql", ".yaml", ".yml"}
TEST_HINT = re.compile(r"(^|/)(tests?|pruebas|spec|__tests__)(/|$)|(\.|_|-)(test|spec)\.")

SKIP_DIRS = {".git", "node_modules", "__pycache__", ".venv", "dist", "build", ".harness",
             ".nucleo", "target", "evidencia", "evidence"}

#: Rutas cuyo contenido NO se indexa: son los datos de prueba del propio verificador y citan
#: identificadores falsos a propósito. Indexarlos hacía que el juez encontrara sus propias
#: fixtures y las declarara citas fantasma del proyecto — encontrado ejecutándolo.
FIXTURE_HINT = re.compile(r"(^|/)(verificacion|verification|gates|tests?/fixtures)(/|$)")


def _rel(path, workspace) -> str:
    """La ruta relativa SIEMPRE con `/`, en todos los sistemas.

    No es cosmética por partida doble. Primero, `TEST_HINT` y `FIXTURE_HINT` reconocen los
    directorios por `/`: con `tests\fixtures` no casaban, el juez indexaba sus propias fixtures
    y declaraba fantasmas los identificadores que ellas inventan a propósito — un FAIL en un
    proyecto impecable, sólo por el sistema operativo. Segundo, esta cadena entra en la
    evidencia: si la misma ejecución escribe `a/b.md` en una máquina y `a\b.md` en otra, dos
    informes del mismo hecho dejan de poder compararse.
    """
    return path.relative_to(workspace).as_posix()


@dataclass
class Link:
    requirement: str
    kind: str            # requirement | criterion | task | code | test | commit
    where: str
    line: int = 0
    excerpt: str = ""


@dataclass
class TraceGraph:
    links: list = field(default_factory=list)
    requirements: set = field(default_factory=set)
    stories: set = field(default_factory=set)

    def by_requirement(self) -> dict:
        out: dict = defaultdict(lambda: defaultdict(list))
        for l in self.links:
            out[l.requirement][l.kind].append(l)
        return out

    def orphan_requirements(self) -> list:
        """Requisitos declarados que nadie implementa ni prueba."""
        idx = self.by_requirement()
        return sorted(r for r in self.requirements
                      if not idx[r].get("test") and not idx[r].get("code"))

    def untraced_stories(self) -> list:
        """Historias que no aparecen en ningún documento de especificación derivado.

        No falla la puerta: una historia se cubre por sus requisitos, no directamente.
        """
        idx = self.by_requirement()
        return sorted(s for s in self.stories
                      if not any(k != "requirement" for k in idx.get(s, {})))

    def untested_requirements(self) -> list:
        idx = self.by_requirement()
        return sorted(r for r in self.requirements if not idx[r].get("test"))

    def phantom_citations(self) -> list:
        """Citas a requisitos que NO existen. Es el defecto medido en un repositorio real."""
        idx = self.by_requirement()
        known = self.requirements | self.stories
        return sorted(r for r in idx if r not in known)

    def to_dict(self) -> dict:
        idx = self.by_requirement()
        return {
            "schema": "harness.trace/v1",
            "requirements": sorted(self.requirements),
            "stories": sorted(self.stories),
            "untraced_stories": self.untraced_stories(),
            "coverage": {r: {k: len(v) for k, v in sorted(idx[r].items())}
                         for r in sorted(self.requirements)},
            "orphans": self.orphan_requirements(),
            "untested": self.untested_requirements(),
            "phantom_citations": self.phantom_citations(),
        }


def _iter_files(root: Path):
    import os
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
        for name in filenames:
            yield Path(dirpath) / name


def build(workspace: Path, *, spec_globs: tuple = ("**/requirements.md", "**/requisitos.md",
                                                   "**/insumos/02-historias/*.md")) -> TraceGraph:
    g = TraceGraph()

    # 1 · qué requisitos EXISTEN. Se leen sólo de los documentos de especificación: un
    #     requisito nace en la especificación, no en el sitio donde alguien lo mencionó.
    for pattern in spec_globs:
        for path in workspace.glob(pattern):
            if not path.is_file() or any(p in SKIP_DIRS for p in path.parts):
                continue
            for n, line in enumerate(path.read_text(encoding="utf-8", errors="ignore").splitlines(), 1):
                for m in ANY_ID.finditer(line):
                    rid = m.group(0)
                    (g.stories if STORY_ID.fullmatch(rid) else g.requirements).add(rid)
                    g.links.append(Link(rid, "requirement",
                                        _rel(path, workspace), n, line.strip()[:120]))

    # 2 · dónde se CITAN, y con qué papel.
    for path in _iter_files(workspace):
        rel = _rel(path, workspace)
        ext = path.suffix.lower()
        if ext not in TEXT_EXT | CODE_EXT:
            continue
        if any(path.match(p) for p in spec_globs) or FIXTURE_HINT.search(rel):
            continue
        try:
            text = path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        if "-" not in text:
            continue
        is_test = bool(TEST_HINT.search(rel))
        kind = ("test" if is_test else
                "task" if path.name in ("tasks.md", "tareas.md", "plan.md") else
                "criterion" if ext in TEXT_EXT else "code")
        for n, line in enumerate(text.splitlines(), 1):
            for m in ANY_ID.finditer(line):
                g.links.append(Link(m.group(0), kind, rel, n, line.strip()[:120]))
    return g


def commits_for(workspace: Path, requirement: str, *, limit: int = 20) -> list:
    """Commits que citan un requisito. Responde a «¿qué entrega contiene este cambio?»."""
    try:
        p = subprocess.run(
            ["git", "-C", str(workspace), "log", f"--grep={requirement}", "--oneline",
             f"-{limit}"], capture_output=True, **TEXT_IO, timeout=30)
        return [l for l in (p.stdout or "").splitlines() if l.strip()]
    except (OSError, subprocess.SubprocessError):
        return []


def answer(workspace: Path, requirement: str) -> dict:
    """Las tres preguntas, para un requisito concreto."""
    g = build(workspace)
    idx = g.by_requirement().get(requirement, {})
    return {
        "requirement": requirement,
        "exists": requirement in g.requirements,
        "declared_in": [f"{l.where}:{l.line}" for l in idx.get("requirement", [])],
        "implemented_by": [f"{l.where}:{l.line}" for l in idx.get("code", [])],
        "tested_by": [f"{l.where}:{l.line}" for l in idx.get("test", [])],
        "planned_in": [f"{l.where}:{l.line}" for l in idx.get("task", [])],
        "commits": commits_for(workspace, requirement),
    }
