# -*- coding: utf-8 -*-
"""Memoria en capas. **Memoria no es evidencia, y mezclarlas arruina las dos.**

    MEMORIA    sirve para recordar, razonar, continuar y reutilizar
               es mutable, se corrige, envejece y se poda

    EVIDENCIA  sirve para probar, auditar, reproducir y verificar
               es inmutable, sólo se añade, y no se corrige nunca

Mezclarlas produce dos daños simultáneos: una evidencia que alguien puede editar deja de probar
nada, y una memoria que no se puede corregir deja de servir para razonar. Por eso viven en
directorios distintos, con contratos distintos, y la política protege una y no la otra.

Las cinco capas, y por qué cinco
--------------------------------
    EPHEMERAL       dentro de un turno. No se persiste.
    RUN             una ejecución. Se borra al cerrarla.
    PROJECT         hechos del proyecto que sobreviven a la ejecución.
    DECISION        qué se decidió y POR QUÉ. Lo más caro de reconstruir.
    DOMAIN          conocimiento del negocio, con su fuente y su fecha.

Cada capa tiene una vida distinta. Una sola bolsa de «memoria» acaba con notas de hace un año
compitiendo por atención con el estado del turno actual, y ninguna sirviendo.
"""

from __future__ import annotations

import json
import re
from dataclasses import asdict, dataclass, field
from pathlib import Path

from core.digest import redact, sha256_text
from core.model import now, write_json

EPHEMERAL, RUN, PROJECT, DECISION, DOMAIN = "ephemeral", "run", "project", "decision", "domain"
LAYERS = (EPHEMERAL, RUN, PROJECT, DECISION, DOMAIN)

#: Vida declarada de cada capa. `None` = no caduca sola.
TTL_DAYS = {EPHEMERAL: 0, RUN: 7, PROJECT: 180, DECISION: None, DOMAIN: None}

DIR = ".harness/memory"


@dataclass
class Note:
    layer: str
    key: str
    body: str
    why: str = ""
    source: str = ""
    tags: list = field(default_factory=list)
    created_at: str = ""
    updated_at: str = ""
    superseded_by: str = ""
    digest: str = ""

    def to_dict(self) -> dict:
        return asdict(self)


class Memory:
    """Almacén de memoria del espacio. Ficheros, uno por nota, legibles a mano.

    Se guarda como Markdown con frontmatter y no como base de datos a propósito: una memoria
    que sólo puede leer el programa que la escribió no sirve para que una persona entienda por
    qué el sistema cree lo que cree.
    """

    def __init__(self, workspace: Path):
        self.root = workspace / DIR

    def _path(self, layer: str, key: str) -> Path:
        safe = re.sub(r"[^a-z0-9._-]+", "-", key.lower()).strip("-")[:80]
        return self.root / layer / f"{safe}.md"

    # ── escritura ────────────────────────────────────────────────────────────────────
    def remember(self, layer: str, key: str, body: str, *, why: str = "", source: str = "",
                 tags: list | None = None) -> Path:
        if layer not in LAYERS:
            raise ValueError(f"capa desconocida: {layer!r}; hay {LAYERS}")
        if layer == EPHEMERAL:
            raise ValueError("la capa efímera no se persiste: vive en el turno y muere con él")
        # La memoria pasa por el redactor igual que la evidencia. Un secreto recordado es un
        # secreto filtrado, y encima con vida indefinida.
        clean_body, hits = redact(body)
        clean_why, _ = redact(why)
        path = self._path(layer, key)
        existing = self.recall(layer, key)
        note = Note(layer=layer, key=key, body=clean_body, why=clean_why, source=source,
                    tags=sorted(set(tags or []) | ({"redactado"} if hits else set())),
                    created_at=(existing.created_at if existing else now()),
                    updated_at=now(), digest=sha256_text(clean_body)[:16])
        path.parent.mkdir(parents=True, exist_ok=True)
        front = {k: v for k, v in note.to_dict().items() if k != "body"}
        path.write_text(
            "---\n" + "\n".join(f"{k}: {json.dumps(v, ensure_ascii=False)}"
                                for k, v in front.items()) + "\n---\n\n" + clean_body + "\n",
            encoding="utf-8", newline="\n")
        return path

    def supersede(self, layer: str, key: str, by: str) -> bool:
        """Una memoria equivocada NO se borra: se marca sustituida.

        Borrarla perdería la información de que alguien creyó eso, que es justo lo que hace
        falta para no volver a creerlo.
        """
        note = self.recall(layer, key)
        if note is None:
            return False
        note.superseded_by = by
        note.updated_at = now()
        p = self._path(layer, key)
        front = {k: v for k, v in note.to_dict().items() if k != "body"}
        p.write_text("---\n" + "\n".join(f"{k}: {json.dumps(v, ensure_ascii=False)}"
                                         for k, v in front.items()) + "\n---\n\n" + note.body + "\n",
                     encoding="utf-8", newline="\n")
        return True

    # ── lectura ──────────────────────────────────────────────────────────────────────
    def recall(self, layer: str, key: str) -> Note | None:
        p = self._path(layer, key)
        if not p.is_file():
            return None
        return self._read(p)

    def _read(self, path: Path) -> Note | None:
        try:
            # Lectura con saltos universales a proposito: un fichero escrito por una
            # version anterior puede traer CRLF, y aqui hay que entenderlo, no exigirlo.
            text = path.read_text(encoding="utf-8")
        except OSError:
            return None
        if not text.startswith("---"):
            return None
        end = text.find("\n---", 3)
        if end == -1:
            return None
        front: dict = {}
        # Las notas escritas a mano usan escalares de bloque YAML (`why: >`). Leyendo línea a
        # línea, el valor quedaba en el indicador —`'>'`— y el texto se perdía entero: medido
        # en un espacio real, 181 de 192 `why` y 39 de 194 `source`. Es justo el campo que
        # dice POR QUÉ importa la nota, y el informe de sesión lo servía vacío.
        lineas = text[3:end].strip("\n").splitlines()
        i = 0
        while i < len(lineas):
            linea = lineas[i]
            # Sólo una línea sin sangrar abre una clave; las sangradas son continuación.
            if ":" not in linea or linea[:1] in (" ", "\t"):
                i += 1
                continue
            k, _, v = linea.partition(":")
            k, v = k.strip(), v.strip()
            if v in (">", "|", ">-", "|-", ">+", "|+"):
                bloque: list = []
                i += 1
                while i < len(lineas) and (not lineas[i].strip() or lineas[i][:1] in (" ", "\t")):
                    bloque.append(lineas[i].strip())
                    i += 1
                # `>` pliega en una línea; `|` conserva los saltos.
                sep = "\n" if v.startswith("|") else " "
                front[k] = sep.join(x for x in bloque if x).strip()
                continue
            try:
                front[k] = json.loads(v)
            except json.JSONDecodeError:
                front[k] = v
            i += 1
        known = {f for f in Note.__dataclass_fields__}          # noqa: SLF001
        return Note(**{k: v for k, v in front.items() if k in known},
                    **{"body": text[end + 4:].strip()})

    def search(self, query: str = "", *, layers: list | None = None,
               include_superseded: bool = False) -> list:
        """Búsqueda literal, sin índice. Es suficiente a esta escala y no añade dependencias."""
        out = []
        q = query.lower()
        for layer in (layers or LAYERS):
            d = self.root / layer
            for p in sorted(d.glob("*.md")) if d.is_dir() else []:
                note = self._read(p)
                if note is None:
                    continue
                if note.superseded_by and not include_superseded:
                    continue
                blob = f"{note.key} {note.body} {note.why} {' '.join(note.tags)}".lower()
                if not q or q in blob:
                    out.append(note)
        return out

    def clear(self, layer: str) -> int:
        """Vacía una capa. Sólo `run` y `ephemeral`: las demás son historia."""
        if layer not in (RUN, EPHEMERAL):
            raise ValueError(f"la capa «{layer}» no se vacía: es historia. Use supersede().")
        d = self.root / layer
        n = 0
        for p in sorted(d.glob("*.md")) if d.is_dir() else []:
            p.unlink()
            n += 1
        return n

    def summary(self) -> dict:
        out = {}
        for layer in LAYERS:
            d = self.root / layer
            notes = [self._read(p) for p in d.glob("*.md")] if d.is_dir() else []
            notes = [n for n in notes if n]
            out[layer] = {"count": len(notes),
                          "superseded": len([n for n in notes if n.superseded_by]),
                          "ttl_days": TTL_DAYS[layer]}
        return out

    def export(self, path: Path) -> Path:
        write_json(path, {
            "schema": "harness.memory/v1",
            "generated_at": now(),
            "summary": self.summary(),
            "notes": [n.to_dict() for n in self.search(include_superseded=True)],
        })
        return path
