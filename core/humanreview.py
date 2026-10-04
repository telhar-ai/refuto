# -*- coding: utf-8 -*-
"""Revisión humana como artefacto, no como casilla.

Regla que ordena todo lo demás
------------------------------
**La ausencia de una revisión obligatoria es `BLOCKED`, nunca `PASS`.** Una casilla que se
marca sola no es una revisión; y una revisión que se puede omitir sin consecuencia no es
obligatoria, por mucho que el documento diga que lo es.

Y su corolario, que es el que de verdad muerde: **quien revisa no puede ser quien generó.** Sin
esa comprobación, la revisión humana es una firma sobre el propio trabajo.

Los cinco tipos existen porque son cinco decisiones distintas, tomadas por personas distintas,
en momentos distintos. Colapsarlos en «aprobado» pierde precisamente la información útil.
"""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from pathlib import Path

from core.model import now, write_json

APPROVAL = "HUMAN_APPROVAL"
VISUAL = "HUMAN_VISUAL_REVIEW"
PR = "HUMAN_PR_REVIEW"
SECURITY = "HUMAN_SECURITY_REVIEW"
RELEASE = "HUMAN_RELEASE_APPROVAL"
KINDS = (APPROVAL, VISUAL, PR, SECURITY, RELEASE)

WHAT = {
    APPROVAL: "aprobar que la especificación describe lo que hay que construir",
    VISUAL:   "mirar la pantalla y decir si se entiende, no sólo si se parece",
    PR:       "revisar el cambio completo antes de integrarlo",
    SECURITY: "aceptar el riesgo residual que el escaneo no puede decidir",
    RELEASE:  "autorizar que esto salga a producción",
}

#: Lo que ninguna máquina comprueba, y por eso la revisión existe. Va en el propio archivo:
#: una revisión que no dice qué buscar se convierte en una firma.
LOOK_FOR = {
    VISUAL:   ["¿el orden de tabulación tiene sentido?",
               "¿el texto alternativo dice algo útil o dice «imagen»?",
               "¿la pantalla se entiende con lector de pantalla?",
               "¿la jerarquía visual lleva al ojo donde hace falta?"],
    PR:       ["¿el cambio hace lo que el requisito pide, y sólo eso?",
               "¿hay algo aquí que nadie sabrá mantener dentro de un año?",
               "¿las pruebas comprueban el comportamiento o la implementación?"],
    SECURITY: ["¿el riesgo residual es aceptable para este contexto?",
               "¿algún hallazgo «bajo» deja de serlo en producción?"],
    APPROVAL: ["¿la fase siguiente se puede construir encima de esto?",
               "¿hay un requisito que nadie sabrá comprobar?"],
    RELEASE:  ["¿se puede revertir esto en cinco minutos?",
               "¿quién está de guardia cuando salga?"],
}

DIR = "evidence/human-review"


@dataclass
class Review:
    kind: str
    subject: str
    decision: str = "PENDING"       # PENDING | APPROVED | REJECTED
    reviewer: str = ""
    reviewer_email: str = ""
    generated_by: str = ""
    notes: str = ""
    look_for: list = field(default_factory=list)
    requested_at: str = ""
    decided_at: str = ""
    artifacts: list = field(default_factory=list)

    def to_dict(self) -> dict:
        return asdict(self) | {"_que_es": WHAT.get(self.kind, "")}


def path_for(workspace: Path, kind: str, subject: str) -> Path:
    safe = "".join(c if c.isalnum() or c in "-_." else "-" for c in subject)[:60]
    return workspace / ".harness" / DIR / f"{kind.lower()}--{safe}.json"


def request(workspace: Path, kind: str, subject: str, *, generated_by: str,
            artifacts: list | None = None) -> Path:
    """Deja la petición de revisión en el árbol. Existir es lo que la hace exigible."""
    if kind not in KINDS:
        raise ValueError(f"tipo de revisión desconocido: {kind!r}")
    p = path_for(workspace, kind, subject)
    if p.exists():
        return p
    review = Review(kind=kind, subject=subject, generated_by=generated_by,
                    look_for=LOOK_FOR.get(kind, []), requested_at=now(),
                    artifacts=artifacts or [])
    write_json(p, review.to_dict())
    return p


def read(path: Path) -> Review | None:
    try:
        d = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    known = {f for f in Review.__dataclass_fields__}          # noqa: SLF001
    return Review(**{k: v for k, v in d.items() if k in known})


def pending(workspace: Path) -> list:
    base = workspace / ".harness" / DIR
    out = []
    for p in sorted(base.glob("*.json")) if base.is_dir() else []:
        r = read(p)
        if r and r.decision == "PENDING":
            out.append((p, r))
    return out


def evaluate(workspace: Path, required: list) -> dict:
    """¿Están hechas las revisiones obligatorias, y por otra persona?

    Devuelve `{"satisfied": bool, "problems": [...], "reviews": [...]}`.
    """
    base = workspace / ".harness" / DIR
    problems, seen = [], []
    have: dict = {}
    for p in sorted(base.glob("*.json")) if base.is_dir() else []:
        r = read(p)
        if r is None:
            problems.append(f"{p.name}: ilegible; una revisión que no se puede leer no consta")
            continue
        have.setdefault(r.kind, []).append(r)
        seen.append(r.to_dict())

    for kind in required:
        got = have.get(kind, [])
        if not got:
            problems.append(f"falta {kind}: {WHAT.get(kind, '')}. Sin ella no se puede afirmar "
                            f"que alguien lo miró.")
            continue
        for r in got:
            if r.decision == "PENDING":
                problems.append(f"{kind} sobre «{r.subject}» sigue PENDIENTE")
            elif r.decision == "REJECTED":
                problems.append(f"{kind} sobre «{r.subject}» fue RECHAZADA: {r.notes or 'sin nota'}")
            elif not r.reviewer:
                problems.append(f"{kind} sobre «{r.subject}» está aprobada y no dice quién: "
                                f"una aprobación sin nombre no imputa a nadie")
            elif r.generated_by and r.reviewer_email and \
                    r.reviewer_email.strip().lower() == r.generated_by.strip().lower():
                problems.append(f"{kind} sobre «{r.subject}»: quien revisa es quien generó "
                                f"({r.reviewer_email}). Eso no es una revisión, es una firma.")
    return {"satisfied": not problems, "problems": problems, "reviews": seen}
