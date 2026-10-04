# -*- coding: utf-8 -*-
"""La forja: qué trabajo tiene usted pendiente, según GitHub o GitLab.

Por qué refuto pregunta a la forja y no a una lista propia
--------------------------------------------------------------
Porque el trabajo pendiente ya está declarado en un sitio, y ese sitio es el que el equipo
actualiza. Una lista propia de refuto sería una segunda verdad que envejece — exactamente el
problema que refuto existe para no crear.

No se autentica ni se piden credenciales: se usa la sesión que la persona ya tiene en `gh` o
`glab`. Si no hay sesión, se dice; no se pide.

Lo que se extrae, y por qué
---------------------------
No sólo el título. Los proyectos serios declaran en el cuerpo de cada historia lo que hace falta
para enrutarla: disciplina, épica, puerta, horas, y dónde vive su especificación. Leer eso es la
diferencia entre enrutar por el vocabulario del proyecto y enrutar adivinando.
"""

from __future__ import annotations

import json
import re
import shutil
import subprocess
from dataclasses import asdict, dataclass, field
from pathlib import Path

from core.proc import TEXT_IO

#: Fila de tabla Markdown: `| **Campo** | Valor |`
FILA = re.compile(r"^\s*\|\s*\**([^|*]+?)\**\s*\|\s*(.+?)\s*\|\s*$", re.M)
#: Identificador de historia en el título: `[S0-ADR1] …`
CLAVE = re.compile(r"^\[([A-Z0-9][A-Z0-9-]{1,20})\]\s*")
#: Enlaces a la especificación dentro del cuerpo.
SPEC_LINK = re.compile(r"\(([^)]*?/(?:spec|especificacion)\.md)\)", re.I)


@dataclass
class Task:
    source: str = "github"
    repo: str = ""
    number: int = 0
    key: str = ""                  # S0-ADR1
    title: str = ""
    url: str = ""
    state: str = "open"
    labels: list = field(default_factory=list)
    assignees: list = field(default_factory=list)
    milestone: str = ""
    fields: dict = field(default_factory=dict)     # la tabla del cuerpo, tal cual
    spec_path: str = ""                            # ruta de spec.md dentro del repo
    body_excerpt: str = ""

    def to_dict(self) -> dict:
        return asdict(self)

    @property
    def label(self) -> str:
        return f"{self.key or '#' + str(self.number)} · {self.title}"


def available() -> dict:
    """Qué forjas se pueden consultar desde aquí. No pide credenciales a nadie."""
    out = {}
    for name, binario, orden in (("github", "gh", ["gh", "auth", "status"]),
                                 ("gitlab", "glab", ["glab", "auth", "status"])):
        if not shutil.which(binario):
            out[name] = {"ok": False, "reason": f"{binario} no está instalado"}
            continue
        try:
            p = subprocess.run(orden, capture_output=True, **TEXT_IO, timeout=45)
        except (OSError, subprocess.SubprocessError) as exc:
            out[name] = {"ok": False, "reason": f"{binario}: {exc}"}
            continue
        ok = p.returncode == 0
        out[name] = {"ok": ok,
                     "reason": "" if ok else f"{binario} está y no hay sesión: `{binario} auth login`"}
    return out


def _gh(args: list, *, cwd: str | None = None, timeout: int = 90):
    try:
        p = subprocess.run(["gh", *args], cwd=cwd, capture_output=True, **TEXT_IO,
                           timeout=timeout)
    except (OSError, subprocess.SubprocessError) as exc:
        return None, str(exc)
    if p.returncode != 0:
        return None, (p.stderr or "").strip()[:220]
    try:
        return json.loads(p.stdout or "null"), ""
    except json.JSONDecodeError as exc:
        return None, f"salida no era JSON: {exc}"


def parse_body(body: str) -> tuple[dict, str]:
    """Extrae la tabla de campos y la ruta de la especificación del cuerpo de una historia.

    La tabla es el vocabulario del proyecto: `Tipo`, `Épica`, `Gate`, `Horas`, `Ejecutor`.
    Leerla es lo que permite enrutar por lo que el equipo declaró en vez de por conjeturas
    sobre el título.
    """
    campos: dict = {}
    for m in FILA.finditer(body or ""):
        clave = m.group(1).strip()
        valor = m.group(2).strip().strip("*").strip()
        if clave.lower() in ("campo", "---", ""):
            continue
        if set(clave) <= set("-: "):
            continue
        campos[clave] = valor
    spec = ""
    m = SPEC_LINK.search(body or "")
    if m:
        ruta = m.group(1)
        # Los enlaces suelen ser absolutos a GitHub; se quiere la ruta dentro del repo.
        spec = re.sub(r"^https?://[^/]+/[^/]+/[^/]+/blob/[^/]+/", "", ruta)
    return campos, spec


def my_tasks(*, repo: str = "", limit: int = 40, state: str = "open") -> tuple[list, str]:
    """Historias asignadas a la sesión actual. Devuelve (tareas, error)."""
    campos = "number,title,url,state,labels,assignees,milestone,body"
    if repo:
        data, err = _gh(["issue", "list", "--repo", repo, "--assignee", "@me",
                         "--state", state, "--limit", str(limit), "--json", campos])
        if err:
            return [], err
        crudas = [{**i, "repository": {"nameWithOwner": repo}} for i in (data or [])]
    else:
        data, err = _gh(["search", "issues", "--assignee=@me", f"--state={state}",
                         "--limit", str(limit),
                         "--json", "number,title,url,repository,state,labels,assignees"])
        if err:
            return [], err
        crudas = data or []

    tareas = []
    for i in crudas:
        cuerpo = i.get("body")
        repo_name = (i.get("repository") or {}).get("nameWithOwner", repo)
        if cuerpo is None and repo_name:
            detalle, _ = _gh(["issue", "view", str(i["number"]), "--repo", repo_name,
                              "--json", "body,labels,milestone,assignees"])
            if detalle:
                cuerpo = detalle.get("body")
                i.setdefault("labels", detalle.get("labels") or [])
                i["milestone"] = detalle.get("milestone")
                i.setdefault("assignees", detalle.get("assignees") or [])
        f, spec = parse_body(cuerpo or "")
        titulo = i.get("title", "")
        m = CLAVE.match(titulo)
        tareas.append(Task(
            repo=repo_name, number=i.get("number", 0),
            key=m.group(1) if m else "",
            title=CLAVE.sub("", titulo).strip(),
            url=i.get("url", ""), state=i.get("state", state),
            labels=[l["name"] for l in (i.get("labels") or [])],
            assignees=[a["login"] for a in (i.get("assignees") or [])],
            milestone=((i.get("milestone") or {}) or {}).get("title", "") or "",
            fields=f, spec_path=spec,
            body_excerpt=(cuerpo or "").strip()[:400]))
    return tareas, ""


def review_requests(*, limit: int = 20) -> tuple[list, str]:
    """Revisiones que le han pedido. Es trabajo pendiente aunque no sea una issue."""
    data, err = _gh(["search", "prs", "--review-requested=@me", "--state=open",
                     "--limit", str(limit), "--json", "number,title,url,repository"])
    if err:
        return [], err
    return [Task(repo=(p.get("repository") or {}).get("nameWithOwner", ""),
                 number=p.get("number", 0), title=p.get("title", ""), url=p.get("url", ""),
                 state="review-requested") for p in (data or [])], ""


def repo_of(workspace: Path) -> str:
    """`owner/name` del repositorio de este espacio, si lo tiene."""
    try:
        p = subprocess.run(["git", "-C", str(workspace), "config", "--get",
                            "remote.origin.url"], capture_output=True, **TEXT_IO, timeout=20)
        url = (p.stdout or "").strip()
    except (OSError, subprocess.SubprocessError):
        return ""
    m = re.search(r"[:/]([^/:]+/[^/]+?)(?:\.git)?/?$", url)
    return m.group(1) if m else ""
