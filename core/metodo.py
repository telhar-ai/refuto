# -*- coding: utf-8 -*-
"""El MÉTODO del espacio: con qué disciplina se trabaja aquí, y cómo se sabe que algo vale.

El hueco que este módulo cierra
-------------------------------
El informe de sesión sabía decir dónde estás, qué componentes hay, contra qué entorno trabajas
y qué no puedes tocar. No sabía decir **cómo se trabaja**. Medido en un espacio real:
su espacio declara siete etapas, cinco niveles de evidencia y un contrato de vacuidad en
`.harness/pipeline.json`, y el informe de 104 líneas mencionaba «AUDIT» cero veces, «etapa»
cero, «afirmación» cero y «atestación» cero.

El efecto práctico no es cosmético. El agente abría la sesión sin saber que existe una escala
de evidencia, así que afirmaba cosas en E0 creyendo que había terminado; sin saber que hay
etapas con prerrequisitos, así que proponía publicar sin haber probado; y sin saber que el
ámbito vacío no aprueba, que es justo la trampa que ese espacio existe para evitar.

Por qué se LEE y no se codifica
-------------------------------
El método es del espacio, no del motor. Un espacio usa AUDIT→RUNTIME con niveles E0-E4; otro
espacio usará otra cosa. Codificar aquí el método de uno sería imponérselo a todos, y volver a
la confusión entre motor y perfil que esta arquitectura separa. Lo que el arnés aporta es
leerlo, comprobar que está completo y ponerlo delante del agente antes de que empiece.

Si un espacio no declara método, no se inventa: no aparece la sección. Un método supuesto es
peor que ninguno, porque se obedece igual.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path

#: Dónde puede estar declarado el método. El primero que exista manda.
DECLARACIONES = (".harness/pipeline.json", ".harness/metodo.json", ".harness/method.json")


@dataclass
class Etapa:
    id: str
    requiere: list = field(default_factory=list)
    porque: str = ""
    extra: dict = field(default_factory=dict)


@dataclass
class Metodo:
    origen: str = ""
    schema: str = ""
    etapas: list = field(default_factory=list)
    niveles: dict = field(default_factory=dict)
    rutas: dict = field(default_factory=dict)
    clases: dict = field(default_factory=dict)
    vacuidad: dict = field(default_factory=dict)
    instrumento: str = ""
    aviso: str = ""

    def __bool__(self) -> bool:
        return bool(self.etapas or self.niveles)


def _instrumento(workspace: Path) -> str:
    """La orden con la que se ejecuta el método, si el espacio trae una."""
    for nombre in ("hz", "run.sh", "metodo", "method"):
        p = workspace / ".harness" / nombre
        if p.is_file():
            return f".harness/{nombre}"
    return ""


def leer(workspace: Path) -> Metodo:
    """El método declarado por el espacio. `Metodo()` vacío si no declara ninguno."""
    for rel in DECLARACIONES:
        p = workspace / rel
        if not p.is_file():
            continue
        try:
            doc = json.loads(p.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            return Metodo(origen=rel, aviso=f"no se pudo leer: {exc}")

        m = Metodo(origen=rel, schema=doc.get("schema", ""),
                   instrumento=_instrumento(workspace))
        crudas = doc.get("etapas") or doc.get("stages") or []
        if isinstance(crudas, dict):
            crudas = [dict(v, id=k) for k, v in crudas.items()]
        for e in crudas:
            if isinstance(e, str):
                m.etapas.append(Etapa(id=e))
                continue
            m.etapas.append(Etapa(
                id=e.get("id") or e.get("nombre") or e.get("name") or "?",
                requiere=list(e.get("requiere") or e.get("requires") or []),
                porque=e.get("porque") or e.get("why") or e.get("proposito") or "",
                extra={k: v for k, v in e.items()
                       if k not in ("id", "nombre", "name", "requiere", "requires",
                                    "porque", "why", "proposito")}))
        m.niveles = doc.get("niveles_evidencia") or doc.get("evidence_levels") or {}
        m.rutas = doc.get("rutas") or doc.get("paths") or {}
        m.clases = doc.get("clases") or doc.get("classes") or {}
        m.vacuidad = doc.get("contrato_vacuidad") or doc.get("emptiness_contract") or {}

        # Una cadena de etapas cuyo prerrequisito no existe es una cadena rota, y se dice.
        ids = {e.id for e in m.etapas}
        rotas = sorted({r for e in m.etapas for r in e.requiere if r not in ids})
        if rotas:
            m.aviso = (f"etapas que se exigen y no están declaradas: {', '.join(rotas)}. "
                       f"La cadena no cierra.")
        return m
    return Metodo()


def seccion(workspace: Path) -> list:
    """Las líneas del informe. Lista vacía si el espacio no declara método."""
    m = leer(workspace)
    if not m:
        return []

    L = ["## Cómo se trabaja aquí", "",
         f"Este espacio declara su propio método en `{m.origen}`. No es una convención que "
         f"puedas reinterpretar: es lo que su instrumento comprueba, y lo que decide si algo "
         f"que hiciste cuenta o no cuenta.", ""]

    if m.aviso:
        L += [f"_Aviso: {m.aviso}_", ""]

    if m.etapas:
        L += [f"### Las {len(m.etapas)} etapas, y por qué cada una", ""]
        for e in m.etapas:
            pre = f" ← exige {', '.join(f'`{r}`' for r in e.requiere)}" if e.requiere else ""
            L.append(f"- **`{e.id}`**{pre} — {e.porque or 'sin motivo declarado'}")
            for k, v in e.extra.items():
                L.append(f"    - _{k}_: {v}")
        L += ["", "**El orden no es una sugerencia.** Una etapa cuyo prerrequisito no cerró "
                  "no se ejecuta, y saltársela no adelanta trabajo: lo invalida.", ""]

    if m.niveles:
        L += ["### La escala de evidencia", "",
              "Toda afirmación vive en un nivel. Decir algo no lo sube de nivel; lo que lo "
              "sube es el respaldo que se le pone detrás.", ""]
        for k in sorted(m.niveles):
            L.append(f"- **`{k}`** — {m.niveles[k]}")
        L += ["", "**Antes de afirmar que algo funciona, di en qué nivel está.** Una "
                  "afirmación sin nivel se lee como el más alto, y casi nunca lo es.", ""]

    if m.vacuidad:
        motivo = m.vacuidad.get("_reason") or m.vacuidad.get("_porque") or ""
        L += ["### El contrato de vacuidad", ""]
        if motivo:
            L += [motivo, ""]
        declarados = (m.vacuidad.get("inaplicable_declarado")
                      or m.vacuidad.get("not_applicable_declared") or {})
        if declarados:
            L += [f"Hay {len(declarados)} comprobación(es) declaradas NO APLICABLES, cada una "
                  f"con motivo y fecha. Ninguna otra puede serlo sin declararse igual:", ""]
            for k, v in list(declarados.items())[:8]:
                porque = v.get("porque") or v.get("why") or "" if isinstance(v, dict) else str(v)
                desde = v.get("desde") or v.get("since") or "" if isinstance(v, dict) else ""
                L.append(f"- `{k}`{f' ({desde})' if desde else ''} — {porque}")
            L.append("")

    if m.clases:
        L += ["### Clases de obra, y qué exige cada una", ""]
        for nombre, c in m.clases.items():
            if not isinstance(c, dict):
                continue
            piezas = []
            if c.get("formatos"):
                piezas.append("formatos " + " ".join(f"`{f}`" for f in c["formatos"]))
            if c.get("prohibe"):
                piezas.append("PROHÍBE " + " ".join(f"`{f}`" for f in c["prohibe"]))
            if c.get("exige_arte_previo"):
                piezas.append("**exige arte previo**")
            if c.get("ajena"):
                piezas.append("obra ajena")
            L.append(f"- **`{nombre}`** — {'; '.join(piezas) or 'sin requisitos declarados'}")
        L.append("")

    if m.rutas:
        L += ["### Dónde vive la evidencia", ""]
        for k, v in m.rutas.items():
            L.append(f"- `{k}` → `{v}`")
        L += ["", "_Estas rutas son autoridad: se leen para saber dónde estás, y se escriben "
                  "ejecutando el método — nunca a mano._", ""]

    if m.instrumento:
        L += ["### Con qué se ejecuta", "",
              f"```bash\n{m.instrumento} run        # ejecuta la cadena y la sella\n"
              f"{m.instrumento} status     # último cierre satisfactorio por etapa\n"
              f"{m.instrumento} verify     # verifica la cadena de evidencia entera\n```", "",
              "**No declares una etapa cerrada sin haberla ejecutado.** El instrumento existe "
              "precisamente porque la palabra de quien hizo el trabajo no es evidencia de que "
              "el trabajo esté hecho.", ""]
    return L
