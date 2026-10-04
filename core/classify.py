# -*- coding: utf-8 -*-
"""De una tarea a los roles que la ejecutan. Sin que nadie tenga que decírselo.

El orden de las fuentes, y por qué ese orden
---------------------------------------------
    1. lo que el PROYECTO declara      `Tipo: ARQ, BE, INFRA` en la tabla de la historia
    2. lo que las ETIQUETAS dicen      `documentation`, `enhancement`, `security`
    3. lo que el TEXTO sugiere         palabras del título y del cuerpo

La primera manda porque es la única que no es una conjetura: alguien del equipo escribió ahí qué
disciplina hace falta. Las otras dos existen para los proyectos que no lo declaran, y **se
marcan como inferencia** para que nadie las confunda con un dato.

Esa distinción no es formalismo. Una clasificación equivocada enruta el trabajo a un rol con el
privilegio equivocado, y el privilegio equivocado es una brecha. Cuando la confianza es baja,
esto **pregunta** en vez de elegir.
"""

from __future__ import annotations

import re
from dataclasses import asdict, dataclass, field

from core.confidence import Scored

#: Vocabulario de disciplina → roles. Las claves son las que usan los proyectos de verdad;
#: se amplía en el manifiesto con `classification.aliases` sin tocar este archivo.
DISCIPLINAS = {
    "ARQ":    ["solution-architect"],
    "ARCH":   ["solution-architect"],
    "BE":     ["backend-engineer"],
    "BACKEND": ["backend-engineer"],
    "FE":     ["frontend-engineer"],
    "FRONTEND": ["frontend-engineer"],
    "UX":     ["ux-designer", "accessibility-engineer"],
    "UI":     ["ux-designer"],
    "QA":     ["test-strategist", "test-engineer"],
    "TEST":   ["test-engineer"],
    "SEC":    ["security-architect", "security-engineer"],
    "SEG":    ["security-architect", "security-engineer"],
    "INFRA":  ["release-engineer", "observability-engineer"],
    "DEVOPS": ["release-engineer"],
    "OPS":    ["observability-engineer"],
    "DAT":    ["data-architect", "data-engineer"],
    "DATA":   ["data-architect", "data-engineer"],
    "DOC":    ["technical-writer"],
    "PM":     ["delivery-manager"],
    "PO":     ["product-strategist"],
    "REQ":    ["requirements-engineer", "acceptance-engineer"],
}

#: Etiquetas de forja → roles. Débil: una etiqueta describe la naturaleza, no la disciplina.
ETIQUETAS = {
    "documentation": ["technical-writer"],
    "docs":          ["technical-writer"],
    "enhancement":   [],
    "bug":           ["test-engineer"],
    "security":      ["security-engineer"],
    "infra":         ["release-engineer"],
    "infrastructure": ["release-engineer"],
    "frontend":      ["frontend-engineer"],
    "backend":       ["backend-engineer"],
    "ux":            ["ux-designer"],
    "performance":   ["performance-engineer"],
}

#: Palabras → roles. La fuente más débil, y por eso pesa menos y siempre se marca inferida.
PALABRAS = {
    "solution-architect":     ("adr", "arquitectura", "decisión", "decision", "diseño técnico",
                               "trade-off", "alternativa", "plano de control"),
    "security-architect":     ("amenaza", "threat", "superficie de ataque", "autorización"),
    "security-engineer":      ("vulnerabilidad", "cve", "secreto", "credencial", "sbom",
                               "escaneo"),
    "backend-engineer":       ("endpoint", "api", "servicio", "cola", "sqs", "scheduler",
                               "migración", "backend", "job"),
    "frontend-engineer":      ("componente", "pantalla", "interfaz", "css", "react", "vista"),
    "data-architect":         ("esquema", "schema", "tabla", "modelo de datos", "contrato de datos"),
    "data-engineer":          ("etl", "pipeline", "ingesta", "transformación"),
    "test-engineer":          ("prueba", "test", "cobertura", "e2e", "regresión"),
    "test-strategist":        ("estrategia de prueba", "pirámide", "plan de pruebas"),
    "ux-designer":            ("wireframe", "maqueta", "recorrido", "flujo de usuario"),
    "accessibility-engineer": ("accesibilidad", "wcag", "lector de pantalla", "contraste"),
    "release-engineer":       ("despliegue", "release", "empaquetado", "ambiente", "staging",
                               "entorno", "feature flag", "flags"),
    "observability-engineer": ("métrica", "traza", "alerta", "slo", "logs", "monitoreo"),
    "requirements-engineer":  ("requisito", "historia de usuario", "criterio de aceptación"),
    "technical-writer":       ("documentar", "runbook", "manual", "readme"),
    "performance-engineer":   ("latencia", "carga", "rendimiento", "timeout", "180 s", "300 s"),
    "adversarial-reviewer":   ("refutar", "revisión adversarial", "spike comparativo"),
    "delivery-manager":       ("plan", "dependencias", "riesgo", "cronograma"),
}

#: Campos de la tabla donde suele venir la disciplina declarada.
CAMPOS_TIPO = ("Tipo", "Tipo / Gate", "Disciplina", "Área", "Area", "Type")


@dataclass
class Classification:
    task: str = ""
    roles: list = field(default_factory=list)
    primary: str = ""
    source: str = ""              # declarado | etiquetas | inferido | ninguno
    evidence: str = "?"           # L declarado en el proyecto · I inferido
    confidence: str = ""
    score: float = 0.0
    signals: list = field(default_factory=list)
    question: str = ""

    @property
    def decidable(self) -> bool:
        return bool(self.primary) and not self.question

    def to_dict(self) -> dict:
        return asdict(self)

    def explain(self) -> str:
        L = [f"{self.task} → {', '.join(self.roles) or '(sin rol)'}  "
             f"[{self.confidence} · {self.source} · evidencia {self.evidence}]"]
        L += [f"    · {s}" for s in self.signals]
        if self.question:
            L.append(f"    ? {self.question}")
        return "\n".join(L)


def _tipos_declarados(fields: dict, tabla: dict) -> list:
    """Los tokens de disciplina declarados, filtrados contra el vocabulario **efectivo**.

    Filtraba contra `DISCIPLINAS` en vez de contra la tabla ampliada con los alias del
    proyecto, así que el punto de extensión existía y no funcionaba: un `Tipo: PLATAFORMA`
    declarado en el manifiesto se descartaba antes de poder usarse.
    """
    for campo in CAMPOS_TIPO:
        raw = fields.get(campo)
        if not raw:
            continue
        # `A (arrancable) · G0` no es una disciplina: es el gate. Se toman sólo los tokens que
        # el vocabulario reconoce; lo demás se ignora en vez de inventarse un significado.
        tokens = [t.strip().upper() for t in re.split(r"[,/·|;]+", raw) if t.strip()]
        return [t for t in tokens if t in tabla]
    return []


def classify(task, *, roles_disponibles: set | None = None,
             aliases: dict | None = None) -> Classification:
    """Decide qué roles ejecutan una tarea, y con qué confianza."""
    tabla = dict(DISCIPLINAS)
    tabla.update({k.upper(): v for k, v in (aliases or {}).items()})

    c = Classification(task=task.label if hasattr(task, "label") else str(task))
    s = Scored(subject=c.task)
    roles: list = []

    # 1 · lo que el proyecto declara
    declarados = _tipos_declarados(getattr(task, "fields", {}) or {}, tabla)
    if declarados:
        for t in declarados:
            roles += tabla[t]
        s.add("tipo-declarado", 0.9, f"el proyecto declara Tipo: {', '.join(declarados)}")
        c.source, c.evidence = "declarado", "L"

    # 2 · etiquetas
    etiq = [l.lower() for l in (getattr(task, "labels", []) or [])]
    sugeridos = [r for l in etiq for r in ETIQUETAS.get(l, [])]
    if sugeridos:
        roles += sugeridos
        s.add("etiquetas", 0.25 if not declarados else 0.05,
              ", ".join(etiq))
        if not declarados:
            c.source, c.evidence = "etiquetas", "L"

    # 3 · texto
    texto = f"{getattr(task, 'title', '')} {getattr(task, 'body_excerpt', '')}".lower()
    inferidos = sorted({rol for rol, claves in PALABRAS.items()
                        if any(k in texto for k in claves)})
    if inferidos:
        if not declarados and not sugeridos:
            roles += inferidos
            s.add("texto", 0.35, f"palabras: {', '.join(inferidos[:4])}")
            c.source, c.evidence = "inferido", "I"
        else:
            s.add("texto-coincide", 0.10,
                  f"el texto también sugiere {', '.join(inferidos[:4])}")

    # Se quitan los que no existen en el registro: enrutar a un rol inexistente es peor que no
    # enrutar, porque el fallo aparece tarde.
    vistos, limpio = set(), []
    for r in roles:
        if roles_disponibles is not None and r not in roles_disponibles:
            continue
        if r not in vistos:
            vistos.add(r)
            limpio.append(r)

    c.roles = limpio
    c.signals = [f"{x.name}: {x.detail}" for x in s.signals]
    c.score, c.confidence = round(s.score, 3), s.level

    if not limpio:
        c.source = c.source or "ninguno"
        c.question = ("no se pudo determinar la disciplina. Declare `Tipo` en la historia, o "
                      "elija el rol con `--role`.")
        return c

    c.primary = limpio[0]
    # Por debajo de CIERTO se pregunta. Enrutar mal da un privilegio que nadie pidió.
    if c.confidence not in ("CIERTO", "PROBABLE"):
        c.question = (f"confianza {c.confidence}: se propone «{c.primary}» por inferencia. "
                      f"Confírmelo con `--role` si no es correcto.")
    return c


def classify_all(tasks: list, *, roles_disponibles: set | None = None,
                 aliases: dict | None = None) -> list:
    return [classify(t, roles_disponibles=roles_disponibles, aliases=aliases) for t in tasks]
