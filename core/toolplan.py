# -*- coding: utf-8 -*-
"""Qué herramientas hacen falta **para este proyecto**, y qué hacer con las que faltan.

El error que evita
------------------
Listar treinta herramientas y decir cuáles faltan. Eso no es un diagnóstico: es inventario. Un
proyecto de Rust sin `mvn` no tiene un problema. Un proyecto con `Dockerfile` sin `docker` sí.

La necesidad se calcula del **stack detectado** y de las **fases que se van a ejecutar**, no de
una lista fija:

    REQUIRED        sin ella, una fase declarada no se puede ejecutar   → BLOCKED
    RECOMMENDED     mejora una fase, pero hay alternativa               → observación
    OPTIONAL        aporta si está                                      → silencio
    NOT_APPLICABLE  este proyecto no la usa                             → no se menciona

Sobre instalar
--------------
Este módulo **nunca instala nada**. Propone, con el método oficial del proveedor para este
sistema operativo, y espera autorización explícita. Instalar software del sistema en silencio
es exactamente el tipo de acción que un harness de gobierno no debe poder hacer sola.

Tampoco propone `curl … | sh` jamás, aunque sea el método que el proveedor documenta: ejecutar
un script remoto sin inspección es la superficie de suministro que refuto existe para
vigilar. Cuando el único método oficial es ése, se dice, y se deja al usuario.
"""

from __future__ import annotations

import platform
import shutil
from dataclasses import asdict, dataclass, field

REQUIRED = "REQUIRED"
RECOMMENDED = "RECOMMENDED"
OPTIONAL = "OPTIONAL"
NOT_APPLICABLE = "NOT_APPLICABLE"

#: `(herramienta, necesidad)` según lo que el proyecto tenga. La clave es un ecosistema o una
#: fase; el valor, lo que eso implica.
BY_ECOSYSTEM = {
    "node":       [("node", REQUIRED), ("npm", REQUIRED), ("pnpm", OPTIONAL), ("yarn", OPTIONAL)],
    "python":     [("python3", REQUIRED), ("pytest", RECOMMENDED), ("uv", OPTIONAL)],
    "jvm":        [("mvn", RECOMMENDED), ("gradle", RECOMMENDED)],
    "cargo":      [("cargo", REQUIRED)],
    "go":         [("go", REQUIRED)],
    "container":  [("docker", REQUIRED), ("trivy", RECOMMENDED)],
    "terraform":  [("terraform", REQUIRED)],
    "helm":       [("helm", REQUIRED), ("kubectl", REQUIRED)],
    "dotnet":     [],
    "ruby":       [],
    "php":        [],
}

BY_PHASE = {
    "IMPLEMENT": [("git", REQUIRED)],
    "TEST":      [("git", REQUIRED)],
    "SECURE":    [("gitleaks", RECOMMENDED), ("syft", RECOMMENDED), ("trivy", RECOMMENDED)],
    "INTEGRATE": [("gh", RECOMMENDED), ("glab", OPTIONAL)],
    "DEPLOY":    [("kubectl", RECOMMENDED), ("docker", RECOMMENDED)],
    "OBSERVE":   [("otel-cli", OPTIONAL)],
    "RELEASE":   [("cosign", OPTIONAL)],
    "DESIGN":    [("playwright", RECOMMENDED)],
    "VALIDATE":  [("playwright", RECOMMENDED)],
}

#: Método oficial por herramienta y sistema. Nada de scripts remotos: si el proveedor sólo
#: documenta `curl | sh`, se declara y no se propone una orden.
INSTALL = {
    "Darwin": {
        "gh":         "brew install gh",
        "glab":       "brew install glab",
        "jq":         "brew install jq",
        "yq":         "brew install yq",
        "rg":         "brew install ripgrep",
        "docker":     "brew install --cask docker",
        "kubectl":    "brew install kubectl",
        "helm":       "brew install helm",
        "terraform":  "brew install terraform",
        "aws":        "brew install awscli",
        "gcloud":     "brew install --cask google-cloud-sdk",
        "az":         "brew install azure-cli",
        "syft":       "brew install syft",
        "trivy":      "brew install trivy",
        "gitleaks":   "brew install gitleaks",
        "cosign":     "brew install cosign",
        "go":         "brew install go",
        "gradle":     "brew install gradle",
        "mvn":        "brew install maven",
        "node":       "brew install node",
        "pnpm":       "brew install pnpm",
        "yarn":       "brew install yarn",
        "uv":         "brew install uv",
        "playwright": "npx playwright install --with-deps",
        "pytest":     "python3 -m pip install --user pytest",
        "otel-cli":   None,     # sólo binario suelto de GitHub Releases; se inspecciona a mano
    },
    "Linux": {
        "gh":         "consulte el repositorio oficial de su distribución (apt/dnf) para «gh»",
        "jq":         "apt install jq  ·  dnf install jq",
        "docker":     "siga la guía oficial de Docker Engine para su distribución",
        "kubectl":    "siga la guía oficial de Kubernetes para su distribución",
        "terraform":  "use el repositorio oficial de HashiCorp",
        "playwright": "npx playwright install --with-deps",
        "pytest":     "python3 -m pip install --user pytest",
    },
}

#: Herramientas cuya instalación NO se propone nunca automáticamente, con el motivo.
NEVER_AUTO = {
    "docker": "instala un servicio del sistema y pide privilegios",
    "gcloud": "instala un SDK grande y modifica el PATH del shell",
    "az":     "ídem",
}


@dataclass
class ToolNeed:
    name: str
    need: str
    present: bool
    version: str = ""
    reasons: list = field(default_factory=list)
    install_hint: str = ""
    auto_installable: bool = False
    blocker: bool = False

    def to_dict(self) -> dict:
        return asdict(self)


def _need_rank(need: str) -> int:
    return {REQUIRED: 3, RECOMMENDED: 2, OPTIONAL: 1, NOT_APPLICABLE: 0}[need]


def plan(*, ecosystems: list, phases: list, tool_facts: list) -> dict:
    """Calcula la necesidad de cada herramienta para ESTE proyecto y ESTAS fases."""
    present = {}
    for t in tool_facts:
        name = t.name if hasattr(t, "name") else t["name"]
        present[name] = (t.present if hasattr(t, "present") else t["present"],
                         t.version if hasattr(t, "version") else t.get("version", ""))

    needs: dict = {}

    def note(name: str, need: str, reason: str) -> None:
        cur = needs.get(name)
        if cur is None:
            ok, ver = present.get(name, (bool(shutil.which(name)), ""))
            cur = needs[name] = ToolNeed(name=name, need=need, present=ok, version=ver)
        if _need_rank(need) > _need_rank(cur.need):
            cur.need = need
        if reason not in cur.reasons:
            cur.reasons.append(reason)

    for eco in ecosystems:
        for name, need in BY_ECOSYSTEM.get(eco, []):
            note(name, need, f"el proyecto usa {eco}")
    for phase in phases:
        for name, need in BY_PHASE.get(phase, []):
            note(name, need, f"la fase {phase} la usa")

    system = platform.system()
    table = INSTALL.get(system, {})
    for need_obj in needs.values():
        if need_obj.present:
            continue
        hint = table.get(need_obj.name)
        if need_obj.name in NEVER_AUTO:
            need_obj.install_hint = (f"{hint or 'consulte la documentación oficial'} — "
                                     f"NO se instala automáticamente: {NEVER_AUTO[need_obj.name]}")
            need_obj.auto_installable = False
        elif hint:
            need_obj.install_hint = hint
            need_obj.auto_installable = True
        else:
            need_obj.install_hint = (
                f"no hay método oficial registrado para {system}. Consulte la documentación "
                f"del proveedor e instálela a mano; después vuelva a ejecutar `refuto doctor`.")
            need_obj.auto_installable = False
        need_obj.blocker = need_obj.need == REQUIRED

    ordered = sorted(needs.values(), key=lambda n: (-_need_rank(n.need), n.present, n.name))
    blockers = [n for n in ordered if n.blocker]
    return {
        "schema": "harness.toolplan/v1",
        "system": system,
        "ecosystems": sorted(set(ecosystems)),
        "phases": list(phases),
        "tools": [n.to_dict() for n in ordered],
        "blockers": [n.name for n in blockers],
        "summary": {
            "required_missing": len(blockers),
            "recommended_missing": len([n for n in ordered
                                        if n.need == RECOMMENDED and not n.present]),
            "satisfied": len([n for n in ordered if n.present]),
        },
    }


def install_proposal(plan_doc: dict) -> dict:
    """Propuesta de instalación. **No ejecuta nada.**

    Devuelve órdenes exactas, para qué sirve cada una y qué falta autorizar. Que el usuario
    pueda leer la orden antes de que se ejecute no es una cortesía: es el control.
    """
    auto, manual = [], []
    for t in plan_doc["tools"]:
        if t["present"] or t["need"] not in (REQUIRED, RECOMMENDED):
            continue
        entry = {"tool": t["name"], "need": t["need"], "why": "; ".join(t["reasons"]),
                 "command": t["install_hint"]}
        (auto if t["auto_installable"] else manual).append(entry)
    return {
        "schema": "harness.install-proposal/v1",
        "requires_authorization": bool(auto),
        "auto": auto,
        "manual": manual,
        "note": ("Ninguna de estas órdenes se ha ejecutado. Refuto no instala software del "
                 "sistema sin autorización explícita, y nunca ejecuta scripts remotos."),
    }
