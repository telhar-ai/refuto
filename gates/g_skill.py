# -*- coding: utf-8 -*-
"""G-SKILL · Las skills cumplen el contrato y cargarían donde se dice que cargan. (H-08)"""

from __future__ import annotations

from collections import Counter

from core.model import BLOCKED, FAIL, Finding, MEDIUM, PASS, Result, Scope
from core.skill import check, discover

GATE_ID = "G-SKILL"
TITLE = "Contrato de las skills"
THRESHOLD = "frontmatter válido · `name` == directorio · descripción presente · sin nombres duplicados"


def run(ctx) -> Result:
    cfg = (ctx.manifest or {}).get("skills") or {}
    roots = [str(ctx.workspace / r) for r in (cfg.get("roots") or [])]
    if not roots:
        roots = [str(ctx.workspace / p) for p in
                 (".claude/skills", ".kiro/skills", ".gemini/skills", "skills")]
    strict = cfg.get("require_name_matches_directory", True)

    skills = discover(roots)
    if not skills:
        return Result(GATE_ID, TITLE, BLOCKED, severity=MEDIUM, threshold=THRESHOLD,
                      scope=Scope(examined=0, universe=f"skills bajo {', '.join(roots)}",
                                  declared=bool(cfg.get("roots")), subject="skills"),
                      measure=f"no se encontró ninguna SKILL.md bajo {', '.join(roots)}")

    findings = []
    for s in skills:
        for problem in check(s, require_name_matches_directory=strict):
            findings.append(Finding(str(s.path.relative_to(ctx.workspace))
                                    if s.path.is_relative_to(ctx.workspace) else str(s.path),
                                    problem))

    names = Counter(s.name for s in skills if s.name)
    for name, count in names.items():
        if count > 1:
            where = [str(s.path) for s in skills if s.name == name]
            findings.append(Finding("skills", f"«{name}» declarado {count} veces: "
                                              f"{', '.join(where)}. Cuál gana depende del orden "
                                              f"de descubrimiento, que no está definido."))

    unversioned = [s.directory for s in skills if not s.version]
    observations = []
    if unversioned:
        observations.append(
            f"{len(unversioned)} skills sin `harness.version` en el frontmatter: no se pueden "
            f"fijar en un lock ni comparar entre espacios. Afecta a: {', '.join(unversioned[:6])}"
            + ("…" if len(unversioned) > 6 else ""))

    scope = Scope(
        examined=len(skills),
        unknown=0,
        universe=f"skills bajo {', '.join(roots)}",
        declared=bool(cfg.get("roots")),
        subject="skills",
        items_expected=len(skills),
        coverage=1.0,
    )
    return Result(GATE_ID, TITLE, PASS if not findings else FAIL, severity=MEDIUM,
                  threshold=THRESHOLD,
                  measure=f"{len(skills)} skills · {len(set(names))} nombres distintos · "
                          f"{len(findings)} incumplimientos",
                  findings=findings, observations=observations, scope=scope)
