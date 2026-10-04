# -*- coding: utf-8 -*-
"""El ciclo de vida SDD. Cada fase declara cuándo puede empezar y cuándo ha terminado.

Por qué criterios de entrada y de salida explícitos
---------------------------------------------------
Sin criterio de entrada, una fase arranca con lo que haya y produce basura plausible. Sin
criterio de salida, «terminada» significa «el agente dejó de escribir», que es exactamente la
afirmación que refuto existe para no aceptar.

Una fase termina cuando **sus artefactos existen y sus puertas pasan**. No cuando el modelo dice
que terminó.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass

#: El ciclo, en orden. No todas las fases aplican a todo trabajo: las que no, se declaran
#: `SKIPPED` con motivo, nunca se omiten en silencio.
ORDER = ("DISCOVER", "SPECIFY", "PLAN", "ARCHITECT", "DESIGN", "IMPLEMENT", "TEST",
         "SECURE", "VALIDATE", "INTEGRATE", "RELEASE", "OBSERVE", "DOCUMENT")


@dataclass
class Phase:
    name: str
    purpose: str
    entry: tuple = ()          # artefactos que deben existir para poder empezar
    exit: tuple = ()           # artefactos que deben existir para poder terminar
    gates: tuple = ()
    optional: bool = False
    notes: str = ""

    def to_dict(self) -> dict:
        return asdict(self)


PHASES = {p.name: p for p in (
    Phase("DISCOVER", "Acotar el problema y decidir si merece la pena resolverlo.",
          entry=("intent",), exit=("problem-statement",),
          notes="Esta fase puede terminar la iniciativa antes de empezarla, y ese es un "
                "resultado válido y barato."),
    Phase("SPECIFY", "Escribir requisitos verificables con su criterio de aceptación.",
          entry=("problem-statement",), exit=("requirements", "acceptance-criteria"),
          gates=("G-TRACE",)),
    Phase("PLAN", "Ordenar el trabajo con dependencias, riesgos y puntos de decisión.",
          entry=("requirements",), exit=("plan", "test-strategy")),
    Phase("ARCHITECT", "Decidir la estructura, con la alternativa descartada.",
          entry=("requirements",), exit=("architecture", "threat-model"),
          gates=("G-SDD",)),
    Phase("DESIGN", "Definir estados, recorrido y accesibilidad.",
          entry=("requirements",), exit=("ux-spec", "a11y-spec"), optional=True),
    Phase("IMPLEMENT", "Escribir el producto contra la especificación aprobada.",
          entry=("plan", "architecture"), exit=("code",),
          gates=("G-POLICY", "G-SDD")),
    Phase("TEST", "Probar lo escrito, citando el requisito que cada prueba comprueba.",
          entry=("code",), exit=("tests", "test-report"),
          gates=("G-TRACE", "G-SDD")),
    Phase("SECURE", "Escanear secretos, dependencias e inventario.",
          entry=("code",), exit=("sbom", "security-report"),
          gates=("G-SECURITY",)),
    Phase("VALIDATE", "Comprobar contra el diseño y refutar lo que se afirma.",
          entry=("code",), exit=("review-report",),
          gates=("G-PR", "G-HUMAN"), notes="Aquí es donde el trabajo deja de ser del agente."),
    Phase("INTEGRATE", "Integrar el cambio en la rama principal, con revisión.",
          entry=("review-report",), exit=("merge",),
          gates=("G-PR", "G-HUMAN"), optional=True),
    Phase("RELEASE", "Empaquetar, firmar y publicar.",
          entry=("review-report",), exit=("release", "attestation"),
          gates=("G-LOCK", "G-HUMAN"), optional=True),
    Phase("OBSERVE", "Comprobar que lo desplegado se comporta como se dijo.",
          entry=("release",), exit=("observation-report",), optional=True,
          notes="Un despliegue no es correcto porque el comando devolviera 0."),
    Phase("DOCUMENT", "Documentar lo que existe, sin inventar lo que no se comprobó.",
          entry=("code",), exit=("documentation",), optional=True),
)}


def plan_for(goal_phases: list | None = None) -> list:
    """Las fases a ejecutar, en orden, sin las opcionales que nadie pidió."""
    if goal_phases:
        wanted = [p for p in ORDER if p in set(goal_phases)]
    else:
        wanted = [p for p in ORDER if not PHASES[p].optional]
    return [PHASES[p] for p in wanted]


def entry_satisfied(phase: Phase, produced: set) -> tuple[bool, list]:
    missing = [a for a in phase.entry if a not in produced]
    return (not missing, missing)


def exit_satisfied(phase: Phase, produced: set) -> tuple[bool, list]:
    missing = [a for a in phase.exit if a not in produced]
    return (not missing, missing)
