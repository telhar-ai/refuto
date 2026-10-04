# -*- coding: utf-8 -*-
"""Confianza declarada. Un descubrimiento sin confianza es una adivinanza con buena prensa.

Todo lo que refuto *infiere* —dónde está el núcleo, cuál es el repositorio de trabajo—
lleva un número y las señales que lo produjeron. Y el número tiene consecuencias: por debajo del
umbral, **se pregunta**; nunca se elige en silencio.

    ≥ 0.85   CIERTO       se puede continuar sin preguntar
    ≥ 0.55   PROBABLE     se recomienda, y se pide confirmación
    ≥ 0.25   POSIBLE      se muestra entre candidatos
    <  0.25  DESCARTADO   no se propone

La escala no es una probabilidad: es una convención con umbrales fijos. Fingir estadística sobre
señales heurísticas sería peor que declarar la convención.
"""

from __future__ import annotations

from dataclasses import dataclass, field

CIERTO, PROBABLE, POSIBLE, DESCARTADO = "CIERTO", "PROBABLE", "POSIBLE", "DESCARTADO"

UMBRAL_CIERTO = 0.85
UMBRAL_PROBABLE = 0.55
UMBRAL_POSIBLE = 0.25


@dataclass
class Signal:
    """Una señal a favor o en contra, con su peso y por qué existe."""
    name: str
    weight: float
    detail: str = ""

    def to_dict(self) -> dict:
        return {"signal": self.name, "weight": round(self.weight, 3), "detail": self.detail}


@dataclass
class Scored:
    """Un candidato con su puntuación y la lista de señales que la produjeron."""
    subject: str
    signals: list = field(default_factory=list)
    payload: dict = field(default_factory=dict)
    #: Un hecho que resuelve la pregunta por sí solo. No compite con las señales: las gana.
    decisive: bool = False
    decisive_reason: str = ""

    def add(self, name: str, weight: float, detail: str = "") -> "Scored":
        self.signals.append(Signal(name, weight, detail))
        return self

    @property
    def raw(self) -> float:
        """Suma sin acotar. Es la que ORDENA.

        Acotar a 1.0 antes de ordenar fue un error real: con 251 repositorios candidatos, todo
        lo que tenía git + remote + stack + CI llegaba al techo y quedaban 251 empatados en
        1.00. Un ranking donde todo empata no es un ranking.
        """
        return sum(s.weight for s in self.signals)

    @property
    def score(self) -> float:
        """Puntuación acotada. Es la que se MUESTRA y la que cruza los umbrales."""
        return max(0.0, min(1.0, self.raw))

    @property
    def level(self) -> str:
        s = self.score
        if s >= UMBRAL_CIERTO:
            return CIERTO
        if s >= UMBRAL_PROBABLE:
            return PROBABLE
        if s >= UMBRAL_POSIBLE:
            return POSIBLE
        return DESCARTADO

    @property
    def decidable(self) -> bool:
        """¿Se puede continuar sin preguntar? Sólo con `CIERTO`."""
        return self.level == CIERTO

    def why(self) -> str:
        """Las tres señales de más peso, para explicar sin abrumar."""
        top = sorted(self.signals, key=lambda s: -abs(s.weight))[:3]
        return " · ".join(f"{s.name}({s.weight:+.2f})" for s in top)

    def settle(self, reason: str) -> "Scored":
        self.decisive = True
        self.decisive_reason = reason
        return self

    def to_dict(self) -> dict:
        return {
            "subject": self.subject,
            "score": round(self.score, 3),
            "raw": round(self.raw, 3),
            "confidence": self.level,
            "decisive": self.decisive,
            "decisive_reason": self.decisive_reason,
            "signals": [s.to_dict() for s in self.signals],
            **self.payload,
        }


def resolve(candidates: list, *, what: str) -> dict:
    """Decide entre candidatos puntuados, o declara que hay que preguntar.

    Devuelve `{"outcome": …, "chosen": …, "candidates": […], "question": …}` con `outcome` en
    `AUTO` · `ASK` · `NONE`. **Nunca elige un candidato ambiguo en silencio**: si el mejor no
    es `CIERTO`, o si hay otro a menos de 0.15 de distancia, se pregunta.
    """
    # Se ordena por `raw`, no por `score`: acotar antes de ordenar empata a todos los buenos.
    ranked = sorted([c for c in candidates if c.level != DESCARTADO],
                    key=lambda c: -c.raw)
    if not ranked:
        return {"outcome": "NONE", "chosen": None, "candidates": [],
                "question": f"No se encontró {what}. ¿Dónde está?"}

    # Un hecho decisivo gana sin discusión: no es una señal más, es que la pregunta ya está
    # respondida (p. ej. «estás trabajando dentro de este repositorio»).
    decisivos = [c for c in ranked if c.decisive]
    if len(decisivos) == 1:
        return {"outcome": "AUTO", "chosen": decisivos[0].to_dict(),
                "candidates": [c.to_dict() for c in ranked[:12]], "question": "",
                "note": decisivos[0].decisive_reason}

    best = ranked[0]
    runner_up = ranked[1] if len(ranked) > 1 else None
    empatado = runner_up is not None and (best.raw - runner_up.raw) < 0.15

    if best.decidable and not empatado:
        return {"outcome": "AUTO", "chosen": best.to_dict(),
                "candidates": [c.to_dict() for c in ranked[:12]], "question": ""}

    razon = ("hay dos candidatos casi empatados" if empatado
             else f"el mejor candidato es {best.level}, no CIERTO")
    return {"outcome": "ASK", "chosen": None,
            "candidates": [c.to_dict() for c in ranked[:12]],
            "total_candidates": len(ranked),
            "question": f"¿Cuál es {what}? ({razon}; se recomienda «{best.subject}»)"}
