# -*- coding: utf-8 -*-
"""Qué dice el diario cuando se le pregunta por el día de trabajo, y qué NO puede decir.

El problema que cierra (medido el 2026-09-28)
---------------------------------------------
Había **52.131 eventos** repartidos en 13 espacios y ninguna herramienta que los leyera:
`refuto evidence --last N` imprime líneas crudas, que sirve para mirar las últimas y no para
saber dónde se va el tiempo. La telemetría estaba recogida y sin explotar — que es una forma
cara de no tenerla.

La regla de esta lectura: **toda cifra con su cobertura**
---------------------------------------------------------
`duration_ms` y `entrada_digest` existen desde ese mismo día. Los eventos anteriores no los
llevan, así que cualquier mediana calculada sobre el diario entero se sacaría de una fracción
minúscula sin decirlo. Aquí no hay ninguna cifra sin el `de N` al lado: una mediana de 12 ms
sobre 40 eventos de 52.131 es un dato distinto de la misma mediana sobre todos, y confundirlos
es exactamente el tipo de verde falso que este programa existe para no producir.

Lo que esto NO mide
-------------------
- **Tokens y coste monetario.** No pasan por el guardián; viven en los transcripts del runtime.
- **El arranque del intérprete.** `duration_ms` empieza a contar dentro del proceso. El coste de
  extremo a extremo se mide por fuera, y la diferencia entre los dos es justo lo que dice si
  hay que optimizar el código o dejar de arrancar un proceso por decisión.
- **Lo que el guardián no ve.** Una orden que el runtime no somete a un gancho no está aquí, y
  su ausencia no es evidencia de que no ocurriera.
"""

from __future__ import annotations

import collections
import json
import os
from datetime import datetime, timedelta
from pathlib import Path

REGISTRO = "~/.config/harness/registry.json"
KIND_DECISION = "policy/decision"
KIND_RESULTADO = "tool/result"


def ledger(workspace: Path) -> Path:
    return Path(workspace) / ".harness" / "evidence" / "ledger.jsonl"


def espacios_registrados() -> dict:
    """`{nombre: [raíces]}` del registro del usuario, o `{}` si no hay registro.

    Vacío significa «no hay censo», no «no hay espacios»: quien llama tiene que distinguirlo,
    porque resumir cero espacios y decir que todo va bien es aprobar un ámbito vacío.
    """
    p = Path(os.path.expanduser(REGISTRO))
    try:
        doc = json.loads(p.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}
    esp = doc.get("espacios")
    if not isinstance(esp, dict):
        return {}
    out = {}
    for nombre, d in esp.items():
        raices = d.get("raices") if isinstance(d, dict) else None
        if isinstance(raices, list):
            out[nombre] = [Path(os.path.expanduser(str(r))) for r in raices]
    return out


def diarios(raices) -> list:
    """Los diarios que existen bajo esas raíces, incluidos los de repositorios anidados."""
    vistos: dict = {}
    for raiz in raices:
        raiz = Path(raiz)
        if not raiz.is_dir():
            continue
        candidatos = [ledger(raiz)]
        # Un espacio multi-repo tiene un diario por repo gobernado. Dos niveles cubren
        # `<espacio>/<repo>` y `<espacio>/<area>/<repo>`, que es como están organizados hoy.
        candidatos += list(raiz.glob("*/.harness/evidence/ledger.jsonl"))
        candidatos += list(raiz.glob("*/*/.harness/evidence/ledger.jsonl"))
        for c in candidatos:
            if c.is_file():
                vistos[str(c.resolve())] = c
    return sorted(vistos.values(), key=str)


def leer(rutas, *, desde: datetime | None = None) -> dict:
    """Los eventos de esos diarios. Devuelve `{eventos, leidos, ilegibles, fuentes}`.

    Una línea que no parsea **se cuenta**, no se ignora: un diario medio corrupto que se lee
    como si estuviera entero produce cifras más bajas y ninguna señal de que faltan.
    """
    eventos: list = []
    ilegibles = 0
    leidos = 0
    fuentes: list = []
    for p in rutas:
        n0 = len(eventos)
        try:
            fh = Path(p).open(encoding="utf-8", errors="replace")
        except OSError:
            ilegibles += 1
            continue
        with fh:
            for linea in fh:
                if not linea.strip():
                    continue
                leidos += 1
                try:
                    e = json.loads(linea)
                except ValueError:
                    ilegibles += 1
                    continue
                if not isinstance(e, dict):
                    ilegibles += 1
                    continue
                if desde is not None and _ts(e) is not None and _ts(e) < desde:
                    continue
                e["_espacio"] = _espacio_de(Path(p))
                eventos.append(e)
        fuentes.append({"path": str(p), "eventos": len(eventos) - n0})
    return {"eventos": eventos, "leidos": leidos, "ilegibles": ilegibles, "fuentes": fuentes}


def _espacio_de(p: Path) -> str:
    """El nombre legible del espacio al que pertenece un diario (`…/<nombre>/.harness/…`)."""
    partes = p.resolve().parts
    try:
        i = len(partes) - 1 - partes[::-1].index(".harness")
    except ValueError:
        return p.parent.name
    return partes[i - 1] if i >= 1 else p.parent.name


def _ts(e: dict):
    v = e.get("ts")
    if not isinstance(v, str):
        return None
    try:
        return datetime.fromisoformat(v)
    except ValueError:
        return None


def _percentil(valores: list, q: float):
    """El valor en el percentil `q` de una lista YA ordenada. `None` si no hay datos."""
    if not valores:
        return None
    if len(valores) == 1:
        return valores[0]
    i = min(len(valores) - 1, max(0, int(round(q * (len(valores) - 1)))))
    return valores[i]


def _stats(valores: list) -> dict:
    v = sorted(valores)
    return {"n": len(v), "mediana": _percentil(v, 0.5), "p95": _percentil(v, 0.95),
            "max": v[-1] if v else None, "total": round(sum(v), 2) if v else 0}


def resumen(eventos: list) -> dict:
    """Todo lo que se puede AFIRMAR de esos eventos, cada cosa con su cobertura."""
    decisiones = [e for e in eventos if e.get("kind") == KIND_DECISION]
    resultados = [e for e in eventos if e.get("kind") == KIND_RESULTADO]

    outcomes = collections.Counter(e.get("outcome") or "?" for e in decisiones)
    dec = sum(outcomes[k] for k in ("allow", "deny", "ask"))
    friccion = (outcomes["deny"] + outcomes["ask"]) / dec * 100 if dec else None

    # Coste del guardián. `duration_ms` existe desde el 2026-09-28: la cobertura NO es adorno.
    medidas = [e["duration_ms"] for e in decisiones
               if isinstance(e.get("duration_ms"), (int, float)) and not isinstance(e.get("duration_ms"), bool)]
    guardian = _stats(medidas)
    guardian.update(de=len(decisiones),
                    cobertura=round(100 * len(medidas) / len(decisiones), 1) if decisiones else None)

    # Duración REAL de cada herramienta: la distancia entre la decisión y su resultado. Se casan
    # por `entrada_digest`, no por cercanía en el tiempo; con varias herramientas en vuelo, la
    # cercanía empareja las de otro.
    por_digest: dict = {}
    for e in decisiones:
        d = e.get("entrada_digest")
        if d and _ts(e) is not None:
            por_digest.setdefault(d, []).append(e)
    duraciones: list = []
    por_herramienta: dict = collections.defaultdict(list)
    emparejados = 0
    for r in resultados:
        d, tr = r.get("entrada_digest"), _ts(r)
        if not d or tr is None or d not in por_digest:
            continue
        previas = [x for x in por_digest[d] if _ts(x) <= tr]
        if not previas:
            continue
        emparejados += 1
        seg = (tr - _ts(max(previas, key=lambda x: _ts(x)))).total_seconds()
        if seg >= 0:
            duraciones.append(seg)
            por_herramienta[r.get("tool") or "?"].append(seg)
    herramientas = _stats(duraciones)
    herramientas.update(resultados=len(resultados), emparejados=emparejados,
                        sin_pareja=len(resultados) - emparejados,
                        decisiones_sin_resultado=max(0, len(decisiones) - emparejados))

    desenlace = collections.Counter()
    for r in resultados:
        ok = r.get("ok")
        desenlace["ok" if ok is True else ("fallo" if ok is False else "sin determinar")] += 1

    reglas = collections.Counter()
    for e in decisiones:
        if e.get("outcome") in ("deny", "ask") and e.get("rule"):
            reglas[(e["outcome"], e["rule"])] += 1

    sellos = [t for t in (_ts(e) for e in eventos) if t is not None]
    return {
        "eventos": len(eventos),
        "desde": min(sellos).isoformat() if sellos else "",
        "hasta": max(sellos).isoformat() if sellos else "",
        "decisiones": {"total": len(decisiones), **{k: outcomes[k] for k in ("allow", "deny", "ask")},
                       "friccion_pct": round(friccion, 1) if friccion is not None else None},
        "guardian_ms": guardian,
        "herramientas_s": herramientas,
        "desenlace": dict(desenlace),
        "reglas": [{"outcome": o, "rule": r, "n": n} for (o, r), n in reglas.most_common(12)],
        "por_espacio": dict(collections.Counter(e.get("_espacio") or "?" for e in eventos).most_common()),
        "por_runtime": dict(collections.Counter(e.get("runtime") for e in decisiones if e.get("runtime")).most_common()),
        "por_herramienta": dict(collections.Counter(e.get("tool") for e in decisiones if e.get("tool")).most_common(8)),
        "lentas": sorted(({"tool": t, **_stats(v)} for t, v in por_herramienta.items()),
                         key=lambda x: (x["mediana"] is None, -(x["mediana"] or 0)))[:8],
        "por_dia": dict(sorted(collections.Counter(
            _ts(e).date().isoformat() for e in decisiones if _ts(e) is not None).items())),
    }


def ventana(dias: int | None):
    return None if not dias or dias <= 0 else datetime.now().astimezone() - timedelta(days=dias)
