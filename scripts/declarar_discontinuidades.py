#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Declara las roturas de la cadena de un espacio, leyendo los digests de su propio diario.

Lo ejecuta una PERSONA: `.harness/evidence/` es ruta protegida y el guardián deniega al agente
escribir ahí. Eso es el control, no un obstáculo — quien reconoce una rotura responde por ella.

    python3 scripts/declarar_discontinuidades.py <espacio> [--escribir] [--firma NOMBRE]

    python3 scripts/declarar_discontinuidades.py /ruta/al/espacio                # en seco
    python3 scripts/declarar_discontinuidades.py /ruta/al/espacio --escribir     # lo aplica

Qué comprueba antes de declarar nada, y por qué se niega si falla:

  · que cada evento reproduzca SU PROPIA huella. Si alguno no, eso es una EDICIÓN y no una
    carrera: no se declara, se investiga.
  · que cada rotura tenga la firma de la carrera: que su `prev` sea una huella REAL y reciente
    del propio diario. Es decir, que el evento se anclara a un estado que existió, sólo que no
    al último. No vale «el hermano inmediato encadena a lo mismo» — con tres escritores, el
    tercero puede anclarse a la cabeza que dejó el primero, y eso sigue siendo concurrencia.
    Si el `prev` no aparece en ninguna parte, el evento se ancló a algo que nunca hubo: la
    causa que se escribiría sería falsa, y no se escribe nada.

No inventa nada: la línea, el `prev` encontrado y la cabeza esperada salen del diario. Si el
diario cambia después, la declaración deja de casar y la cadena vuelve a ROTA. Ver ADR-0019.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

RAIZ = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(RAIZ))

from core.evidence import SCHEMA_DISCONTINUIDADES, _eslabon, ledger_path, ruta_discontinuidades

CAUSA = ("carrera de concurrencia del guardian: dos procesos leyeron la misma cabeza y "
         "encadenaron los dos a ella. Defecto cerrado en refuto 7eb0945 (2026-09-25). "
         "Ninguna huella alterada: los eventos implicados reproducen su propio digest, "
         "comprobado al declarar.")


def main() -> int:
    args = [a for a in sys.argv[1:] if not a.startswith("--")]
    if not args:
        print(__doc__)
        return 64
    ws = Path(args[0]).expanduser().resolve()
    escribir = "--escribir" in sys.argv
    # Quien declara tiene que decir quién es. Un `declared_by` vacío deja una discontinuidad
    # reconocida por nadie, que es casi lo mismo que borrarla sin más: dentro de un año la
    # pregunta útil no es qué pasó, sino a quién preguntarle.
    if escribir and "--firma" not in sys.argv:
        print("  falta `--firma NOMBRE`: una discontinuidad la reconoce alguien, y ese alguien")
        print("  queda escrito en `declared_by`. Sin firma no se escribe.")
        return 64
    firma = sys.argv[sys.argv.index("--firma") + 1] if "--firma" in sys.argv else "(en seco)"
    hoy = __import__("datetime").date.today().isoformat()

    diario = ledger_path(ws)
    if not diario.is_file():
        print(f"  no hay diario en {diario}")
        return 1
    lineas = diario.read_text(encoding="utf-8", errors="replace").splitlines()

    previo, entradas, sospechosas = None, [], []
    huellas: dict = {}                                 # huella -> linea donde se escribio
    for i, l in enumerate(lineas, 1):
        if not l.strip():
            continue
        try:
            ev = json.loads(l)
        except ValueError as exc:
            print(f"  linea {i}: NO es JSON ({exc}).")
            print("  Un diario que no se lee entero no se declara: eso es otra cosa y hay que")
            print("  mirarla a mano. No se escribe nada.")
            return 1
        if "h" not in ev or "prev" not in ev:
            continue                                   # legado: sin cadena, ya se tolera
        if previo is not None and ev["prev"] != previo:
            # La firma de la carrera NO es «el hermano inmediato encadena a lo mismo»: con tres
            # o mas escritores, el tercero puede anclarse a la cabeza que dejo el PRIMERO. Lo
            # que la define es que `prev` sea una huella REAL y reciente del propio diario — el
            # evento se anclo a un estado que existio, solo que no al ultimo. Si `prev` no
            # aparece en ninguna parte, el evento se anclo a algo que nunca hubo, y eso no es
            # concurrencia. Medido en telhar el 2026-09-28: 21 roturas, todas de este tipo.
            origen = huellas.get(ev["prev"])
            if origen is None or (i - origen) > 50:
                sospechosas.append(i)
            entradas.append({"line": i, "found_prev": ev["prev"], "expected_head": previo,
                             "cause": CAUSA + (f" Se anclo a la cabeza de la linea {origen}, "
                                               f"{i - origen} linea(s) antes." if origen else ""),
                             "declared_by": firma, "declared_at": hoy})
        if _eslabon(ev["prev"], ev) != ev["h"]:
            print(f"  linea {i}: la huella NO reproduce su contenido.")
            print("  Eso es una EDICION posterior, no una carrera. No se declara: se investiga.")
            return 1
        huellas[ev["h"]] = i
        previo = ev["h"]

    print(f"  espacio: {ws}")
    print(f"  eventos con cadena: {sum(1 for l in lineas if l.strip() and 'h' in l)}")
    print(f"  roturas encontradas: {len(entradas)}")
    for e in entradas:
        marca = "   <-- SIN la firma de la carrera: revisar" if e["line"] in sospechosas else ""
        print(f"    linea {e['line']}: {e['expected_head'][:12]}... -> {e['found_prev'][:12]}...{marca}")
    if sospechosas:
        print("\n  Hay roturas cuya causa no es la carrera. La causa que se escribiria seria")
        print("  falsa, asi que no se escribe nada.")
        return 1
    if not entradas:
        print("  nada que declarar: la cadena cierra")
        return 0

    doc = {"schema": SCHEMA_DISCONTINUIDADES,
           "_que_es": ("Roturas de la cadena RECONOCIDAS por una persona, con su causa. Solo "
                       "surten efecto si coinciden exactamente con la rotura: linea, prev "
                       "encontrado y cabeza esperada. No amnistian ninguna manipulacion "
                       "posterior: editar, borrar o insertar un evento vuelve a dejar la cadena "
                       "en ROTA. Ver ADR-0019."),
           "entries": entradas}
    destino = ruta_discontinuidades(ws)
    if not escribir:
        print(f"\n  se escribiria en {destino}")
        print("  vuelva a ejecutarlo con --escribir para aplicarlo")
        return 0
    destino.parent.mkdir(parents=True, exist_ok=True)
    destino.write_text(json.dumps(doc, indent=2, ensure_ascii=False) + "\n",
                       encoding="utf-8", newline="\n")
    from core.evidence import verificar_cadena
    r = verificar_cadena(ws)
    print(f"\n  escrito: {destino}")
    print(f"  la cadena queda: {r['estado']} (ok={r['ok']}, {r['eventos']} eventos, "
          f"{len(r['cicatrices'])} cicatriz/ces)")
    return 0 if r["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
