#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Una cita a código tiene que seguir apuntando a lo que dice que apunta.

    python3 scripts/check_citas.py            # comprueba todas
    python3 scripts/check_citas.py --listar   # además, imprime qué hay en cada línea

La falla que cierra, y por qué es una sola
------------------------------------------
Tres veces en este trabajo una medición resultó ser del instrumento y no del sistema:

    `PORT` casaba dentro de «reporte»
    `Redis` casaba dentro de «redistribuir»
    un número de línea copiado una vez y nunca vuelto a verificar

Parecen tres despistes. Son **el mismo**: una coincidencia tomada por medición, sin volver a
mirar qué hay al otro lado del puntero. Y la comprobación obvia —¿existe el fichero?, ¿existe
la línea?— **no la detecta**, porque en los tres casos existía.

Medido el 2026-09-23 sobre este repositorio: de 16 citas `fichero:línea` en la documentación,
**16 resolvían y 6 mentían**. Tres de ellas apuntaban a una línea en blanco. Se quedaron atrás
porque el mismo autor editó esos ficheros después de escribir el documento; el número no se
mueve solo.

Las dos formas, y por qué se prefiere una
-----------------------------------------
    core/model.py::new_run_id     ESTABLE   el símbolo se resuelve a su línea actual
    core/model.py:235             FRÁGIL    el número envejece en silencio

La forma por símbolo **no puede quedarse rancia**: si el símbolo se renombra o desaparece,
esto falla y lo dice. La forma por línea se tolera —a veces se quiere señalar una línea que no
es una definición— pero se le exige que la línea **no esté en blanco**, que es la señal
inequívoca de que el fichero creció por encima y la cita se quedó atrás.

Lo que esta comprobación NO hace
--------------------------------
No entiende lo que el documento afirma sobre esa línea. Una cita puede apuntar a una línea con
contenido y describirla mal, y esto la aprobará. Detecta el desplazamiento, no la
interpretación. Decirlo importa: un comprobador que se presenta como más de lo que es vuelve a
ser el instrumento tomado por el sistema.
"""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

RAIZ = Path(__file__).resolve().parents[1]

#: Directorios de código cuyas citas se comprueban. Se nombran para no intentar resolver
#: rutas de ejemplo (`/ruta/al/espacio/...`) que aparecen en la documentación a propósito.
CODIGO = ("core", "gates", "adapters", "tests", "scripts")

_RUTA = r"(?:" + "|".join(CODIGO) + r")/[A-Za-z0-9_./-]+\.py"
POR_LINEA = re.compile(r"`?(" + _RUTA + r"):(\d+)`?")
POR_SIMBOLO = re.compile(r"`?(" + _RUTA + r")::([A-Za-z_][A-Za-z0-9_]*)`?")

def _linea_del_simbolo(texto: str, simbolo: str) -> int:
    """La línea donde se define `simbolo`, o 0.

    Cuatro formas, y la cuarta se añadió tras un falso positivo del propio comprobador:

        def foo(...)          función
        class Foo             clase
        FOO = ...             asignación
        FOO: dict = ...       asignación ANOTADA

    La primera versión no contemplaba la anotada y declaró inexistente a `gates/base.py::GATES`,
    que está en la línea 16 como `GATES: dict = {`. Tres documentos correctos habrían salido
    marcados como citas rotas. El comprobador de citas fallando por lo mismo que comprueba es
    la advertencia más útil que ha dado hasta ahora: **antes de acusar al sistema, sospecha del
    instrumento**.
    """
    n = re.escape(simbolo)
    pat = re.compile(rf"^\s*(?:def|class)\s+{n}\b"          # def foo / class Foo
                     rf"|^{n}\s*(?::[^=]+)?=")               # FOO = …  /  FOO: dict = …
    for i, linea in enumerate(texto.splitlines(), 1):
        if pat.search(linea):
            return i
    return 0


def docs() -> list:
    return sorted(p for p in RAIZ.rglob("*.md")
                  if ".git" not in p.parts and ".harness" not in p.parts)


def revisar(listar: bool = False) -> tuple[list, int]:
    problemas: list = []
    total = 0
    for md in docs():
        try:
            txt = md.read_text(encoding="utf-8")
        except OSError as exc:
            problemas.append(f"{md.relative_to(RAIZ)}: no se pudo leer ({exc}). "
                             f"No se puede afirmar que sus citas estén bien.")
            continue
        rel_md = str(md.relative_to(RAIZ))

        for m in POR_LINEA.finditer(txt):
            ruta, num = m.group(1), int(m.group(2))
            total += 1
            f = RAIZ / ruta
            if not f.is_file():
                problemas.append(f"{rel_md} → {ruta}:{num}: el fichero no existe")
                continue
            lineas = f.read_text(encoding="utf-8").splitlines()
            if num > len(lineas):
                problemas.append(f"{rel_md} → {ruta}:{num}: fuera de rango "
                                 f"(el fichero tiene {len(lineas)} líneas)")
                continue
            contenido = lineas[num - 1].strip()
            if not contenido:
                problemas.append(
                    f"{rel_md} → {ruta}:{num}: la línea está EN BLANCO. El fichero creció por "
                    f"encima y la cita se quedó atrás. Use `{ruta}::<símbolo>`, que no envejece.")
                continue
            if listar:
                print(f"  {rel_md} → {ruta}:{num}\n      {contenido[:80]}")

        for m in POR_SIMBOLO.finditer(txt):
            ruta, simbolo = m.group(1), m.group(2)
            total += 1
            f = RAIZ / ruta
            if not f.is_file():
                problemas.append(f"{rel_md} → {ruta}::{simbolo}: el fichero no existe")
                continue
            n = _linea_del_simbolo(f.read_text(encoding="utf-8"), simbolo)
            if not n:
                problemas.append(f"{rel_md} → {ruta}::{simbolo}: el símbolo no está en el "
                                 f"fichero. O se renombró, o nunca estuvo.")
                continue
            if listar:
                print(f"  {rel_md} → {ruta}::{simbolo}  (línea {n} hoy)")
    return problemas, total


def main() -> int:
    ap = argparse.ArgumentParser(description="las citas a código siguen apuntando a su sitio")
    ap.add_argument("--listar", action="store_true", help="imprime qué hay en cada cita")
    o = ap.parse_args()
    problemas, total = revisar(o.listar)
    if not total:
        print("  0 citas encontradas. Ámbito vacío no es aprobado: revise el patrón.",
              file=sys.stderr)
        return 1
    if problemas:
        print(f"\n  ✗ {len(problemas)} de {total} citas no apuntan a lo que dicen:\n")
        for p in problemas:
            print(f"      {p}")
        return 1
    print(f"  ✓ {total} citas resuelven")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
