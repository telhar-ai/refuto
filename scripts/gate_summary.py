#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Resume una corrida y decide el código de salida de CI.

Existe para que el flujo NO tenga que interpretar el veredicto con `grep`. BLOCKED sale con 2 y
CI lo trata como fallo: en una tubería, «no se pudo comprobar» tiene que parar la integración.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from core.proc import force_utf8_io  # noqa: E402

# Estos guiones imprimen ✓ y ✗ y los ejecuta CI en cualquier sistema. En una consola
# cp1252 ese carácter no afeaba la salida: abortaba la comprobación con un Traceback,
# y una comprobación que no llega a hablar no dice «pasa» ni «falla».
force_utf8_io()


#: Puertas que un ejecutor SIN AGENTES INSTALADOS no puede comprobar, y por qué cada una.
#:
#: Esto NO convierte `BLOCKED` en `PASS`. Lo que hace es permitir que un trabajo de CI afirme
#: una propiedad **distinta y verificable**: «lo único bloqueado es lo que este entorno no
#: puede comprobar, y estaba declarado de antemano». Si aparece un `BLOCKED` que no está en
#: esta lista, el trabajo falla — porque eso sí es información nueva.
#:
#: La diferencia importa. Sin esta distinción, el trabajo del espacio de ejemplo sale en rojo
#: en toda corrida y para siempre; un rojo permanente se deja de leer, y entonces el día que
#: haya un rojo de verdad nadie lo mira. Con ella, el rojo vuelve a significar algo.
BLOQUEO_ESPERADO = {
    "G-AGENT": "el ejecutor no tiene ningún agente instalado: no hay a quién sondear",
    "G-LOCK": "el espacio de ejemplo no declara origen materializado",
    "G-FLEET": "sin orígenes declarados no hay flota cuya deriva medir",
    "G-TRACE": "el espacio de ejemplo no lleva documentos de requisitos",
    "G-HUMAN": "las revisiones humanas no se conceden desde un ejecutor: es su razón de ser",
    "G-PR": "el espacio de ejemplo no es un repositorio git",
}


def main(argv) -> int:
    esperado = "--bloqueo-esperado" in argv
    argv = [a for a in argv if a != "--bloqueo-esperado"]
    if len(argv) != 2:
        print("uso: gate_summary.py [--bloqueo-esperado] <run.json>", file=sys.stderr)
        return 64
    # Acepta el sobre `harness.envelope/v1` y la forma suelta anterior.
    from core.envelope import payload_of
    doc = payload_of(json.loads(Path(argv[1]).read_text(encoding="utf-8")))
    counts = {}
    bloqueadas = []
    for gate in doc["gates"]:
        counts[gate["status"]] = counts.get(gate["status"], 0) + 1
        print(f"  {gate['status']:<15} {gate['id']:<12} {gate['measure'][:90]}")
        if gate["status"] == "BLOCKED":
            bloqueadas.append(gate["id"])
    print(f"\n  {doc['verdict']}")
    print(f"  reparto: {counts}")
    if counts.get("FAIL") or counts.get("NOT_EXECUTABLE"):
        return 1

    if esperado and bloqueadas:
        inesperadas = [g for g in bloqueadas if g not in BLOQUEO_ESPERADO]
        if inesperadas:
            print(f"\n  ✗ BLOQUEO NO DECLARADO: {', '.join(inesperadas)}")
            print("    Este entorno sí podía comprobarlas. Un bloqueo que nadie esperaba es "
                  "información nueva, y por eso para la integración.")
            return 2
        print("\n  Las puertas bloqueadas son EXACTAMENTE las declaradas para un ejecutor sin "
              "agentes:")
        for g in bloqueadas:
            print(f"      {g:<12} {BLOQUEO_ESPERADO[g]}")
        print("\n  Esto NO es un aprobado. El veredicto del espacio sigue siendo el de arriba "
              "y sigue sin ser integrable.\n  Lo que este trabajo afirma es más estrecho y sí "
              "se puede comprobar: **no apareció ningún rojo ni ningún bloqueo nuevo**.")
        if not counts.get("PASS"):
            print("\n  Pero ninguna puerta aprobó. Ámbito vacío no es aprobado.")
            return 2
        return 0

    if counts.get("BLOCKED"):
        print("\n  BLOCKED no es aprobado: hay verificaciones que no se pudieron correr.")
        return 2
    if not counts.get("PASS"):
        print("\n  Ninguna puerta encontró sujeto que comprobar. Ámbito vacío no es aprobado.")
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
