#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Validador de Aseguramiento Arquitectónico para Diagramas de Refuto.

Comprueba automáticamente:
1. Integridad XML del archivo .drawio.
2. Existencia de las 7 páginas canónicas estructuradas.
3. Ausencia total de emojis y uso exclusivo de iconos SVG vectoriales.
4. Presencia de las 13 puertas canónicas registradas en gates/base.py.
5. Fidelidad de la matriz de adapters (Principia Veritas: Claude, Kiro, Antigravity, Gemini, OpenCode, Codex, Copilot).
6. Separación formal de las 4 Fronteras de Confianza (TB-0 a TB-3) en la Arquitectura Objetivo (Página 7).
7. Ausencia de datos personales o rutas locales absolutas no permitidas.
"""

from __future__ import annotations

import re
import sys
import xml.etree.ElementTree as ET   # nosec B405 — sólo biblioteca estándar por ADR-0002;
# `defusedxml` sería una dependencia. El vector de entidades se trata en el punto de parseo.
from pathlib import Path

# Cargar registro de puertas de refuto
try:
    from gates.base import GATES
except ImportError:
    # Si se ejecuta sin PYTHONPATH en la raíz
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
    from gates.base import GATES

EXPECTED_PAGES = [
    ("page-1-macro", "1. Visión General"),
    ("page-2-integration", "2. Integración en el Ecosistema"),
    ("page-3-epistemic", "3. Núcleo Epistémico"),
    ("page-4-security", "4. Modelo de Seguridad"),
    ("page-5-mcp", "5. Cadena de Suministro"),
    ("page-6-operations", "6. Operación"),
    ("page-7-target", "7. Arquitectura Objetivo"),
]

EXPECTED_ADAPTERS = {
    "Claude Code": "IMPLEMENTADO",
    "Kiro CLI": "IMPLEMENTADO",
    "Google Antigravity": "IMPLEMENTADO",
    "Gemini CLI": "PARCIAL",
    "OpenCode": "PARCIAL",
    "OpenAI Codex": "PARCIAL",
    "GitHub Copilot": "PLANIFICADO",
}

EXPECTED_TRUST_BOUNDARIES = ["TB-0", "TB-1", "TB-2", "TB-3"]

# Detección de emojis gráficos reales
EMOJI_REGEX = re.compile(
    r"[\U0001F600-\U0001F64F"  # Emoticons
    r"\U0001F300-\U0001F5FF"  # Misc Symbols and Pictographs
    r"\U0001F680-\U0001F6FF"  # Transport and Map
    r"\U0001F1E0-\U0001F1FF"  # Regional Indicator Symbols
    r"\U0001F900-\U0001F9FF"  # Supplemental Symbols
    r"\U0001FA70-\U0001FAFF"  # Symbols and Pictographs Extended-A
    r"]",
    re.UNICODE
)

def check_diagram(file_path: Path) -> int:
    errors = []
    warnings = []

    if not file_path.is_file():
        print(f"[FAIL] El archivo de diagrama no existe: {file_path}")
        return 1

    content = file_path.read_text(encoding="utf-8")

    # 0. Declaraciones de entidad, ANTES de parsear.
    #
    # Este guion parsea un fichero del disco, y en CI ese fichero llega dentro de un PR — es
    # decir, entrada NO confiable en un repositorio público. `xml.etree.ElementTree` no resuelve
    # entidades externas, así que XXE no aplica; sí aplica la expansión de entidades internas
    # («billion laughs»), que agota memoria y CPU con un fichero de pocos kilobytes. Lo señaló
    # `bandit` (B314) el 2026-09-25, y la mitigación sin dependencias es rechazar el vector en
    # vez de endurecer el parser: un diagrama legítimo de este proyecto no declara entidades.
    #
    # Se mira el texto y no el árbol a propósito: comprobarlo después de parsear sería
    # comprobarlo después del daño.
    bajo = content.lstrip()[:4096].upper()
    if "<!DOCTYPE" in bajo or "<!ENTITY" in bajo:
        print(f"[FAIL] {file_path} declara DOCTYPE o ENTITY. Un diagrama de este proyecto no "
              f"los usa, y la expansión de entidades es un vector de agotamiento de recursos "
              f"en un parser sin defensa. No se parsea.")
        return 1

    # 1. Validación XML
    try:
        root = ET.fromstring(content)   # nosec B314 — vector de entidades rechazado arriba
    except ET.ParseError as exc:
        print(f"[FAIL] Error de sintaxis XML en {file_path}: {exc}")
        return 1

    # 2. Comprobación de Emojis
    emoji_matches = EMOJI_REGEX.findall(content)
    if emoji_matches:
        errors.append(f"Se detectaron {len(emoji_matches)} emojis en el diagrama: {emoji_matches[:5]} (Debe usarse SVG vectorial)")

    # 3. Comprobación de Rutas Privadas / Personales
    if "/Users/" in content or "example-internal" in content:
        errors.append("Se detectaron posibles rutas o identificadores privados en el texto del diagrama.")

    # 4. Comprobación de Páginas
    diagrams = root.findall("diagram")
    page_ids = {d.get("id"): d.get("name") for d in diagrams}

    for pid, expected_title_sub in EXPECTED_PAGES:
        if pid not in page_ids:
            errors.append(f"Falta la página obligatoria '{pid}' ({expected_title_sub})")
        else:
            actual_name = page_ids[pid] or ""
            if expected_title_sub not in actual_name:
                warnings.append(f"Nombre de página '{pid}' difiere: '{actual_name}' (esperaba contener '{expected_title_sub}')")

    # 5. Comprobación de las 13 Puertas en la página de Operación
    page_6 = next((d for d in diagrams if d.get("id") == "page-6-operations"), None)
    if page_6 is not None:
        p6_text = ET.tostring(page_6, encoding="utf-8").decode("utf-8")
        for gid in GATES.keys():
            if gid not in p6_text:
                errors.append(f"La puerta canónica '{gid}' de gates/base.py no está representada en la página 6")
    else:
        errors.append("No se pudo inspeccionar la página 6 (page-6-operations)")

    # 6. Comprobación de la Matriz de Adapters en Página 4
    page_4 = next((d for d in diagrams if d.get("id") == "page-4-security"), None)
    if page_4 is not None:
        p4_text = ET.tostring(page_4, encoding="utf-8").decode("utf-8")
        for agent_name, expected_stat in EXPECTED_ADAPTERS.items():
            if agent_name not in p4_text:
                errors.append(f"El agente '{agent_name}' no aparece en la matriz de adapters (página 4)")
            if expected_stat not in p4_text:
                errors.append(f"El estado '{expected_stat}' para '{agent_name}' no se encuentra en la página 4")
    else:
        errors.append("No se pudo inspeccionar la página 4 (page-4-security)")

    # 7. Comprobación de la Arquitectura Objetivo en Página 7
    page_7 = next((d for d in diagrams if d.get("id") == "page-7-target"), None)
    if page_7 is not None:
        p7_text = ET.tostring(page_7, encoding="utf-8").decode("utf-8")
        for tb in EXPECTED_TRUST_BOUNDARIES:
            if tb not in p7_text:
                errors.append(f"La Frontera de Confianza '{tb}' no está representada en la página 7 (ADR-0011)")
        for key_term in ["CanonicalEvent", "run_id", "events.jsonl", "Evaluation Plane"]:
            if key_term not in p7_text:
                errors.append(f"El concepto clave '{key_term}' no está en la página 7 (ADR-0009 / ADR-0010)")
    else:
        errors.append("No se pudo inspeccionar la página 7 (page-7-target)")

    # Reporte de Resultados
    print(f"=== REPORTE DE ASEGURAMIENTO ARQUITECTÓNICO: {file_path.name} ===")
    print(f"Páginas auditadas: {len(diagrams)}/7")
    print(f"Puertas verificadas: {len(GATES)}/13")
    print(f"Adapters verificados: {len(EXPECTED_ADAPTERS)}/7")
    print(f"Fronteras de confianza: {len(EXPECTED_TRUST_BOUNDARIES)}/4")

    if warnings:
        print("\n[AVISOS]")
        for w in warnings:
            print(f"  - {w}")

    if errors:
        print("\n[ERRORES DETECTADOS]")
        for e in errors:
            print(f"  - {e}")
        print("\nDictamen: FAIL (Aseguramiento no superado)")
        return 1

    print("\nDictamen: PASS (Todos los invariantes de arquitectura y aseguramiento se cumplen al 100%)")
    return 0

if __name__ == "__main__":
    target = Path("docs/diagrams/refuto-arquitectura-operacion-ingenieria.drawio")
    sys.exit(check_diagram(target))
