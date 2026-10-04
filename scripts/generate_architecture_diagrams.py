#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Generador Canónico de Diagramas de Arquitectura de Refuto.

Genera el libro arquitectónico en formato Draw.io (7 páginas) y sus diagramas
vectoriales SVG exportados con fidelidad completa:
1. 100% Python estándar (sin dependencias externas).
2. Cero emojis; iconos vectoriales SVG limpios embebidos en base64.
3. Principia Veritas: Distinción explícita de estados:
   [IMPLEMENTADO · E3/E4], [PARCIAL / INFERIDO · E1/E2], [PLANIFICADO · E0], [EXTERNO / TERCEROS].
4. Fidelidad al código:
   - 13 Puertas de gates/base.py
   - Matriz de adapters de core/wire.py, core/policy.py y support-matrix.json
   - Pasillos amplios y enrutamiento ortogonal sin solapamiento de líneas y textos.
5. Inclusión de la Arquitectura Objetivo (Página 7) según ADR-0009, ADR-0010 y ADR-0011.
6. Exportación automática de las 7 páginas en formato SVG vectorial en docs/diagrams/.
"""

from __future__ import annotations

import base64
import html
import re
import xml.etree.ElementTree as ET   # nosec B405 — sólo biblioteca estándar por ADR-0002;
# `defusedxml` sería una dependencia. El vector de entidades se trata en el punto de parseo.
from pathlib import Path

# ── Iconos SVG Vectoriales (Base64) ──────────────────────────────────────────
# Diseñados limpios, geométricos, estilo Lucide/Feather, monocromáticos o con acento.

ICONS_SVG = {
    "shield": """<svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="#e11d48" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>""",
    "shield_green": """<svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="#16a34a" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>""",
    "shield_blue": """<svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="#0284c7" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>""",
    "scales": """<svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="#16a34a" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="m16 16 3-8 3 8c-.87.65-1.92 1-3 1s-2.13-.35-3-1Z"/><path d="m2 16 3-8 3 8c-.87.65-1.92 1-3 1s-2.13-.35-3-1Z"/><path d="M7 21h10"/><path d="M12 3v18"/><path d="M3 7h2c2 0 5-1 7-2 2 1 5 2 7 2h2"/></svg>""",
    "layers": """<svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="#2563eb" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polygon points="12 2 2 7 12 12 22 7 12 2"/><polyline points="2 17 12 22 22 17"/><polyline points="2 12 12 17 22 12"/></svg>""",
    "terminal": """<svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="#0284c7" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polyline points="4 17 10 11 4 5"/><line x1="12" y1="19" x2="20" y2="19"/></svg>""",
    "bot": """<svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="#d97706" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="3" y="11" width="18" height="10" rx="2"/><circle cx="12" cy="5" r="2"/><path d="M12 7v4"/><line x1="8" y1="16" x2="8" y2="16"/><line x1="16" y1="16" x2="16" y2="16"/></svg>""",
    "check_circle": """<svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="#7c3aed" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="m9 12 2 2 4-4"/><circle cx="12" cy="12" r="10"/></svg>""",
    "alert_triangle": """<svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="#dc2626" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="m21.73 18-8-14a2 2 0 0 0-3.48 0l-8 14A2 2 0 0 0 4 21h16a2 2 0 0 0 1.73-3Z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg>""",
    "database": """<svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="#16a34a" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><ellipse cx="12" cy="5" rx="9" ry="3"/><path d="M21 12c0 1.66-4 3-9 3s-9-1.34-9-3"/><path d="M3 5v14c0 1.66 4 3 9 3s9-1.34 9-3V5"/></svg>""",
    "lock": """<svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="#d97706" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="3" y="11" width="18" height="11" rx="2" ry="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/></svg>""",
    "cpu": """<svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="#0284c7" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="4" y="4" width="16" height="16" rx="2"/><rect x="9" y="9" width="6" height="6"/><path d="M15 2v2"/><path d="M15 20v2"/><path d="M2 15h2"/><path d="M2 9h2"/><path d="M20 15h2"/><path d="M20 9h2"/><path d="M9 2v2"/><path d="M9 20v2"/></svg>""",
    "network": """<svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="#0284c7" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="3" y="3" width="6" height="6" rx="1"/><rect x="15" y="3" width="6" height="6" rx="1"/><rect x="9" y="15" width="6" height="6" rx="1"/><path d="M6 9v3a1 1 0 0 0 1 1h4m6-4v3a1 1 0 0 1-1 1h-4m0 0v2"/></svg>""",
    "git_branch": """<svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="#4f46e5" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><line x1="6" y1="3" x2="6" y2="15"/><circle cx="18" cy="6" r="3"/><circle cx="6" cy="18" r="3"/><path d="M18 9a9 9 0 0 1-9 9"/></svg>""",
    "activity": """<svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="#059669" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polyline points="22 12 18 12 15 21 9 3 6 12 2 12"/></svg>""",
    "target": """<svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="#9333ea" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"/><circle cx="12" cy="6" r="6"/><circle cx="12" cy="12" r="2"/></svg>""",
}

def get_icon_data_uri(name: str) -> str:
    raw = ICONS_SVG.get(name, ICONS_SVG["shield"])
    b64 = base64.b64encode(raw.encode("utf-8")).decode("ascii")
    return f"data:image/svg+xml;base64,{b64}"

def escape_bare_amp(text: str) -> str:
    """Escapa únicamente los ampersands sueltos que no forman parte de entidades XML/HTML válidas."""
    return re.sub(r'&(?!(?:amp|lt|gt|quot|apos|#\d+|#x[0-9a-fA-F]+);)', '&amp;', text)

def img_tag(icon_name: str, size: int = 16) -> str:
    uri = get_icon_data_uri(icon_name)
    return f"<img src='{uri}' width='{size}' height='{size}' style='vertical-align:-2px; margin-right:6px;' alt=''/>"

def status_badge(status: str) -> str:
    """Genera un badge HTML formal según Principia Veritas."""
    mapping = {
        "IMPLEMENTED": ("#16a34a", "#ffffff", "IMPLEMENTADO · E3/E4"),
        "PARTIAL": ("#d97706", "#ffffff", "PARCIAL / INFERIDO · E1/E2"),
        "PLANNED": ("#4f46e5", "#ffffff", "PLANIFICADO · E0"),
        "EXTERNAL": ("#475569", "#ffffff", "EXTERNO / TERCEROS"),
        "VERIFIED": ("#059669", "#ffffff", "VERIFICADO EMPÍRICAMENTE"),
    }
    bg, fg, label = mapping.get(status, ("#64748b", "#ffffff", status))
    return (f"<span style='background:{bg}; color:{fg}; font-size:9px; "
            f"padding:2px 6px; border-radius:3px; font-weight:bold; letter-spacing:0.3px; margin-left:6px; display:inline-block; vertical-align:middle;'>"
            f"{label}</span>")

# ── Generador y Exportador de Diagramas ───────────────────────────────────────

class PageBuilder:
    def __init__(self, root_elem: ET.Element, page_id: str, name: str, width: int = 2100, height: int = 740):
        self.root = root_elem
        self.prefix = page_id
        self.name = name
        self.width = width
        self.height = height
        self.cell_seq = 1

        # Registro interno de elementos para exportación vectorial SVG
        self.elements_by_id: dict[str, dict] = {}
        self.elements_order: list[dict] = []

    def _next_id(self) -> str:
        cid = f"{self.prefix}_c{self.cell_seq}"
        self.cell_seq += 1
        return cid

    def add_header(self, title: str, subtitle: str, x: int = 50, y: int = 25, width: int = 2000, height: int = 60, icon: str = "shield") -> str:
        cid = self._next_id()
        icon_html = img_tag(icon, 18)
        title_esc = escape_bare_amp(title)
        subtitle_esc = escape_bare_amp(subtitle)
        val = f"{icon_html} <b>{title_esc}</b><br/><span style='font-size:11px; color:#cbd5e1;'>{subtitle_esc}</span>"
        style = ("html=1;whiteSpace=wrap;fillColor=#0f172a;strokeColor=#1e293b;strokeWidth=2;"
                 "fontColor=#ffffff;fontSize=13;fontStyle=1;rounded=1;arcSize=6;shadow=1;"
                 "align=center;verticalAlign=middle;fontFamily=Segoe UI,Helvetica Neue,Arial,sans-serif;")
        cell = ET.SubElement(self.root, "mxCell", {
            "id": cid, "value": val, "style": style, "parent": "1", "vertex": "1"
        })
        ET.SubElement(cell, "mxGeometry", {"x": str(x), "y": str(y), "width": str(width), "height": str(height), "as": "geometry"})

        data = {"type": "header", "id": cid, "title": title, "subtitle": subtitle, "x": x, "y": y, "w": width, "h": height, "icon": icon, "val": val}
        self.elements_by_id[cid] = data
        self.elements_order.append(data)
        return cid

    def add_card(self, title: str, body_html: str, x: int, y: int, width: int, height: int,
                 status: str | None = None, icon: str = "shield", fill: str = "#ffffff",
                 stroke: str = "#64748b", font_color: str = "#0f172a") -> str:
        cid = self._next_id()
        header_parts = []
        if icon:
            header_parts.append(img_tag(icon, 16))
        header_parts.append(f"<b>{escape_bare_amp(title)}</b>")
        if status:
            header_parts.append(status_badge(status))
        
        body_clean = escape_bare_amp(body_html)
        full_val = f"{''.join(header_parts)}<br/><div style='margin-top:6px; line-height:1.45;'>{body_clean}</div>"
        style = (f"html=1;whiteSpace=wrap;rounded=1;arcSize=6;fillColor={fill};strokeColor={stroke};strokeWidth=1.5;"
                 f"fontColor={font_color};fontSize=11;align=left;spacingLeft=14;spacingRight=14;shadow=1;"
                 f"fontFamily=Segoe UI,Helvetica Neue,Arial,sans-serif;")
        cell = ET.SubElement(self.root, "mxCell", {
            "id": cid, "value": full_val, "style": style, "parent": "1", "vertex": "1"
        })
        ET.SubElement(cell, "mxGeometry", {"x": str(x), "y": str(y), "width": str(width), "height": str(height), "as": "geometry"})

        data = {
            "type": "card", "id": cid, "title": title, "body": body_clean,
            "x": x, "y": y, "w": width, "h": height, "status": status,
            "icon": icon, "fill": fill, "stroke": stroke, "font_color": font_color, "val": full_val
        }
        self.elements_by_id[cid] = data
        self.elements_order.append(data)
        return cid

    def add_boundary(self, label: str, x: int, y: int, width: int, height: int, stroke: str = "#94a3b8", fill: str = "none") -> str:
        cid = self._next_id()
        style = (f"html=1;whiteSpace=wrap;rounded=1;arcSize=4;fillColor={fill};strokeColor={stroke};strokeWidth=1.5;"
                 f"dashed=1;fontColor=#475569;fontSize=11;fontStyle=1;align=left;verticalAlign=top;spacingLeft=12;spacingTop=8;"
                 f"fontFamily=Segoe UI,Helvetica Neue,Arial,sans-serif;")
        label_clean = escape_bare_amp(label)
        cell = ET.SubElement(self.root, "mxCell", {
            "id": cid, "value": label_clean, "style": style, "parent": "1", "vertex": "1"
        })
        ET.SubElement(cell, "mxGeometry", {"x": str(x), "y": str(y), "width": str(width), "height": str(height), "as": "geometry"})

        data = {"type": "boundary", "id": cid, "label": label_clean, "x": x, "y": y, "w": width, "h": height, "stroke": stroke, "fill": fill}
        self.elements_by_id[cid] = data
        self.elements_order.append(data)
        return cid

    def add_section_header(self, text: str, x: int, y: int, width: int = 2000, height: int = 32, fill: str = "#1e293b") -> str:
        cid = self._next_id()
        style = (f"html=1;whiteSpace=wrap;fillColor={fill};fontColor=#ffffff;fontSize=12;fontStyle=1;"
                 f"align=center;verticalAlign=middle;fontFamily=Segoe UI,Helvetica Neue,Arial,sans-serif;")
        val = f"<b>{escape_bare_amp(text)}</b>"
        cell = ET.SubElement(self.root, "mxCell", {
            "id": cid, "value": val, "style": style, "parent": "1", "vertex": "1"
        })
        ET.SubElement(cell, "mxGeometry", {"x": str(x), "y": str(y), "width": str(width), "height": str(height), "as": "geometry"})

        data = {"type": "section_header", "id": cid, "text": text, "x": x, "y": y, "w": width, "h": height, "fill": fill, "val": val}
        self.elements_by_id[cid] = data
        self.elements_order.append(data)
        return cid

    def add_flow_edge(self, source_id: str, target_id: str, label: str,
                      stroke: str = "#2563eb", width: float = 2.0, dashed: bool = False,
                      exit_xy: tuple[float, float] = (1.0, 0.5), entry_xy: tuple[float, float] = (0.0, 0.5),
                      points: list[tuple[int, int]] | None = None) -> str:
        cid = self._next_id()
        dash_str = "dashed=1;" if dashed else ""
        style = (f"edgeStyle=orthogonalEdgeStyle;rounded=1;orthogonalLoop=1;jettySize=auto;html=1;"
                 f"strokeColor={stroke};strokeWidth={width};fontColor=#0f172a;fontSize=10;fontStyle=1;"
                 f"labelBackgroundColor=#ffffff;labelBorderColor=#cbd5e1;spacing=4;{dash_str}"
                 f"fontFamily=Segoe UI,Helvetica Neue,Arial,sans-serif;"
                 f"exitX={exit_xy[0]};exitY={exit_xy[1]};entryX={entry_xy[0]};entryY={entry_xy[1]};")
        label_clean = escape_bare_amp(label)
        cell = ET.SubElement(self.root, "mxCell", {
            "id": cid, "value": label_clean, "style": style, "parent": "1", "source": source_id, "target": target_id, "edge": "1"
        })
        geom = ET.SubElement(cell, "mxGeometry", {"relative": "1", "as": "geometry"})
        if points:
            pts_elem = ET.SubElement(geom, "Array", {"as": "points"})
            for px, py in points:
                ET.SubElement(pts_elem, "mxPoint", {"x": str(px), "y": str(py)})

        data = {
            "type": "edge", "id": cid, "source": source_id, "target": target_id,
            "label": label, "stroke": stroke, "stroke_width": width, "dashed": dashed,
            "exit_xy": exit_xy, "entry_xy": entry_xy, "points": points
        }
        self.elements_by_id[cid] = data
        self.elements_order.append(data)
        return cid

    def to_svg(self) -> str:
        """Exporta la página canónica a SVG vectorial con soporte completo para foreignObject."""
        w, h = self.width, self.height
        lines: list[str] = [
            f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {w} {h}" width="{w}" height="{h}">',
            '<defs>',
            '  <filter id="softShadow" x="-5%" y="-5%" width="110%" height="110%" filterUnits="userSpaceOnUse">',
            '    <feGaussianBlur in="SourceAlpha" stdDeviation="4"/>',
            '    <feOffset dx="0" dy="2"/>',
            '    <feComponentTransfer><feFuncA type="linear" slope="0.10"/></feComponentTransfer>',
            '    <feMerge><feMergeNode/><feMergeNode in="SourceGraphic"/></feMerge>',
            '  </filter>',
        ]

        # Generar marcadores de flecha para cada color usado
        strokes = {el["stroke"] for el in self.elements_order if el["type"] == "edge" and "stroke" in el}
        for s in strokes:
            marker_id = f"marker-{s.replace('#', '')}"
            lines.append(
                f'  <marker id="{marker_id}" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse">'
                f'<path d="M 0 2 L 10 5 L 0 8 z" fill="{s}"/></marker>'
            )
        lines.append('</defs>')

        # Fondo del lienzo
        lines.append(f'<rect width="{w}" height="{h}" fill="#0b1120"/>')

        # 1. Dibujar Contenedores y Fronteras (TB Boundaries)
        for el in self.elements_order:
            if el["type"] == "boundary":
                fill = el["fill"] if el["fill"] != "none" else "#0f172a"
                lines.append(
                    f'<rect x="{el["x"]}" y="{el["y"]}" width="{el["w"]}" height="{el["h"]}" rx="8" '
                    f'fill="{fill}" fill-opacity="0.3" stroke="{el["stroke"]}" stroke-width="1.5" stroke-dasharray="6,4"/>'
                )
                lines.append(
                    f'<text x="{el["x"] + 14}" y="{el["y"] + 24}" font-family="Segoe UI, -apple-system, sans-serif" '
                    f'font-size="11" font-weight="bold" fill="{el["stroke"]}">{html.escape(el["label"])}</text>'
                )

        # 2. Dibujar Encabezados de Sección
        for el in self.elements_order:
            if el["type"] == "section_header":
                lines.append(
                    f'<rect x="{el["x"]}" y="{el["y"]}" width="{el["w"]}" height="{el["h"]}" rx="4" '
                    f'fill="{el["fill"]}" stroke="#334155" stroke-width="1"/>'
                )
                lines.append(
                    f'<text x="{el["x"] + el["w"] // 2}" y="{el["y"] + el["h"] // 2 + 4}" text-anchor="middle" '
                    f'font-family="Segoe UI, -apple-system, sans-serif" font-size="12" font-weight="bold" fill="#ffffff">{html.escape(el["text"])}</text>'
                )

        # 3. Dibujar Encabezado Principal
        for el in self.elements_order:
            if el["type"] == "header":
                lines.append('<g filter="url(#softShadow)">')
                lines.append(
                    f'<rect x="{el["x"]}" y="{el["y"]}" width="{el["w"]}" height="{el["h"]}" rx="8" '
                    f'fill="#0f172a" stroke="#1e293b" stroke-width="2"/>'
                )
                lines.append(
                    f'<foreignObject x="{el["x"] + 10}" y="{el["y"] + 8}" width="{el["w"] - 20}" height="{el["h"] - 16}">'
                    f'<div xmlns="http://www.w3.org/1999/xhtml" style="font-family: Segoe UI, -apple-system, sans-serif; text-align: center; color: #ffffff; line-height: 1.35;">'
                    f'{el["val"]}'
                    f'</div></foreignObject>'
                )
                lines.append('</g>')

        # 4. Dibujar Tarjetas de Arquitectura
        for el in self.elements_order:
            if el["type"] == "card":
                lines.append('<g filter="url(#softShadow)">')
                lines.append(
                    f'<rect x="{el["x"]}" y="{el["y"]}" width="{el["w"]}" height="{el["h"]}" rx="6" '
                    f'fill="{el["fill"]}" stroke="{el["stroke"]}" stroke-width="1.5"/>'
                )
                # Contenido HTML real formateado
                lines.append(
                    f'<foreignObject x="{el["x"] + 14}" y="{el["y"] + 10}" width="{el["w"] - 28}" height="{el["h"] - 20}">'
                    f'<div xmlns="http://www.w3.org/1999/xhtml" style="font-family: Segoe UI, -apple-system, sans-serif; font-size: 11px; color: {el["font_color"]}; line-height: 1.45;">'
                    f'{el["val"]}'
                    f'</div></foreignObject>'
                )
                lines.append('</g>')

        # 5. Dibujar Aristas de Flujo (Orthogonal Flow Edges)
        for el in self.elements_order:
            if el["type"] == "edge":
                src = self.elements_by_id.get(el["source"])
                tgt = self.elements_by_id.get(el["target"])
                if not src or not tgt:
                    continue

                sx = src["x"] + int(src["w"] * el["exit_xy"][0])
                sy = src["y"] + int(src["h"] * el["exit_xy"][1])
                tx = tgt["x"] + int(tgt["w"] * el["entry_xy"][0])
                ty = tgt["y"] + int(tgt["h"] * el["entry_xy"][1])

                marker_id = f"marker-{el['stroke'].replace('#', '')}"
                dash_attr = 'stroke-dasharray="6,4"' if el["dashed"] else ''

                if el.get("points"):
                    pts = el["points"]
                    d = f"M {sx} {sy} " + " ".join(f"L {px} {py}" for px, py in pts) + f" L {tx} {ty}"
                    # Ubicar etiqueta en el segmento intermedio
                    mid_idx = len(pts) // 2
                    lx, ly = pts[mid_idx]
                else:
                    if sx < tx:
                        mx = (sx + tx) // 2
                        d = f"M {sx} {sy} L {mx} {sy} L {mx} {ty} L {tx} {ty}"
                        lx, ly = mx, (sy + ty) // 2
                    elif sy < ty:
                        my = (sy + ty) // 2
                        d = f"M {sx} {sy} L {sx} {my} L {tx} {my} L {tx} {ty}"
                        lx, ly = (sx + tx) // 2, my
                    else:
                        d = f"M {sx} {sy} L {tx} {ty}"
                        lx, ly = (sx + tx) // 2, (sy + ty) // 2

                lines.append(
                    f'<path d="{d}" fill="none" stroke="{el["stroke"]}" stroke-width="{el["stroke_width"]}" '
                    f'{dash_attr} marker-end="url(#{marker_id})"/>'
                )

                if el["label"]:
                    label_clean = html.escape(el["label"])
                    label_w = max(60, len(el["label"]) * 7 + 16)
                    lines.append(
                        f'<rect x="{lx - label_w // 2}" y="{ly - 10}" width="{label_w}" height="20" rx="3" '
                        f'fill="#ffffff" stroke="#cbd5e1" stroke-width="1"/>'
                    )
                    lines.append(
                        f'<text x="{lx}" y="{ly + 4}" text-anchor="middle" '
                        f'font-family="Segoe UI, -apple-system, sans-serif" font-size="10" font-weight="bold" '
                        f'fill="#0f172a">{label_clean}</text>'
                    )

        lines.append('</svg>')
        return "\n".join(lines)


class DrawioBuilder:
    def __init__(self):
        self.root = ET.Element("mxfile", {
            "host": "app.diagrams.net",
            "modified": "2026-09-22T23:59:00.000Z",
            "agent": "refuto-canonical-generator/1.0",
            "version": "21.0.0",
            "type": "device"
        })
        self.pages: list[PageBuilder] = []

    def add_page(self, page_id: str, name: str, width: int = 2100, height: int = 740) -> PageBuilder:
        diagram = ET.SubElement(self.root, "diagram", {"id": page_id, "name": name})
        mxGraphModel = ET.SubElement(diagram, "mxGraphModel", {
            "dx": str(width), "dy": str(height), "grid": "1", "gridSize": "10",
            "guides": "1", "tooltips": "1", "connect": "1", "arrows": "1",
            "fold": "1", "page": "1", "pageScale": "1", "pageWidth": str(width),
            "pageHeight": str(height), "math": "0", "shadow": "1"
        })
        root_cell = ET.SubElement(mxGraphModel, "root")
        ET.SubElement(root_cell, "mxCell", {"id": "0"})
        ET.SubElement(root_cell, "mxCell", {"id": "1", "parent": "0"})
        page_builder = PageBuilder(root_cell, page_id, name, width, height)
        self.pages.append(page_builder)
        return page_builder

    def to_string(self) -> str:
        raw = ET.tostring(self.root, encoding="utf-8")
        return raw.decode("utf-8")


# ── Construcción de las 7 Páginas Canónicas ───────────────────────────────────

def build_page_1_macro(builder: DrawioBuilder):
    p = builder.add_page("page-1-macro", "1. Visión General (Macro-Arquitectura)", width=2100, height=740)
    p.add_header(
        "REFUTO v0.3.0 · GOBIERNO FORMAL Y CONTENCIÓN DE AGENTES DE CÓDIGO",
        "«Un agente no puede ser juez de sí mismo» · Defensa en Profundidad · Escala Epistémica E0–E4 · 100% Python Estándar",
        icon="shield"
    )

    # Principios Rectores
    p.add_card(
        "PRINCIPIO I: EL REPARTO ARQUITECTÓNICO",
        "• <b style='color:#0369a1;'>CORE (Universal)</b>: Manifiesto, lock, política, 13 puertas y ledger inmutable.<br/>"
        "• <b style='color:#0f766e;'>ADAPTER (Traductor)</b>: Aislamiento por agente (CLI, ACP, MCP) sin aplanar capacidades.<br/>"
        "• <b style='color:#4338ca;'>NATIVE (Capacidad)</b>: Verificación directa en el runtime sin inferencias vacías.",
        x=50, y=100, width=640, height=100, icon="layers", fill="#f8fafc", stroke="#64748b"
    )
    p.add_card(
        "PRINCIPIO II: DEFENSAS EN 3 CAPAS",
        "• <b style='color:#be123c;'>Capa 1 (Compilada)</b>: Reglas estáticas en workspace (sintáctica, deny/allow).<br/>"
        "• <b style='color:#e11d48;'>Capa 2 (Guardián)</b>: Interceptor <code>PreToolUse</code> con <code>realpath</code> y redactor.<br/>"
        "• <b style='color:#9f1239;'>Capa 3 (Remota)</b>: CI y ramas Git protegidas (inviolable por el proceso local).",
        x=730, y=100, width=640, height=100, icon="shield", fill="#fff1f2", stroke="#f43f5e", font_color="#881337"
    )
    p.add_card(
        "PRINCIPIO III: CONTRATO DE VERDAD",
        "• <b style='color:#15803d;'>Invariante Fundamental</b>: «Un ámbito vacío nunca aprueba» (prohíbe vacuous truth).<br/>"
        "• <b style='color:#16a34a;'>Postcondición Dura</b>: <code>PASS</code> con hallazgos lanza <code>ValueError</code>.<br/>"
        "• <b style='color:#047857;'>Dirección Única</b>: JSONL estructurado con SHA-256 ──► Reporte y ledger inmutables.",
        x=1410, y=100, width=640, height=100, icon="scales", fill="#f0fdf4", stroke="#22c55e", font_color="#14532d"
    )

    # 4 Bloques Principales de Flujo
    c1 = p.add_card(
        "1. ORQUESTACIÓN & ENTORNO",
        "<div style='color:#0284c7; font-weight:bold; font-size:10px; margin-bottom:4px;'>COMANDOS CLI Y SONDA</div>"
        "• <code>refuto doctor</code>: Diagnostica PATH, codesign y router.<br/>"
        "• <code>refuto install</code>: Despliegue atómico de política y manifiesto.<br/>"
        "• <code>refuto chat</code>: Inyecta sesión gobernada y brief en el LLM.",
        x=50, y=230, width=370, height=180, status="IMPLEMENTED", icon="terminal", stroke="#0284c7"
    )
    c2 = p.add_card(
        "2. GUARDIÁN ADVERSARIAL",
        "<div style='color:#e11d48; font-weight:bold; font-size:10px; margin-bottom:4px;'>CONTENCIÓN CAPA 2 (core/guard.py)</div>"
        "• Intercepta ganchos <code>PreToolUse</code> antes de tocar I/O.<br/>"
        "• Resuelve <code>realpath</code> (anula symlinks y rutas relativas <code>../</code>).<br/>"
        "• Protege código del juez (<code>.harness/</code>, <code>gates/</code>, tests).<br/>"
        "• Redacta 9 familias de secretos y credenciales en memoria.",
        x=590, y=230, width=370, height=180, status="IMPLEMENTED", icon="shield", stroke="#e11d48"
    )
    c3 = p.add_card(
        "3. RUNTIME DE AGENTE",
        "<div style='color:#d97706; font-weight:bold; font-size:10px; margin-bottom:4px;'>EJECUCIÓN ACOTADA (adapters/)</div>"
        "• Runtimes: Claude Code, Kiro CLI, Antigravity, Gemini, Codex.<br/>"
        "• Opera bajo restricciones de ruta, cuotas y presupuesto USD.<br/>"
        "• Genera código y artefactos en el espacio gobernado.<br/>"
        "• Bloqueado sin guardián salvo directiva explícita de omisión.",
        x=1130, y=230, width=370, height=180, status="IMPLEMENTED", icon="bot", stroke="#d97706"
    )
    c4 = p.add_card(
        "4. VERIFICACIÓN FORMAL",
        "<div style='color:#7c3aed; font-weight:bold; font-size:10px; margin-bottom:4px;'>MOTOR DE 13 PUERTAS (gates/)</div>"
        "• <code>refuto verify</code>: Evaluación de las 13 puertas canónicas.<br/>"
        "• Valida cadena MCP H-02 y lock inmutable Git SHA.<br/>"
        "• Emite veredicto formal estructurado <code>Result</code>.<br/>"
        "• Persiste en diario inmutable <code>.harness/evidence/ledger.jsonl</code>.",
        x=1680, y=230, width=370, height=180, status="IMPLEMENTED", icon="check_circle", stroke="#7c3aed"
    )

    # Conectores Horizontales con Pasillo Amplio (170px entre tarjetas)
    p.add_flow_edge(c1, c2, "Hook PreToolUse", stroke="#e11d48", width=2.2, exit_xy=(1.0, 0.45), entry_xy=(0.0, 0.45))
    p.add_flow_edge(c2, c3, "Control de Acciones", stroke="#0284c7", width=2.2, exit_xy=(1.0, 0.45), entry_xy=(0.0, 0.45))
    p.add_flow_edge(c3, c4, "Entrega de Código", stroke="#16a34a", width=2.2, exit_xy=(1.0, 0.45), entry_xy=(0.0, 0.45))
    p.add_flow_edge(c4, c2, "27 Pruebas Adversariales (E3)", stroke="#e11d48", width=2.0, dashed=True,
                    exit_xy=(0.5, 1.0), entry_xy=(0.5, 1.0), points=[(1865, 450), (775, 450)])

    # Navegación Jerárquica hacia las páginas 2-7
    p.add_section_header("MAPA DE NAVEGACIÓN JERÁRQUICA (DESGLOSE ARQUITECTÓNICO EN PÁGINAS 2 A 7)", x=50, y=490, width=2000, height=32)

    nav_cards = [
        ("PÁGINA 2: ECOSISTEMA & SIDECAR", "• Integración en caliente con agentes.<br/>• Patrón Sidecar & Gatekeeper.<br/>• Erradicación de la auto-evaluación.", "network", "#eff6ff", "#3b82f6", "#1e3a8a"),
        ("PÁGINA 3: NÚCLEO EPISTÉMICO", "• Dataclass <code>Result</code> y contrato.<br/>• Álgebra formal de 5 estados.<br/>• Prohibición de ámbito vacío.", "scales", "#f0fdf4", "#16a34a", "#14532d"),
        ("PÁGINA 4: SEGURIDAD & GUARDIÁN", "• Defensa en 3 capas activas.<br/>• Intercepción <code>PreToolUse</code>.<br/>• Matriz empírica de 7 runtimes.", "shield", "#fff1f2", "#e11d48", "#881337"),
        ("PÁGINA 5: CADENA MCP & LOCK", "• Protocolo MCP 2026-07-28.<br/>• Cadena referencial H-02 y lock.<br/>• Remediación P0 de aislamiento.", "lock", "#fffbeb", "#d97706", "#78350f"),
        ("PÁGINA 6: OPERACIÓN & 13 PUERTAS", "• Ciclo CLI de 13 fases deterministas.<br/>• Escalera de 5 peldaños de agentes.<br/>• Catálogo de 13 puertas canónicas.", "check_circle", "#faf5ff", "#7c3aed", "#581c87"),
        ("PÁGINA 7: ARQUITECTURA OBJETIVO", "• Canonical Run & Event Stream.<br/>• Grafo de Evidencia y OTel Tracing.<br/>• Replay Forense y Flota Distribuida.", "target", "#fdf4ff", "#a21caf", "#701a75"),
    ]
    x_pos = 50
    w_card = 315
    for title, body, icon, fill, stroke, font_c in nav_cards:
        p.add_card(title, body, x=x_pos, y=540, width=w_card, height=130, icon=icon, fill=fill, stroke=stroke, font_color=font_c)
        x_pos += w_card + 22


def build_page_2_integration(builder: DrawioBuilder):
    p = builder.add_page("page-2-integration", "2. Integración en el Ecosistema de Harneses", width=2100, height=740)
    p.add_header(
        "INTEGRACIÓN EN EL ECOSISTEMA ACTUAL DE HARNESSES Y EVALUADORES DE AGENTES",
        "Patrón Sidecar & Gatekeeper · Contención en Tiempo Real · Auditoría Formal en CI/CD · Cero Dependencias",
        icon="network"
    )

    # Comparación: El Problema vs La Solución
    p.add_card(
        "[EL PROBLEMA] ARQUITECTURA DE HARNESS TRADICIONAL (AUTORREGULACIÓN CIEGA)",
        "• <b>Auto-evaluación Permisiva</b>: El agente opera con permisos directos de escritura en el workspace. Puede reescribir suites de pruebas para forzar aprobación.<br/>"
        "• <b>Evaluación de Caja Negra Tardía</b>: El harness convencional solo evalúa el código de salida final en CI; no supervisa el proceso en caliente.<br/>"
        "• <b>Alucinación de Herramientas MCP</b>: El agente declara haber consultado una herramienta externa, cuando el servidor ni siquiera arrancó.<br/>"
        "• <b>Falsos Positivos por Ámbito Vacío</b>: Si un test runner evalúa 0 casos por un filtro roto, sale con código 0 y el CI lo marca como exitoso.<br/>"
        "• <b>Fuga de Datos y Secretos</b>: Variables de entorno y credenciales son expuestas en commits o logs sin redacción preventiva.",
        x=50, y=100, width=960, height=180, icon="alert_triangle", fill="#fff1f2", stroke="#f43f5e", font_color="#881337"
    )
    p.add_card(
        "[LA SOLUCIÓN] REFUTO COMO GUARDIÁN Y JUEZ INDEPENDIENTE (DEFENSA EN PROFUNDIDAD)",
        "• <b>Separación Estricta de Poderes</b>: El agente es el sujeto evaluado; <code>refuto</code> es el evaluador externo, aislado e inviolable.<br/>"
        "• <b>Intercepción en Caliente (PreToolUse)</b>: Bloquea comandos destructivos y resuelve <code>realpath</code> antes de que el proceso toque el sistema.<br/>"
        "• <b>Integridad Referencial MCP H-02</b>: Handshake en frío obligatorio (<code>server/discover</code> y <code>tools/list</code>) antes de certificar herramientas.<br/>"
        "• <b>Axioma de Verdad</b>: Un ámbito vacío NUNCA aprueba; dictamina <code>NOT_APPLICABLE</code> con justificación causal en <code>measure</code>.<br/>"
        "• <b>Redactor Automático de Secretos</b>: 9 familias de credenciales protegidas en memoria antes de persistir en disco o diario.",
        x=1090, y=100, width=960, height=180, icon="shield_green", fill="#f0fdf4", stroke="#16a34a", font_color="#14532d"
    )

    # 4 Etapas de la Integración Sidecar & Gatekeeper
    c1 = p.add_card(
        "1. AGENTES & RUNTIMES",
        "<div style='font-size:10px; color:#0284c7; margin-bottom:2px;'>Claude Code · Kiro · Antigravity · Gemini · SWE-bench</div>"
        "• Inicia la tarea y despacha instrucciones al modelo LLM.<br/>"
        "• Solicita invocación de herramientas (shell, edit, mcp).<br/>"
        "• Totalmente agnóstico del harness subyacente.",
        x=50, y=315, width=370, height=155, status="IMPLEMENTED", icon="bot", stroke="#0284c7"
    )
    c2 = p.add_card(
        "2. REFUTO WIRE & GANCHOS",
        "<div style='font-size:10px; color:#e11d48; margin-bottom:2px;'>INYECCIÓN PreToolUse (PATRÓN SIDECAR)</div>"
        "• <code>refuto install</code> despliega hooks de intercepción nativos.<br/>"
        "• Conecta en caliente con el ciclo de vida del agente.<br/>"
        "• Resuelve paths y consulta el motor de política.",
        x=590, y=315, width=370, height=155, status="IMPLEMENTED", icon="layers", stroke="#e11d48"
    )
    c3 = p.add_card(
        "3. ESPACIO GOBERNADO",
        "<div style='font-size:10px; color:#d97706; margin-bottom:2px;'>DEFENSA CANÓNICA REALPATH</div>"
        "• Bloquea acceso de escritura a <code>.harness/</code>, <code>gates/</code> y tests.<br/>"
        "• Permite desarrollo seguro dentro del árbol permitido.<br/>"
        "• Anula enlaces simbólicos maliciosos y escapes <code>../</code>.",
        x=1130, y=315, width=370, height=155, status="IMPLEMENTED", icon="shield", stroke="#d97706"
    )
    c4 = p.add_card(
        "4. VERIFICACIÓN & CI/CD",
        "<div style='font-size:10px; color:#7c3aed; margin-bottom:2px;'>GATEKEEPER FORMAL REMOTO</div>"
        "• <code>refuto verify</code> evalúa la suite de 13 puertas canónicas.<br/>"
        "• Emite dictamen <code>Result</code> y registra en <code>ledger.jsonl</code>.<br/>"
        "• Bloquea el pull request o merge si hay fallos o estados no limpios.",
        x=1680, y=315, width=370, height=155, status="IMPLEMENTED", icon="check_circle", stroke="#7c3aed"
    )

    p.add_flow_edge(c1, c2, "Despacho de Herramienta", stroke="#0284c7", width=2.2, exit_xy=(1.0, 0.45), entry_xy=(0.0, 0.45))
    p.add_flow_edge(c2, c3, "Intercepción y Validación", stroke="#e11d48", width=2.2, exit_xy=(1.0, 0.45), entry_xy=(0.0, 0.45))
    p.add_flow_edge(c3, c4, "Entrega a Integración", stroke="#16a34a", width=2.2, exit_xy=(1.0, 0.45), entry_xy=(0.0, 0.45))

    # Qué Soluciona y Qué Mejora
    p.add_card(
        "QUÉ SOLUCIONA: VECTORES DE FALLA CRÍTICOS ELIMINADOS",
        "• <b>Reescritura del Juez</b>: Impide que el agente modifique las pruebas o políticas para auto-aprobarse.<br/>"
        "• <b>Escape por Symlinks</b>: Neutraliza enlaces simbólicos dirigidos fuera del espacio gobernado.<br/>"
        "• <b>Comandos Destructivos</b>: Intercepta <code>rm -rf</code>, <code>mkfs</code>, <code>dd</code> y <code>git push --force</code>.<br/>"
        "• <b>Fuga de Credenciales</b>: Redacta automáticamente 9 familias de secretos en memoria antes de tocar disco.<br/>"
        "• <b>Falso Éxito MCP</b>: Detecta servidores MCP ausentes, caídos o sin herramientas anunciadas.",
        x=50, y=500, width=960, height=185, icon="shield", fill="#f8fafc", stroke="#64748b"
    )
    p.add_card(
        "QUÉ MEJORA: MÉTRICAS DE CALIDAD Y CONFIANZA TÉCNICA",
        "• <b>Certeza Epistémica Elevada</b>: Transforma afirmaciones discursivas (E0/E1) en evidencia reproducible y probada (E3/E4).<br/>"
        "• <b>Cero Dependencias Externas</b>: 100% Python estándar (sin <code>pip install</code>), ejecución nativa en cualquier runner CI.<br/>"
        "• <b>Compatibilidad Multi-Runtime Unificada</b>: Mismo modelo de verdad para Claude, Kiro, Antigravity, Gemini y Codex.<br/>"
        "• <b>Integridad Criptográfica de Suministro</b>: Lock fijado por commit SHA completo de Git y sumas SHA-256 por archivo.<br/>"
        "• <b>Trazabilidad Forense Inmutable</b>: Diario append-only <code>ledger.jsonl</code> con firma de procedencia Git.",
        x=1090, y=500, width=960, height=185, icon="scales", fill="#f0fdf4", stroke="#16a34a", font_color="#14532d"
    )


def build_page_3_epistemic(builder: DrawioBuilder):
    p = builder.add_page("page-3-epistemic", "3. Núcleo Epistémico y Verdad", width=2100, height=700)
    p.add_header(
        "NÚCLEO EPISTÉMICO & MODELO CONTRACTUAL DE VERDAD (core/model.py, core/evidence.py)",
        "Formalización matemática del resultado de verificación · Invariantes duros · Trazabilidad append-only inmutable",
        icon="scales"
    )

    c1 = p.add_card(
        "DATACLASS RESULT (core/model.py)",
        "• <b>id</b>: Identificador formal de la puerta evaluada.<br/>"
        "• <b>status</b>: Estado formal emitido (uno de los 5 estados canónicos).<br/>"
        "• <b>severity</b>: <code>CRITICAL</code> · <code>HIGH</code> · <code>MEDIUM</code> · <code>LOW</code> · <code>INFO</code>.<br/>"
        "• <b>measure</b>: Métrica cuantitativa o justificación formal obligatoria.<br/>"
        "• <b>findings</b>: Lista de violaciones detectadas (<code>where</code>, <code>line</code>, <code>message</code>).<br/>"
        "• <b>evidence</b>: Pruebas empíricas (hashes SHA-256, RPC digests, exit codes).<br/>"
        "• <b>provenance</b>: Contexto git (commit, dirty, branch) y host UTC.<br/>"
        "• <b>duration_ms</b>: Tiempo exacto de cómputo en milisegundos.<br/>"
        "• <b>blocks</b>: Booleano que determina si retiene la integración.",
        x=50, y=105, width=560, height=240, status="IMPLEMENTED", icon="database", stroke="#16a34a"
    )
    c2 = p.add_card(
        "ÁLGEBRA DE LOS 5 ESTADOS FORMALES",
        "• <span style='background:#16a34a; color:#fff; padding:1px 6px; border-radius:3px; font-weight:bold;'>PASS (Aprobado)</span>: Comprobado formalmente y cumple al 100%.<br/>"
        "• <span style='background:#dc2626; color:#fff; padding:1px 6px; border-radius:3px; font-weight:bold;'>FAIL (Fallido)</span>: Comprobado formalmente y no cumple.<br/>"
        "• <span style='background:#d97706; color:#fff; padding:1px 6px; border-radius:3px; font-weight:bold;'>BLOCKED (Bloqueado)</span>: Dependencia no disponible (nunca PASS).<br/>"
        "• <span style='background:#991b1b; color:#fff; padding:1px 6px; border-radius:3px; font-weight:bold;'>NOT_EXECUTABLE (Error)</span>: La puerta falló en su propia ejecución.<br/>"
        "• <span style='background:#64748b; color:#fff; padding:1px 6px; border-radius:3px; font-weight:bold;'>NOT_APPLICABLE (N/A)</span>: Ámbito sin sujeto (exige medida causal).<br/>"
        "<div style='margin-top:6px; padding:4px 8px; background:#fef2f2; border:1px solid #fecaca; border-radius:4px; color:#991b1b; font-size:10px;'>"
        "<b>Regla de Bloqueo</b>: <code>BLOCKING = {FAIL, BLOCKED, NOT_EXECUTABLE}</code> detiene el avance de integración.</div>",
        x=770, y=105, width=560, height=240, status="IMPLEMENTED", icon="check_circle", stroke="#16a34a"
    )
    c3 = p.add_card(
        "INVARIANTES DUROS (Result.__post_init__)",
        "<b>1. PASS con hallazgos es IMPOSIBLE</b>:<br/>"
        "   <code>if self.status == PASS and self.findings: raise ValueError(...)</code><br/>"
        "   Elimina fallos falsos positivos donde una puerta aprueba reportando errores.<br/>"
        "<b>2. Un ámbito vacío NUNCA aprueba</b>:<br/>"
        "   Cero elementos evaluados jamás produce PASS. Dictamina NOT_APPLICABLE o FAIL.<br/>"
        "<b>3. NOT_APPLICABLE exige medida causal</b>:<br/>"
        "   Sin justificación explícita en <code>measure</code>, la instancia es inválida.<br/>"
        "<b>4. Irreversibilidad del Veredicto</b>:<br/>"
        "   Ningún método del core puede transformar FAIL o BLOCKED en PASS.",
        x=1490, y=105, width=560, height=240, status="IMPLEMENTED", icon="lock", fill="#f0fdf4", stroke="#16a34a", font_color="#14532d"
    )

    p.add_flow_edge(c1, c2, "Valida Estado", stroke="#16a34a", width=2.0, exit_xy=(1.0, 0.5), entry_xy=(0.0, 0.5))
    p.add_flow_edge(c2, c3, "Aplica Invariantes", stroke="#16a34a", width=2.0, exit_xy=(1.0, 0.5), entry_xy=(0.0, 0.5))

    # Escalera Epistémica E0 a E4 y Contrato de Evidencia
    p.add_card(
        "ESCALA GRADUADA DE CERTEZA EPISTÉMICA (E0 A E4)",
        "<table style='width:100%; font-size:10.5px; border-collapse:collapse; margin-top:4px;'>"
        "<tr style='background:#f1f5f9; text-align:left;'><th style='padding:4px;'>Nivel</th><th>Denominación</th><th>Criterio de Validación Empírica</th></tr>"
        "<tr><td><span style='background:#94a3b8; color:#fff; padding:1px 5px; border-radius:3px; font-weight:bold;'>E0</span></td><td><b>Dicho</b></td><td>Afirmación discursiva o promesa en prompt sin comprobación.</td></tr>"
        "<tr><td><span style='background:#38bdf8; color:#fff; padding:1px 5px; border-radius:3px; font-weight:bold;'>E1</span></td><td><b>Documentado</b></td><td>Consta formalmente en especificación, esquema o salida <code>--help</code>.</td></tr>"
        "<tr><td><span style='background:#0284c7; color:#fff; padding:1px 5px; border-radius:3px; font-weight:bold;'>E2</span></td><td><b>Reproducible</b></td><td>Verificable mediante comando determinista en frío en máquina limpia.</td></tr>"
        "<tr><td><span style='background:#16a34a; color:#fff; padding:1px 5px; border-radius:3px; font-weight:bold;'>E3</span></td><td><b>Probado</b></td><td>Fijado y protegido por suite de pruebas unitarias o adversariales.</td></tr>"
        "<tr><td><span style='background:#7c3aed; color:#fff; padding:1px 5px; border-radius:3px; font-weight:bold;'>E4</span></td><td><b>Observado</b></td><td>Comprobado en ejecución real, fechada, con versión, SO y hardware.</td></tr>"
        "</table>",
        x=50, y=380, width=960, height=260, status="IMPLEMENTED", icon="scales", fill="#ffffff", stroke="#16a34a"
    )

    p.add_card(
        "CONTRATO DE EVIDENCIA Y REGISTRO EN LEDGER (core/evidence.py)",
        "• <b>Estructura de Hallazgo (<code>Finding</code>)</b>: Ubicación (<code>where</code>), línea (<code>line</code>), regla violada (<code>rule</code>) y mensaje técnico descriptivo.<br/>"
        "• <b>Contrato de Evidencia (<code>Evidence</code>)</b>: Huellas criptográficas SHA-256 de archivos tocados, payloads JSON de handshakes MCP y códigos de salida de procesos.<br/>"
        "• <b>Procedencia Git Inviolable (<code>Provenance</code>)</b>: Commit SHA de 40 dígitos, estado del árbol de trabajo (<code>is_dirty</code>), rama activa y marca temporal ISO 8601 UTC.<br/>"
        "• <b>Diario Append-Only (<code>ledger.jsonl</code>)</b>: Cada veredicto se concatena sin reescribir la historia. Los registros son inmutables y trazables para auditoría externa.",
        x=1090, y=380, width=960, height=260, status="IMPLEMENTED", icon="database", fill="#ffffff", stroke="#16a34a"
    )


def build_page_4_security(builder: DrawioBuilder):
    p = builder.add_page("page-4-security", "4. Modelo de Seguridad en 3 Capas y Guardián", width=2100, height=740)
    p.add_header(
        "MODELO DE SEGURIDAD EN 3 CAPAS & GUARDIÁN DINÁMICO ADVERSARIAL",
        "Contención procedimental · Resolución canónica realpath · Redactor de secretos · Matriz empírica de 7 runtimes",
        icon="shield"
    )

    # 3 Capas de Seguridad
    p.add_card(
        "CAPA 1: POLÍTICA COMPILADA (ESTÁTICA)",
        "• Se compila al vocabulario nativo de cada runtime:<br/>"
        "  - Claude Code: <code>settings.local.json</code><br/>"
        "  - Kiro CLI: <code>.kiro/agents/*.json</code><br/>"
        "  - Google Antigravity: <code>.agents/hooks.json</code><br/>"
        "  - Gemini CLI: <code>.gemini/policies/harness.json</code><br/>"
        "  - OpenCode: <code>opencode.harness.json</code><br/>"
        "• Define reglas sintácticas <code>deny</code>/<code>ask</code>.<br/>"
        "• <i style='color:#be123c;'>Limitación</i>: No inspecciona contenidos ni resuelve symlinks.",
        x=50, y=100, width=640, height=190, status="IMPLEMENTED", icon="layers", fill="#fff1f2", stroke="#f43f5e", font_color="#881337"
    )
    p.add_card(
        "CAPA 2: GUARDIÁN DINÁMICO (core/guard.py)",
        "• Intercepta ganchos <code>PreToolUse</code> antes de tocar I/O.<br/>"
        "• Resuelve rutas canónicas absolutas con <code>realpath</code>:<br/>"
        "  - Neutraliza enlaces simbólicos fuera del workspace.<br/>"
        "  - Anula secuencias de escape de directorio <code>../../</code>.<br/>"
        "• Protege código del juez (<code>.harness/</code>, <code>gates/</code>, tests).<br/>"
        "• Redactor preventivo de 9 familias de secretos en memoria.<br/>"
        "• Bloquea comandos peligrosos (<code>rm -rf</code>, <code>mkfs</code>, <code>dd</code>).",
        x=730, y=100, width=640, height=190, status="IMPLEMENTED", icon="shield", fill="#fef2f2", stroke="#e11d48", font_color="#991b1b"
    )
    p.add_card(
        "CAPA 3: AISLAMIENTO REMOTO (CI & GIT)",
        "• Verificación formal fuera del alcance del proceso del agente.<br/>"
        "• Ejecución en contenedor limpio en GitHub Actions / GitLab CI.<br/>"
        "• Ramas Git protegidas con revisión humana obligatoria.<br/>"
        "• <b>Invariante de Diseño</b>: Las capas 1 y 2 son preventivas y de conveniencia local; la Capa 3 es la garantía criptográfica inviolable.",
        x=1410, y=100, width=640, height=190, status="IMPLEMENTED", icon="lock", fill="#f8fafc", stroke="#64748b", font_color="#0f172a"
    )

    # Matriz Empírica de 7 Runtimes (con Principia Veritas y corrección de Gemini)
    p.add_section_header("MATRIZ EMPÍRICA DE ADAPTERS Y CAPACIDAD DE GUARDIA (AUDITORÍA DE CÓDIGO)", x=50, y=310, width=2000, height=32)

    adapters_data = [
        ("Claude Code", "2.1.251", "PreToolUse en settings.local.json", "IMPLEMENTED", "stream-json", "Max budget USD, schema JSON, dontAsk"),
        ("Kiro CLI", "2.20.1", "preToolUse en .kiro/agents/*.json", "IMPLEMENTED", "acp", "KnowledgeBase indexada, --cloud KAS"),
        ("Google Antigravity", "2.15.1", "PreToolUse en .agents/hooks.json", "IMPLEMENTED", "antigravity-native", "PreInvocation brief, matcher * en I/O"),
        ("Gemini CLI", "0.55.1", "Compilación de política implementada; Hook de runtime requiere trusted folder", "PARTIAL", "acp", "Policy Engine dual, folder trust estricto"),
        ("OpenCode", "1.2.27", "Handshake ACP y política de permisos generada; sin hook pre-escritura en CLI", "PARTIAL", "acp", "Servidor persistente HTTP opencode serve"),
        ("OpenAI Codex", "0.151.0", "Handshake MCP y política de sandbox generada; hook de I/O no documentado", "PARTIAL", "mcp-server", "Expone MCP tools/listChanged en stdio"),
        ("GitHub Copilot", "N/A", "Planificado para futuras extensiones; sin soporte actual en core/wire.py", "PLANNED", "no-adapter", "Extensión de IDE / CLI sin gancho expuesto"),
    ]

    x_ad = 50
    w_ad = 278
    for name, ver, guard_info, stat, proto, extras in adapters_data:
        body = (f"• <b>Versión</b>: {ver}<br/>"
                f"• <b>Protocolo</b>: <code>{proto}</code><br/>"
                f"• <b>Guardián</b>: {guard_info}<br/>"
                f"• <b>Capacidad</b>: {extras}")
        p.add_card(name, body, x=x_ad, y=360, width=w_ad, height=195, status=stat, icon="bot", stroke="#64748b")
        x_ad += w_ad + 12

    # Redactor de Secretos
    p.add_card(
        "REDACTOR DE SECRETOS PREVENTIVO EN MEMORIA (core/digest.py)",
        "• <b>9 Familias de Credenciales Detectadas</b>: AWS Access Key / Secret, GitHub Personal Access Token (PAT), Google Cloud API Keys, OpenAI API Keys, Slack Bot Tokens, Claves privadas SSH/RSA/EC, JSON Web Tokens (JWT), Variables de entorno sensibles (DATABASE_URL) y Contraseñas literales.<br/>"
        "• <b>Lógica Dual Prueba vs. Indicio</b>: Si se detecta una credencial de alta entropía con formato exacto, el guardián emite <code>DENY</code> inmediato. Si se detecta un nombre sospechoso en una asignación sin credencial real, emite <code>ASK</code> para intervención humana.<br/>"
        "• <b>Invariante de Redacción</b>: Ninguna credencial interceptada se almacena en texto plano en el diario de eventos ni en los artefactos de evidencia.",
        x=50, y=580, width=2000, height=105, status="IMPLEMENTED", icon="shield", fill="#f8fafc", stroke="#64748b"
    )


def build_page_5_mcp(builder: DrawioBuilder):
    p = builder.add_page("page-5-mcp", "5. Cadena de Suministro, Protocolo MCP y Lock", width=2100, height=720)
    p.add_header(
        "CADENA DE SUMINISTRO MCP & LOCK CRIPTOGRÁFICO DE ORIGEN (H-02)",
        "Protocolo MCP 2026-07-28 y fallback legado · Integridad referencial · Lockfile inmutable Git SHA",
        icon="lock"
    )

    c1 = p.add_card(
        "1. DEFINICIÓN EN MANIFIESTO",
        "• <code>harness.manifest.json</code><br/>"
        "• Declara servidores MCP locales y remotos.<br/>"
        "• Herramientas autorizadas por servidor.<br/>"
        "• Variables de entorno requeridas.",
        x=50, y=110, width=370, height=170, status="IMPLEMENTED", icon="database", stroke="#0284c7"
    )
    c2 = p.add_card(
        "2. SONDAJE EN FRÍO MCP",
        "• Interrogación sin modelo ni créditos.<br/>"
        "• <b>Primario</b>: <code>server/discover</code> (2026-07-28).<br/>"
        "• <b>Fallback</b>: <code>initialize</code> (2025-06-18 legado).<br/>"
        "• Lista y valida herramientas anunciadas.",
        x=590, y=110, width=370, height=170, status="IMPLEMENTED", icon="network", stroke="#d97706"
    )
    c3 = p.add_card(
        "3. FIJACIÓN CRIPTOGRÁFICA",
        "• <code>refuto lock</code> genera <code>refuto.lock</code>.<br/>"
        "• Commit SHA completo de Git (40 hex).<br/>"
        "• Sumas SHA-256 de binarios y scripts.<br/>"
        "• Versión exacta reportada por el servidor.",
        x=1130, y=110, width=370, height=170, status="IMPLEMENTED", icon="lock", stroke="#16a34a"
    )
    c4 = p.add_card(
        "4. PUERTA G-MCP EN CI",
        "• Comprueba integridad en frío.<br/>"
        "• Servidor no arranca ──► <code>FAIL</code>.<br/>"
        "• Herramienta falta ──► <code>FAIL</code>.<br/>"
        "• Sin MCP configurado ──► <code>NOT_APPLICABLE</code>.",
        x=1680, y=110, width=370, height=170, status="IMPLEMENTED", icon="check_circle", stroke="#7c3aed"
    )

    p.add_flow_edge(c1, c2, "Entrada Declarativa", stroke="#0284c7", width=2.2, exit_xy=(1.0, 0.45), entry_xy=(0.0, 0.45))
    p.add_flow_edge(c2, c3, "Resultados de Handshake", stroke="#d97706", width=2.2, exit_xy=(1.0, 0.45), entry_xy=(0.0, 0.45))
    p.add_flow_edge(c3, c4, "Lockfile Criptográfico", stroke="#16a34a", width=2.2, exit_xy=(1.0, 0.45), entry_xy=(0.0, 0.45))

    # Aislamiento P0 de Refuto contra su propio entorno
    p.add_card(
        "REMEDIACIÓN P0 DE AISLAMIENTO: REFUTO AISLADO DE SU PROPIO MANIFIESTO",
        "• <b>Hallazgo Histórico Crítico</b>: Durante la auditoría inicial, la puerta G-MCP evaluó servidores MCP de refuto sobre el manifiesto de un proyecto cliente ajeno, produciendo fallos cruzados y contaminación de contexto.<br/>"
        "• <b>Solución Arquitectónica Aplicada</b>: Aislamiento estricto de rutas. Refuto solo evalúa las herramientas declaradas en el workspace auditado actual. Si un repositorio no declara servidores MCP, la puerta dictamina <code>NOT_APPLICABLE</code> justificando <code>sin servidores MCP declarados</code>.<br/>"
        "• <b>Invariante de Hermeticidad</b>: Ningún proceso hijo o servidor MCP puede heredar variables de entorno que apunten a repositorios paralelos.",
        x=50, y=330, width=2000, height=130, status="IMPLEMENTED", icon="shield", fill="#f8fafc", stroke="#64748b"
    )

    # Detalle del Protocolo MCP y Esquema de Lock
    p.add_card(
        "DETALLE DEL PROTOCOLO MCP 2026-07-28 Y FALLBACK LEGADO",
        "• <b>Handshake Moderno (<code>server/discover</code>)</b>: Llamada unificada que retorna capacidades completas, versión del protocolo y herramientas soportadas en un solo viaje de ida y vuelta.<br/>"
        "• <b>Handshake Legado (<code>initialize</code>)</b>: Utilizado cuando el servidor responde versión 2025-06-18 o no implementa discovery. Se envía <code>initialize</code> seguido de <code>notifications/initialized</code> y posterior consulta a <code>tools/list</code>.<br/>"
        "• <b>Gestión de Timeouts</b>: Conexiones por stdio con timeout estricto de 20 segundos para evitar bloqueos por procesos colgados.",
        x=50, y=490, width=980, height=180, status="IMPLEMENTED", icon="network", stroke="#0284c7"
    )
    p.add_card(
        "ESTRUCTURA DEL LOCKFILE CRIPTOGRÁFICO (refuto.lock)",
        "• <b>git_commit</b>: SHA-1 / SHA-256 completo del árbol de trabajo en el momento del congelamiento.<br/>"
        "• <b>servers</b>: Mapa indexado por nombre de servidor con comando exacto, variables de entorno y hash del ejecutable.<br/>"
        "• <b>tools</b>: Esquema completo de parámetros de cada herramienta anunciada con su firma SHA-256.<br/>"
        "• <b>Inmutabilidad</b>: Cualquier adición, mutación o eliminación de herramienta sin regenerar el lockfile es rechazada por G-LOCK.",
        x=1070, y=490, width=980, height=180, status="IMPLEMENTED", icon="lock", stroke="#16a34a"
    )


def build_page_6_operations(builder: DrawioBuilder):
    p = builder.add_page("page-6-operations", "6. Operación, Ciclo de 13 Fases y 13 Puertas", width=2100, height=720)
    p.add_header(
        "OPERACIÓN, CICLO DE VIDA DE 13 FASES Y MOTOR DE 13 PUERTAS FORMALES",
        "Pipeline procedimental determinista · Escalera de ejecutabilidad de agentes · Catálogo canónico de 13 puertas",
        icon="check_circle"
    )

    # Las 13 Fases del Ciclo de Vida
    p.add_section_header("PIPELINE PROCEDIMENTAL DE 13 FASES DETERMINISTAS", x=50, y=100, width=2000, height=28)
    phases = [
        ("1. doctor", "Sondea entorno y PATH"),
        ("2. probe", "Prueba handshakes en frío"),
        ("3. init", "Inicializa workspace"),
        ("4. compile", "Compila política a agentes"),
        ("5. wire", "Engancha ganchos locales"),
        ("6. chat", "Sesión gobernada LLM"),
        ("7. manifest", "Valida esquema manifiesto"),
        ("8. verify", "Evalúa 13 puertas canónicas"),
        ("9. audit", "Audita integridad y ganchos"),
        ("10. lock", "Genera lockfile inmutable"),
        ("11. export", "Exporta paquete evidencia"),
        ("12. unwire", "Restaura estado previo"),
        ("13. selftest", "Suite hermética 487 tests"),
    ]
    x_ph = 50
    w_ph = 145
    for name, desc in phases:
        p.add_card(name, desc, x=x_ph, y=135, width=w_ph, height=90, icon="terminal", fill="#f8fafc", stroke="#0284c7")
        x_ph += w_ph + 10

    # Escalera de 5 Peldaños
    p.add_card(
        "ESCALERA DE 5 PELDAÑOS DE EJECUTABILIDAD DE AGENTES (support-matrix.json)",
        "• <span style='background:#94a3b8; color:#fff; padding:1px 5px; border-radius:3px; font-weight:bold;'>DISCOVERED</span>: Binario localizado en el PATH del sistema o configuración.<br/>"
        "• <span style='background:#38bdf8; color:#fff; padding:1px 5px; border-radius:3px; font-weight:bold;'>INSTALLED</span>: Firma de código y versión comprobadas mediante comando básico.<br/>"
        "• <span style='background:#0284c7; color:#fff; padding:1px 5px; border-radius:3px; font-weight:bold;'>STARTABLE</span>: Responde a <code>--help</code> o proceso sin fallos inmediatos de arranque.<br/>"
        "• <span style='background:#16a34a; color:#fff; padding:1px 5px; border-radius:3px; font-weight:bold;'>FUNCTIONAL</span>: Responde a handshake estructurado (ACP, MCP o stream-json) sin consumir créditos.<br/>"
        "• <span style='background:#7c3aed; color:#fff; padding:1px 5px; border-radius:3px; font-weight:bold;'>VERIFIED</span>: Ejecuta una tarea gobernada completa con presupuesto y guardián activo.",
        x=50, y=245, width=980, height=190, status="IMPLEMENTED", icon="layers", stroke="#2563eb"
    )

    # Principio Inviolable
    p.add_card(
        "PRINCIPIO FUNDAMENTAL: EL ÁMBITO VACÍO NUNCA APRUEBA",
        "• <b>Definición del Axioma</b>: Si una prueba o puerta no encuentra sujetos que evaluar (archivos coincidentes, pruebas configuradas o servidores), NUNCA puede emitir un resultado <code>PASS</code>.<br/>"
        "• <b>Resolución Formal</b>: Debe emitir <code>NOT_APPLICABLE</code> si el sujeto no es obligatorio para el proyecto, o <code>FAIL</code> si la condición era requerida por contrato.<br/>"
        "• <b>Erradicación de Falsos Positivos</b>: Elimina el clásico fallo de CI donde un glob mal escrito produce 0 tests ejecutados y el runner devuelve exit code 0.",
        x=1070, y=245, width=980, height=190, status="IMPLEMENTED", icon="scales", fill="#f0fdf4", stroke="#16a34a", font_color="#14532d"
    )

    # Catálogo de las 13 Puertas Formales (gates/base.py)
    p.add_section_header("CATÁLOGO DE LAS 13 PUERTAS CANÓNICAS DE VERIFICACIÓN (gates/base.py)", x=50, y=455, width=2000, height=28)

    gates_catalog = [
        ("G-AGENT", "CRITICAL", "Ejecutabilidad real de los agentes instalados"),
        ("G-MCP", "CRITICAL", "Integridad referencial y handshake de MCP"),
        ("G-POLICY", "HIGH", "Política: fuente única compilada y aplicada"),
        ("G-LOCK", "HIGH", "Lock criptográfico del origen y Git SHA"),
        ("G-FLEET", "HIGH", "Deriva de la flota materializada y copias"),
        ("G-SKILL", "MEDIUM", "Contrato formal de las skills instaladas"),
        ("G-MANIFEST", "HIGH", "Manifiesto válido, completo y sin esquemas rotos"),
        ("G-SDD", "HIGH", "Puertas de aseguramiento heredadas del núcleo SDD"),
        ("G-TRACE", "HIGH", "Trazabilidad de la cadena y linaje de artefactos"),
        ("G-SECURITY", "CRITICAL", "Seguridad: 9 familias de secretos y dependencias"),
        ("G-PR", "HIGH", "El cambio como unidad de revisión atómica"),
        ("G-HUMAN", "HIGH", "Revisión humana registrada y firmas de aprobación"),
        ("G-ROLES", "MEDIUM", "Registro de roles válido y permisos por función"),
    ]

    x_g = 50
    y_g = 495
    w_g = 295
    h_g = 80
    for idx, (gid, sev, title) in enumerate(gates_catalog):
        col = idx % 6
        row = idx // 6
        gx = x_g + col * (w_g + 20)
        gy = y_g + row * (h_g + 12)
        sev_color = "#dc2626" if sev == "CRITICAL" else ("#d97706" if sev == "HIGH" else "#2563eb")
        body = f"<span style='color:{sev_color}; font-weight:bold; font-size:10px;'>{sev}</span> · {title}"
        p.add_card(gid, body, x=gx, y=gy, width=w_g, height=h_g, status="IMPLEMENTED", icon="check_circle", stroke="#7c3aed")


def build_page_7_target(builder: DrawioBuilder):
    p = builder.add_page("page-7-target", "7. Arquitectura Objetivo (Target Architecture)", width=2100, height=740)
    p.add_header(
        "ARQUITECTURA OBJETIVO: CANONICAL RUN, EVENT MODEL & EVIDENCE GRAPH (ADR-0009, ADR-0010, ADR-0011)",
        "Fronteras de confianza explícitas · Flujo desacoplado de eventos · Grafo de evidencia criptográfico · Telemetría OTel",
        icon="target"
    )

    # 4 Fronteras de Confianza (Trust Boundaries) como contenedores visuales
    # TB-0: Operador / Host (x=50..510)
    p.add_boundary("TB-0: FRONTERA DEL OPERADOR Y SUPERVISOR HOST (Privilegiado, No Accesible por LLM)", 50, 95, 460, 580, stroke="#0284c7")
    # TB-1: Proceso del Agente (x=550..1010)
    p.add_boundary("TB-1: PROCESO DEL AGENTE SUPERVISADO (Código Terceros, Confinado)", 550, 95, 460, 580, stroke="#d97706")
    # TB-2: Plano de Herramientas (x=1050..1510)
    p.add_boundary("TB-2: PLANO DE HERRAMIENTAS & SERVIDORES MCP (Subprocesos Aislados)", 1050, 95, 460, 580, stroke="#e11d48")
    # TB-3: Almacén Protegido (x=1550..2050)
    p.add_boundary("TB-3: ALMACÉN DE EVIDENCIA & POLÍTICAS (Inmutable, Append-Only)", 1550, 95, 500, 580, stroke="#16a34a")

    # Contenido TB-0 (Operador / Supervisor)
    t0_c1 = p.add_card(
        "SUPERVISOR DE CORRIDA (Run Supervisor)",
        "• Genera <code>run_id</code> unívoco (UUIDv4/ULID).<br/>"
        "• Asigna secuencia monótona <code>seq</code> a eventos.<br/>"
        "• Gestiona máquina de estados formal:<br/>"
        "  <code>INIT</code> ➔ <code>GUARD_ON</code> ➔ <code>EXEC</code> ➔ <code>EVAL</code> ➔ <code>DONE</code>.<br/>"
        "• Orquesta timeouts y señales de proceso.",
        x=70, y=140, width=420, height=155, status="PLANNED", icon="terminal", stroke="#0284c7"
    )
    p.add_card(
        "COMPILADOR DE POLÍTICA Y SONDAS",
        "• Lee <code>policy.json</code> (Única Fuente de Verdad).<br/>"
        "• Compila a esquemas nativos sin tocar el agente.<br/>"
        "• Ejecuta sondas en frío para verificar ejecutabilidad.<br/>"
        "• Aplica RBAC y perfiles de gobierno de flota.",
        x=70, y=320, width=420, height=150, status="IMPLEMENTED", icon="layers", stroke="#0284c7"
    )
    t0_c3 = p.add_card(
        "CANAL DE APROBACIÓN HUMANA (Escalation)",
        "• Interrupción interactiva ante reglas <code>ASK</code>.<br/>"
        "• Confirmación explícita para comandos sensibles.<br/>"
        "• Emite token de aprobación firmado para la sesión.",
        x=70, y=495, width=420, height=140, status="IMPLEMENTED", icon="check_circle", stroke="#0284c7"
    )

    # Contenido TB-1 (Proceso del Agente)
    t1_c1 = p.add_card(
        "RUNTIME DEL AGENTE (LLM Context)",
        "• Instancia de agente (Claude, Kiro, Antigravity, Gemini).<br/>"
        "• Mantiene contexto conversacional y razonamiento.<br/>"
        "• Despacha llamadas a herramientas por stdio/RPC.<br/>"
        "• <i style='color:#be123c;'>Sin acceso a secretos ni a políticas del juez</i>.",
        x=570, y=140, width=420, height=155, status="EXTERNAL", icon="bot", stroke="#d97706"
    )
    t1_c2 = p.add_card(
        "MAPEJADOR CANÓNICO DE EVENTOS",
        "• Captura streams nativos (stream-json, ACP, stdout).<br/>"
        "• Transforma a <code>CanonicalEvent</code> estructurado:<br/>"
        "  - <code>run_id</code>, <code>seq</code>, <code>timestamp</code>, <code>event_type</code>.<br/>"
        "  - <code>actor</code>, <code>payload</code>, <code>verdict</code>.<br/>"
        "• Puente compatible con spans de OpenTelemetry (OTel).",
        x=570, y=320, width=420, height=150, status="PLANNED", icon="activity", stroke="#d97706"
    )
    p.add_card(
        "MOTOR DE REPLAY FORENSE",
        "• Reproduce fielmente corridas pasadas desde diario.<br/>"
        "• Diagnostica alucinaciones o derivas de comportamiento.<br/>"
        "• Compara salidas entre distintas versiones de modelos.",
        x=570, y=495, width=420, height=140, status="PLANNED", icon="target", stroke="#d97706"
    )

    # Contenido TB-2 (Herramientas & MCP)
    t2_c1 = p.add_card(
        "GUARDIÁN PRE-HERRAMIENTA (Dynamic Guard)",
        "• Interceptor síncrono <code>PreToolUse</code>.<br/>"
        "• Valida rutas canónicas resueltas con <code>realpath</code>.<br/>"
        "• Bloquea lectura/escritura en <code>protected_paths</code>.<br/>"
        "• Redacta 9 familias de credenciales en memoria.<br/>"
        "• Emite veredicto síncrono: <code>ALLOW</code> / <code>DENY</code> / <code>ASK</code>.",
        x=1070, y=140, width=420, height=155, status="IMPLEMENTED", icon="shield", stroke="#e11d48"
    )
    t2_c2 = p.add_card(
        "SERVIDORES MCP CONFINADOS",
        "• Procesos locales de herramientas (Playwright, Git, etc.).<br/>"
        "• Conexión mediante transporte stdio / JSON-RPC.<br/>"
        "• Ejecutan únicamente herramientas autorizadas en lockfile.<br/>"
        "• Restricción de permisos I/O gobernada por el sistema.",
        x=1070, y=320, width=420, height=150, status="EXTERNAL", icon="network", stroke="#e11d48"
    )
    t2_c3 = p.add_card(
        "SISTEMA DE ARCHIVOS DEL PROYECTO",
        "• Árbol de código fuente gobernado.<br/>"
        "• Operaciones de lectura y edición autorizadas.<br/>"
        "• Protegido contra escrituras destructivas (<code>rm -rf</code>).",
        x=1070, y=495, width=420, height=140, status="EXTERNAL", icon="database", stroke="#e11d48"
    )

    # Contenido TB-3 (Almacén de Evidencia & Evaluación)
    t3_c1 = p.add_card(
        "DIARIO INMUTABLE DE EVENTOS (events.jsonl)",
        "• Registro append-only en <code>.harness/runs/</code>.<br/>"
        "• Persistencia síncrona con <code>fsync</code> en hitos críticos.<br/>"
        "• Cada evento lleva hash y firma del supervisor.<br/>"
        "• Trazabilidad forense completa punto a punto.",
        x=1590, y=140, width=420, height=155, status="PLANNED", icon="database", stroke="#16a34a"
    )
    t3_c2 = p.add_card(
        "GRAFO DE EVIDENCIA CRIPTOGRÁFICO",
        "• DAG de aserciones, artefactos y ejecuciones.<br/>"
        "• Nodos dirigidos: <code>AssertionNode</code>, <code>ArtifactNode</code>.<br/>"
        "• Aristas causales: <code>VERIFIED_BY</code>, <code>REFUTES</code>.<br/>"
        "• Huellas SHA-256 inmutables de código y outputs.<br/>"
        "• Prohíbe formalmente el paso por verdad vacía.",
        x=1590, y=320, width=420, height=150, status="PLANNED", icon="scales", stroke="#16a34a"
    )
    t3_c3 = p.add_card(
        "PLANO DE EVALUACIÓN FORMAL (Evaluation Plane)",
        "• Evaluador puro de las 13 puertas canónicas.<br/>"
        "• Emite veredicto inmutable <code>Result</code> con 5 estados.<br/>"
        "• Invariante duro: <code>PASS</code> con hallazgos es un error estructural.<br/>"
        "• Exporta ledger y reportes para auditoría en CI/CD.",
        x=1590, y=495, width=420, height=140, status="IMPLEMENTED", icon="check_circle", stroke="#16a34a"
    )

    # Conexiones y Separación de Flujos (ADR-0011) en Pasillos Libres (Sin cruces)
    # Control Flow: Supervisor -> Runtime (Fila 1 horizontal)
    p.add_flow_edge(t0_c1, t1_c1, "Control Flow (Start)", stroke="#0284c7", width=2.2, exit_xy=(1.0, 0.5), entry_xy=(0.0, 0.5))
    # Interception Flow: Runtime -> Guard (Fila 1 horizontal)
    p.add_flow_edge(t1_c1, t2_c1, "Interception (PreToolUse)", stroke="#e11d48", width=2.2, exit_xy=(1.0, 0.5), entry_xy=(0.0, 0.5))
    # Execution Flow: Guard -> MCP / Filesystem (Vertical en TB-2)
    p.add_flow_edge(t2_c1, t2_c2, "Tool Call (Allowed)", stroke="#16a34a", width=2.0, exit_xy=(0.5, 1.0), entry_xy=(0.5, 0.0))
    p.add_flow_edge(t2_c2, t2_c3, "I/O Disk", stroke="#64748b", width=1.5, exit_xy=(0.5, 1.0), entry_xy=(0.5, 0.0))
    # Approval Flow: Guard -> Approval Escalation (Por pasillo entre filas y columnas, sin cruces)
    p.add_flow_edge(t2_c1, t0_c3, "Approval Flow (ASK)", stroke="#d97706", width=2.0, dashed=True,
                    exit_xy=(0.0, 0.7), entry_xy=(1.0, 0.5), points=[(1040, 248), (1040, 482), (530, 482), (530, 565)])
    # Event Stream: Runtime -> Mapper -> Event Journal (Por pasillo entre filas y columnas, sin cruces)
    p.add_flow_edge(t1_c1, t1_c2, "Telemetry Stream", stroke="#d97706", width=2.0, exit_xy=(0.5, 1.0), entry_xy=(0.5, 0.0))
    p.add_flow_edge(t1_c2, t3_c1, "Event Stream (Append-Only)", stroke="#059669", width=2.2, exit_xy=(1.0, 0.2), entry_xy=(0.0, 0.5),
                    points=[(1030, 350), (1030, 308), (1540, 308), (1540, 217)])
    # Evidence Flow: Journal & Gates -> Evidence Graph (Vertical en TB-3)
    p.add_flow_edge(t3_c1, t3_c2, "Events to DAG", stroke="#16a34a", width=2.0, exit_xy=(0.5, 1.0), entry_xy=(0.5, 0.0))
    p.add_flow_edge(t3_c3, t3_c2, "Gate Results to DAG", stroke="#7c3aed", width=2.0, exit_xy=(0.5, 0.0), entry_xy=(0.5, 1.0))


# ── Función Principal de Generación y Exportación ─────────────────────────────

def generate_all():
    builder = DrawioBuilder()
    build_page_1_macro(builder)
    build_page_2_integration(builder)
    build_page_3_epistemic(builder)
    build_page_4_security(builder)
    build_page_5_mcp(builder)
    build_page_6_operations(builder)
    build_page_7_target(builder)

    output_dir = Path("docs/diagrams")
    output_dir.mkdir(parents=True, exist_ok=True)
    drawio_path = output_dir / "refuto-arquitectura-operacion-ingenieria.drawio"

    # 1. Generación y Validación del Archivo Draw.io XML
    xml_content = builder.to_string()
    # nosec B314 — el contenido lo acaba de generar `builder.to_string()` tres líneas arriba:
    # no hay entrada ajena que pueda declarar entidades. El riesgo está en el guion que LEE
    # ficheros del disco (`check_diagram_assurance.py`), y allí sí se rechaza el vector.
    ET.fromstring(xml_content)  # nosec B314 — contenido autogenerado en esta función
    drawio_path.write_text(xml_content, encoding="utf-8", newline="\n")
    print(f"✓ Diagrama Draw.io generado: {drawio_path} ({len(xml_content)} bytes, {len(builder.pages)} páginas)")

    # 2. Exportación Vectorial SVG de Cada Página
    for p in builder.pages:
        svg_content = p.to_svg()
        ET.fromstring(svg_content)  # nosec B314 — contenido autogenerado por `p.to_svg()`
        svg_file = output_dir / f"{p.prefix}.svg"
        svg_file.write_text(svg_content, encoding="utf-8", newline="\n")
        print(f"  ✓ Exportada página vectorial: {svg_file.name} ({len(svg_content)} bytes)")

    # 3. Exportación del Diagrama Maestro de Arquitectura (refuto-arquitectura-operacion-ingenieria.svg)
    # Refleja la arquitectura macro del sistema completo (Página 1)
    macro_svg = builder.pages[0].to_svg()
    master_svg_file = output_dir / "refuto-arquitectura-operacion-ingenieria.svg"
    master_svg_file.write_text(macro_svg, encoding="utf-8", newline="\n")
    print(f"✓ Diagrama SVG maestro actualizado: {master_svg_file} ({len(macro_svg)} bytes)")


if __name__ == "__main__":
    generate_all()
