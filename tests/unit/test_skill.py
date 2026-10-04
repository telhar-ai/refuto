# -*- coding: utf-8 -*-
"""Contrato de skill y el subconjunto de YAML del frontmatter.

El parser falló contra su propio ejemplo la primera vez: decidía la forma del contenedor al
abrirlo en vez de al ver su primer hijo, así que una lista anidada era «elemento de lista sin
clave». Cada caso de aquí es una forma que `SKILL.md` usa de verdad.
"""

from __future__ import annotations

import unittest

from core.skill import _parse_frontmatter, check, load
from tests.fixtures import Workspace


class TestFrontmatter(unittest.TestCase):
    def parse(self, text):
        data, _, err = _parse_frontmatter(text)
        self.assertEqual(err, "", f"no debía fallar: {err}")
        return data

    def test_plano(self):
        self.assertEqual(self.parse("---\nname: a\ndescription: b\n---\nz"),
                         {"name": "a", "description": "b"})

    def test_lista_simple(self):
        self.assertEqual(self.parse("---\na:\n  - x\n  - y\n---\nz"), {"a": ["x", "y"]})

    def test_lista_anidada_dos_niveles(self):
        self.assertEqual(self.parse("---\nh:\n  requires:\n    tools:\n      - read\n---\nz"),
                         {"h": {"requires": {"tools": ["read"]}}})

    def test_escalares_tipados(self):
        d = self.parse("---\na: 1\nb: true\nc: false\nd: [x, y]\ne: 'texto'\n---\nz")
        self.assertEqual(d, {"a": 1, "b": True, "c": False, "d": ["x", "y"], "e": "texto"})

    def test_mapa_y_lista_hermanos(self):
        d = self.parse("---\nname: s\nh:\n  version: 1.0.0\n  compat:\n    claude: si\n---\nz")
        self.assertEqual(d["h"]["compat"]["claude"], "si")

    # ── formas inválidas: error explícito, nunca un mapa a medias ────────────────────
    def test_sin_frontmatter(self):
        _, _, err = _parse_frontmatter("# solo cuerpo")
        self.assertIn("no empieza", err)

    def test_frontmatter_sin_cerrar(self):
        _, _, err = _parse_frontmatter("---\nname: a\nsin cierre")
        self.assertIn("no se cierra", err)

    def test_lista_en_la_raiz(self):
        _, _, err = _parse_frontmatter("---\n- x\n---\nz")
        self.assertIn("raíz", err)

    def test_lista_mezclada_con_claves(self):
        _, _, err = _parse_frontmatter("---\na:\n  b: 1\n  - x\n---\nz")
        self.assertIn("mezclada", err)

    def test_linea_sin_dos_puntos(self):
        _, _, err = _parse_frontmatter("---\nesto no es una clave\n---\nz")
        self.assertIn("clave: valor", err)


class TestContrato(unittest.TestCase):
    def test_skill_conforme(self):
        with Workspace("sk") as ws:
            p = ws.skill("frontend", "frontend")
            self.assertEqual(check(load(p)), [])

    def test_nombre_distinto_del_directorio(self):
        with Workspace("sk2") as ws:
            p = ws.skill("revision", "revision-adversarial")
            problems = check(load(p))
            self.assertTrue(any("no coincide con el directorio" in x for x in problems))

    def test_nombre_no_kebab(self):
        with Workspace("sk3") as ws:
            p = ws.skill("Mi_Skill", "Mi_Skill")
            self.assertTrue(any("minúsculas-con-guiones" in x for x in check(load(p))))

    def test_sin_descripcion(self):
        with Workspace("sk4") as ws:
            p = ws.file(".claude/skills/x/SKILL.md", "---\nname: x\n---\n\n" + "cuerpo " * 40)
            self.assertTrue(any("description" in x for x in check(load(p))))

    def test_cuerpo_vacio(self):
        with Workspace("sk5") as ws:
            p = ws.file(".claude/skills/x/SKILL.md",
                        "---\nname: x\ndescription: " + "d" * 100 + "\n---\n\nhola")
            self.assertTrue(any("vacío" in x for x in check(load(p))))

    def test_permite_no_exigir_coincidencia(self):
        """Algún runtime puede no exigirlo. El contrato se relaja por configuración, no a mano."""
        with Workspace("sk6") as ws:
            p = ws.skill("revision", "revision-adversarial")
            self.assertEqual(check(load(p), require_name_matches_directory=False), [])
