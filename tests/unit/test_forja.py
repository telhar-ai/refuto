# -*- coding: utf-8 -*-
"""Forja y clasificación: de una issue al rol que la ejecuta, sin que nadie lo defina."""

from __future__ import annotations

import unittest

from core.classify import classify
from core.forge import Task, parse_body


CUERPO = """**Historia del Sprint 0** · [spec.md](https://github.com/O/R/blob/main/sprints/s0/X/spec.md)

Texto de contexto.

| Campo | Valor |
|---|---|
| **ID** | S0-ADR1 |
| **Tipo** | ARQ, BE |
| **Épica** | S0 Fundación |
| **Horas** | 40 h |
| **Ejecutor** | Robert (Tech Lead) |
"""


class TestLecturaDeLaHistoria(unittest.TestCase):
    def test_extrae_la_tabla_de_campos(self):
        campos, _ = parse_body(CUERPO)
        self.assertEqual(campos["Tipo"], "ARQ, BE")
        self.assertEqual(campos["Épica"], "S0 Fundación")
        self.assertEqual(campos["ID"], "S0-ADR1")

    def test_extrae_la_ruta_de_la_spec_relativa_al_repo(self):
        _, spec = parse_body(CUERPO)
        self.assertEqual(spec, "sprints/s0/X/spec.md")

    def test_ignora_las_filas_separadoras(self):
        campos, _ = parse_body(CUERPO)
        self.assertNotIn("---", campos)
        self.assertNotIn("Campo", campos)

    def test_un_cuerpo_vacio_no_revienta(self):
        self.assertEqual(parse_body(""), ({}, ""))
        self.assertEqual(parse_body(None), ({}, ""))


class TestClasificacion(unittest.TestCase):
    ROLES = {"solution-architect", "backend-engineer", "frontend-engineer", "technical-writer",
             "release-engineer", "observability-engineer", "security-engineer", "test-engineer",
             "ux-designer", "accessibility-engineer", "data-architect", "data-engineer",
             "security-architect", "performance-engineer", "requirements-engineer",
             "acceptance-engineer", "test-strategist", "delivery-manager", "product-strategist",
             "adversarial-reviewer", "reviewer"}

    def tarea(self, **kw) -> Task:
        base = dict(repo="O/R", number=9, key="S0-X", title="algo", fields={}, labels=[],
                    body_excerpt="")
        base.update(kw)
        return Task(**base)

    def test_lo_declarado_manda_y_se_marca_como_leido(self):
        c = classify(self.tarea(fields={"Tipo": "ARQ, BE"}), roles_disponibles=self.ROLES)
        self.assertEqual(c.primary, "solution-architect")
        self.assertIn("backend-engineer", c.roles)
        self.assertEqual(c.source, "declarado")
        self.assertEqual(c.evidence, "L")
        self.assertEqual(c.confidence, "CIERTO")
        self.assertFalse(c.question)

    def test_lo_inferido_se_marca_como_inferido(self):
        """Confundir una inferencia con un dato enruta el trabajo a un privilegio que nadie pidió."""
        c = classify(self.tarea(title="Añadir endpoint de exportación a la API"),
                     roles_disponibles=self.ROLES)
        self.assertEqual(c.source, "inferido")
        self.assertEqual(c.evidence, "I")
        self.assertIn("backend-engineer", c.roles)

    def test_sin_ninguna_senal_pregunta_en_vez_de_elegir(self):
        c = classify(self.tarea(title="zzz"), roles_disponibles=self.ROLES)
        self.assertEqual(c.roles, [])
        self.assertIn("no se pudo determinar", c.question)

    def test_el_gate_no_se_confunde_con_una_disciplina(self):
        """`Tipo / Gate: A (arrancable) · G0` no declara disciplina: no se inventa una."""
        c = classify(self.tarea(fields={"Tipo / Gate": "A (arrancable) · G0"},
                                title="zzz"), roles_disponibles=self.ROLES)
        self.assertNotEqual(c.source, "declarado")

    def test_no_enruta_a_un_rol_que_no_existe(self):
        c = classify(self.tarea(fields={"Tipo": "ARQ"}), roles_disponibles={"backend-engineer"})
        self.assertNotIn("solution-architect", c.roles)

    def test_las_etiquetas_valen_menos_que_lo_declarado(self):
        c = classify(self.tarea(fields={"Tipo": "BE"}, labels=["documentation"]),
                     roles_disponibles=self.ROLES)
        self.assertEqual(c.primary, "backend-engineer")

    def test_admite_vocabulario_propio_del_proyecto(self):
        c = classify(self.tarea(fields={"Tipo": "PLATAFORMA"}),
                     roles_disponibles=self.ROLES,
                     aliases={"PLATAFORMA": ["release-engineer"]})
        self.assertEqual(c.primary, "release-engineer")
        self.assertEqual(c.source, "declarado")

    def test_toda_clasificacion_explica_sus_senales(self):
        c = classify(self.tarea(fields={"Tipo": "ARQ"}), roles_disponibles=self.ROLES)
        self.assertTrue(c.signals)
        self.assertIn("solution-architect", c.explain())


class TestForjaSinSesion(unittest.TestCase):
    def test_available_no_pide_credenciales(self):
        from core.forge import available
        out = available()
        for name in ("github", "gitlab"):
            self.assertIn(name, out)
            self.assertIn("ok", out[name])

    def test_repo_of_en_un_directorio_sin_git(self):
        from core.forge import repo_of
        from tests.fixtures import Workspace
        with Workspace("forja") as ws:
            self.assertEqual(repo_of(ws.root), "")


class TestSesionConTarea(unittest.TestCase):
    def test_sin_repositorio_lo_dice_en_vez_de_fallar(self):
        from core.session import task_context
        from tests.fixtures import Workspace
        with Workspace("tarea") as ws:
            _, err = task_context(ws.root, "9")
            self.assertIn("--repo", err)
