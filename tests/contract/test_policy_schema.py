# -*- coding: utf-8 -*-
"""`schemas/policy.schema.json` describe las políticas que este programa produce de verdad.

Por qué hace falta, medido el 2026-09-23: `scripts/check_schemas.py` comprueba que un esquema
cae dentro del subconjunto que `core.schema` implementa — **no valida ni una sola instancia**.
Con sólo ese control, un esquema publicado puede describir un contrato que ningún documento
real cumple, y nada lo diría. Un contrato que nadie contrasta es documentación, y este
repositorio existe para no cerrar nada con documentación.

Las tres cosas que se fijan aquí son independientes a propósito: las instancias reales validan,
el validador no está mudo, y el esquema no se queda atrás cuando `Policy` gana un campo.
"""

from __future__ import annotations

import json
import unittest
from pathlib import Path

from core.policy import Policy
from core.refinement import MODO, REGLAS, documento_hijo
from core.schema import load_schema, validate

RAIZ = Path(__file__).resolve().parents[2]
EJEMPLO = RAIZ / "examples" / "tres-capas"


def _esquema() -> dict:
    return load_schema("policy.schema.json")


class TestLasPoliticasRealesValidan(unittest.TestCase):
    """Las que el programa escribe, no unas inventadas para la ocasión."""

    def _casos(self):
        yield "Policy.default()", Policy.default().to_dict()
        from core.policy import documento_base
        yield "documento_base()", documento_base()
        yield "documento_hijo()", documento_hijo("proyecto", "../../x/.harness/policy.json")
        yield "documento_hijo(anclado)", documento_hijo(
            "proyecto", "../../x/.harness/policy.json",
            padre_doc={"schema": "harness.policy/v1", "version": "1"})
        for ruta in sorted(EJEMPLO.rglob(".harness/policy.json")):
            yield str(ruta.relative_to(EJEMPLO)), json.loads(
                ruta.read_text(encoding="utf-8"))

    def test_todas(self):
        esquema = _esquema()
        vistos = 0
        for etiqueta, doc in self._casos():
            vistos += 1
            with self.subTest(etiqueta):
                self.assertEqual([], validate(doc, esquema),
                                 f"«{etiqueta}» no cumple el contrato que publicamos")
        # Un ámbito vacío nunca aprueba: si `rglob` dejara de encontrar los ejemplos, este
        # caso pasaría sin haber validado nada.
        self.assertGreaterEqual(vistos, 7, "se validaron menos documentos de los que hay")


class TestElValidadorNoEstaMudo(unittest.TestCase):
    """El control. Sin él, «0 errores» no distingue «cumple» de «no se comprobó nada»."""

    def test_un_documento_mal_formado_produce_errores(self):
        esquema = _esquema()
        for etiqueta, doc in (
                ("schema equivocado", {"schema": "otra.cosa/v1"}),
                ("sin schema", {"name": "x"}),
                ("clave desconocida", {"schema": "harness.policy/v1", "inventada": 1}),
                ("lista donde va booleano", {"schema": "harness.policy/v1",
                                             "block_secret_content": []}),
                ("cadena donde va lista", {"schema": "harness.policy/v1",
                                           "command_deny": "sudo:*"}),
                ("extends vacío", {"schema": "harness.policy/v1", "extends": ""}),
        ):
            with self.subTest(etiqueta):
                self.assertNotEqual([], validate(doc, esquema),
                                    f"el validador aceptó «{etiqueta}»")


class TestElEsquemaNoSeQuedaAtras(unittest.TestCase):
    """La deriva silenciosa: `Policy` gana un campo y el esquema lo rechaza como desconocido.

    `additionalProperties: false` convierte esa deriva en un rechazo de documentos válidos, y
    `core/refinement.py` ya tiene una guarda equivalente para la tabla de monotonía. Ésta es la
    otra mitad.
    """

    def test_todo_campo_de_Policy_tiene_propiedad(self):
        props = set(_esquema()["properties"])
        faltan = sorted(set(Policy.__dataclass_fields__) - props)
        self.assertEqual([], faltan,
                         f"campos de Policy que el esquema rechazaría: {faltan}")

    def test_lo_que_el_esquema_añade_es_metadato_de_cadena(self):
        """Y sólo eso: cualquier otra propiedad de más sería una restricción que el código no
        aplica, es decir, un contrato que promete lo que nadie cumple."""
        props = set(_esquema()["properties"])
        self.assertEqual({"extends", "extends_digest", "name"},
                         props - set(Policy.__dataclass_fields__))

    def test_la_descripcion_de_default_modes_no_contradice_su_regla(self):
        """Regresión de una contradicción real, no hipotética.

        `default_modes` estaba clasificado `PROPIO` y se reclasificó a `MODO` al medir que
        `adapters/claude.py` lo compila a `permissions.defaultMode`. El código y las pruebas se
        corrigieron; el esquema publicado siguió diciendo «PROPIO: no se hereda. No es una
        restricción de seguridad» — la afirmación exacta que la medición había falsado, viva en
        el único fichero que un integrador externo lee.

        Lo que se prohíbe aquí son las dos AFIRMACIONES que la medición falsó, no la palabra
        `PROPIO`: la descripción buena la menciona a propósito, para dejar constancia de que se
        creyó y se cayó. Borrar esa constancia es perder justo lo que evita volver a creerlo.
        """
        self.assertEqual(MODO, REGLAS["default_modes"], "premisa: la regla es MODO")
        desc = _esquema()["properties"]["default_modes"]["description"]
        self.assertIn("MODO", desc)
        for falsada in ("PROPIO: no se hereda", "No es una restricción de seguridad"):
            self.assertNotIn(falsada, desc,
                             f"el esquema vuelve a afirmar «{falsada}», que se midió falsa")


if __name__ == "__main__":
    unittest.main()
