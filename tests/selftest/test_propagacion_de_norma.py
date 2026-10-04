# -*- coding: utf-8 -*-
"""Qué de la norma del motor llega a un espacio ya instalado, y qué no.

La hipótesis que esto falsa a medias
------------------------------------
`init`/`install` escriben la norma ENTERA copiada y `upgrade` **no toca la política** por
diseño. De ahí se sigue, aparentemente, que ninguna corrección de la norma base llega a un
espacio ya instalado. Medido el 2026-09-24, y es falso en la mitad que más importa:

    `Policy.load` compone TODA política con la raíz del motor (`core.trust.componer_con_raiz`)
    y `protected_paths` ACUMULA → el efectivo es la UNIÓN.

Así que una protección NUEVA se propaga sola, sin `upgrade` y sin tocar el fichero del espacio.
Lo que no se propaga es la EXCEPCIÓN, y por la razón contraria: `writable_paths` es `REDUCE` y
la lista del hijo manda, así que un espacio que declaró la excepción anclada a la raíz se queda
con ella y **no se enfrentaba de nada**.

Estas pruebas fijan las dos mitades por separado. Juntarlas en una sola afirmación
—«la norma se propaga» o «no se propaga»— es exactamente el error que se cometió al razonarlo
sin medirlo, y el que costó una retractación.
"""

from __future__ import annotations

import json
import unittest
from pathlib import Path

from core.policy import DEFAULT_PROTECTED, DEFAULT_WRITABLE, Policy, decide_write
from tests.fixtures import Workspace

#: La política tal como la escribía el instalador ANTES de que los patrones cubrieran el
#: anidamiento. Se escribe literal a propósito: derivarla de las constantes de hoy haría que la
#: prueba se moviera con ellas y dejara de describir a ningún espacio real.
NORMA_ANTERIOR = {
    "schema": "harness.policy/v1",
    "version": "1",
    "protected_paths": [
        "verification/**", "verificacion/**", ".kiro/steering/**", ".harness/**",
        "inputs/**", "insumos/**", "evidence/**", "evidencia/**", "gates/**", "policies/**",
        "*.lock.json", "harness.manifest.json", "harness.lock.json",
    ],
    "writable_paths": [".harness/memory/**"],
}


class TestLaProteccionNuevaSePropagaSola(unittest.TestCase):
    """`ACUMULA` + composición con la raíz del motor ⟹ el efectivo es la unión."""

    def _cargar(self, ws):
        ruta = ws.json(".harness/policy.json", NORMA_ANTERIOR)
        return Policy.load(ruta)

    def test_un_espacio_con_la_norma_anterior_protege_los_repos_hijos(self):
        """Sin `upgrade`, sin tocar su fichero, y aunque su fichero no lo diga."""
        with Workspace("norma-anterior") as ws:
            pol = self._cargar(ws)
            for ruta in ("repo-hijo/.harness/bin/guard",
                         "repo-hijo/.harness/policy.json",
                         "repo-hijo/evidence/run.json",
                         "a/b/repo-nieto/gates/g.py"):
                with self.subTest(ruta=ruta):
                    self.assertEqual("deny", decide_write(pol, ws.root, ruta).outcome,
                                     "la protección del motor no llegó al espacio instalado")

    def test_y_el_fichero_del_espacio_NO_lo_declara(self):
        """La contraparte: sin esto, lo de arriba lo satisfaría un fichero ya corregido."""
        self.assertNotIn("**/.harness/**", NORMA_ANTERIOR["protected_paths"])
        with Workspace("norma-anterior-decl") as ws:
            escrito = json.loads((ws.json(".harness/policy.json", NORMA_ANTERIOR))
                                 .read_text(encoding="utf-8"))
            self.assertEqual(NORMA_ANTERIOR["protected_paths"], escrito["protected_paths"])

    def test_toda_proteccion_de_fabrica_acaba_cubierta(self):
        with Workspace("norma-anterior-todas") as ws:
            pol = self._cargar(ws)
            faltan = [p for p in DEFAULT_PROTECTED
                      if not pol.is_protected(p.removeprefix("**/").removesuffix("/**")
                                              .replace("*", "sonda"))]
            self.assertEqual([], faltan, f"no se propagaron: {faltan}")


class TestLaExcepcionNoSePropagaYSeDeclara(unittest.TestCase):
    """`REDUCE`: la lista del hijo manda, así que una excepción nueva NO le llega."""

    def test_los_repos_hijos_se_quedan_sin_memoria_de_agente(self):
        with Workspace("excepcion-vieja") as ws:
            pol = Policy.load(ws.json(".harness/policy.json", NORMA_ANTERIOR))
            self.assertEqual("allow", decide_write(pol, ws.root,
                                                   ".harness/memory/nota.md").outcome)
            self.assertEqual("deny", decide_write(pol, ws.root,
                                                  "repo-hijo/.harness/memory/nota.md").outcome,
                             "la excepción del motor se propagó, y `REDUCE` dice que no puede")

    def test_upgrade_lo_MIDE_y_lo_nombra(self):
        """Una denegación colateral que el dueño no pidió tiene que ser visible.

        No es un agujero —es más estricto, no menos— y precisamente por eso nada la señalaba: no
        rompe ninguna puerta, sólo impide callando que los repositorios hijos recuerden.
        """
        import refuto

        with Workspace("deriva-medida") as ws:
            ws.json(".harness/policy.json", NORMA_ANTERIOR)
            deriva = refuto._deriva_de_norma(ws.root)
            self.assertIn("**/.harness/memory/**", deriva,
                          f"la deriva real no se detectó; medido: {deriva}")

    def test_un_espacio_al_dia_no_declara_deriva(self):
        """Sin esta mitad, la de arriba se satisface declarando deriva siempre."""
        import refuto

        with Workspace("sin-deriva") as ws:
            ws.json(".harness/policy.json", Policy.default().to_dict())
            self.assertEqual([], refuto._deriva_de_norma(ws.root))

    def test_la_excepcion_de_fabrica_cubre_cualquier_profundidad(self):
        """La corrección que el espacio se está perdiendo, enunciada sobre la norma de hoy."""
        pol = Policy.default()
        self.assertEqual(("**/.harness/memory/**",), tuple(DEFAULT_WRITABLE))
        self.assertTrue(pol.is_writable("repo-hijo/.harness/memory/nota.md"))


class TestLaRetiradaTampocoSePropagaYSeDeclara(unittest.TestCase):
    """La tercera mitad, medida el 2026-10-03: lo que la norma RETIRA no se va del espacio.

    Es el mismo mecanismo que hace que una protección nueva llegue sola —`ACUMULA`, el efectivo
    es la unión— visto desde el otro lado: el fichero del espacio sigue declarando el patrón
    viejo y la unión lo mantiene vivo. No es un agujero (deniega más, no menos) y por eso nada
    lo señalaba; lo que hace es impedir callando trabajo legítimo.
    """

    def test_el_patron_retirado_sigue_denegando_segun_su_forma(self):
        """Cuánto bloqueo queda depende de la forma que copió el espacio, y no es lo mismo.

        Medido el 2026-10-03 sobre once espacios instalados: nueve declaran `policies/**`
        —anclado a la raíz, que es lo que escribía el instalador— y uno declara
        `**/policies/**`, porque su dueño lo parcheó a mano para cubrir el anidamiento. Con el
        motor ya acotado, el primero deja de bloquear el código del producto en profundidad y el
        segundo lo sigue bloqueando entero.
        """
        from core.policy import RETIRADAS_DE_NORMA

        self.assertIn("policies/**", RETIRADAS_DE_NORMA)
        self.assertIn("policies/**", NORMA_ANTERIOR["protected_paths"])
        casos = (("policies/**", "allow"), ("**/policies/**", "deny"))
        for patron, esperado in casos:
            with self.subTest(patron=patron), Workspace("residuo-forma") as ws:
                pol = Policy.load(ws.json(".harness/policy.json",
                                          {**NORMA_ANTERIOR,
                                           "protected_paths": [patron, ".harness/**"]}))
                self.assertEqual(esperado,
                                 decide_write(pol, ws.root,
                                              "security/policies/acceso.rego").outcome,
                                 f"{patron} no alcanza lo que se midió")
                # Las dos formas sobran igual: las dos siguen denegando en la raíz, que es
                # donde el espacio podría tener sus propias reglas de producto.
                self.assertEqual("deny",
                                 decide_write(pol, ws.root, "policies/reglas.rego").outcome)

    def test_y_la_norma_de_hoy_NO_lo_deniega(self):
        """La contraparte: si el motor también lo denegara, lo de arriba no mediría nada."""
        with Workspace("norma-de-hoy") as ws:
            for ruta in ("security/policies/acceso.rego", "policies/reglas.rego"):
                with self.subTest(ruta=ruta):
                    self.assertEqual("allow",
                                     decide_write(Policy.default(), ws.root, ruta).outcome)

    def test_upgrade_lo_MIDE_y_lo_nombra_como_residuo(self):
        import refuto

        with Workspace("residuo-medido") as ws:
            ws.json(".harness/policy.json", NORMA_ANTERIOR)
            residuo = refuto._residuo_de_norma(ws.root)
            self.assertEqual(["policies/**"], [p for p, _, _ in residuo],
                             f"el residuo real no se detectó; medido: {residuo}")
            self.assertTrue(all(m for _, m, _ in residuo),
                            "un patrón que sobra sin motivo no se puede decidir")
            self.assertEqual([str(ws.root / ".harness" / "policy.json")],
                             [f for _, _, f in residuo],
                             "sin decir qué fichero lo declara, «quítelo» no es una instrucción")

    def test_lo_encuentra_tambien_cuando_lo_declara_el_PADRE(self):
        """El hueco que tuvo la primera versión de este control, y cómo se encontró.

        Medido el 2026-10-03 sobre los espacios instalados: el único con herencia real de tres
        capas no declara `protected_paths` en su `.harness/policy.json` —lo declara el documento
        del padre— así que mirando sólo el fichero del espacio salía limpio teniendo el bloqueo
        completo. Un control que mide la capa equivocada dice «sin residuo» con la misma cara
        que uno que mide bien.
        """
        import refuto

        with Workspace("residuo-heredado") as ws:
            ws.json(".harness/base-policy.json",
                    {"schema": "harness.policy/v1", "name": "padre", "version": "1",
                     "protected_paths": ["**/policies/**", "**/.harness/**"]})
            ws.json(".harness/policy.json",
                    {"schema": "harness.policy/v1", "name": "hijo", "version": "1",
                     "extends": "base-policy.json"})
            residuo = refuto._residuo_de_norma(ws.root)
            self.assertEqual(["**/policies/**"], [p for p, _, _ in residuo],
                             f"el residuo del padre no se vio; medido: {residuo}")
            # Resuelto: `extends` se sigue con `resolve()`, y en macOS `/var` es un enlace a
            # `/private/var`. Comparar sin resolver haría fallar la prueba por el enlace del
            # sistema y no por el defecto.
            self.assertEqual([(ws.root / ".harness" / "base-policy.json").resolve()],
                             [Path(f).resolve() for _, _, f in residuo],
                             "señala el fichero del hijo, que no es donde se arregla")

    def test_un_espacio_al_dia_no_declara_residuo(self):
        """Sin esta mitad, la de arriba se satisface declarando residuo siempre."""
        import refuto

        with Workspace("sin-residuo") as ws:
            ws.json(".harness/policy.json", Policy.default().to_dict())
            self.assertEqual([], refuto._residuo_de_norma(ws.root))

    def test_el_residuo_NO_se_cuenta_como_deriva(self):
        """Las dos listas se arreglan al revés: una se añade, la otra se quita.

        Mezclarlas haría que la salida imprimiera «✗ falta» sobre un patrón que sobra.
        """
        import refuto

        with Workspace("residuo-no-es-deriva") as ws:
            ws.json(".harness/policy.json", NORMA_ANTERIOR)
            self.assertNotIn("policies/**", refuto._deriva_de_norma(ws.root))


if __name__ == "__main__":
    unittest.main()
