# -*- coding: utf-8 -*-
"""Lo que el arnés escribe para vigilar al agente, el agente no lo puede reescribir.

El defecto que esto fija
------------------------
`DEFAULT_PROTECTED` enumeraba a mano los directorios de configuración de los runtimes:
`.claude`, `.agents`, `.kiro`, `.codex`. Los runtimes que el producto soporta son más, y la
lista no se movió con ellos. Medido el 2026-10-03 derivando los artefactos de `compile_policy`
de cada adaptador y pasándolos por `decide_write` con la política de fábrica, **3 de 7 salían
`allow`**:

    .gemini/hooks/harness-guard.json   allow   ← el fichero que INSTALA el guardián
    .aidlc/verification-bridge.json    allow   ← qué puertas exige cada etapa
    opencode.harness.json              allow   ← la política compilada de opencode

El primero es el caso puro: un agente que puede reescribir el gancho que lo vigila no está
vigilado, y la política declaraba —en el informe de sesión, patrón a patrón— que sí.

Por qué esta prueba DERIVA la tabla en vez de escribirla
--------------------------------------------------------
Repetir la lista a mano es exactamente cómo divergió. Una prueba que enumerase las siete rutas
envejecería igual que la constante: el adaptador número ocho entraría con su ruta nueva y nadie
se enteraría. Aquí el sujeto lo declara el propio adaptador, así que un adaptador que escriba
donde no se protege deja la suite en rojo sin que nadie actualice nada.

El coste de derivar es que el sujeto puede vaciarse —si `all_specs()` devolviera `[]`, o si
ningún adaptador compilara política, no habría nada que comprobar y la prueba pasaría—. Un
ámbito vacío no aprueba: se comprueba aparte y es la primera prueba del fichero.
"""

from __future__ import annotations

import unittest

from adapters.registry import all_specs
from core.policy import DEFAULT_PROTECTED, RUTA_BASE, Policy, decide_write
from tests.fixtures import Workspace


def _artefactos() -> list:
    """`[(runtime, ruta)]` de todo lo que un adaptador escribe al compilar la política."""
    pol = Policy.default()
    pares = []
    for spec in all_specs():
        compilado = spec.compile_policy(pol) or {}
        for ruta in (compilado.get("artifacts") or {}):
            pares.append((spec.name, ruta))
    return pares


class TestElSujetoNoEstaVacio(unittest.TestCase):
    """Un ámbito vacío nunca aprueba, y menos el de un control derivado."""

    def test_hay_adaptadores_y_compilan_artefactos(self):
        self.assertGreaterEqual(len(all_specs()), 5, "el registro de adaptadores está vacío")
        arts = _artefactos()
        self.assertGreaterEqual(len(arts), 5,
                                f"sin artefactos no hay nada que proteger: {arts}")
        runtimes = {n for n, _ in arts}
        self.assertGreaterEqual(len(runtimes), 4,
                                f"sólo un runtime compila política: {sorted(runtimes)}")


class TestTodoArtefactoDelGuardianEstaProtegido(unittest.TestCase):
    """La propiedad, sobre la política de fábrica y sobre un espacio real."""

    def test_la_politica_de_fabrica_los_protege_todos(self):
        pol = Policy.default()
        escribibles = [(n, r) for n, r in _artefactos() if not pol.is_protected(r)]
        self.assertEqual([], escribibles,
                         f"el arnés escribe lo que el agente puede reescribir: {escribibles}")

    def test_el_guardian_los_deniega_en_un_espacio_instalado(self):
        """`is_protected` es el patrón; `decide_write` es la decisión que se toma de verdad."""
        with Workspace("artefactos-guardian") as ws:
            pol = Policy.load(ws.json(".harness/policy.json",
                                      {"schema": "harness.policy/v1", "name": "e",
                                       "version": "1"}))
            for runtime, ruta in _artefactos():
                with self.subTest(runtime=runtime, ruta=ruta):
                    d = decide_write(pol, ws.root, ruta)
                    self.assertEqual("deny", d.outcome,
                                     f"{runtime} escribe {ruta} y el guardián lo permite")

    def test_tambien_en_un_repositorio_hijo(self):
        """El defecto del 2026-09-24: sin `**/` la protección sólo cubría la raíz."""
        with Workspace("artefactos-hijo") as ws:
            pol = Policy.load(ws.json(".harness/policy.json",
                                      {"schema": "harness.policy/v1", "name": "e",
                                       "version": "1"}))
            for runtime, ruta in _artefactos():
                with self.subTest(runtime=runtime, ruta=ruta):
                    d = decide_write(pol, ws.root, f"repo-hijo/{ruta}")
                    self.assertEqual("deny", d.outcome,
                                     f"el artefacto de {runtime} del hijo es reescribible")


class TestLaNormaProtegeElDocumentoYNoElArbol(unittest.TestCase):
    """`policies/**` → `policies/base.json`: la otra mitad del mismo cambio.

    Sin esta clase el arreglo se podría revertir ampliando el patrón otra vez, y las pruebas de
    arriba seguirían en verde: `**/policies/**` también protege `.gemini/policies/harness.json`.
    """

    def setUp(self):
        self.pol = Policy.default()

    def test_el_documento_de_norma_esta_protegido_en_cada_raiz_de_autoridad(self):
        """Ya NO por `protected_paths`: lo cubre `authority_paths`, que es otro mecanismo.

        Esta prueba cambió el 2026-10-03 con el mecanismo, y el cambio es el hallazgo: pedirle a
        `is_protected` que cubra el documento de norma era pedirle que globeara `policies/` por
        todo el árbol, que es el defecto. Ahora se pregunta a quién corresponde.
        """
        self.assertFalse(self.pol.is_protected(RUTA_BASE),
                         "sigue en `protected_paths`: volvería el sobre-bloqueo por nombre")
        patron, raiz = self.pol.is_authority(RUTA_BASE, ("",))
        self.assertTrue(patron, "el documento de norma no es artefacto de autoridad")
        self.assertEqual("", raiz)
        patron_h, raiz_h = self.pol.is_authority(f"repo-hijo/{RUTA_BASE}", ("", "repo-hijo"))
        self.assertTrue(patron_h, "el documento de norma de un hijo gobernado quedó libre")
        self.assertEqual("repo-hijo", raiz_h)

    def test_el_codigo_del_producto_bajo_policies_NO_esta_protegido(self):
        """El sobre-bloqueo medido: reglas del producto en un directorio `policies/`."""
        for ruta in ("security/policies/acceso.rego",
                     "apps/web/policies/rate-limit.ts",
                     "infra/policies/iam.tf",
                     "policies/README.md"):
            with self.subTest(ruta=ruta):
                self.assertFalse(self.pol.is_protected(ruta),
                                 f"{ruta} es código del producto y la norma lo deniega")

    def test_el_patron_de_arbol_entero_no_vuelve(self):
        self.assertNotIn("**/policies/**", DEFAULT_PROTECTED)
        self.assertNotIn("policies/**", DEFAULT_PROTECTED)

    def test_la_politica_compilada_de_gemini_no_depende_de_ese_patron(self):
        """Estaba protegida por accidente: coincidía con `policies/**`.

        Acotar el patrón sin cubrirla por su propio motivo habría convertido una protección
        incidental en un agujero, y nada lo habría dicho.
        """
        self.assertTrue(self.pol.is_protected(".gemini/policies/harness.json"))
        self.assertTrue(self.pol.is_protected("repo-hijo/.gemini/policies/harness.json"))


class TestPorQueElErrorReparableEsElCorrecto(unittest.TestCase):
    """La razón del acotamiento, como prueba: el espacio no puede retirar lo que sobra.

    Esto no prueba el arreglo: prueba el COSTE de equivocarse en la dirección contraria, que es
    lo que hace que «ante la duda, protege más» sea falso en esta herramienta.
    """

    def test_un_espacio_no_puede_declarar_la_excepcion_que_lo_desbloquearia(self):
        from core.policy import PoliticaIlegible

        with Workspace("excepcion-imposible") as ws:
            ruta = ws.json(".harness/policy.json",
                           {"schema": "harness.policy/v1", "name": "e", "version": "1",
                            "writable_paths": ["**/.harness/memory/**",
                                               "**/security/policies/**"]})
            with self.assertRaises(PoliticaIlegible) as caja:
                Policy.load(ruta)
            self.assertIn("writable_paths", str(caja.exception))

    def test_y_redeclarar_la_proteccion_sin_el_patron_no_la_retira(self):
        """`ACUMULA`: el efectivo es la unión, así que quitar es inexpresable."""
        with Workspace("retirada-inexpresable") as ws:
            pol = Policy.load(ws.json(".harness/policy.json",
                                      {"schema": "harness.policy/v1", "name": "e",
                                       "version": "1",
                                       "protected_paths": ["**/sólo-esto/**"]}))
            self.assertTrue(pol.is_protected(".harness/policy.json"),
                            "la protección del motor se pudo retirar desde el espacio")

    def test_pero_anadir_proteccion_propia_si_funciona(self):
        """La dirección reparable: un espacio con más norma en `policies/` la declara él."""
        with Workspace("anadir-proteccion") as ws:
            pol = Policy.load(ws.json(".harness/policy.json",
                                      {"schema": "harness.policy/v1", "name": "e",
                                       "version": "1",
                                       "protected_paths": ["**/policies/**"]}))
            self.assertEqual("deny",
                             decide_write(pol, ws.root, "policies/example-org.json").outcome)


if __name__ == "__main__":
    unittest.main()
