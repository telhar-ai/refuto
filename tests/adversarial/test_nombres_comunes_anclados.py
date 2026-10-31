# -*- coding: utf-8 -*-
"""Las palabras COMUNES de gobierno, ancladas: `evidence`, `gates`, `inputs`, `verification`.

Qué defecto fija esta familia
-----------------------------
`policies/**` se acotó el 2026-10-03 porque `**/policies/**` protegía el código del producto
para cubrir un documento de norma. Las otras seis palabras se quedaron con `**/`, y son la
misma clase de error: nombres que el producto usa para su propio código.

Medido en un espacio multi-repo real sobre el DIARIO del guardián —lo que el agente intentó
escribir de verdad, no un censo de directorios—: de 4 denegaciones por `**/evidence/**`, **3
eran código fuente** (`<repo>/src/lib/evidence/`, `<repo>/src/modules/evidence/`, un esquema de
contrato) y 1 era gobierno. ~75 % de error, la misma proporción que midió `policies/**`.

El caso concreto: un módulo del producto cuyo DOMINIO es la evidencia —un servicio de anclaje
Merkle— quedaba entero fuera del alcance del agente, incluidos los ficheros que ya existían. Y
el espacio no podía repararlo: retirar el patrón es inexpresable (`ACUMULA` une), y la excepción
que lo compensaría es `REDUCE` y levanta `HerenciaIrresoluble`, con lo que el guardián deniega
TODO.

Por qué el arreglo no es sólo mover los patrones
-------------------------------------------------
Anclar a la raíz de autoridad, por sí solo, habría desprotegido el gobierno ANIDADO del modelo
SDD —`sdd/espacios/<nombre>/{evidencia,insumos,verificacion}/`—, que no está en la raíz de
ningún espacio salvo que ese repositorio traiga su propio `.harness/`. Así que el cambio tiene
dos mitades y las dos se prueban aquí:

    palabra SUELTA   ->  `authority_paths`: la raíz de cada espacio gobernado
    FORMA de ruta    ->  `protected_paths` con `**/`: cuatro segmentos no colisionan con código

Son adversariales: no comprueban que el camino bueno funcione, sino que el mecanismo no se
puede rodear y que lo que se retiró quedó NOMBRADO.
"""

from __future__ import annotations

import unittest

from core.policy import (
    ALLOW,
    DEFAULT_AUTHORITY,
    DEFAULT_PROTECTED,
    DENY,
    RETIRADAS_DE_NORMA,
    Policy,
    decide_write,
)
from tests.fixtures import Workspace

#: Las seis palabras que se anclaron el 2026-10-05, más `policies` que se ancló antes.
PALABRAS = ("evidence", "evidencia", "inputs", "insumos", "gates",
            "verification", "verificacion")

#: Árbol que reproduce la confusión real: código del producto en directorios con esos nombres,
#: gobierno en la raíz, un repositorio hijo gobernado, y gobierno anidado con forma SDD.
ARBOL = (
    ".harness",
    "evidence", "evidencia", "inputs", "insumos", "gates",
    "verification", "verificacion",
    "repo-hijo/.harness", "repo-hijo/evidence", "repo-hijo/gates",
    "security/servicio/src/lib/evidence",
    "security/servicio/src/modules/evidence",
    "security/servicio/tests/unit/evidence",
    "labs/probatio/packages/evidence",
    "platform/mcp/servers/evidence",
    "apps/web/src/gates",
    "core/gateway/src/verification",
    "packages/api/src/inputs",
    "domain/pricing/insumos",
    "ai/mneme/sdd/espacios/memoria/evidencia",
    "core/sso/sdd/espacios/admision/insumos",
    "product/panel/sdd/espacios/frontera/verificacion",
)


def _montar(ws) -> Policy:
    for d in ARBOL:
        (ws.root / d).mkdir(parents=True, exist_ok=True)
    return Policy.load(ws.json(".harness/policy.json",
                               {"schema": "harness.policy/v1", "name": "e", "version": "1"}))


class TestA_ElCodigoDelProductoSeEscribe(unittest.TestCase):
    """A · el código que sólo comparte el NOMBRE del directorio no está protegido."""

    RUTAS = (
        "security/servicio/src/lib/evidence/leaf-order.ts",
        "security/servicio/src/modules/evidence/service.ts",
        "security/servicio/tests/unit/evidence/orden.test.ts",
        "labs/probatio/packages/evidence/index.ts",
        "platform/mcp/servers/evidence/server.ts",
        "apps/web/src/gates/feature-flag.ts",
        "core/gateway/src/verification/jwt.ts",
        "packages/api/src/inputs/schema.ts",
        "domain/pricing/insumos/tabla.ts",
    )

    def test_codigo_con_nombre_de_gobierno(self):
        with Workspace("nca-a") as ws:
            pol = _montar(ws)
            for ruta in self.RUTAS:
                with self.subTest(ruta=ruta):
                    d = decide_write(pol, ws.root, ruta)
                    self.assertEqual(d.outcome, ALLOW,
                                     f"«{ruta}» se denegó por «{d.rule}»: es código del producto")


class TestB_ElGobiernoDeLaRaizSigueProtegido(unittest.TestCase):
    """B · lo que se anclaba a la raíz de un espacio gobernado no se abrió."""

    def test_raiz_del_espacio(self):
        with Workspace("nca-b") as ws:
            pol = _montar(ws)
            for palabra in PALABRAS:
                with self.subTest(palabra=palabra):
                    d = decide_write(pol, ws.root, f"{palabra}/informe.md")
                    self.assertEqual(d.outcome, DENY, f"«{palabra}/» quedó sin proteger")

    def test_raiz_de_un_repositorio_hijo_gobernado(self):
        """El agujero del 2026-09-24 no vuelve: el hijo con `.harness/` es raíz de autoridad."""
        with Workspace("nca-b2") as ws:
            pol = _montar(ws)
            for ruta in ("repo-hijo/evidence/informe.md", "repo-hijo/gates/puerta.py"):
                with self.subTest(ruta=ruta):
                    d = decide_write(pol, ws.root, ruta)
                    self.assertEqual(d.outcome, DENY, f"«{ruta}» quedó sin proteger")


class TestC_ElGobiernoAnidadoPorFormaDeRuta(unittest.TestCase):
    """C · la forma SDD sigue protegida a cualquier profundidad, aunque su repositorio NO sea
    raíz de autoridad."""

    RUTAS = (
        "ai/mneme/sdd/espacios/memoria/evidencia/medicion.md",
        "core/sso/sdd/espacios/admision/insumos/cliente.pdf",
        "product/panel/sdd/espacios/frontera/verificacion/matriz.md",
    )

    def test_forma_sdd_a_cualquier_profundidad(self):
        with Workspace("nca-c") as ws:
            pol = _montar(ws)
            for ruta in self.RUTAS:
                with self.subTest(ruta=ruta):
                    d = decide_write(pol, ws.root, ruta)
                    self.assertEqual(d.outcome, DENY, f"«{ruta}» quedó sin proteger")


class TestD_PlantarUnaRaizNoDesprotege(unittest.TestCase):
    """D · la monotonía del mecanismo, aplicada a las palabras nuevas."""

    def test_plantar_harness_dentro_no_abre_nada(self):
        with Workspace("nca-d") as ws:
            pol = _montar(ws)
            (ws.root / "evidence" / ".harness").mkdir(parents=True, exist_ok=True)
            d = decide_write(pol, ws.root, "evidence/informe.md")
            self.assertEqual(d.outcome, DENY,
                             "plantar una raíz más profunda desprotegió el gobierno")


class TestE_LoRetiradoQuedaNombrado(unittest.TestCase):
    """E · el residuo es medible, que es lo que `refuto upgrade` necesita."""

    def test_cada_palabra_retirada_esta_registrada(self):
        for palabra in PALABRAS:
            with self.subTest(palabra=palabra):
                self.assertIn(f"{palabra}/**", RETIRADAS_DE_NORMA,
                              f"«{palabra}/**» se retiró sin registrar el motivo: "
                              f"`refuto upgrade` no podrá nombrar el residuo")
                self.assertTrue(RETIRADAS_DE_NORMA[f"{palabra}/**"].strip(),
                                "la retirada está registrada con motivo vacío")

    def test_ninguna_palabra_suelta_sigue_globeada_en_protected(self):
        """El control que impide reintroducir el defecto al añadir una palabra nueva."""
        for palabra in PALABRAS + ("policies",):
            with self.subTest(palabra=palabra):
                self.assertNotIn(f"**/{palabra}/**", DEFAULT_PROTECTED,
                                 f"«**/{palabra}/**» volvió a `protected_paths`: eso protege el "
                                 f"código del producto y el espacio no puede retirarlo")

    def test_cada_palabra_retirada_esta_anclada(self):
        """Retirar sin anclar sería abrir el gobierno, no acotarlo."""
        for palabra in PALABRAS:
            with self.subTest(palabra=palabra):
                self.assertIn(f"{palabra}/**", DEFAULT_AUTHORITY,
                              f"«{palabra}/**» se retiró de `protected_paths` y no se ancló en "
                              f"`authority_paths`: el gobierno de la raíz quedó abierto")


class TestF_LaExcepcionNoAlcanzaElArnes(unittest.TestCase):
    """F · control negativo: abrir las palabras comunes no abre lo que el arnés reserva."""

    RUTAS = (
        ".harness/policy.json",
        ".harness/evidence/ledger.jsonl",
        "repo-hijo/.harness/policy.json",
        "security/servicio/src/lib/evidence/.harness/policy.json",
    )

    def test_el_arnes_sigue_cerrado(self):
        with Workspace("nca-f") as ws:
            pol = _montar(ws)
            for ruta in self.RUTAS:
                with self.subTest(ruta=ruta):
                    (ws.root / ruta).parent.mkdir(parents=True, exist_ok=True)
                    d = decide_write(pol, ws.root, ruta)
                    self.assertEqual(d.outcome, DENY, f"«{ruta}» quedó escribible")


if __name__ == "__main__":
    unittest.main()
