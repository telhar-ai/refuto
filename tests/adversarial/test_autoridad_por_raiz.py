# -*- coding: utf-8 -*-
"""`authority_paths`: gobierno por autoridad, no por nombre de directorio.

Qué mecanismo se prueba, y por qué hacía falta uno nuevo
-------------------------------------------------------
`protected_paths` compara contra la ruta relativa al ESPACIO. Por ese único vocabulario se
estaban forzando dos semánticas distintas, y las dos fallaban de forma medida:

    `**/policies/**`   de 61 directorios `policies/` clasificables en un espacio real, 46 eran
                       CÓDIGO y 15 gobierno: ~75 % de error. Y el espacio no podía retirarlo.
    `policies/**`      sólo la raíz, así que el documento de norma de cada repositorio hijo
                       quedaba reescribible (el agujero del 2026-09-24).

`authority_paths` compara contra la ruta relativa a cada RAÍZ DE AUTORIDAD que contenga al
objetivo —un directorio con `.harness/`, y la raíz del espacio siempre—. Eso expresa «el
artefacto de gobierno de un espacio» sin decir «cualquier cosa que se llame así».

Estas pruebas son adversariales: no comprueban que el camino bueno funcione (eso lo hace
`tests/unit/test_policy.py`), sino que el mecanismo **no se puede rodear**. Una familia por
cada vector, nombradas A..J para poder citarlas una a una en la evidencia.
"""

from __future__ import annotations

import os
import unittest
from pathlib import Path

from core.policy import (
    ALLOW,
    DEFAULT_AUTHORITY,
    DENY,
    Policy,
    decide_write,
    raices_de_autoridad,
)
from tests.fixtures import Workspace

#: Árbol mínimo que reproduce la confusión real: un espacio con un hijo gobernado, código
#: fuente en directorios llamados `policies/` y gobierno del producto en otro.
ARBOL = (
    ".harness",
    "policies",
    "repo-hijo/.harness",
    "repo-hijo/policies",
    "ai/praxis/packages/backend/src/kernel/mk/policies",
    "domain/governance/policies",
    "security/policies",
)


def _montar(ws) -> Policy:
    for d in ARBOL:
        (ws.root / d).mkdir(parents=True, exist_ok=True)
    return Policy.load(ws.json(".harness/policy.json",
                               {"schema": "harness.policy/v1", "name": "e", "version": "1"}))


class TestA_CodigoLegitimoSeEscribe(unittest.TestCase):
    """A · el código que sólo comparte el nombre del directorio NO está protegido."""

    def test_codigo_en_policies_anidado(self):
        with Workspace("aut-a") as ws:
            pol = _montar(ws)
            for ruta in ("ai/praxis/packages/backend/src/kernel/mk/policies/x.rs",
                         "domain/governance/policies/x.yaml",
                         "security/policies/acceso.rego",
                         "apps/web/policies/rate-limit.ts",
                         "a/b/c/d/e/policies/f.py"):
                with self.subTest(ruta=ruta):
                    d = decide_write(pol, ws.root, ruta)
                    self.assertEqual(ALLOW, d.outcome,
                                     f"código bloqueado por el nombre del directorio: {d.rule}")


class TestB_GobiernoNoSeEscribe(unittest.TestCase):
    """B · el artefacto de gobierno no se escribe, en la raíz del espacio o de un hijo."""

    def test_en_la_raiz_del_espacio_y_del_hijo(self):
        with Workspace("aut-b") as ws:
            pol = _montar(ws)
            for ruta in ("policies/base.json", "policies/reglas.rego", "policies/cualquiera.yaml",
                         "repo-hijo/policies/base.json", "repo-hijo/policies/sub/otro.json"):
                with self.subTest(ruta=ruta):
                    d = decide_write(pol, ws.root, ruta)
                    self.assertEqual(DENY, d.outcome, "artefacto de gobierno reescribible")
                    self.assertIn("policies", d.rule)

    def test_el_motivo_dice_en_que_raiz_se_anclo(self):
        """Sin eso, «denegado por policies/**» es indistinguible del patrón viejo."""
        with Workspace("aut-b2") as ws:
            pol = _montar(ws)
            self.assertIn("raíz del espacio",
                          decide_write(pol, ws.root, "policies/base.json").reason)
            self.assertIn("repo-hijo",
                          decide_write(pol, ws.root, "repo-hijo/policies/base.json").reason)


class TestC_CoincidenciaTextualNoConcedePermisos(unittest.TestCase):
    """C · ni de más ni de menos: el nombre no decide, la posición sí."""

    def test_nombres_vecinos_no_arrastran(self):
        with Workspace("aut-c") as ws:
            pol = _montar(ws)
            # Parecidos a la raíz de autoridad, pero NO son ella.
            for ruta, esperado in (("policies-de-rrhh/manual.md", ALLOW),
                                   ("mis-policies/x.json", ALLOW),
                                   ("policiesx/x.json", ALLOW),
                                   ("docs/policies.md", ALLOW),
                                   ("policies/x", DENY)):
                with self.subTest(ruta=ruta):
                    self.assertEqual(esperado, decide_write(pol, ws.root, ruta).outcome)


class TestD_TravesiaNoEscapa(unittest.TestCase):
    """D · `..` no saca la escritura del espacio ni cambia la raíz de anclaje."""

    def test_salir_del_espacio(self):
        with Workspace("aut-d") as ws:
            pol = _montar(ws)
            for ruta in ("../fuera.txt", "repo-hijo/../../fuera.txt",
                         "policies/../../fuera.txt", "a/../../../etc/hosts"):
                with self.subTest(ruta=ruta):
                    d = decide_write(pol, ws.root, ruta)
                    self.assertEqual(DENY, d.outcome)
                    self.assertEqual("fuera-del-espacio", d.rule)

    def test_volver_a_entrar_no_desancla(self):
        """`ai/../policies/base.json` resuelve a `policies/base.json` y se trata como tal."""
        with Workspace("aut-d2") as ws:
            pol = _montar(ws)
            d = decide_write(pol, ws.root, "ai/../policies/base.json")
            self.assertEqual(DENY, d.outcome)
            self.assertIn("policies", d.rule)

    def test_y_al_contrario_no_inventa_proteccion(self):
        """La contraparte: `policies/../ai/x.rs` resuelve a código y se permite."""
        with Workspace("aut-d3") as ws:
            pol = _montar(ws)
            self.assertEqual(ALLOW, decide_write(pol, ws.root, "policies/../ai/x.rs").outcome)


class TestE_EnlaceSimbolicoNoConvierte(unittest.TestCase):
    """E · un enlace no transforma una ruta permitida en acceso a una protegida, ni al revés."""

    def test_enlace_hacia_el_gobierno_se_deniega(self):
        with Workspace("aut-e") as ws:
            pol = _montar(ws)
            (ws.root / "atajo").symlink_to(ws.root / "policies")
            d = decide_write(pol, ws.root, "atajo/base.json")
            self.assertEqual(DENY, d.outcome,
                             "un enlace convirtió gobierno en escribible")
            self.assertIn("policies", d.rule)

    def test_enlace_que_sale_del_espacio_se_deniega(self):
        with Workspace("aut-e2") as ws:
            pol = _montar(ws)
            (ws.root / "fuga").symlink_to(Path(ws.home))
            d = decide_write(pol, ws.root, "fuga/robado.txt")
            self.assertEqual(DENY, d.outcome)
            self.assertEqual("fuera-del-espacio", d.rule)

    def test_un_marcador_de_autoridad_por_enlace_no_cuenta_de_menos(self):
        """`.harness` como ENLACE a un directorio sigue siendo raíz: `is_dir()` lo sigue.

        Importa que cuente: si no contara, mover el `.harness/` de un hijo a un enlace
        desprotegería su documento de norma.
        """
        with Workspace("aut-e3") as ws:
            pol = _montar(ws)
            real = ws.root / "otro-harness"; real.mkdir()
            hijo = ws.root / "hijo-enlazado"; (hijo / "policies").mkdir(parents=True)
            (hijo / ".harness").symlink_to(real)
            self.assertIn("hijo-enlazado",
                          raices_de_autoridad(ws.root.resolve(),
                                              (hijo / "policies" / "base.json").resolve()))
            self.assertEqual(DENY,
                             decide_write(pol, ws.root, "hijo-enlazado/policies/base.json").outcome)


class TestF_VariacionDeCaja(unittest.TestCase):
    """F · la caja no se usa para evadir, y se declara qué hace cada plataforma.

    `fnmatch.fnmatch` normaliza la caja en plataformas insensibles (macOS, Windows) y no lo hace
    en Linux. Eso NO es un defecto: en APFS `POLICIES/` y `policies/` son el MISMO directorio, y
    en ext4 son dos. Comparar sensible en macOS sería el agujero; comparar insensible en Linux
    protegería un directorio que no existe. La prueba afirma lo que corresponde a la plataforma
    donde corre, en vez de fijar una de las dos y fallar en la otra.
    """

    def test_caja_distinta(self):
        with Workspace("aut-f") as ws:
            pol = _montar(ws)
            d = decide_write(pol, ws.root, "POLICIES/base.json")
            insensible = os.path.normcase("A") == "a"
            if insensible:
                self.assertEqual(DENY, d.outcome,
                                 "en un sistema insensible a la caja es el MISMO directorio")
            else:
                self.assertEqual(ALLOW, d.outcome,
                                 "en un sistema sensible es OTRO directorio, y no es gobierno")

    def test_y_el_directorio_real_siempre_se_protege(self):
        with Workspace("aut-f2") as ws:
            pol = _montar(ws)
            self.assertEqual(DENY, decide_write(pol, ws.root, "policies/base.json").outcome)


class TestG_RutaRelativa(unittest.TestCase):
    """G · formas relativas equivalentes dan la misma decisión."""

    def test_formas_de_la_misma_ruta(self):
        with Workspace("aut-g") as ws:
            pol = _montar(ws)
            for ruta in ("policies/base.json", "./policies/base.json",
                         "policies//base.json", "./repo-hijo/./policies/base.json"):
                with self.subTest(ruta=ruta):
                    self.assertEqual(DENY, decide_write(pol, ws.root, ruta).outcome)


class TestH_RutaAbsoluta(unittest.TestCase):
    """H · una ruta absoluta no evade: se resuelve y se relativiza igual."""

    def test_absoluta_dentro_del_espacio(self):
        with Workspace("aut-h") as ws:
            pol = _montar(ws)
            self.assertEqual(DENY,
                             decide_write(pol, ws.root,
                                          str(ws.root / "policies" / "base.json")).outcome)
            self.assertEqual(DENY,
                             decide_write(pol, ws.root,
                                          str(ws.root / "repo-hijo/policies/base.json")).outcome)

    def test_absoluta_de_codigo_sigue_permitida(self):
        with Workspace("aut-h2") as ws:
            pol = _montar(ws)
            self.assertEqual(ALLOW, decide_write(
                pol, ws.root,
                str(ws.root / "ai/praxis/packages/backend/src/kernel/mk/policies/x.rs")).outcome)

    def test_absoluta_fuera_del_espacio(self):
        with Workspace("aut-h3") as ws:
            pol = _montar(ws)
            d = decide_write(pol, ws.root, "/etc/hosts")
            self.assertEqual(DENY, d.outcome)
            self.assertEqual("fuera-del-espacio", d.rule)


class TestI_FronteraDeEspacioAnidado(unittest.TestCase):
    """I · un espacio anidado no rompe la frontera: añade autoridad, no la quita."""

    def test_plantar_una_raiz_no_desprotege(self):
        """El vector que decidió el diseño: evaluar en TODAS las raíces, no en la más cercana.

        Con «la más cercana», crear `policies/.harness/` haría que la ruta relativa de
        `policies/base.json` fuera `base.json`, que no casa con `policies/**`. Es decir, el
        gobierno se desprotegería plantando un directorio.
        """
        with Workspace("aut-i") as ws:
            pol = _montar(ws)
            antes = decide_write(pol, ws.root, "policies/base.json")
            self.assertEqual(DENY, antes.outcome)
            (ws.root / "policies" / ".harness").mkdir(parents=True, exist_ok=True)
            despues = decide_write(pol, ws.root, "policies/base.json")
            self.assertEqual(DENY, despues.outcome,
                             "plantar una raíz de autoridad desprotegió el gobierno")

    def test_un_hijo_gobernado_añade_autoridad(self):
        with Workspace("aut-i2") as ws:
            pol = _montar(ws)
            self.assertEqual(ALLOW, decide_write(pol, ws.root, "nuevo/policies/x.json").outcome)
            (ws.root / "nuevo" / ".harness").mkdir(parents=True, exist_ok=True)
            self.assertEqual(DENY, decide_write(pol, ws.root, "nuevo/policies/x.json").outcome,
                             "un espacio gobernado nuevo no protegió su propio gobierno")

    def test_el_objetivo_no_es_su_propia_raiz(self):
        """Si lo fuera, la ruta relativa quedaría vacía y nada casaría nunca."""
        with Workspace("aut-i3") as ws:
            _montar(ws)
            r = raices_de_autoridad(ws.root.resolve(), (ws.root / "repo-hijo").resolve())
            self.assertNotIn("repo-hijo", r)


class TestJ_UnaPoliticaLocalNoAnulaLaSuperior(unittest.TestCase):
    """J · el hijo no puede retirar `authority_paths`, ni vaciándolo ni redeclarándolo."""

    def test_vaciarlo_es_inexpresable(self):
        with Workspace("aut-j") as ws:
            for d in ARBOL:
                (ws.root / d).mkdir(parents=True, exist_ok=True)
            pol = Policy.load(ws.json(".harness/policy.json",
                                      {"schema": "harness.policy/v1", "name": "e",
                                       "version": "1", "authority_paths": []}))
            self.assertEqual(DENY, decide_write(pol, ws.root, "policies/base.json").outcome,
                             "vaciar el campo retiró la protección: ACUMULA no se aplicó")

    def test_redeclararlo_mas_estrecho_tampoco(self):
        with Workspace("aut-j2") as ws:
            for d in ARBOL:
                (ws.root / d).mkdir(parents=True, exist_ok=True)
            pol = Policy.load(ws.json(".harness/policy.json",
                                      {"schema": "harness.policy/v1", "name": "e",
                                       "version": "1",
                                       "authority_paths": ["solo-esto/**"]}))
            self.assertEqual(DENY, decide_write(pol, ws.root, "policies/base.json").outcome)
            self.assertEqual(["policies/**", "solo-esto/**"], sorted(pol.authority_paths))

    def test_pero_añadir_los_suyos_si_funciona_y_se_hereda(self):
        """La dirección reparable: un cliente declara SU gobierno y el proyecto no lo retira."""
        with Workspace("aut-j3") as ws:
            for d in ARBOL + ("gobierno", "repo-hijo/gobierno"):
                (ws.root / d).mkdir(parents=True, exist_ok=True)
            ws.json(".harness/base-policy.json",
                    {"schema": "harness.policy/v1", "name": "cliente", "version": "1",
                     "authority_paths": ["gobierno/**"]})
            pol = Policy.load(ws.json(".harness/policy.json",
                                      {"schema": "harness.policy/v1", "name": "proyecto",
                                       "version": "1", "extends": "base-policy.json"}))
            self.assertEqual(DENY, decide_write(pol, ws.root, "gobierno/norma.md").outcome)
            self.assertEqual(DENY,
                             decide_write(pol, ws.root, "repo-hijo/gobierno/norma.md").outcome,
                             "lo declarado por el cliente no alcanzó al repositorio hijo")
            self.assertEqual(DENY, decide_write(pol, ws.root, "policies/base.json").outcome,
                             "declarar lo propio retiró lo heredado del motor")


class TestElMecanismoNoEsVacuo(unittest.TestCase):
    """Un ámbito vacío nunca aprueba, y un mecanismo sin patrones no prueba nada."""

    def test_hay_patrones_de_autoridad_de_fabrica(self):
        self.assertGreaterEqual(len(DEFAULT_AUTHORITY), 1)
        self.assertIn("policies/**", DEFAULT_AUTHORITY)

    def test_y_la_decision_depende_de_ellos(self):
        """Sin esto, todas las pruebas de arriba pasarían con `protected_paths` haciendo el trabajo."""
        with Workspace("aut-no-vacuo") as ws:
            for d in ARBOL:
                (ws.root / d).mkdir(parents=True, exist_ok=True)
            pol = Policy.load(ws.json(".harness/policy.json",
                                      {"schema": "harness.policy/v1", "name": "e",
                                       "version": "1"}))
            self.assertEqual(DENY, decide_write(pol, ws.root, "policies/base.json").outcome)
            sin = Policy(protected_paths=tuple(pol.protected_paths), authority_paths=())
            self.assertEqual(ALLOW, decide_write(sin, ws.root, "policies/base.json").outcome,
                             "lo deniega otro mecanismo: esta suite no mide `authority_paths`")

    def test_el_patron_de_arbol_entero_no_vuelve(self):
        from core.policy import DEFAULT_PROTECTED
        self.assertNotIn("**/policies/**", DEFAULT_PROTECTED)
        self.assertNotIn("**/policies/base.json", DEFAULT_PROTECTED)


if __name__ == "__main__":
    unittest.main()
