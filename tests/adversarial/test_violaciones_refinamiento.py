# -*- coding: utf-8 -*-
"""Las violaciones que el refinamiento tenía, y que ahora no puede tener.

Cinco encontradas el 2026-09-23 auditando la implementación recién hecha. Tres se cierran
aquí; dos quedan **declaradas y abiertas** por decisión, no por olvido — ver el final.

Lo que estas pruebas tienen de distinto
---------------------------------------
Las de `test_monotonia.py` atacan declarando campos en padre e hijo. **Todas pasaban** con el
código defectuoso, porque el agujero estaba justo en lo que ninguna escribía: **el campo que
el padre NO declara**. Un ataque sólo prueba lo que toca, y diez ataques que comparten el
mismo punto ciego no son diez pruebas.
"""

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from core.policy import (DEFAULT_COMMAND_DENY, HerenciaIrresoluble, Policy, decide_command)
from core.refinement import MODO, ORDEN_MODOS, REGLAS

PADRE_CALLA = {"schema": "harness.policy/v1", "name": "cliente", "version": "1",
               "protected_paths": ["del-cliente/**"]}


def _montar(hijo: dict, padre: dict = PADRE_CALLA) -> Path:
    d = Path(tempfile.mkdtemp())
    (d / ".harness").mkdir()
    (d / ".harness" / "cliente.json").write_text(json.dumps(padre), encoding="utf-8",
                                                 newline="\n")
    (d / ".harness" / "policy.json").write_text(json.dumps(hijo), encoding="utf-8",
                                                newline="\n")
    return d / ".harness" / "policy.json"


def _hijo(**campos) -> dict:
    return {"schema": "harness.policy/v1", "name": "proyecto", "version": "1",
            "extends": "cliente.json", **campos}


class TestElPadreAportaLoQueAPLICA_noLoQueESCRIBE(unittest.TestCase):
    """V1 y V6. El refinamiento comparaba documentos crudos.

    Los valores de fábrica sólo se materializan cuando `Policy.from_dict` rellena un campo
    AUSENTE, así que un padre que no los escribía aportaba el conjunto vacío a la unión. Medido
    antes del arreglo: hijo con una orden denegada → efectivo **1** entrada, y `rm -rf /` y
    `sudo` salían `allow`.

    El agujero NO lo introduce el refinamiento —un hijo sin `extends` que declara una lista
    corta pierde igual las 16—: lo aporta `from_dict`, donde declarar un campo lo sustituye.
    Lo que la herencia añade es convertirlo en el camino por defecto, porque el propósito de un
    hijo es declarar sólo lo suyo.
    """

    def test_el_hijo_no_puede_descartar_las_denegaciones_de_fabrica(self):
        pol = Policy.load(_montar(_hijo(command_deny=["mia:*"])))
        self.assertGreaterEqual(
            len(pol.command_deny), len(DEFAULT_COMMAND_DENY),
            "el hijo descartó las órdenes denegadas de fábrica declarando una lista corta")
        for peligrosa in ("rm -rf /", "sudo algo"):
            self.assertEqual("deny", decide_command(pol, peligrosa).outcome,
                             f"«{peligrosa}» pasó a permitida al heredar")
        self.assertEqual("deny", decide_command(pol, "mia x").outcome,
                         "lo que el hijo añade tiene que seguir aplicándose")

    def test_la_CIMA_de_la_cadena_YA_NO_puede_vaciar_un_campo(self):
        """V6, **cerrada el 2026-09-23**. Esta prueba estaba invertida y decía por qué.

        Lo que decía la versión anterior, literalmente: «lo cerraría un `policies/base.json`
        versionado —con `refuto` como capa 1 de verdad—, no un parche aquí. Esta prueba fija
        el comportamiento actual: si alguien lo cambia sin crear esa capa, cae y obliga a
        explicar por qué.»

        La explicación. La capa 1 existe ahora, y no es un fichero en disco: es la LÍNEA BASE
        DEL MOTOR (`core.trust.documento_raiz`), derivada de `Policy.default()` y compuesta
        como padre implícito de toda cadena. Se eligió componer y no validar porque en los
        campos `ACUMULA` el efectivo es la unión, y entonces vaciar `command_deny` deja de ser
        una violación que haya que cazar para convertirse en algo que **no se puede escribir**
        — la misma tesis que este módulo ya defendía para las aristas.

        Un fichero en disco habría sido peor: es material y, por tanto, editable por quien
        pueda escribir en el árbol. La norma raíz viaja con el código.
        """
        pol = Policy.load(_montar(_hijo(), {**PADRE_CALLA, "command_deny": []}))
        self.assertEqual("deny", decide_command(pol, "rm -rf /").outcome,
                         "la cima vació `command_deny` y el efectivo se lo permitió: la "
                         "composición con la raíz del motor no está actuando")
        self.assertIn("sudo:*", pol.command_deny,
                      "las órdenes denegadas de fábrica tienen que sobrevivir a una cima "
                      "que declara la lista vacía")


class TestEndureceNoSeBurlaPorOmision(unittest.TestCase):
    """V7 — no estaba en la lista y es la peor de la familia.

    El padre no escribe `block_secret_content` (de fábrica `True`); el hijo lo pone a `False`.
    Antes: la cadena resolvía **sin violación** y la detección de secretos quedaba apagada. El
    invariante que `core/refinement.py` declara en su propio docstring, falsado por una
    omisión — sin malicia y sin nada que lo reportara.
    """

    def test_apagar_una_comprobacion_que_el_padre_no_escribe_se_rechaza(self):
        self.assertTrue(Policy.default().block_secret_content,
                        "premisa: de fábrica la detección está encendida")
        with self.assertRaises(HerenciaIrresoluble) as cm:
            Policy.load(_montar(_hijo(block_secret_content=False)))
        self.assertIn("block_secret_content", str(cm.exception))

    def test_un_PADRE_que_la_apaga_tampoco_vale_aunque_el_hijo_la_encienda(self):
        """La otra mitad, reescrita el 2026-09-23 al cerrarse V6.

        Antes se comprobaba que un hijo pudiera ENCENDER lo que su padre apagaba, y el
        efectivo salía `True`. Ese escenario ya no se puede construir: con la línea base del
        motor como padre implícito, el documento del PADRE es él mismo un hijo de la raíz, y
        apagar un endurecimiento de fábrica lo invalida — lo rescate el nieto o no.

        Se rechaza en vez de absorberlo en silencio a propósito. Bajo semántica de `meet`
        puro el efectivo sería `True` igualmente y no haría falta decir nada; pero entonces el
        documento diría una cosa y el sistema haría otra, que es exactamente la situación de
        «dos políticas» que este módulo existe para impedir. Un documento que declara algo que
        no se puede honrar se arregla, no se interpreta.
        """
        with self.assertRaises(HerenciaIrresoluble) as cm:
            Policy.load(_montar(_hijo(block_secret_content=True),
                                {**PADRE_CALLA, "block_secret_content": False}))
        self.assertIn("block_secret_content", str(cm.exception))

    def test_endurecer_desde_la_linea_base_SIGUE_permitido(self):
        """Sin esta mitad, la prueba de arriba se satisface rechazando toda política."""
        pol = Policy.load(_montar(_hijo(protected_paths=["del-proyecto/**"]),
                                  {**PADRE_CALLA, "block_secret_content": True}))
        self.assertTrue(pol.block_secret_content)
        self.assertIn("del-proyecto/**", pol.protected_paths)
        self.assertIn("del-cliente/**", pol.protected_paths)
        self.assertTrue(pol.is_protected("gates/g_agent.py"))


class TestElModoDelGuardianEsUnaRestriccion(unittest.TestCase):
    """V5. `default_modes` estaba clasificado como `PROPIO` — «no es seguridad sino
    interacción». Falsado midiendo: `adapters/claude.py` lo compila a
    `permissions.defaultMode`, así que un hijo podía pasar de `ask` a `bypassPermissions`.

    Matiz que la medición dio y que no se pierde: **NO está comprobado** que
    `bypassPermissions` anule el gancho `PreToolUse`. Eso es comportamiento de Claude Code y
    aquí está `NOT_RUN`. La reclasificación procede igual — lo que no se puede afirmar no se
    concede — pero el titular «apaga la consulta a la persona» sería más de lo que se midió.
    """

    def _con_modos(self, padre_modo, hijo_modo, runtime="claude"):
        return _montar(_hijo(default_modes={runtime: hijo_modo}),
                       {**PADRE_CALLA, "default_modes": {runtime: padre_modo}})

    def test_el_hijo_no_puede_ablandar_el_modo(self):
        with self.assertRaises(HerenciaIrresoluble) as cm:
            Policy.load(self._con_modos("ask", "bypassPermissions"))
        self.assertIn("más permisivo", str(cm.exception))

    def test_el_hijo_si_puede_endurecerlo(self):
        pol = Policy.load(self._con_modos("acceptEdits", "ask"))
        self.assertEqual("ask", pol.default_modes["claude"])

    def test_un_modo_no_rankeable_exige_igualdad(self):
        """`declared-in-agent` y `unknown` vienen de fábrica y no se pueden ordenar: su
        permisividad la decide otro fichero, o no se sabe. Sin orden no hay demostración."""
        self.assertNotIn("unknown", ORDEN_MODOS)
        with self.assertRaises(HerenciaIrresoluble) as cm:
            Policy.load(self._con_modos("unknown", "default", runtime="codex"))
        self.assertIn("no se puede demostrar", str(cm.exception))

    def test_lo_que_el_hijo_no_menciona_conserva_el_modo_del_padre(self):
        pol = Policy.load(_montar(_hijo(), {**PADRE_CALLA,
                                           "default_modes": {"claude": "ask"}}))
        self.assertEqual("ask", pol.default_modes["claude"])

    def test_default_modes_ya_no_esta_clasificado_como_propio(self):
        """Regresión de la clasificación, no del comportamiento.

        La guarda de monotonía comprueba que TODO campo tenga regla; no puede comprobar que
        la regla sea la correcta. `default_modes: PROPIO` pasó esa guarda y era el agujero.
        Esta prueba fija la decisión para que revertirla cueste explicarlo.
        """
        self.assertEqual(MODO, REGLAS["default_modes"])


class TestLoQueSIGUE_abierto(unittest.TestCase):
    """V2 / V3 / V4 · `extends` sale del espacio. **Declarado, no cerrado.**

    Por qué no se cierra, y no es pereza: el arreglo obvio —«exigir que el padre quede dentro
    del espacio»— **mata la arquitectura**. El padre legítimo de un proyecto es la política de
    su cliente, que vive un nivel por encima: la contención por espacio daría falso justo en
    el caso que la cadena existe para permitir.

    Severidad real, y por eso se puede dejar abierto con la cara descubierta: explotarlo exige
    escribir el `.harness/policy.json` del hijo, que está en `protected_paths`. Es una
    diferencia de defensa en profundidad respecto de `decide_write` —que sí aplica contención
    con `realpath`— no una escalada desde cero.

    Esta prueba **documenta el comportamiento actual**. Si alguien cierra la contención, cae, y
    ése es el momento de decidir a conciencia dónde se declara la raíz de políticas base.
    """

    def test_extends_a_una_ruta_de_fuera_del_espacio_resuelve_hoy(self):
        fuera = Path(tempfile.mkdtemp())
        (fuera / "ajena.json").write_text(json.dumps(
            {"schema": "harness.policy/v1", "name": "ajena", "version": "1",
             "protected_paths": ["z/**"]}), encoding="utf-8", newline="\n")
        d = Path(tempfile.mkdtemp())
        (d / ".harness").mkdir()
        (d / ".harness" / "policy.json").write_text(json.dumps(
            {"schema": "harness.policy/v1", "name": "p", "version": "1",
             "extends": str(fuera / "ajena.json")}), encoding="utf-8", newline="\n")
        pol = Policy.load(d / ".harness" / "policy.json")
        self.assertIn("z/**", pol.protected_paths,
                      "el comportamiento documentado cambió: revise la decisión de V2/V3/V4")


if __name__ == "__main__":
    unittest.main()
