# -*- coding: utf-8 -*-
"""Concesiones de privilegio: el ÚNICO mecanismo del modelo que abre, y por eso el más probado.

Todo lo demás en `Policy` restringe o restringe-con-excepción-heredada. `privilege_grants` es la
única tabla cuyo efecto es convertir un `deny` en `allow`, así que la pregunta no es «¿funciona?»
sino **«¿qué NO autoriza?»**. Cada prueba de abajo es una forma de que autorizara algo que nadie
concedió.

El callejón que esto resuelve, observado el 2026-09-25 en un espacio real: un agente necesitaba
cinco lecturas de diagnóstico con `sudo` sobre un host concreto para cerrar un ticket. Con
`command_deny` plano las únicas salidas eran que una persona tecleara cada orden, o mover `sudo`
de «rechazo» a «consulta» para todo el espacio y para siempre.

Lo que hace que no sea un agujero, y lo que estas pruebas fijan
---------------------------------------------------------------
1. La concesión vive en `.harness/policy.json`, que la política protege: **un agente no puede
   concederse privilegio a sí mismo**. Eso no se prueba aquí porque lo prueba
   `test_attacks.py` sobre `protected_paths` — se nombra para que nadie lo busque en el sitio
   equivocado.
2. `effects: read-only` se verifica contra `Ê`, **y una orden opaca no cuenta como read-only**.
3. Caduca, es de un host, es de un rol, y una concesión mal formada no concede nada.
4. Se compara contra cada SEGMENTO, así que encadenar no amplía la concesión.
"""

from __future__ import annotations

import os
import platform
import unittest
from pathlib import Path

from core.effects import efectos
from core.grants import (APROBACION_POR_OMISION, EFECTOS_POR_OMISION, Concesion, buscar,
                         problemas_declarados)
from core.policy import ALLOW, ASK, DENY, Policy, decide_command

RAIZ = Path(__file__).resolve().parents[2]
ESTE_HOST = platform.node()
ROL = "site-reliability-engineer"

BASE = {
    "id": "diagnostico-de-lectura",
    "roles": [ROL],
    "hosts": [ESTE_HOST],
    "runtimes": ["*"],
    "commands": ["sudo grep *", "sudo strings *"],
    "lifts": ["deny"],
    "effects": "read-only",
    "human_approval": "once-per-grant",
    "expires": "2099-01-01",
    "evidence": "SHOME-120",
}
ORDEN = "sudo grep -a marca /var/log/api.log"


def _politica(**cambios) -> Policy:
    p = Policy.default()
    g = dict(BASE)
    g.update(cambios)
    p.privilege_grants = (g,)
    return p


class _ConRol(unittest.TestCase):
    """El rol llega por el entorno, así que se fija y se restaura."""

    def setUp(self):
        self._previo = os.environ.get("HARNESS_ROLE")
        os.environ["HARNESS_ROLE"] = ROL

    def tearDown(self):
        if self._previo is None:
            os.environ.pop("HARNESS_ROLE", None)
        else:
            os.environ["HARNESS_ROLE"] = self._previo


class TestQueNOAutorizaUnaConcesion(_ConRol):
    def test_sin_concesion_declarada_sigue_denegando(self):
        self.assertEqual(DENY, decide_command(Policy.default(), ORDEN, RAIZ).outcome)

    def test_una_orden_que_la_concesion_no_describe(self):
        """El caso que motivó todo: `sudo grep` autorizado no autoriza `sudo cat /etc/shadow`."""
        self.assertEqual(DENY, decide_command(_politica(), "sudo cat /etc/shadow",
                                              RAIZ).outcome)

    def test_caducada(self):
        d = decide_command(_politica(expires="2020-01-01"), ORDEN, RAIZ)
        self.assertEqual(DENY, d.outcome)
        self.assertIn("CADUCÓ", d.reason)

    def test_otro_host(self):
        d = decide_command(_politica(hosts=["una-maquina-que-no-es-esta"]), ORDEN, RAIZ)
        self.assertEqual(DENY, d.outcome)

    def test_otro_rol(self):
        d = decide_command(_politica(roles=["technical-writer"]), ORDEN, RAIZ)
        self.assertEqual(DENY, d.outcome)

    def test_sin_rol_declarado_en_la_sesion(self):
        """Una concesión para un rol no autoriza a una sesión que no declara rol."""
        os.environ.pop("HARNESS_ROLE", None)
        self.assertEqual(DENY, decide_command(_politica(), ORDEN, RAIZ).outcome)

    def test_read_only_que_en_realidad_escribe(self):
        p = _politica(commands=["sudo tee *"])
        self.assertEqual(DENY, decide_command(p, "sudo tee /etc/hosts", RAIZ).outcome)

    def test_read_only_que_no_se_puede_demostrar(self):
        """Una orden OPACA no cuenta como de sólo lectura.

        No poder demostrar que no escribe no es haber demostrado que no escribe. Es la misma
        asimetría que `Ê ⊆ Effects` impone en todo el producto, aplicada donde más importa:
        en el único sitio que concede.
        """
        p = _politica(commands=["sudo python3 *"])
        d = decide_command(p, "sudo python3 -c 'print(1)'", RAIZ)
        self.assertEqual(DENY, d.outcome)
        self.assertTrue(d.opaco)

    def test_encadenar_no_amplia_la_concesion(self):
        """Se compara contra cada SEGMENTO. `sudo grep x; sudo rm -rf /` no pasa por el primero."""
        p = _politica()
        self.assertEqual(DENY, decide_command(p, f"{ORDEN}; sudo rm -rf /tmp/x", RAIZ).outcome)

    def test_una_concesion_mal_formada_no_concede_nada(self):
        for etq, cambios in (("sin id", {"id": ""}),
                             ("sin expires", {"expires": ""}),
                             ("expires ilegible", {"expires": "el martes"}),
                             ("hosts vacío", {"hosts": []}),
                             ("roles vacío", {"roles": []}),
                             ("commands vacío", {"commands": []}),
                             ("effects inventado", {"effects": "lo-que-sea"}),
                             ("aprobación inventada", {"human_approval": "claro-que-si"})):
            with self.subTest(caso=etq):
                self.assertEqual(DENY, decide_command(_politica(**cambios), ORDEN,
                                                      RAIZ).outcome)

    def test_una_lista_vacia_no_significa_cualquiera(self):
        """El defecto clásico de estas tablas: «sin especificar» leído como «todo»."""
        self.assertIn("NO significa «cualquiera»",
                      " ".join(Concesion.from_dict({**BASE, "hosts": []}).problemas()))

    def test_una_concesion_no_autoriza_lo_que_no_estaba_denegado(self):
        """Una concesión no es una lista de permisos: sólo levanta un rechazo concreto.

        Con `commands: ["*"]` —lo más ancho que se puede escribir— una orden que la política no
        rechazaba sigue decidiéndose por la política, no por la concesión.
        """
        d = decide_command(_politica(commands=["*"]), "ls -la", RAIZ)
        self.assertEqual(ALLOW, d.outcome)
        self.assertEqual("", d.rule, "la concesión se atribuyó una decisión que no tomó")


class TestQueSIAutorizaYComoLoDice(_ConRol):
    def test_la_concesion_que_aplica_autoriza_y_se_nombra(self):
        d = decide_command(_politica(), ORDEN, RAIZ)
        self.assertEqual(ALLOW, d.outcome)
        self.assertEqual("concesion:diagnostico-de-lectura", d.rule)
        self.assertIn("SHOME-120", d.reason, "la evidencia no viajó al motivo")

    def test_aprobacion_por_instancia_pregunta(self):
        d = decide_command(_politica(human_approval="each-time"), ORDEN, RAIZ)
        self.assertEqual(ASK, d.outcome)

    def test_el_comodin_de_host_y_rol_se_escribe_a_proposito(self):
        d = decide_command(_politica(roles=["*"], hosts=["*"]), ORDEN, RAIZ)
        self.assertEqual(ALLOW, d.outcome)

    def test_los_valores_por_omision_son_los_ESTRICTOS(self):
        c = Concesion.from_dict({"id": "x"})
        self.assertEqual("read-only", EFECTOS_POR_OMISION)
        self.assertEqual("each-time", APROBACION_POR_OMISION)
        self.assertEqual(EFECTOS_POR_OMISION, c.effects)
        self.assertEqual(APROBACION_POR_OMISION, c.human_approval)


class TestElDiagnosticoDistingueNoHayDeNoAplica(_ConRol):
    """«No hay concesión» y «la hay y caducó ayer» se arreglan distinto."""

    def test_una_concesion_que_describe_la_orden_explica_por_que_no_aplico(self):
        for cambios, esperado in ((_politica(expires="2020-01-01"), "CADUCÓ"),
                                  (_politica(hosts=["otra"]), "esta máquina es"),
                                  (_politica(roles=["technical-writer"]), "esta sesión declara")):
            with self.subTest(esperado=esperado):
                self.assertIn(esperado, decide_command(cambios, ORDEN, RAIZ).reason)

    def test_y_sin_concesion_no_se_inventa_un_diagnostico(self):
        self.assertNotIn("concesión", decide_command(Policy.default(), ORDEN, RAIZ).reason)

    def test_las_mal_formadas_se_pueden_enumerar_para_decirlo(self):
        """No conceden nada y aun así son un problema: alguien creyó estar autorizando algo."""
        self.assertEqual([], problemas_declarados(Policy.default()))
        self.assertTrue(problemas_declarados(_politica(expires="")))


class TestLaMonotoniaDeLaConcesion(unittest.TestCase):
    def test_privilege_grants_declara_su_regla(self):
        from core.refinement import REDUCE_LISTA, REGLAS
        self.assertEqual(REDUCE_LISTA, REGLAS["privilege_grants"])

    def test_el_hijo_no_puede_anadir_una_concesion(self):
        from core.refinement import refinar
        r = refinar({"schema": "harness.policy/v1", "version": "1"},
                    {"schema": "harness.policy/v1", "version": "1",
                     "privilege_grants": [BASE]})
        self.assertNotEqual("PASS", r.status,
                            "un hijo se concedió privilegio que su padre no le dio")

    def test_el_hijo_SI_puede_retirar_una_concesion(self):
        """La contraparte: sin ella, lo de arriba se satisface rechazando toda herencia."""
        from core.refinement import refinar
        r = refinar({"schema": "harness.policy/v1", "version": "1",
                     "privilege_grants": [BASE]},
                    {"schema": "harness.policy/v1", "version": "1", "privilege_grants": []})
        self.assertEqual("PASS", r.status, r.violaciones)
        self.assertEqual([], list(r.politica.privilege_grants))

    def test_modificar_una_concesion_heredada_es_anadir(self):
        from core.refinement import refinar
        r = refinar({"schema": "harness.policy/v1", "version": "1",
                     "privilege_grants": [BASE]},
                    {"schema": "harness.policy/v1", "version": "1",
                     "privilege_grants": [{**BASE, "expires": "2099-12-31"}]})
        self.assertNotEqual("PASS", r.status,
                            "un hijo alargó la caducidad de una concesión heredada")


class TestLaExcepcionDeLaRaizEsUnaYSePuedeContar(unittest.TestCase):
    """`RAIZ_NO_ACOTA` es la única excepción a «toda política se compone con la raíz del motor».

    Existe porque sin ella el campo era código muerto: medido el 2026-09-25, con la raíz vacía y
    `REDUCE_LISTA`, un espacio que declaraba UNA concesión obtenía `HerenciaIrresoluble` — ningún
    espacio podía declarar ninguna nunca. La trampa que ADR-0014 documenta para `writable_paths`.

    Y es peligrosa por naturaleza: cada campo que se le añada es un campo que la norma base deja
    de acotar. Por eso se cuenta.
    """

    def test_la_raiz_deja_de_acotar_exactamente_un_campo(self):
        from core.trust import RAIZ_NO_ACOTA
        self.assertEqual({"privilege_grants"}, set(RAIZ_NO_ACOTA),
                         "la raíz dejó de acotar un campo más y nadie lo declaró aquí")

    def test_y_ese_campo_trae_su_motivo_escrito(self):
        from core.trust import RAIZ_NO_ACOTA
        for campo, motivo in RAIZ_NO_ACOTA.items():
            with self.subTest(campo=campo):
                self.assertGreater(len(motivo.strip()), 80)

    def test_un_espacio_SI_puede_declarar_su_concesion(self):
        import json
        import tempfile

        with tempfile.TemporaryDirectory() as d:
            raiz = Path(d)
            (raiz / ".harness").mkdir()
            doc = {"schema": "harness.policy/v1", "name": "demo", "version": "1",
                   "privilege_grants": [BASE]}
            ruta = raiz / ".harness" / "policy.json"
            ruta.write_text(json.dumps(doc), encoding="utf-8")
            p = Policy.load(ruta)
            self.assertEqual(1, len(p.privilege_grants))

    def test_pero_la_monotonia_entre_capas_REALES_sigue_rigiendo(self):
        """La excepción es sólo para la raíz. Un proyecto no se concede lo que su cliente no dio."""
        from core.refinement import refinar
        r = refinar({"schema": "harness.policy/v1", "version": "1"},
                    {"schema": "harness.policy/v1", "version": "1",
                     "privilege_grants": [BASE]})
        self.assertNotEqual("PASS", r.status)


class TestBuscarNoDependeDelEntorno(unittest.TestCase):
    """`buscar` se prueba directo, sin variables de entorno, para que el fallo sea localizable.

    Se le pasan los EFECTOS, como hace `decide_command`. Estas dos pruebas los omitían y
    concedían igual, porque la comprobación de `read-only` se saltaba cuando `efectos is None`:
    afirmaban sobre la inyección de host/rol/fecha y de paso fijaban un `fail-open` que este
    módulo argumenta no tener. Omitir el dato no es un caso a preservar — es la forma de llamada
    que había que cerrar.
    """

    def test_el_host_y_el_rol_se_pueden_inyectar(self):
        p = _politica()
        ef = efectos(ORDEN)
        self.assertIsNotNone(buscar(p, ORDEN, canal="deny", rol=ROL, host=ESTE_HOST, efectos=ef).concesion)
        self.assertIsNone(buscar(p, ORDEN, canal="deny", rol="otro", host=ESTE_HOST, efectos=ef).concesion)
        self.assertIsNone(buscar(p, ORDEN, canal="deny", rol=ROL, host="otro", efectos=ef).concesion)

    def test_la_fecha_se_puede_inyectar(self):
        from datetime import date
        p = _politica(expires="2026-06-01")
        ef = efectos(ORDEN)
        self.assertIsNotNone(buscar(p, ORDEN, canal="deny", rol=ROL, host=ESTE_HOST, efectos=ef,
                                    hoy=date(2026, 5, 31)).concesion)
        self.assertIsNone(buscar(p, ORDEN, canal="deny", rol=ROL, host=ESTE_HOST, efectos=ef,
                                 hoy=date(2026, 6, 2)).concesion)

    def test_sin_efectos_una_concesion_read_only_no_concede(self):
        """La asimetría, dicha entera: no traer `Ê` es no poder verificar, luego no conceder.

        Es el mismo criterio que el caso opaco. Antes, `efectos=None` saltaba la comprobación
        completa y `read-only` volvía a ser una promesa de quien escribe la concesión.
        """
        v = buscar(_politica(), ORDEN, canal="deny", rol=ROL, host=ESTE_HOST, efectos=None)
        self.assertIsNone(v.concesion)
        self.assertTrue(any("no trae los efectos" in d for d in v.descartes),
                        f"el descarte tiene que explicarse, y dice: {v.descartes}")


if __name__ == "__main__":
    unittest.main()


# ─────────────────────────────────────────────────────────────────────────────────────────
# El canal `command_ask`, y el runtime. Añadido el 2026-10-31.
#
# Hasta esa fecha una concesión sólo levantaba `command_deny`. `git push:*` y `glab mr:*` viven
# en `command_ask`, así que NINGUNA concesión podía autorizarlos: medido sobre la política real
# de telhar, con una concesión que nombraba la orden, `git push` seguía dando `ask`. En Claude
# Code eso no se notaba; en Codex `ask` viaja como `deny` (`core/dialect.py`, medido contra
# 0.166.0: «PreToolUse hook returned unsupported permissionDecision:ask»), y entonces publicar
# no tenía camino declarado alguno — ni ejecutar, ni pedirlo.
# ─────────────────────────────────────────────────────────────────────────────────────────

PUBLICAR = {
    "id": "publicacion-gobernada",
    "roles": ["*"],
    "hosts": ["*"],
    "runtimes": ["codex"],
    "commands": ["git push *", "glab mr *"],
    "lifts": ["ask"],
    "effects": "unrestricted",
    "human_approval": "once-per-grant",
    "expires": "2099-01-01",
    "evidence": "SHOME-131",
}
EMPUJE = "git push -u origin feat/issue-12-algo"


def _publicacion(**cambios) -> Policy:
    g = dict(PUBLICAR)
    g.update(cambios)
    p = Policy.default()
    p.privilege_grants = (g,)
    return p


class TestLaConcesionLevantaTambienElAsk(_ConRol):
    """El defecto que esto cierra: `command_ask` no consultaba las concesiones."""

    def test_sin_concesion_el_empuje_se_consulta(self):
        d = decide_command(Policy.default(), EMPUJE, RAIZ, runtime="codex")
        self.assertEqual(ASK, d.outcome)
        self.assertEqual("git push:*", d.rule)

    def test_con_concesion_y_aprobacion_de_clase_se_ejecuta(self):
        d = decide_command(_publicacion(), EMPUJE, RAIZ, runtime="codex")
        self.assertEqual(ALLOW, d.outcome)
        self.assertEqual("concesion:publicacion-gobernada", d.rule)
        self.assertIn("SHOME-131", d.reason, "la evidencia no viajó al motivo")

    def test_con_aprobacion_por_instancia_sigue_preguntando_pero_se_nombra(self):
        """`each-time` no deja de preguntar: sólo dice que había una concesión detrás."""
        d = decide_command(_publicacion(human_approval="each-time"), EMPUJE, RAIZ,
                           runtime="codex")
        self.assertEqual(ASK, d.outcome)
        self.assertEqual("concesion:publicacion-gobernada", d.rule)

    def test_glab_mr_tambien(self):
        d = decide_command(_publicacion(), "glab mr create --draft", RAIZ, runtime="codex")
        self.assertEqual(ALLOW, d.outcome)

    def test_la_asimetria_se_conserva(self):
        """Levantar `ask` no convierte la tabla en una lista de permisos.

        Lo que una concesión NO puede seguir haciendo es autorizar lo que la política no
        restringía: `ls -la` se decide por la política aunque la concesión diga `["*"]`.
        """
        d = decide_command(_publicacion(commands=["*"]), "ls -la", RAIZ, runtime="codex")
        self.assertEqual(ALLOW, d.outcome)
        self.assertEqual("", d.rule, "la concesión se atribuyó una decisión que no tomó")

    def test_un_rechazo_le_gana_a_la_concesion_de_consulta(self):
        """Encadenar no amplía: el `deny` de otro segmento se impone sobre el `ask` levantado."""
        d = decide_command(_publicacion(), f"{EMPUJE} && sudo rm -rf /tmp/x", RAIZ,
                           runtime="codex")
        self.assertEqual(DENY, d.outcome)

    def test_el_empuje_forzado_sigue_rechazado(self):
        """`git push --force:*` es `command_deny` y esta concesión no lo nombra."""
        d = decide_command(_publicacion(), "git push --force origin main", RAIZ,
                           runtime="codex")
        self.assertEqual(DENY, d.outcome)


class TestElRuntimeAcotaLaConcesion(_ConRol):
    """Una concesión escrita para un runtime no puede degradar a otro.

    El motivo no es simetría: los runtimes no tienen el mismo repertorio de respuestas. En
    Codex `ask` no pregunta —no ejecuta—, así que una concesión le devuelve un camino que no
    tenía. En Claude Code `ask` SÍ pregunta, así que la misma concesión le QUITA la pregunta.
    Sin `runtimes`, arreglar un runtime degradaba el otro en silencio.
    """

    def test_otro_runtime_no_queda_cubierto(self):
        d = decide_command(_publicacion(), EMPUJE, RAIZ, runtime="claude")
        self.assertEqual(ASK, d.outcome)
        self.assertEqual("git push:*", d.rule, "la concesión de codex se aplicó a claude")

    def test_y_dice_por_que_no_aplico(self):
        d = decide_command(_publicacion(), EMPUJE, RAIZ, runtime="claude")
        self.assertIn("esta sesión corre en «claude»", d.reason)

    def test_una_llamada_sin_runtime_no_cobra_una_concesion_de_runtime(self):
        """Vacío es «no se dijo», y no se dijo no es «cualquiera»."""
        d = decide_command(_publicacion(), EMPUJE, RAIZ)
        self.assertEqual(ASK, d.outcome)
        self.assertEqual("git push:*", d.rule)

    def test_el_comodin_de_runtime_se_escribe_a_proposito(self):
        d = decide_command(_publicacion(runtimes=["*"]), EMPUJE, RAIZ, runtime="claude")
        self.assertEqual(ALLOW, d.outcome)

    def test_sin_el_campo_la_concesion_esta_MAL_FORMADA(self):
        """Un campo ausente en una tabla de autorización no puede significar «todo»."""
        sin = dict(PUBLICAR)
        del sin["runtimes"]
        p = Policy.default()
        p.privilege_grants = (sin,)
        self.assertEqual(ASK, decide_command(p, EMPUJE, RAIZ, runtime="codex").outcome)
        self.assertTrue(any("runtimes" in m for m in problemas_declarados(p)),
                        "no se puede enumerar para decirlo")

    def test_una_lista_vacia_de_runtimes_tampoco_concede(self):
        p = _publicacion(runtimes=[])
        self.assertEqual(ASK, decide_command(p, EMPUJE, RAIZ, runtime="codex").outcome)
        self.assertTrue(problemas_declarados(p))

    def test_el_runtime_no_llega_por_el_entorno(self):
        """Se pasa por parámetro a propósito: el guardián ya lo tiene en `--runtime`.

        Si se leyera del entorno, la decisión y su traducción podrían hablar de runtimes
        distintos — el guardián serializa con el `--runtime` que recibió.
        """
        previo = os.environ.get("HARNESS_GUARD_RUNTIME")
        os.environ["HARNESS_GUARD_RUNTIME"] = "codex"
        try:
            d = decide_command(_publicacion(), EMPUJE, RAIZ)
            self.assertEqual(ASK, d.outcome, "la variable de entorno concedió por la puerta de atrás")
        finally:
            if previo is None:
                os.environ.pop("HARNESS_GUARD_RUNTIME", None)
            else:
                os.environ["HARNESS_GUARD_RUNTIME"] = previo


class TestElCanalAcotaLaConcesion(_ConRol):
    """`lifts` existe porque los patrones son `fnmatch` y no tienen negación.

    Medido el 2026-10-31, antes del campo: una concesión con `commands: ["git push *"]`,
    escrita para levantar la CONSULTA de `git push:*`, levantaba también el RECHAZO de
    `git push --force:*` — el patrón casa las dos órdenes y «empuja, pero no forzado» no se
    puede escribir. La única manera de darle camino a la publicación era abrir de paso el
    empuje forzado, que es exactamente lo que `command_deny` existe para impedir.
    """

    def test_una_concesion_de_consulta_NO_levanta_un_rechazo(self):
        for orden in ("git push --force origin main", "git push -f origin main"):
            with self.subTest(orden=orden):
                d = decide_command(_publicacion(), orden, RAIZ, runtime="codex")
                self.assertEqual(DENY, d.outcome)
                self.assertNotIn("concesion", d.rule)

    def test_y_aun_asi_levanta_la_consulta_que_sí_declara(self):
        """El control de arriba no vale nada si de paso rompe el caso legítimo."""
        self.assertEqual(ALLOW, decide_command(_publicacion(), EMPUJE, RAIZ,
                                               runtime="codex").outcome)

    def test_una_concesion_de_rechazo_NO_levanta_una_consulta(self):
        """La asimetría va en los dos sentidos, o es una regla con una excepción."""
        d = decide_command(_publicacion(lifts=["deny"]), EMPUJE, RAIZ, runtime="codex")
        self.assertEqual(ASK, d.outcome)
        self.assertEqual("git push:*", d.rule)

    def test_declarar_los_dos_canales_se_escribe_a_proposito(self):
        p = _publicacion(lifts=["ask", "deny"])
        self.assertEqual(ALLOW, decide_command(p, EMPUJE, RAIZ, runtime="codex").outcome)
        self.assertEqual(ALLOW, decide_command(p, "git push --force origin main", RAIZ,
                                               runtime="codex").outcome)

    def test_sin_el_campo_la_concesion_esta_MAL_FORMADA(self):
        sin = dict(PUBLICAR)
        del sin["lifts"]
        p = Policy.default()
        p.privilege_grants = (sin,)
        self.assertEqual(ASK, decide_command(p, EMPUJE, RAIZ, runtime="codex").outcome)
        self.assertTrue(any("lifts" in m for m in problemas_declarados(p)))

    def test_un_canal_inventado_no_concede_y_se_puede_decir(self):
        p = _publicacion(lifts=["todo"])
        self.assertEqual(ASK, decide_command(p, EMPUJE, RAIZ, runtime="codex").outcome)
        self.assertTrue(any("todo" in m for m in problemas_declarados(p)))

    def test_el_canal_equivocado_no_ensucia_el_motivo_del_otro(self):
        """Una concesión de consulta no es «una concesión que no aplicó» en el canal de rechazo.

        Si se anotara como descarte, el motivo de cada `deny` arrastraría concesiones que
        nadie escribió para ese canal, y el diagnóstico que `descartes` existe para dar
        dejaría de distinguir «la hay y caducó» de «la hay y habla de otra cosa».
        """
        d = decide_command(_publicacion(), "git push --force origin main", RAIZ,
                           runtime="codex")
        self.assertNotIn("publicacion-gobernada", d.reason)


class TestElDiagnosticoNoProponeUnValorInvalido(unittest.TestCase):
    """Un diagnóstico que sugiere un valor que no existe cuesta otra vuelta a quien lo lee."""

    def test_lifts_no_sugiere_el_comodin_porque_no_lo_admite(self):
        c = Concesion.from_dict({"id": "x"})
        sobre_lifts = [m for m in c.problemas() if m.startswith("`lifts`")]
        self.assertEqual(1, len(sobre_lifts))
        self.assertNotIn('["*"]', sobre_lifts[0], "propone un comodín que `lifts` no admite")
        self.assertIn("ask", sobre_lifts[0])
        self.assertIn("deny", sobre_lifts[0])

    def test_los_otros_cuatro_si_lo_sugieren_porque_si_lo_admiten(self):
        c = Concesion.from_dict({"id": "x"})
        for campo in ("roles", "hosts", "runtimes", "commands"):
            with self.subTest(campo=campo):
                m = next(m for m in c.problemas() if m.startswith(f"`{campo}`"))
                self.assertIn('["*"]', m)
