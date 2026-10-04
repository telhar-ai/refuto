# -*- coding: utf-8 -*-
"""La herencia tiene que gobernar la ejecución, no sólo poder analizarse.

El defecto que cierran, medido el 2026-09-23 contra el guardián REAL
-------------------------------------------------------------------
Un cliente denegaba una orden. Un proyecto declaraba `extends` y no la repetía. El guardián
—que es `core/guard.py`, el gancho `PreToolUse` que decide de verdad— respondió:

    permissionDecision: "allow"

`Policy.load()` llamaba a `from_dict()` y **no resolvía `extends`**. El refinamiento existía,
estaba probado, y vivía en un comando de consulta que la ejecución nunca tocaba. El resultado
era el peor de los posibles: la herramienta informaba de que la herencia estaba bien mientras
ninguna de sus reglas se aplicaba.

Por qué estas pruebas van por el guardián y no por `refinar()`
---------------------------------------------------------------
Probar el refinamiento en aislamiento demuestra que compone bien. No demuestra que alguien lo
use. Las dos cosas se pueden cumplir por separado indefinidamente, y de hecho lo estuvieron.
Aquí se ejecuta **el guardián como proceso**, con su entrada real, y se lee su decisión.

Estas pruebas son el gate de L2. Si alguna cae, la capa de cliente vuelve a ser documentación.
"""

from __future__ import annotations

import json
import subprocess
import sys
import unittest
from pathlib import Path

from core.policy import HerenciaIrresoluble, Policy, PoliticaIlegible
from core.proc import TEXT_IO
from tests.fixtures import Workspace

RAIZ = Path(__file__).resolve().parents[2]

#: Una orden que NINGUNA política por omisión de refuto deniega. Si se usara `sudo`, la
#: prueba pasaría por la lista de fábrica y no demostraría nada sobre la herencia.
ORDEN_DEL_CLIENTE = "herramienta-solo-del-cliente --ejecutar"

CLIENTE = {"schema": "harness.policy/v1", "name": "cliente", "version": "1",
           "command_deny": ["herramienta-solo-del-cliente:*"],
           "protected_paths": ["secretos-del-cliente/**"]}


def _montar(ws, hijo: dict, padre: dict | None = CLIENTE, *, padre_nombre="cliente.json"):
    h = ws.root / ".harness"
    h.mkdir(parents=True, exist_ok=True)
    if padre is not None:
        (h / padre_nombre).write_text(json.dumps(padre), encoding="utf-8", newline="\n")
    (h / "policy.json").write_text(json.dumps(hijo), encoding="utf-8", newline="\n")
    return h / "policy.json"


def _guardian(ws, *, comando=None, ruta=None, contenido="x") -> dict:
    """Ejecuta el guardián COMO PROCESO, por su entrada real, y devuelve su decisión."""
    argv = [sys.executable, "-m", "core.guard", "--runtime", "claude", "--stdin",
            "--workspace", str(ws.root)]
    if comando:
        argv += ["--command", comando]
    if ruta:
        argv += ["--path", ruta, "--content", contenido]
    p = subprocess.run(argv, input="{}", capture_output=True, cwd=str(RAIZ), **TEXT_IO)
    try:
        return json.loads(p.stdout)["hookSpecificOutput"]
    except (ValueError, KeyError) as exc:                       # pragma: no cover
        raise AssertionError(f"el guardián no devolvió una decisión legible: {exc}\n"
                             f"stdout={p.stdout[:300]}\nstderr={p.stderr[:300]}") from None


class TestElGuardianVeLaReglaHeredada(unittest.TestCase):
    """GATE B. La prueba arquitectónica principal."""

    def test_una_regla_que_SOLO_esta_en_el_padre_se_aplica(self):
        with Workspace("her-gate-b") as ws:
            _montar(ws, {"schema": "harness.policy/v1", "name": "proyecto", "version": "1",
                         "extends": "cliente.json",
                         "protected_paths": ["contratos/**"]})
            d = _guardian(ws, comando=ORDEN_DEL_CLIENTE)
            self.assertEqual("deny", d["permissionDecision"],
                             "el guardián permitió una orden que el padre deniega")
            self.assertIn("herramienta-solo-del-cliente", d["permissionDecisionReason"],
                          "denegó, pero no por la regla del padre — el motivo importa: es lo "
                          "que demuestra de dónde vino el rechazo")

    def test_una_ruta_protegida_SOLO_por_el_padre_se_aplica(self):
        with Workspace("her-ruta") as ws:
            _montar(ws, {"schema": "harness.policy/v1", "extends": "cliente.json",
                         "protected_paths": ["contratos/**"]})
            d = _guardian(ws, ruta="secretos-del-cliente/x.txt")
            self.assertEqual("deny", d["permissionDecision"],
                             "se escribió en una ruta que el padre protege")

    def test_lo_que_nadie_prohibe_sigue_pasando(self):
        """El control que impide que esto se cierre con un «deniega todo»."""
        with Workspace("her-permite") as ws:
            _montar(ws, {"schema": "harness.policy/v1", "extends": "cliente.json"})
            self.assertEqual("allow", _guardian(ws, comando="echo hola")["permissionDecision"])

    def test_sin_herencia_el_comportamiento_no_cambia(self):
        """Regresión: un espacio que no declara `extends` funciona exactamente igual."""
        with Workspace("her-sin") as ws:
            _montar(ws, {"schema": "harness.policy/v1",
                         "command_deny": ["propia-del-proyecto:*"]}, padre=None)
            self.assertEqual("deny",
                             _guardian(ws, comando="propia-del-proyecto --x")["permissionDecision"])
            self.assertEqual("allow", _guardian(ws, comando="echo hola")["permissionDecision"])


class TestLaResolucionFallaCerrada(unittest.TestCase):
    """Ningún camino de fallo puede acabar en `allow`.

    Todos levantan `HerenciaIrresoluble`, subclase de `PoliticaIlegible`, que el guardián ya
    trataba denegando. Heredar de ella es lo que hace que esto falle cerrado sin tocar el
    guardián — el sitio donde un `except` nuevo y mal puesto costaría más caro.
    """

    def _deniega(self, ws, caso):
        d = _guardian(ws, comando="echo hola")
        self.assertEqual("deny", d["permissionDecision"],
                         f"{caso}: se permitió con la política sin resolver")
        return d

    def test_padre_ausente(self):
        with Workspace("her-ausente") as ws:
            _montar(ws, {"schema": "harness.policy/v1", "extends": "no-existe.json"},
                    padre=None)
            d = self._deniega(ws, "padre ausente")
            self.assertIn("parece gobernado sin estarlo", d["permissionDecisionReason"])

    def test_padre_ilegible(self):
        with Workspace("her-ilegible") as ws:
            h = ws.root / ".harness"; h.mkdir(parents=True, exist_ok=True)
            (h / "cliente.json").write_text("{{{ roto", encoding="utf-8", newline="\n")
            (h / "policy.json").write_text(
                json.dumps({"schema": "harness.policy/v1", "extends": "cliente.json"}),
                encoding="utf-8", newline="\n")
            d = self._deniega(ws, "padre ilegible")
            self.assertIn("no poder leerlo no es no tenerlo",
                          d["permissionDecisionReason"].lower())

    def test_padre_de_otro_contrato(self):
        with Workspace("her-ajeno") as ws:
            _montar(ws, {"schema": "harness.policy/v1", "extends": "cliente.json"},
                    padre={"schema": "otro:contrato/v9", "pii_patterns": [],
                           "client_identifiers": []})
            self._deniega(ws, "padre de otro programa")

    def test_hijo_que_relaja_al_padre(self):
        """La relajación que SÍ es expresable, y por tanto hay que detectar.

        Vaciar `protected_paths` no sirve como ataque: ese campo acumula y la retirada es
        inexpresable (ver `test_monotonia::M1`). Lo que sí se puede escribir es ENSANCHAR un
        campo `REDUCE` —`writable_paths` abre agujeros en lo protegido— o apagar un booleano
        que el padre exige. Ahí la unión ensancharía de verdad, así que se rechaza.
        """
        with Workspace("her-relaja") as ws:
            _montar(ws, {"schema": "harness.policy/v1", "extends": "cliente.json",
                         "writable_paths": ["secretos-del-cliente/**"]})
            d = self._deniega(ws, "hijo que ensancha writable_paths")
            self.assertIn("no refina", d["permissionDecisionReason"])
            self.assertIn("writable_paths", d["permissionDecisionReason"])

    def test_hijo_que_apaga_una_comprobacion_del_padre(self):
        with Workspace("her-apaga") as ws:
            padre = dict(CLIENTE); padre["block_secret_content"] = True
            _montar(ws, {"schema": "harness.policy/v1", "extends": "cliente.json",
                         "block_secret_content": False}, padre=padre)
            d = self._deniega(ws, "hijo que apaga la detección de secretos")
            self.assertIn("block_secret_content", d["permissionDecisionReason"])

    def test_ciclo_en_la_cadena(self):
        with Workspace("her-ciclo") as ws:
            h = ws.root / ".harness"; h.mkdir(parents=True, exist_ok=True)
            (h / "policy.json").write_text(
                json.dumps({"schema": "harness.policy/v1", "extends": "policy.json"}),
                encoding="utf-8", newline="\n")
            d = self._deniega(ws, "ciclo")
            self.assertIn("ciclo", d["permissionDecisionReason"])

    def test_el_padre_cambio_bajo_el_ancla(self):
        with Workspace("her-digest") as ws:
            from core.refinement import identidad_de
            _montar(ws, {"schema": "harness.policy/v1", "extends": "cliente.json",
                         "extends_digest": identidad_de(CLIENTE).digest,
                         "protected_paths": ["secretos-del-cliente/**"]})
            # El cliente se endurece: legítimo por sí mismo, pero rompe el ancla del hijo.
            otro = dict(CLIENTE); otro["command_deny"] = list(CLIENTE["command_deny"]) + ["z:*"]
            (ws.root / ".harness" / "cliente.json").write_text(
                json.dumps(otro), encoding="utf-8", newline="\n")
            d = self._deniega(ws, "padre cambiado")
            self.assertIn("El padre cambió", d["permissionDecisionReason"])


#: Un padre con listas de MÁS DE UN elemento. Con una sola entrada, «reordenar» no es nada
#: y la prueba del orden pasaría sin tocar el mecanismo.
CLIENTE_ORDENABLE = {
    "schema": "harness.policy/v1", "name": "cliente", "version": "1",
    "command_deny": ["herramienta-solo-del-cliente:*", "otra-del-cliente:*"],
    "protected_paths": ["secretos-del-cliente/**", "contratos-del-cliente/**"],
}


class TestElAnclaDaLaVueltaEntera(unittest.TestCase):
    """El caso POSITIVO de `--anchor`, que nunca se había escrito.

    Las dos pruebas del ancla que ya existían —`test_el_padre_cambio_bajo_el_ancla`, aquí
    arriba, y `M8` en `test_monotonia`— sólo exigen que un padre ALTERADO se detecte. Las
    dos pasaban mientras `--anchor` estaba roto de raíz, porque daban el veredicto correcto
    por el motivo equivocado: el ancla se escribía con el digest del documento DECLARADO
    (`documento_hijo`) y se comprobaba contra el COMPUESTO con la norma base
    (`politica_efectiva`), así que NINGÚN ancla casaba nunca y todo caía a
    `NOT_EXECUTABLE`.

    Medido el 2026-09-24 en un espacio real: ancla `41164aa7…`, comprobación `7738a16e…`,
    con el fichero del padre sin tocar desde antes de escribirse el ancla. El mensaje
    afirmaba «el padre cambió» sobre un padre intacto.

    Un aserto negativo no puede distinguir «el mecanismo funciona» de «el mecanismo está
    roto y falla siempre». Hace falta el positivo, y va por el guardián: que resuelva no
    basta, tiene que gobernar.
    """

    def _con_ancla(self, ws, padre: dict):
        from core.refinement import documento_hijo
        hijo = documento_hijo("proyecto", "cliente.json", padre_doc=padre)
        self.assertIn("extends_digest", hijo, "`documento_hijo` no ancló nada que probar")
        _montar(ws, hijo, padre=padre)
        return hijo

    def test_un_ancla_recien_escrita_resuelve_y_gobierna(self):
        with Workspace("anc-ida-vuelta") as ws:
            self._con_ancla(ws, CLIENTE_ORDENABLE)
            d = _guardian(ws, comando=ORDEN_DEL_CLIENTE)
            self.assertEqual("deny", d["permissionDecision"],
                             "un ancla escrita por el propio producto no dio la vuelta: el "
                             "espacio quedó sin gobierno nada más instalarlo")
            self.assertIn("herramienta-solo-del-cliente", d["permissionDecisionReason"])
            self.assertEqual("allow", _guardian(ws, comando="echo hola")["permissionDecision"],
                             "resolvió denegándolo todo, que no es resolver")

    def test_reordenar_una_lista_del_padre_no_es_un_cambio(self):
        """`protected_paths` es un conjunto. Que se escriba en otro orden no cambia qué
        protege, y no puede invalidar la identidad de quien hereda de él."""
        with Workspace("anc-orden") as ws:
            self._con_ancla(ws, CLIENTE_ORDENABLE)
            revuelto = dict(CLIENTE_ORDENABLE)
            for campo in ("command_deny", "protected_paths"):
                revuelto[campo] = list(reversed(CLIENTE_ORDENABLE[campo]))
            (ws.root / ".harness" / "cliente.json").write_text(
                json.dumps(revuelto), encoding="utf-8", newline="\n")
            d = _guardian(ws, comando=ORDEN_DEL_CLIENTE)
            self.assertEqual("deny", d["permissionDecision"],
                             "reordenar dos patrones rompió el ancla: una falsa alarma que "
                             "deja el espacio inoperante sin que la política haya cambiado")
            self.assertNotIn("cambió", d["permissionDecisionReason"],
                             "denegó, pero acusando al padre de haber cambiado")

    def test_alterar_de_verdad_al_padre_sigue_rompiendo_el_ancla(self):
        """El control que impide arreglar lo anterior aflojando el ancla."""
        with Workspace("anc-cambio") as ws:
            self._con_ancla(ws, CLIENTE_ORDENABLE)
            otro = dict(CLIENTE_ORDENABLE)
            otro["command_deny"] = ["herramienta-solo-del-cliente:*"]   # retira una regla
            (ws.root / ".harness" / "cliente.json").write_text(
                json.dumps(otro), encoding="utf-8", newline="\n")
            d = _guardian(ws, comando="echo hola")
            self.assertEqual("deny", d["permissionDecision"],
                             "el padre cambió de verdad y el ancla no se enteró")
            self.assertIn("cambió", d["permissionDecisionReason"])


class TestUnaSolaSemantica(unittest.TestCase):
    """`Policy.load` y `refuto policy refine` no pueden dar respuestas distintas."""

    def test_load_y_explicar_coinciden(self):
        from core.refinement import explicar
        with Workspace("her-una") as ws:
            ruta = _montar(ws, {"schema": "harness.policy/v1", "extends": "cliente.json",
                                "protected_paths": ["contratos/**"]})
            doc = json.loads(ruta.read_text(encoding="utf-8"))
            cargada = Policy.load(ruta)
            explicada = explicar(ruta, doc)
            self.assertEqual("PASS", explicada.status)
            self.assertEqual(set(cargada.command_deny),
                             set(explicada.politica.command_deny),
                             "las dos vías dan políticas distintas: hay dos semánticas")
            self.assertEqual(set(cargada.protected_paths),
                             set(explicada.politica.protected_paths))

    def test_la_excepcion_es_subclase_de_la_que_el_guardian_ya_captura(self):
        """Si dejara de serlo, el guardián dejaría de denegar y no habría prueba que lo viera
        salvo las de arriba. Se afirma aquí porque es la razón del diseño."""
        self.assertTrue(issubclass(HerenciaIrresoluble, PoliticaIlegible))


class TestLasTresCapasEnDirectoriosDistintos(unittest.TestCase):
    """El caso REAL: `refuto → cliente → proyecto` repartido en tres directorios.

    Las pruebas de arriba montan padre e hijo en el MISMO `.harness/`. Eso demuestra que la
    resolución compone, no que sirva para la forma en que se usa: un cliente es un directorio y
    sus proyectos son subdirectorios suyos, así que el `extends` real atraviesa carpetas y
    empieza por `../..`. Medido el 2026-09-23: funcionaba, y no había una sola prueba que lo
    dijera — que es como funciona hasta que alguien toca la resolución de rutas.
    """

    def _montar_tres(self, ws):
        base = ws.root / "base" / ".harness"
        cliente = ws.root / "acme" / ".harness"
        proyecto = ws.root / "acme" / "web" / ".harness"
        for d in (base, cliente, proyecto):
            d.mkdir(parents=True, exist_ok=True)
        (base / "policy.json").write_text(json.dumps(
            {"schema": "harness.policy/v1", "name": "refuto-base", "version": "1",
             "command_deny": ["orden-de-la-base:*"]}), encoding="utf-8", newline="\n")
        (cliente / "policy.json").write_text(json.dumps(
            {"schema": "harness.policy/v1", "name": "acme", "version": "1",
             "extends": "../../base/.harness/policy.json",
             "command_deny": ["orden-del-cliente:*"],
             "protected_paths": ["contratos/**"]}), encoding="utf-8", newline="\n")
        (proyecto / "policy.json").write_text(json.dumps(
            {"schema": "harness.policy/v1", "name": "web", "version": "1",
             "extends": "../../.harness/policy.json",
             "protected_paths": ["infra/**"]}), encoding="utf-8", newline="\n")
        return proyecto.parent

    def _decidir(self, raiz, **kw):
        argv = [sys.executable, "-m", "core.guard", "--runtime", "claude", "--stdin",
                "--workspace", str(raiz)]
        if kw.get("comando"):
            argv += ["--command", kw["comando"]]
        if kw.get("ruta"):
            argv += ["--path", kw["ruta"], "--content", "x"]
        p = subprocess.run(argv, input="{}", capture_output=True, cwd=str(RAIZ), **TEXT_IO)
        return json.loads(p.stdout)["hookSpecificOutput"]

    def test_el_proyecto_obedece_una_regla_del_ABUELO(self):
        """Dos saltos de `extends`, dos directorios arriba cada uno."""
        with Workspace("her-3capas") as ws:
            raiz = self._montar_tres(ws)
            d = self._decidir(raiz, comando="orden-de-la-base --x")
            self.assertEqual("deny", d["permissionDecision"],
                             "la cadena se cortó antes de llegar a la capa base")
            self.assertIn("orden-de-la-base", d["permissionDecisionReason"])

    def test_el_proyecto_obedece_una_regla_del_CLIENTE(self):
        with Workspace("her-3capas-cli") as ws:
            raiz = self._montar_tres(ws)
            self.assertEqual("deny", self._decidir(
                raiz, comando="orden-del-cliente --x")["permissionDecision"])
            self.assertEqual("deny", self._decidir(
                raiz, ruta="contratos/x.txt")["permissionDecision"])

    def test_el_proyecto_conserva_lo_suyo_y_no_deniega_todo(self):
        with Workspace("her-3capas-propio") as ws:
            raiz = self._montar_tres(ws)
            self.assertEqual("deny", self._decidir(
                raiz, ruta="infra/main.tf")["permissionDecision"])
            # El control que impide aprobar esto con un guardián que deniegue siempre.
            self.assertEqual("allow", self._decidir(
                raiz, ruta="src/app.js")["permissionDecision"])
            self.assertEqual("allow", self._decidir(
                raiz, comando="echo hola")["permissionDecision"])


class TestElAltaNaceHeredando(unittest.TestCase):
    """`init --extends` tiene que producir un hijo, no una copia — y no producir nada si falla.

    El defecto que cierran: `init` e `install` escribían `Policy.default().to_dict()`, la norma
    entera copiada en cada espacio. Once espacios son once copias que nadie vuelve a comparar, y
    la primera que alguien recorta deja de estar gobernada sin que ningún comando lo diga.
    """

    def _init(self, destino: Path, *extra):
        destino.mkdir(parents=True, exist_ok=True)
        return subprocess.run(
            [sys.executable, "refuto.py", "--workspace", str(destino), "init", *extra],
            capture_output=True, cwd=str(RAIZ), **TEXT_IO)

    def test_el_hijo_declara_lo_suyo_y_NADA_mas(self):
        with Workspace("alta-hijo") as ws:
            padre = ws.root / "base.json"
            padre.write_text(json.dumps(
                {"schema": "harness.policy/v1", "name": "refuto", "version": "1",
                 "command_deny": ["orden-de-la-base:*"]}), encoding="utf-8", newline="\n")
            self._init(ws.root / "acme", "--extends", str(padre))
            doc = json.loads((ws.root / "acme" / ".harness" / "policy.json")
                             .read_text(encoding="utf-8"))
            self.assertEqual({"schema", "name", "version", "extends"}, set(doc),
                             "el hijo trae claves que no son suyas: es una copia, no una "
                             "herencia, y lo copiado diverge sin avisar")
            self.assertNotIn("command_deny", doc)

    def test_la_ruta_relativa_se_resuelve_DESDE_EL_HIJO_no_desde_el_cwd(self):
        """Medido el 2026-09-23 dando de alta un espacio real, y es un fallo de los caros.

        `init` resolvía `--extends` contra `Path.cwd()` y GUARDABA la referencia relativa al
        directorio del hijo (`referencia_a(..., desde=harness_dir)`). Dos bases distintas para
        el mismo valor: lo que se teclea y lo que queda escrito son rutas a sitios distintos.
        Con `--workspace`, que es la forma de dar de alta un espacio ajeno, el CWD ni siquiera
        está en el árbol del espacio, así que la forma relativa —la única que sobrevive a mover
        el árbol, y la que la documentación enseña— fallaba siempre.

        Falló cerrado, que es lo único que evitó que fuera grave: no escribió nada. Pero el
        mensaje mandaba a materializar una capa base que no era el problema.
        """
        with Workspace("alta-relativa") as ws:
            (ws.root / "consultora" / ".harness").mkdir(parents=True)
            (ws.root / "consultora" / ".harness" / "policy.json").write_text(json.dumps(
                {"schema": "harness.policy/v1", "name": "consultora", "version": "1",
                 "command_deny": ["solo-de-la-consultora:*"]}), encoding="utf-8", newline="\n")
            # Desde `<destino>/.harness/` hay que subir dos para llegar al hermano.
            destino = ws.root / "proyecto"
            p = self._init(destino, "--extends", "../../consultora/.harness/policy.json")
            self.assertEqual(0, p.returncode,
                             f"la forma relativa que documentamos no dio de alta: {p.stderr}")
            doc = json.loads((destino / ".harness" / "policy.json")
                             .read_text(encoding="utf-8"))
            self.assertEqual("../../consultora/.harness/policy.json", doc["extends"],
                             "lo guardado no es lo tecleado")
            pol = Policy.load(destino / ".harness" / "policy.json")
            self.assertIn("solo-de-la-consultora:*", pol.command_deny,
                          "la cadena se escribió pero no resuelve a la política del padre")

    def test_un_padre_ausente_no_escribe_NADA(self):
        """No basta con fallar: no puede quedar un `policy.json` que existe y no gobierna.

        Si se escribiera primero y se comprobara después, el paso siguiente de `install` vería
        el fichero, lo daría por bueno, y el espacio quedaría con una política que el guardián
        rechaza en cada decisión — gobernado a la vista y denegando todo en la práctica.
        """
        with Workspace("alta-sin-padre") as ws:
            destino = ws.root / "roto"
            p = self._init(destino, "--extends", str(ws.root / "no-existe.json"))
            self.assertNotEqual(0, p.returncode, "se dio por buena un alta sin padre")
            self.assertFalse((destino / ".harness" / "policy.json").exists(),
                             "quedó escrita una política que no resuelve")

    def test_sin_extends_el_alta_no_cambia(self):
        """Regresión: quien no pide herencia sigue recibiendo la norma completa."""
        with Workspace("alta-sin-herencia") as ws:
            destino = ws.root / "suelto"
            self._init(destino)
            doc = json.loads((destino / ".harness" / "policy.json")
                             .read_text(encoding="utf-8"))
            self.assertIn("command_deny", doc)
            self.assertNotIn("extends", doc)


if __name__ == "__main__":
    unittest.main()
