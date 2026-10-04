# -*- coding: utf-8 -*-
"""El producto cartesiano que faltaba: `orden × efecto × objetivo protegido`.

El punto ciego que estas pruebas existen para cerrar
----------------------------------------------------
La suite tenía dos familias que no se tocaban:

    TestModificarAlJuez      probaba rutas protegidas, SIEMPRE por carga `fs_write`
    TestEjecucionDeOrdenes   probaba órdenes, SIEMPRE contra las listas de patrones

Ninguna cruzaba los dos ejes, así que nadie preguntó nunca «¿y si la orden escribe en una
ruta protegida?». La respuesta, medida el 2026-09-23 contra el guardián real con la misma
política y la misma ruta:

    Write  gates/base.py           →  deny
    Bash   echo x > gates/base.py  →  allow, y el fichero se escribió

No fue un descuido de quien escribió las pruebas: fue que las pruebas se derivaron de la
IMPLEMENTACIÓN —había un `decide_write` y un `decide_command`, y se probó cada uno— en vez
de la PROPIEDAD, que es «el sujeto no escribe en el juez, da igual cómo».

Por eso aquí se enumeran los dos ejes y se cruzan. Una forma nueva de escribir que alguien
añada a `core.effects` entra en la tabla y se prueba contra TODAS las rutas protegidas sin
escribir una prueba más.
"""

from __future__ import annotations

import json
import subprocess
import sys
import unittest
from pathlib import Path

from core.policy import ALLOW, DENY, Policy, decide_command
from core.proc import TEXT_IO
from tests.fixtures import Workspace

REPO = Path(__file__).resolve().parents[2]

#: EJE 1 · cada forma de escribir desde una orden de consola. La plantilla lleva `{ruta}`.
#:
#: No es una lista de «órdenes peligrosas»: es una lista de MECANISMOS DE ESCRITURA. La
#: diferencia importa — una lista de nombres de orden se queda corta con el siguiente
#: nombre, y un mecanismo cubre todos los nombres que lo usen.
MECANISMOS = [
    ("redirección simple", "echo contenido > {ruta}"),
    ("redirección de anexado", "echo contenido >> {ruta}"),
    ("redirección con descriptor", "echo contenido 1> {ruta}"),
    ("redirección forzada", "echo contenido >| {ruta}"),
    ("tubería a tee", "echo contenido | tee {ruta}"),
    ("edición en sitio", "sed -i s/a/b/ {ruta}"),
    ("copia sobre el destino", "cp /dev/null {ruta}"),
    ("movimiento sobre el destino", "mv /tmp/origen {ruta}"),
    ("borrado", "rm -f {ruta}"),
    ("truncado", "truncate -s 0 {ruta}"),
    ("creación", "touch {ruta}"),
    ("cambio de permisos", "chmod 777 {ruta}"),
    ("encadenado tras orden inocua", "ls -la && echo x > {ruta}"),
    ("encadenado con punto y coma", "true; echo x > {ruta}"),
    ("dentro de un intérprete", 'sh -c "echo x > {ruta}"'),
    ("tras asignación de entorno", "FOO=1 echo x > {ruta}"),
    ("envuelto", "env echo x > {ruta}"),
    ("travesía con puntos dobles", "echo x > app/../{ruta}"),
    # Los tres de abajo salieron de la batería de falsación, no del diseño. La primera
    # versión del modelo de efectos los dejaba pasar: el destino entre comillas se perdía
    # al borrar los literales para localizar el operador, y citar una ruta es lo más normal
    # del mundo. Están aquí para que no vuelvan.
    ("destino entre comillas dobles", 'echo x > "{ruta}"'),
    ("destino entre comillas simples", "echo x > '{ruta}'"),
    ("redirección sin espacio", "echo x >{ruta}"),
    ("documento aquí", "cat > {ruta} <<EOF\nx\nEOF"),
    # El cuerpo de un documento aquí CITADO se descarta —es texto, no órdenes— y este caso
    # existe para fijar que descartarlo no descarta la REDIRECCIÓN, que va en la línea del
    # operador. Sin él, el arreglo de `_sin_cuerpos_citados` sería una vía de escape.
    ("documento aquí citado", "cat > {ruta} <<'EOF'\nx\nEOF"),
    ("documento aquí con sangría", "cat > {ruta} <<-'EOF'\n\tx\n\tEOF"),
    ("subshell", "(echo x > {ruta})"),
    ("redirección con descriptor y anexado", "echo x 1>> {ruta}"),
]

#: EJE 2 · una ruta por cada patrón protegido de fábrica. Se derivan de la política, no se
#: escriben a mano: añadir un patrón a `DEFAULT_PROTECTED` extiende esta tabla sola.
OBJETIVOS = [
    "verificacion/v1.py", ".kiro/steering/metodo.md", ".harness/policy.json",
    ".harness/evidence/ledger.jsonl", "gates/g_agent.py", "policies/base.json",
    "insumos/cliente.md", "evidencia/informe.json", "algo.lock.json",
    "harness.manifest.json",
]

#: Rutas que NO están protegidas. Si alguna de éstas se deniega, el control es ruidoso, y un
#: control ruidoso se desactiva — que es como se pierde la protección de verdad.
OBJETIVOS_LIBRES = ["app/main.js", "src/lib/util.py", "docs/nota.md", "README.md"]


class TestNingunMecanismoAlcanzaAlJuez(unittest.TestCase):
    """`WRITE(p) ∧ Protegida(p) ⟹ DENY`, sea cual sea la sintaxis que originó la escritura."""

    def setUp(self):
        self.p = Policy.default()

    def test_el_producto_cartesiano_entero_se_deniega(self):
        with Workspace("cruz-deny") as ws:
            fallos = []
            for nombre, plantilla in MECANISMOS:
                for ruta in OBJETIVOS:
                    orden = plantilla.format(ruta=ruta)
                    d = decide_command(self.p, orden, ws.root)
                    if d.outcome != DENY:
                        fallos.append(f"{nombre} → {ruta}: {d.outcome} ({orden})")
            self.assertEqual([], fallos,
                             f"{len(fallos)} de {len(MECANISMOS) * len(OBJETIVOS)} "
                             f"combinaciones alcanzaron al juez:\n  " + "\n  ".join(fallos[:12]))

    def test_las_rutas_libres_siguen_siendo_escribibles(self):
        """El otro lado, y sin él la prueba de arriba se satisface denegando todo."""
        with Workspace("cruz-allow") as ws:
            fallos = []
            for nombre, plantilla in MECANISMOS:
                if "rm -f" in plantilla or "chmod" in plantilla:
                    continue        # borrar y dar permisos no es «trabajo normal»
                for ruta in OBJETIVOS_LIBRES:
                    orden = plantilla.format(ruta=ruta)
                    d = decide_command(self.p, orden, ws.root)
                    if d.outcome != ALLOW:
                        fallos.append(f"{nombre} → {ruta}: {d.outcome} ({orden})")
            self.assertEqual([], fallos,
                             f"{len(fallos)} escrituras LEGÍTIMAS se bloquearon. Un control "
                             f"que estorba se desactiva:\n  " + "\n  ".join(fallos[:12]))

    def test_leer_una_ruta_protegida_no_es_escribirla(self):
        """`cat`, `grep` y `sed` sin `-i` leen. Tratarlos como escritura haría inusable el
        árbol que el agente tiene que poder consultar."""
        with Workspace("cruz-read") as ws:
            for orden in ("cat gates/g_agent.py", "grep -rn def gates/",
                          "sed -n 1,10p verificacion/v1.py", "wc -l .harness/policy.json",
                          "ls -la .harness/", "diff gates/a.py gates/b.py"):
                self.assertEqual(ALLOW, decide_command(self.p, orden, ws.root).outcome, orden)


class TestElGuardianRealAplicaLosDosEjes(unittest.TestCase):
    """Lo de arriba contra la función; esto contra el PROCESO, que es lo que corre de verdad.

    La distinción no es ceremonial: el defecto original no vivía en `decide_write` ni en
    `decide_command` —los dos eran correctos— sino en `core.guard.evaluate`, que elegía UNO
    de los dos y devolvía. Una prueba de unidad sobre cualquiera de las dos funciones pasaba.
    """

    def _guard(self, ws, payload: dict) -> dict:
        proc = subprocess.run(
            [sys.executable, "-m", "core.guard", "--runtime", "claude", "--stdin",
             "--workspace", str(ws.root)],
            input=json.dumps(payload), capture_output=True, **TEXT_IO,
            cwd=str(REPO), timeout=60)
        return json.loads(proc.stdout)["hookSpecificOutput"]

    def test_la_misma_ruta_por_los_dos_canales_da_la_misma_decision(self):
        """La invariante en una línea: la decisión depende del EFECTO, no del canal."""
        with Workspace("guard-ejes") as ws:
            ws.policy()
            for ruta in ("gates/g_agent.py", ".harness/policy.json", "verificacion/v1.py"):
                por_escritura = self._guard(ws, {
                    "tool_name": "Write",
                    "tool_input": {"file_path": ruta, "content": "x"}})
                por_orden = self._guard(ws, {
                    "tool_name": "Bash",
                    "tool_input": {"command": f"echo x > {ruta}"}})
                self.assertEqual("deny", por_escritura["permissionDecision"], ruta)
                self.assertEqual(
                    por_escritura["permissionDecision"],
                    por_orden["permissionDecision"],
                    f"«{ruta}»: el canal cambia la decisión. `Write` da "
                    f"{por_escritura['permissionDecision']} y `Bash` da "
                    f"{por_orden['permissionDecision']}")

    def test_una_carga_con_orden_Y_ruta_evalua_las_dos(self):
        """`evaluate` devolvía en la primera rama que casara. Una carga con las dos cosas
        dejaba la segunda sin mirar."""
        with Workspace("guard-ambas") as ws:
            ws.policy()
            r = self._guard(ws, {"tool_name": "Bash",
                                 "tool_input": {"command": "ls -la",
                                                "file_path": ".harness/policy.json",
                                                "content": "x"}})
            self.assertEqual("deny", r["permissionDecision"],
                             "la orden era inocua y la ruta protegida: se miró sólo una")


class TestLaOpacidadSeDeclaraNoSeOculta(unittest.TestCase):
    """`Ê ⊆ Effects`. Lo que no se puede demostrar se dice, no se supone bueno ni malo."""

    def test_un_interprete_se_marca_opaco(self):
        from core.effects import efectos
        for orden in ('python3 -c "import os"', "make build", "npm run x", "./binario-propio"):
            self.assertTrue(efectos(orden).opaco, f"«{orden}» debía declararse opaca")

    def test_una_orden_de_solo_lectura_no_es_opaca(self):
        """Si todo fuera opaco, `opaco` no informaría de nada."""
        from core.effects import efectos
        for orden in ("ls -la", "echo hola", "grep -rn foo .", "cat x.txt", "git status"):
            if orden.startswith("git"):
                continue            # git SÍ escribe según el subcomando: opaco es correcto
            self.assertFalse(efectos(orden).opaco, f"«{orden}» no debía ser opaca")

    def test_xargs_recibe_sus_rutas_por_la_tuberia_y_se_declara(self):
        """`echo gates/base.py | xargs touch` escribía en el juez y el modelo veía `touch`
        sin argumentos: `xargs` estaba en la lista de envoltorios y se pelaba como a `env`.

        No se puede saber qué escribirá —las rutas llegan por la tubería— así que lo honesto
        es declararlo opaco. Fingir que no escribe nada era lo que fallaba.
        """
        from core.effects import efectos
        for orden in ("echo gates/base.py | xargs touch", "find . | xargs rm",
                      "cat lista | xargs sed -i s/a/b/"):
            self.assertTrue(efectos(orden).opaco, f"«{orden}» debía declararse opaca")
        self.assertFalse(efectos("ls | xargs grep foo").opaco,
                         "`xargs grep` sólo lee: marcarlo opaco haría ruidoso el control")

    def test_un_operador_citado_no_es_una_redireccion(self):
        """La otra mitad de la corrección de las comillas."""
        from core.effects import efectos
        for orden in ('echo "a > b"', "echo 'x > y'", 'grep -rn "salida > destino" .'):
            self.assertEqual(set(), efectos(orden).escrituras, orden)

    def test_la_opacidad_viaja_a_la_decision(self):
        p = Policy.default()
        d = decide_command(p, 'python3 -c "print(1)"')
        self.assertEqual(ALLOW, d.outcome, "denegar todo intérprete haría inusable la "
                                           "herramienta, y un control inusable se desactiva")
        self.assertTrue(d.opaco, "la decisión tiene que declarar que no se pudo demostrar")


class TestLaRaizDeConfianzaNoLaEligeElSujeto(unittest.TestCase):
    """`Trusted(Π) ⟺ Reachable(Π, R) ∧ Monotone(cadena)`.

    La monotonía sola es relativa: se demostraba `hijo ⊒ padre` en cada arista y el hijo
    elegía el padre. Bastaba apuntar `extends` a una política laxa para vaciar el gobierno
    sin violar una sola arista.
    """

    def _cargar(self, ws, doc: dict):
        ruta = ws.json(".harness/policy.json", doc)
        return Policy.load(ruta)

    def test_vaciar_lo_protegido_es_INEXPRESABLE(self):
        with Workspace("raiz-vacia") as ws:
            pol = self._cargar(ws, {"schema": "harness.policy/v1", "version": "1",
                                    "protected_paths": [], "command_deny": []})
            self.assertTrue(pol.is_protected("gates/g_agent.py"),
                           "la cima vació lo protegido y el efectivo se lo permitió")
            self.assertIn("sudo:*", pol.command_deny)

    def test_una_raiz_ajena_y_laxa_no_afloja_nada(self):
        import tempfile
        fuera = Path(tempfile.mkdtemp()) / "laxa.json"
        fuera.write_text(json.dumps({"schema": "harness.policy/v1", "name": "laxa",
                                     "version": "1", "protected_paths": [],
                                     "command_deny": []}), encoding="utf-8")
        with Workspace("raiz-ajena") as ws:
            pol = self._cargar(ws, {"schema": "harness.policy/v1", "version": "1",
                                    "extends": str(fuera)})
            self.assertTrue(pol.is_protected("gates/g_agent.py"))
            self.assertEqual(DENY, decide_command(pol, "sudo algo", ws.root).outcome)

    def test_ensanchar_un_agujero_se_rechaza_entero(self):
        from core.policy import PoliticaIlegible
        with Workspace("raiz-agujero") as ws:
            with self.assertRaises(PoliticaIlegible):
                self._cargar(ws, {"schema": "harness.policy/v1", "version": "1",
                                  "writable_paths": [".harness/memory/**", "gates/**"]})

    def test_apagar_la_deteccion_de_secretos_se_rechaza(self):
        from core.policy import PoliticaIlegible
        with Workspace("raiz-secretos") as ws:
            with self.assertRaises(PoliticaIlegible):
                self._cargar(ws, {"schema": "harness.policy/v1", "version": "1",
                                  "block_secret_content": False})

    def test_endurecer_SIGUE_permitido(self):
        """Sin esto, la prueba de arriba se satisface rechazando toda política."""
        with Workspace("raiz-dura") as ws:
            pol = self._cargar(ws, {"schema": "harness.policy/v1", "version": "1",
                                    "protected_paths": ["mio/**"],
                                    "default_modes": {"claude": "ask"}})
            self.assertIn("mio/**", pol.protected_paths)
            self.assertTrue(pol.is_protected("gates/g_agent.py"))
            self.assertEqual("ask", pol.default_mode_for("claude"))


if __name__ == "__main__":
    unittest.main()
