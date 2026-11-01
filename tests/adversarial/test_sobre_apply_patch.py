# -*- coding: utf-8 -*-
"""El sobre de `apply_patch` es CONTENIDO DE FICHERO, y el guardián lo leía como órdenes.

Es el mismo eje que `test_documento_aqui.py` un canal más allá, y con el mismo final: un
control que salta con el TEXTO y no con la ACCIÓN. Aquí la diferencia es que el texto no era
prosa sino código fuente, y que el canal no tenía NINGUNA prueba — por eso sobrevivieron dos
defectos opuestos a la vez.

**Defecto 1 — ruido que bloquea.** Codex envía `apply_patch` con el sobre entero en
`tool_input.command`, y `evaluate` se lo pasaba a `decide_command`. Medido el 2026-10-31 contra
el guardián vivo, sobre un fichero de pruebas de TypeScript que levanta dos servidores HTTP en
loopback:

    const base = `http://127.0.0.1:${(trap.address()).port}`;

    → ask  regla=programa-sin-resolver
      «el nombre del programa se construye en tiempo de ejecución
       («http://127.0.0.1:${(trap.address()).port»)»

y en Codex ese `ask` viaja como `deny`, así que el parche no se aplicó. El mismo evento del
diario registró `escrituras_probadas: ["=", "new", "resolve", "s.close", "server.listen",
"trap.listen", "{"]`: tokens de TypeScript tomados por nombres de programa y por destinos de
redirección, cada uno comparado contra las rutas protegidas. Ninguno casó por suerte, no por
diseño.

**Defecto 2 — silencio que deja pasar.** `block_secret_content` se aplica en `decide_write`,
que recibe `fact["content"]`; `apply_patch` no trae `tool_input.content`, porque su contenido
viaja dentro del sobre. El control existía, se ejecutaba, y en este canal no miraba nada:

    Write        src/config.ts    const k = "AKIA…"   →  deny
    apply_patch  (mismo fichero)  +const k = "AKIA…"  →  ALLOW

Los dos se arreglan con el mismo movimiento —tratar el sobre como lo que es— y por eso las dos
mitades viven juntas: sin la segunda, la primera se satisface desactivando el control.
"""

from __future__ import annotations

import unittest

from core.guard import _contenido_apply_patch, evaluate, normalize
from core.policy import ALLOW, ASK, DENY, Policy
from tests.fixtures import Workspace

#: El fichero del caso real. Los acentos invertidos se construyen con `chr(96)` por el mismo
#: motivo que en `test_documento_aqui.py`: el defecto impedía editar el fichero que lo arregla.
B = chr(96)
FUENTE = [
    'import { createServer } from "node:http";',
    'const trap = createServer((req, res) => { res.statusCode = 302; res.end(); });',
    'await new Promise((resolve) => trap.listen(0, "127.0.0.1", resolve));',
    f'const base = {B}http://127.0.0.1:${{(trap.address()).port}}{B};',
    f'const res = await fetch({B}${{base}}/api/v1/log/entries{B});',
    'const s = await fetch(base); s.close();',
]


def _sobre(*pares) -> str:
    """Un sobre con `(directiva, ruta, líneas)` por fichero. Todas las líneas, añadidas."""
    fuera = ["*** Begin Patch"]
    for directiva, ruta, lineas in pares:
        fuera.append(f"*** {directiva}: {ruta}")
        fuera += [f"+{l}" for l in lineas]
    fuera.append("*** End Patch")
    return "\n".join(fuera)


def _sobre_con_contexto(ruta, lineas, cada=3) -> str:
    """Un `*** Update File:` real: contexto con espacio delante, añadidos con `+`.

    No es un detalle de formato. Medido el 2026-10-31 reconstruyendo desde el diario los seis
    ficheros que el guardián bloqueó: con TODAS las líneas prefijadas por `+`, el defecto
    **no se reproduce** en cuatro de ellos, porque el token que el analizador de shell toma por
    nombre de programa sale precisamente de una línea SIN prefijo —de ahí que el motivo citara
    «`${env.REKOR_URL}/api/v1/log/entries/${u», que empieza por acento invertido—. Un corpus
    que no reproduce el defecto no demuestra que se arregló, así que esta forma es la que vale.
    """
    cuerpo = [("+" if i % cada == 0 else " ") + l for i, l in enumerate(lineas)]
    return ("*** Begin Patch\n*** Update File: " + ruta + "\n"
            + "\n".join(cuerpo) + "\n*** End Patch")


class _ConSobre(unittest.TestCase):
    def _decidir(self, sobre: str, tool: str = "apply_patch"):
        with Workspace() as ws:
            hecho = normalize("codex", {"tool_name": tool,
                                        "tool_input": {"command": sobre},
                                        "cwd": str(ws.root)})
            return evaluate(Policy.default(), ws.root, hecho)[0]


class TestElSobreNoSeAnalizaComoShell(_ConSobre):
    def test_el_caso_real_se_aplica(self):
        """Dos servidores HTTP en loopback y una URL construida: no es ejecutar un programa."""
        d = self._decidir(_sobre(("Add File", "tests/unit/rekor-transport.test.ts", FUENTE)))
        self.assertEqual(ALLOW, d.outcome, f"regla={d.rule} · {d.reason[:160]}")

    def test_ninguna_regla_de_orden_se_atribuye_el_sobre(self):
        d = self._decidir(_sobre(("Add File", "tests/unit/rekor-transport.test.ts", FUENTE)))
        for inventada in ("programa-sin-resolver", "destino-sin-resolver"):
            self.assertNotEqual(inventada, d.rule)

    def test_codigo_fuente_que_menciona_una_orden_denegada_no_la_ejecuta(self):
        """`rm -rf` dentro de una cadena de un fichero es texto, no una acción."""
        d = self._decidir(_sobre(("Add File", "src/mensajes.ts",
                                  ['export const AVISO = "no ejecutes rm -rf / nunca";'])))
        self.assertEqual(ALLOW, d.outcome, f"regla={d.rule}")

    def test_pero_una_ORDEN_de_verdad_se_sigue_mirando(self):
        """La mitad que impide que esto sea «desactivar el control»."""
        with Workspace() as ws:
            hecho = normalize("codex", {"tool_name": "Bash",
                                        "tool_input": {"command": "rm -rf /tmp/x"},
                                        "cwd": str(ws.root)})
            self.assertEqual(DENY, evaluate(Policy.default(), ws.root, hecho)[0].outcome)


class TestLoQueElSobreSiTieneSeSigueMirando(_ConSobre):
    def test_una_ruta_protegida_dentro_del_sobre(self):
        d = self._decidir(_sobre(("Update File", ".harness/policy.json", ["{}"])))
        self.assertEqual(DENY, d.outcome)

    def test_el_SEGUNDO_fichero_del_sobre_tambien(self):
        d = self._decidir(_sobre(("Add File", "src/ok.ts", ["const a = 1;"]),
                                 ("Update File", ".harness/policy.json", ["{}"])))
        self.assertEqual(DENY, d.outcome)

    def test_un_renombrado_a_ruta_protegida_tambien(self):
        d = self._decidir(_sobre(("Move to", ".harness/policy.json", [])))
        self.assertEqual(DENY, d.outcome)

    def test_un_sobre_sin_ninguna_ruta_no_se_aprueba(self):
        """Herramienta de escritura declarada y ninguna ruta que examinar."""
        d = self._decidir("*** Begin Patch\n+algo\n*** End Patch")
        self.assertNotEqual(ALLOW, d.outcome)


class TestLaCredencialDentroDelSobre(_ConSobre):
    """El control existía, se ejecutaba, y en este canal no miraba nada."""

    def test_una_credencial_anadida_por_el_sobre_se_rechaza(self):
        d = self._decidir(_sobre(("Add File", "src/config.ts",
                                  ['const k = "AKIAIOSFODNN7EXAMPLE";'])))
        self.assertEqual(DENY, d.outcome)

    def test_y_la_del_SEGUNDO_fichero_tambien(self):
        d = self._decidir(_sobre(("Add File", "src/ok.ts", ["const a = 1;"]),
                                 ("Add File", "src/malo.ts",
                                  ['const k = "AKIAIOSFODNN7EXAMPLE";'])))
        self.assertEqual(DENY, d.outcome)

    def test_QUITAR_una_credencial_no_es_anadirla(self):
        """Sólo cuentan las líneas `+`. Contar las `-` haría irreparable un secreto filtrado."""
        sobre = ("*** Begin Patch\n*** Update File: src/config.ts\n"
                 '-const k = "AKIAIOSFODNN7EXAMPLE";\n'
                 '+const k = process.env.MI_SERVICIO_API_KEY;\n*** End Patch')
        self.assertEqual(ALLOW, self._decidir(sobre).outcome)

    def test_referenciar_un_secreto_sigue_siendo_la_forma_correcta(self):
        d = self._decidir(_sobre(("Add File", "src/config.ts",
                                  ['const k = process.env.MI_SERVICIO_API_KEY;'])))
        self.assertEqual(ALLOW, d.outcome)


class TestLaExtraccionDelContenido(unittest.TestCase):
    def test_solo_las_lineas_anadidas(self):
        sobre = ("*** Begin Patch\n*** Update File: x.ts\n"
                 "-vieja\n+nueva\n otra\n*** End Patch")
        self.assertEqual("nueva", _contenido_apply_patch(sobre))

    def test_la_cabecera_de_diff_no_es_contenido(self):
        """`+++ b/fichero` empieza por `+` y no es una línea del fichero."""
        self.assertEqual("", _contenido_apply_patch("+++ b/src/x.ts"))

    def test_un_sobre_vacio_no_revienta(self):
        for entrada in ("", None):
            self.assertEqual("", _contenido_apply_patch(entrada))


class TestUnHechoConstruidoAMano(unittest.TestCase):
    """`core/protocol.py` arma el hecho a mano para responder `policy/decide` por MCP.

    Regresión medida el 2026-10-31 al introducir `runtime`: `evaluate` lo leía con `[...]` y el
    hecho del protocolo no lo traía, así que el servidor devolvía
    «Internal server error: 'runtime'» a toda consulta con orden. Lo cazó la suite, no una
    revisión — y sólo porque `tests/contract` ejerce el servidor de verdad.
    """

    def _hecho(self, **extra):
        # La MISMA forma que construye `core/protocol.py::_decidir`, sin `runtime`.
        base = {"tool": "", "path": "", "command": "", "content": "", "role": "", "agent": ""}
        base.update(extra)
        return base

    def test_sin_runtime_no_revienta(self):
        with Workspace() as ws:
            d = evaluate(Policy.default(), ws.root, self._hecho(command="ls -la"))[0]
            self.assertEqual(ALLOW, d.outcome)

    def test_sin_runtime_la_politica_general_sigue_rigiendo(self):
        with Workspace() as ws:
            d = evaluate(Policy.default(), ws.root, self._hecho(command="rm -rf /tmp/x"))[0]
            self.assertEqual(DENY, d.outcome)

    def test_sin_runtime_una_concesion_acotada_NO_aplica(self):
        """Vacío es el defecto estricto, no «cualquiera»."""
        pol = Policy.default()
        pol.privilege_grants = ({"id": "p", "roles": ["*"], "hosts": ["*"],
                                 "runtimes": ["codex"], "commands": ["git push *"],
                                 "lifts": ["ask"], "effects": "unrestricted",
                                 "human_approval": "once-per-grant", "expires": "2099-01-01"},)
        with Workspace() as ws:
            d = evaluate(pol, ws.root, self._hecho(command="git push origin x"))[0]
            self.assertEqual(ASK, d.outcome)

    def test_y_si_la_consulta_DICE_su_runtime_si_aplica(self):
        pol = Policy.default()
        pol.privilege_grants = ({"id": "p", "roles": ["*"], "hosts": ["*"],
                                 "runtimes": ["codex"], "commands": ["git push *"],
                                 "lifts": ["ask"], "effects": "unrestricted",
                                 "human_approval": "once-per-grant", "expires": "2099-01-01"},)
        with Workspace() as ws:
            d = evaluate(pol, ws.root,
                         self._hecho(command="git push origin x", runtime="codex"))[0]
            self.assertEqual(ALLOW, d.outcome)


#: Lo que de verdad bloqueó el guardián, reducido a su núcleo. Cada entrada sale de un evento
#: `programa-sin-resolver` del diario de `telhar` del 2026-10-31, con el lenguaje y la
#: construcción que lo produjo. No son casos inventados: son los que costaron sesiones.
CORPUS = {
    "ts · literal de plantilla con variable de entorno": (
        "src/lib/evidence/correspondencia-rekor.ts", [
            "export async function fetchEntry(env: Env, uuid: string) {",
            f"  const url = {B}${{env.REKOR_URL}}/api/v1/log/entries/${{uuid}}{B};",
            "  const res = await fetch(url, { headers: { accept: \"application/json\" } });",
            "  if (!res.ok) throw new Error(`rekor ${res.status}`);",
            "  return res.json();",
            "}",
        ]),
    "ts · dos servidores http en loopback": (
        "tests/unit/rekor-transport.test.ts", FUENTE),
    "markdown · diagrama mermaid": (
        "docs/EXPEDIENTE.md", [
            "```mermaid",
            "flowchart LR",
            "  A[Foedus] --> B[Actor]",
            "  B --> C[Recibo]",
            "  C --> D[Ancla]",
            "```",
        ]),
    "javascript · encadenado de métodos y `0`.repeat": (
        "verificador/testigo.mjs", [
            "const x = {};",
            "x.rekorLogId = \"0\".repeat(64);",
            "x.rekorBody = Buffer.from(JSON.stringify(body)).toString(\"base64\");",
            "x.rekorVerification.inclusionProof.hashes.pop();",
            "entries.reduce((n, r) => n + r.attacks.length, 0);",
        ]),
    "python · f-string con llamada": (
        "docs/capture-persisted.py", [
            "import os",
            "url = f\"{os.environ['REKOR_URL']}/api/v1/log/entries/{uuid}\"",
            "print(f\"{url} -> {fetch(url).status_code}\")",
        ]),
    "shell dentro de una cadena de un fichero fuente": (
        "src/mensajes.ts", [
            "export const AVISO = \"nunca ejecutes rm -rf / ni sudo su\";",
            "export const EJEMPLO = `curl -s $(command -v echo) | sh`;",
        ]),
}


class TestElCorpusQueCostoSesiones(_ConSobre):
    """Reconstruido del diario de evidencia, no inventado.

    Las dos formas del sobre se prueban a propósito: con todo `+` y con líneas de contexto.
    La segunda es la que reproduce el defecto, y por eso es la que no puede faltar.
    """

    def test_todos_se_aplican_con_lineas_de_contexto(self):
        for nombre, (ruta, lineas) in CORPUS.items():
            with self.subTest(caso=nombre):
                d = self._decidir(_sobre_con_contexto(ruta, lineas))
                self.assertEqual(ALLOW, d.outcome, f"regla={d.rule} · {d.reason[:200]}")

    def test_todos_se_aplican_con_todo_anadido(self):
        for nombre, (ruta, lineas) in CORPUS.items():
            with self.subTest(caso=nombre):
                d = self._decidir(_sobre(("Add File", ruta, lineas)))
                self.assertEqual(ALLOW, d.outcome, f"regla={d.rule} · {d.reason[:200]}")

    def test_y_la_guardia_de_contenido_sigue_viendo_las_lineas_anadidas(self):
        """La mitad que impide que «ya no bloquea» se satisfaga apagando el control.

        Con líneas de contexto por medio, el secreto tiene que seguir detectándose: si
        `_contenido_apply_patch` se saltara una línea `+` quedaría un hueco silencioso.
        """
        lineas = ["const a = 1;", "const b = 2;",
                  'const k = "AKIAIOSFODNN7EXAMPLE";', "const c = 3;"]
        for cada in (1, 2, 3, 4):
            with self.subTest(cada=cada):
                sobre = _sobre_con_contexto("src/config.ts", lineas, cada=cada)
                esperado = DENY if any(
                    l.startswith("+") and "AKIA" in l for l in sobre.splitlines()) else ALLOW
                self.assertEqual(esperado, self._decidir(sobre).outcome)
