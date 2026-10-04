# -*- coding: utf-8 -*-
"""El juez se prueba a sí mismo. Cuatro casos por puerta, y cada uno prueba algo distinto:

    positivo              con todo bien, aprueba
    negativo              con el defecto que existe para detectar, FALLA
    entrada corrupta      con basura, NO aprueba (NOT_EXECUTABLE o FAIL, nunca PASS)
    dependencia ausente   sin lo que necesita, BLOQUEA (no aprueba, no falla)

La cuarta es la que casi nadie escribe y la que evita el fraude cómodo: sin ella, «no pude
comprobarlo» acaba en verde en la primera semana.
"""

from __future__ import annotations

import json
import unittest

from core.model import BLOCKED, FAIL, NOT_APPLICABLE, NOT_EXECUTABLE, PASS
from gates.base import GATES, run_gate
from tests.fixtures import Workspace


class GateCase(unittest.TestCase):
    """Base con los asertos del contrato de auto-prueba."""

    def assert_status(self, result, expected, msg=""):
        self.assertEqual(result.status, expected,
                         f"{result.id}: se esperaba {expected}, hubo {result.status} "
                         f"— {result.measure} {msg}")

    def assert_not_pass(self, result, msg=""):
        self.assertNotEqual(result.status, PASS,
                            f"{result.id} APROBÓ cuando no debía. {result.measure} {msg}")


# ── G-MANIFEST ───────────────────────────────────────────────────────────────────────
class TestGateManifest(GateCase):
    def test_positivo(self):
        with Workspace("man-ok") as ws:
            ws.manifest(gates=sorted(GATES))
            self.assert_status(run_gate("G-MANIFEST", ws.context()), PASS)

    def test_negativo_agente_sin_adapter(self):
        with Workspace("man-bad") as ws:
            ws.manifest(agents={"inventado": {"required": True}}, gates=sorted(GATES))
            r = run_gate("G-MANIFEST", ws.context())
            self.assert_status(r, FAIL)
            self.assertTrue(any("inventado" in f.as_text() for f in r.findings))

    def test_negativo_artefacto_declarado_y_ausente(self):
        with Workspace("man-art") as ws:
            ws.manifest(artifacts=["no/existe.md"], gates=sorted(GATES))
            self.assert_status(run_gate("G-MANIFEST", ws.context()), FAIL)

    def test_entrada_corrupta(self):
        with Workspace("man-corrupt") as ws:
            ws.file(".harness/harness.manifest.json", "{ esto no es json")
            self.assert_status(run_gate("G-MANIFEST", ws.context()), NOT_EXECUTABLE)

    def test_dependencia_ausente(self):
        with Workspace("man-none") as ws:
            self.assert_status(run_gate("G-MANIFEST", ws.context()), BLOCKED)


# ── G-POLICY ─────────────────────────────────────────────────────────────────────────
class TestGatePolicy(GateCase):
    def test_positivo(self):
        with Workspace("pol-ok") as ws:
            ws.manifest(agents={"claude": {"required": True}})
            ws.policy()
            self.assert_status(run_gate("G-POLICY", ws.context()), PASS)

    def test_negativo_guardian_desactivado(self):
        """Si el guardián deja pasar una escritura sobre la propia política, la puerta falla.

        Es H-03 exactamente: la política existía y NO estaba enganchada en la ruta que se usa.

        Reescrita el 2026-09-23. La simulación anterior vaciaba `protected_paths` en el
        documento, y eso **ya no se puede escribir**: toda política se compone con la línea
        base del motor, así que la lista efectiva vuelve a traer las rutas de fábrica y el
        guardián sigue denegando. Que la simulación se haya vuelto imposible es la noticia
        buena; lo que no puede pasar es que la prueba desaparezca con ella.

        Ahora se simula lo que un guardián mal configurado hace de verdad y sí es
        expresable: el fichero de política deja de existir en la ruta que el guardián lee.
        """
        with Workspace("pol-off") as ws:
            ws.manifest(agents={"claude": {"required": True}})
            ws.policy()
            (ws.root / ".harness" / "policy.json").unlink()
            r = run_gate("G-POLICY", ws.context())
            self.assertNotEqual(PASS, r.status,
                                "sin política en la ruta que el guardián lee, la puerta no "
                                "puede aprobar")

    def test_vaciar_lo_protegido_ya_no_es_expresable(self):
        """La contraparte de lo anterior, y la propiedad que lo sustituye.

        Un documento que declara `protected_paths: []` no desactiva nada: el efectivo es la
        unión con la norma base. Se comprueba sobre la política CARGADA, que es la que aplica
        el guardián, no sobre el documento escrito."""
        from core.policy import Policy as _P
        with Workspace("pol-vacia") as ws:
            ws.manifest(agents={"claude": {"required": True}})
            ruta = ws.policy(protected_paths=[], secret_read_deny=[])
            efectiva = _P.load(ruta)
            self.assertTrue(efectiva.is_protected("gates/g_agent.py"))
            self.assertTrue(efectiva.is_protected("repo-hijo/gates/g_agent.py"))
            self.assertTrue(efectiva.is_protected(".harness/policy.json"))

    def test_entrada_corrupta(self):
        with Workspace("pol-corrupt") as ws:
            ws.manifest()
            ws.file(".harness/policy.json", "no json")
            self.assert_status(run_gate("G-POLICY", ws.context()), NOT_EXECUTABLE)

    def test_dependencia_ausente(self):
        with Workspace("pol-none") as ws:
            ws.manifest()
            self.assert_status(run_gate("G-POLICY", ws.context()), BLOCKED)


# ── G-SKILL ──────────────────────────────────────────────────────────────────────────
class TestGateSkill(GateCase):
    def test_positivo(self):
        with Workspace("sk-ok") as ws:
            ws.manifest()
            ws.skill("revision", "revision")
            ws.skill("frontend", "frontend")
            self.assert_status(run_gate("G-SKILL", ws.context()), PASS)

    def test_negativo_nombre_no_coincide_con_directorio(self):
        """El defecto real: `revision/` declarando `revision-adversarial`. En Claude Code esa
        skill no carga, y sin esta puerta nadie se entera hasta que hace falta."""
        with Workspace("sk-name") as ws:
            ws.manifest()
            ws.skill("revision", "revision-adversarial")
            r = run_gate("G-SKILL", ws.context())
            self.assert_status(r, FAIL)
            self.assertTrue(any("no coincide con el directorio" in f.as_text() for f in r.findings))

    def test_negativo_nombre_duplicado(self):
        with Workspace("sk-dup") as ws:
            ws.manifest()
            ws.skill("a", "misma")
            ws.skill("b", "misma")
            r = run_gate("G-SKILL", ws.context())
            self.assert_status(r, FAIL)

    def test_negativo_sin_descripcion(self):
        with Workspace("sk-nodesc") as ws:
            ws.manifest()
            ws.file(".claude/skills/x/SKILL.md", "---\nname: x\n---\n\n" + "cuerpo " * 40)
            self.assert_status(run_gate("G-SKILL", ws.context()), FAIL)

    def test_entrada_corrupta(self):
        with Workspace("sk-corrupt") as ws:
            ws.manifest()
            ws.file(".claude/skills/x/SKILL.md", "---\nname: x\nsin cierre del frontmatter")
            self.assert_not_pass(run_gate("G-SKILL", ws.context()))

    def test_dependencia_ausente(self):
        with Workspace("sk-none") as ws:
            ws.manifest()
            self.assert_status(run_gate("G-SKILL", ws.context()), BLOCKED)


# ── G-LOCK ───────────────────────────────────────────────────────────────────────────
class TestGateLock(GateCase):
    COMMIT = "ea11fe8c09ee3e6e1111111111111111111111aa"

    def _ws(self, name):
        ws = Workspace(name)
        ws.manifest()
        ws.file("verificacion/comun.py", "ORIGINAL\n")
        ws.file("verificacion/v1.py", "ORIGINAL\n")
        ws.lock_for("nucleo", self.COMMIT, ["verificacion/comun.py", "verificacion/v1.py"])
        return ws

    def test_positivo(self):
        with self._ws("lock-ok") as ws:
            self.assert_status(run_gate("G-LOCK", ws.context(offline=True)), PASS)

    def test_negativo_archivo_modificado(self):
        with self._ws("lock-mod") as ws:
            ws.file("verificacion/v1.py", "MANIPULADO\n")
            r = run_gate("G-LOCK", ws.context(offline=True))
            self.assert_status(r, FAIL)
            self.assertTrue(any("huella distinta" in f.as_text() for f in r.findings))

    def test_negativo_archivo_borrado(self):
        with self._ws("lock-del") as ws:
            (ws.root / "verificacion/v1.py").unlink()
            self.assert_status(run_gate("G-LOCK", ws.context(offline=True)), FAIL)

    def test_negativo_ancla_mutable(self):
        """El corazón de H-06: si el lock guarda una ETIQUETA en vez de un SHA, no ancla nada.
        Quien mueva la etiqueta cambia el juez sin que el lock lo note."""
        with self._ws("lock-tag") as ws:
            doc = ws.context().read_json(ws.root / ".harness/harness.lock.json")
            doc["sources"]["nucleo"]["commit"] = "v3.0.1"
            ws.json(".harness/harness.lock.json", doc)
            r = run_gate("G-LOCK", ws.context(offline=True))
            self.assert_status(r, FAIL)
            self.assertTrue(any("no es un SHA" in f.as_text() for f in r.findings))

    def test_verify_nunca_escribe_el_lock(self):
        """Invariante I1. Es lo que distingue este lock del que se reescribía antes de comparar."""
        from core.digest import sha256_file
        with self._ws("lock-ro") as ws:
            path = ws.root / ".harness/harness.lock.json"
            before = sha256_file(path)
            ws.file("verificacion/v1.py", "MANIPULADO\n")
            run_gate("G-LOCK", ws.context(offline=True))
            self.assertEqual(before, sha256_file(path),
                             "verify() reescribió el lock: eso convierte la comprobación en "
                             "una tautología, que es la causa raíz de H-06")

    def test_entrada_corrupta(self):
        with Workspace("lock-corrupt") as ws:
            ws.manifest()
            ws.file(".harness/harness.lock.json", "{{{")
            self.assert_status(run_gate("G-LOCK", ws.context(offline=True)), NOT_EXECUTABLE)

    def test_dependencia_ausente(self):
        with Workspace("lock-none") as ws:
            ws.manifest()
            self.assert_status(run_gate("G-LOCK", ws.context(offline=True)), BLOCKED)


# ── G-FLEET ──────────────────────────────────────────────────────────────────────────
class TestGateFleet(GateCase):
    COMMIT = "b" * 40

    def _ws(self, name):
        ws = Workspace(name)
        ws.file("shared/agent.md", "CANON\n")
        ws.manifest(sources={"canon": {"uri": "https://example.invalid/c.git", "ref": "v1.0.0",
                                       "materialize": [{"from": "agent.md", "to": "shared/agent.md"}]}})
        ws.lock_for("canon", self.COMMIT, ["shared/agent.md"])
        return ws

    def test_positivo(self):
        with self._ws("fleet-ok") as ws:
            self.assert_status(run_gate("G-FLEET", ws.context()), PASS)

    def test_negativo_copia_editada(self):
        """H-07 medido: 14 de 14 agentes compartidos divergieron sin que nadie lo supiera."""
        with self._ws("fleet-drift") as ws:
            ws.file("shared/agent.md", "EDITADO EN LA COPIA\n")
            r = run_gate("G-FLEET", ws.context())
            self.assert_status(r, FAIL)
            self.assertTrue(any("editado en el espacio" in f.as_text() for f in r.findings))

    def test_negativo_materializado_sin_ancla(self):
        with self._ws("fleet-extra") as ws:
            m = ws.context().read_json(ws.root / ".harness/harness.manifest.json")
            m["sources"]["canon"]["materialize"].append({"from": "x.md", "to": "shared/x.md"})
            ws.json(".harness/harness.manifest.json", m)
            self.assert_status(run_gate("G-FLEET", ws.context()), FAIL)

    def test_dependencia_ausente(self):
        with Workspace("fleet-none") as ws:
            ws.manifest()
            self.assert_status(run_gate("G-FLEET", ws.context()), BLOCKED)


# ── G-MCP ────────────────────────────────────────────────────────────────────────────
class TestGateMcp(GateCase):
    def test_sin_referencias_no_aplica_y_NO_aprueba(self):
        """Antes esto exigía `PASS` y se llamaba `test_positivo_sin_referencias`.

        Exigía justo el defecto: un espacio sin un solo agente MCP producía una puerta VERDE
        de integridad referencial, con la medida «nada que verificar». El umbral de la puerta
        ya decía «resultado vacío nunca es aprobado» y el código decía lo contrario; la
        prueba fijaba el código. Se corrige la prueba porque afirmaba algo falso, no para que
        el código pase.
        """
        with Workspace("mcp-empty") as ws:
            ws.manifest()
            r = run_gate("G-MCP", ws.context(offline=True))
            self.assert_status(r, NOT_APPLICABLE)
            self.assert_not_pass(r)
            self.assertTrue(r.measure.strip(), "NOT_APPLICABLE sin motivo es un PASS con otro "
                                               "nombre")

    def test_con_referencias_la_puerta_SI_aplica(self):
        """La otra mitad del contrato: en cuanto hay una referencia MCP, la puerta tiene
        sujeto y ya no puede escurrirse por `NOT_APPLICABLE`. Qué veredicto dé depende del
        espacio; lo que no puede es declararse fuera de ámbito."""
        with Workspace("mcp-ok") as ws:
            ws.manifest()
            ws.json(".kiro/agents/a.json", {"name": "a", "tools": ["@figma"]})
            ws.json(".kiro/settings/mcp.json", {"mcpServers": {
                "figma": {"url": "https://mcp.figma.com/mcp", "type": "http"}}})
            r = run_gate("G-MCP", ws.context(offline=True))
            self.assertNotEqual(NOT_APPLICABLE, r.status,
                                f"con referencias declaradas no puede salir fuera de ámbito: "
                                f"{r.measure}")
            self.assertIn("1 referencias declaradas", r.measure)

    def test_negativo_servidor_no_declarado(self):
        """H-02 exacto: un agente exige `@navegador` y ningún mcp.json lo configura."""
        with Workspace("mcp-ghost") as ws:
            ws.manifest()
            ws.json(".kiro/agents/visual.json", {
                "name": "visual", "tools": ["read", "@navegador"],
                "allowedTools": ["read", "@navegador/*"]})
            ws.json(".kiro/settings/mcp.json", {"mcpServers": {"figma": {
                "url": "https://mcp.figma.com/mcp", "type": "http"}}})
            r = run_gate("G-MCP", ws.context(offline=True))
            self.assert_status(r, FAIL)
            self.assertTrue(any("navegador" in f.as_text() for f in r.findings))

    def test_negativo_servidor_deshabilitado(self):
        with Workspace("mcp-off") as ws:
            ws.manifest()
            ws.json(".kiro/agents/a.json", {"name": "a", "tools": ["@figma"]})
            ws.json(".kiro/settings/mcp.json", {"mcpServers": {
                "figma": {"url": "https://x", "type": "http", "disabled": True}}})
            self.assert_status(run_gate("G-MCP", ws.context(offline=True)), FAIL)

    def test_dependencia_ausente_bloquea_no_aprueba(self):
        """Un servidor HTTP que no se puede interrogar es BLOCKED. Nunca PASS.

        Es la regla que impide el fraude cómodo: sin ella, «no pude comprobarlo» acaba en verde."""
        with Workspace("mcp-http") as ws:
            ws.manifest()
            ws.json(".kiro/agents/a.json", {"name": "a", "tools": ["@figma"],
                                            "allowedTools": ["@figma/get_screenshot"]})
            ws.json(".kiro/settings/mcp.json", {"mcpServers": {
                "figma": {"url": "https://mcp.figma.com/mcp", "type": "http"}}})
            r = run_gate("G-MCP", ws.context())
            self.assert_status(r, BLOCKED)

    def test_entrada_corrupta(self):
        with Workspace("mcp-corrupt") as ws:
            ws.manifest()
            ws.file(".kiro/agents/a.json", "no json")
            ws.file(".kiro/settings/mcp.json", "tampoco")
            self.assert_not_pass(run_gate("G-MCP", ws.context(offline=True)))


# ── G-AGENT ──────────────────────────────────────────────────────────────────────────
class TestGateAgent(GateCase):
    def test_negativo_agente_sin_adapter(self):
        with Workspace("ag-unknown") as ws:
            ws.manifest(agents={"inventado": {"required": True}})
            self.assert_status(run_gate("G-AGENT", ws.context()), FAIL)

    def test_dependencia_ausente(self):
        with Workspace("ag-none") as ws:
            ws.manifest(agents={})
            self.assert_status(run_gate("G-AGENT", ws.context()), BLOCKED)

    def test_negativo_agente_que_no_arranca(self):
        """Se inyecta una sonda ya hecha: la puerta debe fallar sin volver a sondear.

        Es H-01: el binario está, y no funciona."""
        from core.probe import ProbeReport
        with Workspace("ag-broken") as ws:
            ws.manifest(agents={"codex": {"required": True}})
            ctx = ws.context()
            ctx.probes = [ProbeReport(agent="codex", level="INSTALLED",
                                      executable="/usr/local/bin/codex", version="0.103.0",
                                      stopped_because="muerto por señal 9",
                                      signature={"checked": True, "verdict": "REVOKED",
                                                 "revoked": True})]
            r = run_gate("G-AGENT", ctx)
            self.assert_status(r, FAIL)
            self.assertTrue(any("REVOKED" in f.as_text() for f in r.findings))

    def test_positivo_con_sonda_inyectada(self):
        from core.probe import ProbeReport
        with Workspace("ag-ok") as ws:
            ws.manifest(agents={"claude": {"required": True}})
            ctx = ws.context()
            ctx.probes = [ProbeReport(agent="claude", level="FUNCTIONAL", version="2.1.247",
                                      executable="/usr/bin/claude")]
            self.assert_status(run_gate("G-AGENT", ctx), PASS)


# ── G-SDD ────────────────────────────────────────────────────────────────────────────
class TestGateSdd(GateCase):
    #: Un verificador externo de mentira, pero real: se ejecuta de verdad y deja su informe.
    RUNNER = ('import json, pathlib, sys\n'
              'p = pathlib.Path("evidencia"); p.mkdir(exist_ok=True)\n'
              '(p / "informe.json").write_text(json.dumps({\n'
              '    "veredicto": "%s", "commit": "abc123", "puertas": %s}),\n'
              '    encoding="utf-8")\n')

    def _con_verificador(self, ws, puertas, *, declarar=True, runner="verificacion/verificar.py"):
        ws.file(runner, self.RUNNER % ("compuesto", json.dumps(puertas)))
        over = {}
        if declarar:
            over["integrations"] = {"spec_core": {"runner": runner,
                                                  "report": "evidencia/informe.json"}}
        ws.manifest(**over)
        return ws

    def test_sin_integracion_declarada_no_aplica_y_NO_aprueba(self):
        """Antes esto era `BLOCKED`, y `BLOCKED` se lee como «falta algo por hacer».

        No falta nada: este espacio simplemente no tiene un verificador externo. Un amarillo
        permanente en todo espacio normal enseña a ignorar el amarillo, que es justo lo que
        hace falta que nadie aprenda.
        """
        with Workspace("sdd-none") as ws:
            ws.manifest()
            r = run_gate("G-SDD", ws.context())
            self.assert_status(r, NOT_APPLICABLE)
            self.assert_not_pass(r)

    def test_un_verificador_en_el_arbol_SIN_declarar_no_se_ejecuta(self):
        """Encontrar un programa no es tener permiso para correrlo.

        La versión anterior ejecutaba cualquier `verificacion/verificar.py` que apareciera en
        el árbol. Eso es ejecución arbitraria disparada por un nombre de fichero, y además
        ataba la puerta a la distribución de un repositorio privado.
        """
        with Workspace("sdd-undeclared") as ws:
            self._con_verificador(ws, [{"clave": "V1", "estado": "cumple"}], declarar=False)
            r = run_gate("G-SDD", ws.context())
            self.assert_status(r, NOT_APPLICABLE)
            self.assertFalse((ws.root / "evidencia" / "informe.json").exists(),
                             "se ejecutó un verificador que el manifiesto no declara")
            self.assertIn("no lo declara", r.measure)

    def test_positivo_declarado_y_en_verde(self):
        with Workspace("sdd-ok") as ws:
            self._con_verificador(ws, [{"clave": "V1", "nombre": "uno", "estado": "cumple"},
                                       {"clave": "V2", "nombre": "dos", "estado": "cumple"}])
            r = run_gate("G-SDD", ws.context())
            self.assert_status(r, PASS)
            self.assertEqual("abc123", r.provenance.get("commit"))

    def test_negativo_declarado_y_en_rojo(self):
        with Workspace("sdd-bad") as ws:
            self._con_verificador(ws, [{"clave": "V1", "nombre": "uno", "estado": "no cumple",
                                        "medida": "falla", "hallazgos": ["h1"]}])
            r = run_gate("G-SDD", ws.context())
            self.assert_status(r, FAIL)
            self.assertTrue(any("V1" in f.as_text() for f in r.findings))

    def test_declarado_y_ausente_si_bloquea(self):
        """Declarado y ausente SÍ es un bloqueo: alguien contaba con él."""
        with Workspace("sdd-missing") as ws:
            ws.manifest(integrations={"spec_core": {"runner": "verificacion/verificar.py",
                                                    "report": "evidencia/informe.json"}})
            self.assert_status(run_gate("G-SDD", ws.context()), BLOCKED)

    def test_entrada_corrupta(self):
        """El verificador corre y deja un informe ilegible: no aprueba."""
        with Workspace("sdd-corrupt") as ws:
            ws.file("verificacion/verificar.py",
                    'import pathlib\n'
                    'p = pathlib.Path("evidencia"); p.mkdir(exist_ok=True)\n'
                    '(p / "informe.json").write_text("{{{ roto", encoding="utf-8")\n')
            ws.manifest(integrations={"spec_core": {"runner": "verificacion/verificar.py",
                                                    "report": "evidencia/informe.json"}})
            self.assert_status(run_gate("G-SDD", ws.context()), NOT_EXECUTABLE)

    def test_informe_sin_ninguna_puerta_no_aprueba(self):
        """El puente funcionó y al otro lado no había nada. Un puente vacío no aprueba."""
        with Workspace("sdd-vacio") as ws:
            self._con_verificador(ws, [])
            r = run_gate("G-SDD", ws.context())
            self.assert_not_pass(r)
            self.assert_status(r, NOT_EXECUTABLE)


# ── cobertura de la propia suite ─────────────────────────────────────────────────────
class TestSuiteCubreTodasLasPuertas(unittest.TestCase):
    def test_toda_puerta_registrada_tiene_su_clase_de_prueba(self):
        """Añadir una puerta sin escribirle pruebas debe romper la suite, no pasar inadvertido."""
        import importlib
        clases = set()
        for module in ("tests.selftest.test_gates", "tests.selftest.test_gates_nuevas"):
            mod = importlib.import_module(module)
            clases |= {n.replace("TestGate", "").lower()
                       for n, obj in vars(mod).items()
                       if isinstance(obj, type) and n.startswith("TestGate")}
        faltan = [g for g in GATES if g.replace("G-", "").lower() not in clases]
        self.assertFalse(faltan, f"puertas sin pruebas propias: {faltan}")
