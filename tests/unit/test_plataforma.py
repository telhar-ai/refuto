# -*- coding: utf-8 -*-
"""Capacidades, herramientas, roles, enrutado, memoria y vínculo."""

from __future__ import annotations

import subprocess
import unittest
from pathlib import Path

from core.capability import (
    AVAILABLE, BLOCKED, CapabilityGraph, Capability, FUNCTIONAL, MISSING, at_least, usable,
)
from core.discovery import ToolFact
from core.memory import DECISION, PROJECT, RUN, Memory
from core.policy import Policy
from core.probe import ProbeReport
from core.roles import load as load_roles
from core.routing import fallback, route
from tests.fixtures import GHP_SINTETICA
from core.toolplan import install_proposal, plan
from tests.fixtures import Workspace


def graph_with(**states) -> CapabilityGraph:
    g = CapabilityGraph()
    for provider, caps in states.items():
        g.merge({name: Capability(name, st, provider, "prueba") for name, st in caps.items()},
                provider=provider)
    return g


class TestCapacidades(unittest.TestCase):
    def test_solo_functional_y_verified_sirven_para_planificar(self):
        for st in (FUNCTIONAL, "VERIFIED"):
            self.assertTrue(usable(st))
        for st in (MISSING, "DETECTED", "INSTALLED", AVAILABLE, BLOCKED):
            self.assertFalse(usable(st), st)

    def test_blocked_no_se_compara_como_un_peldano(self):
        """BLOCKED no es «menos que FUNCTIONAL»: es una salida lateral."""
        self.assertFalse(at_least(BLOCKED, AVAILABLE))
        self.assertFalse(at_least(AVAILABLE, BLOCKED))
        self.assertTrue(at_least(BLOCKED, BLOCKED))

    def test_un_agente_que_no_arranca_da_capacidades_BLOCKED_no_MISSING(self):
        """La diferencia importa: MISSING invita a instalar algo que ya está instalado."""
        from core.capability import from_probe
        rep = ProbeReport(agent="codex", level="INSTALLED", version="0.103.0",
                          executable="/usr/bin/codex", stopped_because="muerto por señal 9")
        caps = from_probe(rep)
        self.assertTrue(caps)
        self.assertTrue(all(c.state == BLOCKED for c in caps.values()))

    def test_un_agente_no_instalado_no_aporta_capacidades(self):
        from core.capability import from_probe
        self.assertEqual(from_probe(ProbeReport(agent="x", level="NOT_INSTALLED")), {})

    def test_el_grafo_toma_el_estado_mas_fuerte(self):
        g = graph_with(a={"agent.mcp": AVAILABLE}, b={"agent.mcp": FUNCTIONAL})
        self.assertEqual(g.state("agent.mcp"), FUNCTIONAL)

    def test_un_bloqueado_no_tapa_a_uno_que_funciona(self):
        g = graph_with(roto={"agent.mcp": BLOCKED}, bueno={"agent.mcp": FUNCTIONAL})
        self.assertEqual(g.state("agent.mcp"), FUNCTIONAL)
        self.assertEqual(g.providers_for(["agent.mcp"]), ["bueno"])


class TestHerramientas(unittest.TestCase):
    def facts(self, **present) -> list:
        return [ToolFact(name=n, present=v, category="x", why="porque sí")
                for n, v in present.items()]

    def test_un_proyecto_de_rust_no_necesita_maven(self):
        p = plan(ecosystems=["cargo"], phases=["IMPLEMENT"],
                 tool_facts=self.facts(cargo=True, git=True, mvn=False))
        self.assertNotIn("mvn", [t["name"] for t in p["tools"]])

    def test_lo_requerido_y_ausente_bloquea(self):
        p = plan(ecosystems=["container"], phases=[], tool_facts=self.facts(docker=False))
        self.assertIn("docker", p["blockers"])
        self.assertEqual(p["summary"]["required_missing"], 1)

    def test_toda_necesidad_dice_por_que(self):
        p = plan(ecosystems=["node"], phases=["SECURE"], tool_facts=self.facts())
        for t in p["tools"]:
            self.assertTrue(t["reasons"], f"{t['name']} no dice por qué se necesita")

    def test_nunca_propone_ejecutar_un_script_remoto(self):
        p = plan(ecosystems=list({"node", "container", "terraform", "helm", "python"}),
                 phases=["SECURE", "DEPLOY", "OBSERVE", "RELEASE", "VALIDATE"],
                 tool_facts=self.facts())
        for t in p["tools"]:
            hint = (t["install_hint"] or "").lower()
            self.assertNotIn("| sh", hint, t["name"])
            self.assertNotIn("| bash", hint, t["name"])

    def test_la_propuesta_no_ejecuta_nada(self):
        prop = install_proposal(plan(ecosystems=["node"], phases=["SECURE"],
                                     tool_facts=self.facts()))
        self.assertIn("se ha ejecutado", prop["note"])
        self.assertIn("Ninguna", prop["note"])

    def test_lo_que_pide_privilegios_no_es_auto_instalable(self):
        p = plan(ecosystems=["container"], phases=[], tool_facts=self.facts(docker=False))
        docker = next(t for t in p["tools"] if t["name"] == "docker")
        self.assertFalse(docker["auto_installable"])


class TestEnrutado(unittest.TestCase):
    def setUp(self):
        self.specs = __import__("adapters.registry", fromlist=["ADAPTERS"]).ADAPTERS
        self.policy = Policy.default()

    def test_elige_por_capacidad_no_por_nombre(self):
        g = graph_with(kiro={"agent.headless": FUNCTIONAL, "agent.tool_use": FUNCTIONAL},
                       claude={"agent.headless": FUNCTIONAL})
        d = route("frontend-engineer", g, self.specs)
        self.assertEqual(d.chosen, "kiro", d.explain())
        self.assertIn("claude", d.rejected)

    def test_prefiere_donde_la_politica_SI_se_aplica(self):
        """La primera versión ordenaba por «menor superficie» y elegía sistemáticamente el
        único runtime donde la política NO se aplica. Exactamente al revés."""
        g = graph_with(opencode={"agent.headless": FUNCTIONAL, "agent.tool_use": FUNCTIONAL},
                       claude={"agent.headless": FUNCTIONAL, "agent.tool_use": FUNCTIONAL})
        d = route("frontend-engineer", g, self.specs, policy=self.policy)
        self.assertEqual(d.chosen, "claude", d.explain())
        self.assertEqual(d.status, "READY")

    def test_si_falta_una_capacidad_del_entorno_ningun_agente_lo_arregla(self):
        g = graph_with(claude={"agent.headless": FUNCTIONAL, "agent.tool_use": FUNCTIONAL})
        d = route("visual-validator", g, self.specs)
        self.assertEqual(d.status, "BLOCKED")
        self.assertIn("browser.automation", d.missing_capabilities)

    def test_un_runtime_bloqueado_se_descarta_con_motivo(self):
        g = graph_with(codex={"agent.headless": BLOCKED},
                       kiro={"agent.headless": FUNCTIONAL})
        d = route("reviewer", g, self.specs)
        self.assertEqual(d.chosen, "kiro")
        self.assertIn("bloqueada", d.rejected["codex"])

    def test_toda_decision_explica_por_que(self):
        g = graph_with(kiro={"agent.headless": FUNCTIONAL})
        d = route("reviewer", g, self.specs)
        self.assertTrue(d.rationale)
        self.assertIn("kiro", d.explain())

    def test_el_fallback_no_cambia_en_silencio_si_baja_el_control(self):
        g = graph_with(claude={"agent.headless": FUNCTIONAL, "agent.tool_use": FUNCTIONAL},
                       opencode={"agent.headless": FUNCTIONAL, "agent.tool_use": FUNCTIONAL})
        d = route("frontend-engineer", g, self.specs, policy=self.policy)
        f = fallback(d, g, self.specs, failed=d.chosen, policy=self.policy)
        self.assertEqual(f.chosen, "opencode")
        self.assertTrue(f.needs_confirmation, "sustituyó en silencio bajando el control")

    def test_el_fallback_nunca_reelige_al_que_fallo(self):
        """`prefer` no bastaba: el criterio de orden pone la política por delante de la
        preferencia, así que el que acababa de fallar volvía a salir elegido."""
        g = graph_with(claude={"agent.headless": FUNCTIONAL, "agent.tool_use": FUNCTIONAL},
                       kiro={"agent.headless": FUNCTIONAL, "agent.tool_use": FUNCTIONAL})
        d = route("frontend-engineer", g, self.specs, policy=self.policy)
        f = fallback(d, g, self.specs, failed=d.chosen, policy=self.policy)
        self.assertNotEqual(f.chosen, d.chosen, f.explain())
        self.assertIn(d.chosen, f.rejected)

    def test_sin_sustituto_queda_bloqueado(self):
        g = graph_with(kiro={"agent.headless": FUNCTIONAL})
        d = route("reviewer", g, self.specs)
        f = fallback(d, g, self.specs, failed="kiro")
        self.assertEqual(f.status, "BLOCKED")


class TestMemoria(unittest.TestCase):
    def test_la_memoria_no_guarda_secretos(self):
        with Workspace("mem") as ws:
            m = Memory(ws.root)
            p = m.remember(PROJECT, "k", f"token {GHP_SINTETICA}")
            self.assertNotIn(GHP_SINTETICA[:10], p.read_text(encoding="utf-8"))
            self.assertIn("redactado", m.recall(PROJECT, "k").tags)

    def test_la_capa_efimera_no_se_persiste(self):
        with Workspace("mem2") as ws:
            with self.assertRaises(ValueError):
                Memory(ws.root).remember("ephemeral", "k", "x")

    def test_las_decisiones_no_se_borran_se_sustituyen(self):
        with Workspace("mem3") as ws:
            m = Memory(ws.root)
            m.remember(DECISION, "d", "creíamos X")
            with self.assertRaises(ValueError):
                m.clear(DECISION)
            self.assertTrue(m.supersede(DECISION, "d", by="d2"))
            self.assertEqual([n.key for n in m.search("creíamos")], [])
            self.assertEqual([n.key for n in m.search("creíamos", include_superseded=True)], ["d"])

    def test_run_si_se_vacia(self):
        with Workspace("mem4") as ws:
            m = Memory(ws.root)
            m.remember(RUN, "a", "x")
            self.assertEqual(m.clear(RUN), 1)

    def test_memoria_y_evidencia_viven_en_sitios_distintos(self):
        """Mezclarlas arruina las dos: la evidencia deja de probar y la memoria de servir."""
        from core.evidence import ledger_path
        with Workspace("mem5") as ws:
            p = Memory(ws.root).remember(PROJECT, "k", "algo que recordar")
            self.assertNotIn(str(ledger_path(ws.root).parent), str(p))


class TestVinculo(unittest.TestCase):
    def _repo(self, ws, rel):
        r = ws.root / rel
        r.mkdir(parents=True, exist_ok=True)
        subprocess.run(["git", "init", "-q"], cwd=r, capture_output=True)
        return r

    def test_el_vinculo_gana_a_la_heuristica(self):
        from core.binding import bind_repo, write
        from core.discovery import _apply_binding
        with Workspace("bind") as ws:
            a, b = self._repo(ws, "a"), self._repo(ws, "b")
            write(ws.root, [bind_repo({"subject": str(b), "commit": "", "remote": ""})])
            block = {"outcome": "ASK", "chosen": None,
                     "candidates": [{"subject": str(a)}, {"subject": str(b)}], "question": "?"}
            out = _apply_binding(block, __import__("core.binding", fromlist=["read"]).read(ws.root),
                                 "repository")
            self.assertEqual(out["outcome"], "AUTO")
            self.assertEqual(Path(out["chosen"]["subject"]), b)

    def test_un_vinculo_a_algo_que_ya_no_esta_pide_revincular_no_adivina(self):
        from core.binding import bind_repo, read, write
        from core.discovery import _apply_binding
        with Workspace("bind2") as ws:
            a = self._repo(ws, "a")
            write(ws.root, [bind_repo({"subject": "/ya/no/existe", "commit": "", "remote": ""})])
            out = _apply_binding({"outcome": "AUTO", "chosen": {"subject": str(a)},
                                  "candidates": [{"subject": str(a)}]},
                                 read(ws.root), "repository")
            self.assertEqual(out["outcome"], "ASK")
            self.assertTrue(out["binding_stale"])

    def test_un_commit_distinto_es_un_problema_no_una_actualizacion(self):
        from core.binding import verify, write, Binding
        with Workspace("bind3") as ws:
            write(ws.root, [Binding(kind="sdd_core", path=str(ws.root), commit="a" * 40,
                                    version="1.0.0")])
            disc = {"sdd_core": {"candidates": [{"subject": str(ws.root), "commit": "b" * 40,
                                                 "version": "1.0.0"}]},
                    "repository": {"candidates": []}}
            out = verify(ws.root, disc)
            self.assertTrue(any("No se acepta solo" in p for p in out["problems"]), out)

    def test_decide_nunca_elige_un_ambiguo(self):
        from core.binding import decide
        block = {"outcome": "ASK", "chosen": None, "question": "¿cuál?",
                 "candidates": [{"subject": "/a"}, {"subject": "/b"}]}
        cand, why = decide(block, what="el núcleo")
        self.assertIsNone(cand)
        self.assertIn("cuál", why)


class TestRoles(unittest.TestCase):
    def test_el_registro_real_es_valido(self):
        from core.roles import validate_registry
        self.assertEqual(validate_registry(), [])

    def test_ningun_rol_de_solo_lectura_pide_consola(self):
        for r in load_roles().values():
            if "no_shell" in r.constraints:
                self.assertNotIn("shell", r.allowed_tools, r.id)

    def test_el_revisor_no_puede_aprobarse_a_si_mismo(self):
        self.assertIn("no_self_approval", load_roles()["reviewer"].constraints)

    def test_el_revisor_adversarial_no_arregla_lo_que_critica(self):
        r = load_roles()["adversarial-reviewer"]
        self.assertIn("no_fix_what_it_reviews", r.constraints)
        self.assertNotIn("write", r.allowed_tools)

    def test_el_validador_visual_observa_y_no_repara(self):
        self.assertIn("no_modify_product", load_roles()["visual-validator"].constraints)

    def test_toda_cadena_de_traspaso_termina(self):
        from core.roles import chain_from
        for rid in load_roles():
            self.assertLessEqual(len(chain_from(rid)), len(load_roles()), rid)
