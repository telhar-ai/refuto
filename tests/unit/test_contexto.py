# -*- coding: utf-8 -*-
"""Contexto persistente: lo que hace que un agente abierto **a secas** sepa dónde está.

El fallo que estas pruebas fijan: refuto enganchaba el control pero no dejaba contexto, así
que `claude` en un espacio gobernado se presentaba como asistente genérico y ofrecía «explorar
el repo». El control estaba; la conciencia de estar gobernado, no.
"""

from __future__ import annotations

import unittest

from core import context_files as CF
from tests.fixtures import Workspace


class TestBloqueDelimitado(unittest.TestCase):
    def test_crea_el_archivo_si_no_existe(self):
        with Workspace("cf1") as ws:
            r = CF.upsert(ws.root / "CLAUDE.md", "BLOQUE")
            self.assertEqual(r.action, "created")
            self.assertEqual((ws.root / "CLAUDE.md").read_text(encoding="utf-8").strip(), "BLOQUE")

    def test_NO_pisa_lo_que_alguien_escribio(self):
        """Pisar el trabajo de alguien para instalar contexto es empezar mal."""
        with Workspace("cf2") as ws:
            p = ws.file("CLAUDE.md", "# Mi proyecto\n\nReglas mías que importan.\n")
            CF.upsert(p, f"{CF.INICIO}\ngenerado\n{CF.FIN}")
            texto = p.read_text(encoding="utf-8")
            self.assertIn("Reglas mías que importan", texto)
            self.assertIn("generado", texto)

    def test_reemplaza_su_propio_bloque_sin_duplicarlo(self):
        with Workspace("cf3") as ws:
            p = ws.file("CLAUDE.md", "cabecera\n")
            CF.upsert(p, f"{CF.INICIO}\nv1\n{CF.FIN}")
            CF.upsert(p, f"{CF.INICIO}\nv2\n{CF.FIN}")
            texto = p.read_text(encoding="utf-8")
            self.assertEqual(texto.count(CF.INICIO), 1)
            self.assertIn("v2", texto)
            self.assertNotIn("v1", texto)
            self.assertIn("cabecera", texto)

    def test_se_puede_retirar_dejando_lo_ajeno(self):
        with Workspace("cf4") as ws:
            p = ws.file("CLAUDE.md", "mío\n")
            CF.upsert(p, f"{CF.INICIO}\ngenerado\n{CF.FIN}")
            CF.remove(p)
            texto = p.read_text(encoding="utf-8")
            self.assertIn("mío", texto)
            self.assertNotIn("generado", texto)

    def test_si_solo_habia_bloque_el_archivo_desaparece(self):
        with Workspace("cf5") as ws:
            p = ws.root / "CLAUDE.md"
            CF.upsert(p, f"{CF.INICIO}\nx\n{CF.FIN}")
            CF.remove(p)
            self.assertFalse(p.exists())


class TestInstalacion(unittest.TestCase):
    def test_escribe_el_documento_y_lo_enlaza_en_cada_runtime(self):
        with Workspace("cf6") as ws:
            ws.policy()
            CF.install(ws.root)
            self.assertTrue((ws.root / CF.DOC).is_file())
            for t in CF.TARGETS.values():
                p = ws.root / t["file"]
                self.assertTrue(p.is_file(), t["file"])
                self.assertTrue(CF.BLOQUE.search(p.read_text(encoding="utf-8")), t["file"])

    def test_claude_importa_en_vez_de_duplicar(self):
        """El contenido vive en un sitio; cuatro copias divergen."""
        with Workspace("cf7") as ws:
            ws.policy()
            CF.install(ws.root)
            self.assertIn(f"@{CF.DOC}", (ws.root / "CLAUDE.md").read_text(encoding="utf-8"))

    def test_el_contexto_dice_lo_que_esta_protegido(self):
        with Workspace("cf8") as ws:
            ws.policy()
            CF.install(ws.root)
            texto = (ws.root / CF.DOC).read_text(encoding="utf-8")
            self.assertIn("verificacion/**", texto)
            self.assertIn("fuera de tu control", texto)
            for st in ("PASS", "FAIL", "BLOCKED", "NOT_EXECUTABLE"):
                self.assertIn(st, texto)

    def test_audit_detecta_que_falta(self):
        with Workspace("cf9") as ws:
            ws.policy()
            self.assertFalse(CF.audit(ws.root)["context_doc"])
            CF.install(ws.root)
            out = CF.audit(ws.root)
            self.assertTrue(out["ok"], out)

    def test_audit_detecta_un_enlace_retirado_a_mano(self):
        with Workspace("cf10") as ws:
            ws.policy()
            CF.install(ws.root)
            CF.remove(ws.root / "CLAUDE.md")
            self.assertFalse(CF.audit(ws.root)["ok"])

    def test_desinstalar_lo_deja_todo_limpio(self):
        with Workspace("cf11") as ws:
            ws.policy()
            CF.install(ws.root)
            CF.uninstall(ws.root)
            self.assertFalse((ws.root / CF.DOC).exists())
            for t in CF.TARGETS.values():
                p = ws.root / t["file"]
                if p.exists():
                    self.assertFalse(CF.BLOQUE.search(p.read_text(encoding="utf-8")))

    def test_kiro_recibe_su_propio_archivo_de_steering(self):
        with Workspace("cf12") as ws:
            ws.policy()
            (ws.root / ".kiro" / "steering").mkdir(parents=True)
            CF.install(ws.root)
            self.assertTrue((ws.root / ".kiro/steering/zz-harness.md").is_file())


class TestSondaSinEnsuciar(unittest.TestCase):
    def test_verify_task_no_escribe_en_el_espacio(self):
        """La sonda dejaba `.harness-probe.txt` en el repositorio de la persona: ensuciaba el
        árbol, salía en `git status` y fallaba en cuanto el directorio no era escribible."""
        import inspect
        from adapters.claude import ClaudeAdapter
        src = inspect.getsource(ClaudeAdapter.verify_task)
        self.assertIn("TemporaryDirectory", src)
        self.assertNotIn('".harness-probe.txt"', src)


class TestChatSinEspacio(unittest.TestCase):
    def test_en_un_espacio_sin_gobernar_avisa_en_vez_de_reventar(self):
        from core.session import plan
        with Workspace("chat-raw") as ws:
            sp = plan(ws.root, runtime="claude")
            self.assertTrue(sp.blockers)
            self.assertTrue(any("refuto install" in b for b in sp.blockers), sp.blockers)
