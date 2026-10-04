# -*- coding: utf-8 -*-
"""Descubrimiento. Cada prueba fija una forma concreta de adivinar mal."""

from __future__ import annotations

import json
import subprocess
import unittest
from pathlib import Path

from core.confidence import CIERTO, DESCARTADO, POSIBLE, Scored, resolve
from core.discovery import (
    _cheap_repo_scan, find_cores, find_repositories, inspect_core, scan_environment, scan_tools,
)
from tests.fixtures import Workspace


def make_core(ws: Workspace, rel: str, *, version="1.0.0", files=None, tamper=False):
    """Fabrica un núcleo con manifiesto y huellas reales."""
    import hashlib
    root = ws.root / rel
    (root / "verificacion").mkdir(parents=True, exist_ok=True)
    (root / "estandares").mkdir(parents=True, exist_ok=True)
    entries = []
    for name, content in (files or {"verificacion/comun.py": "X = 1\n",
                                    "estandares/metodo.md": "# método\n"}).items():
        p = root / name
        p.parent.mkdir(parents=True, exist_ok=True)
        # LF explícito: la huella declarada abajo es la del texto tal cual, y sin esto
        # Windows traduciría cada salto a CRLF y el núcleo se declararía manipulado.
        p.write_text(content, encoding="utf-8", newline="\n")
        entries.append({"origen": name, "destino": name,
                        "sha256": hashlib.sha256(content.encode()).hexdigest()})
    if tamper:
        (root / entries[0]["origen"]).write_text("MANIPULADO\n", encoding="utf-8")
    (root / "VERSION").write_text(version + "\n", encoding="utf-8")
    (root / "manifiesto.json").write_text(json.dumps(
        {"nucleo": "prueba", "version": version, "materializa": entries},
        ensure_ascii=False, indent=2), encoding="utf-8")
    return root


def make_repo(ws: Workspace, rel: str, *, stack: str = "package.json") -> Path:
    root = ws.root / rel
    root.mkdir(parents=True, exist_ok=True)
    subprocess.run(["git", "init", "-q"], cwd=root, capture_output=True)
    (root / stack).write_text("{}\n", encoding="utf-8")
    return root


class TestNucleo(unittest.TestCase):
    def test_un_nucleo_valido_es_cierto(self):
        with Workspace("core-ok") as ws:
            root = make_core(ws, "nucleo")
            s = inspect_core(root)
            self.assertEqual(s.level, CIERTO, s.why())
            self.assertIn("íntegro", s.payload["integrity"])

    def test_una_carpeta_llamada_sdd_sin_manifiesto_NO_es_un_nucleo(self):
        """Es la confusión que este módulo existe para no cometer: el nombre no es evidencia."""
        with Workspace("core-fake") as ws:
            fake = ws.root / "sdd"
            (fake / "verificacion").mkdir(parents=True)
            (fake / "estandares").mkdir(parents=True)
            s = inspect_core(fake)
            self.assertNotEqual(s.level, CIERTO)
            self.assertTrue(any("no hay manifiesto" in p for p in s.payload["problems"]))

    def test_un_nucleo_manipulado_pierde_confianza(self):
        with Workspace("core-bad") as ws:
            root = make_core(ws, "nucleo", tamper=True)
            s = inspect_core(root)
            self.assertTrue(any(x.name == "integridad-rota" for x in s.signals))
            self.assertTrue(s.payload["problems"])

    def test_un_manifest_que_es_una_lista_no_revienta(self):
        """`manifest.json` como ARRAY existe en la realidad (catálogos, extensiones). La
        primera versión reventaba el descubrimiento entero por un archivo ajeno."""
        with Workspace("core-list") as ws:
            d = ws.root / "cosa"
            d.mkdir()
            (d / "manifest.json").write_text("[1,2,3]", encoding="utf-8")
            s = inspect_core(d)
            self.assertNotEqual(s.level, CIERTO)

    def test_dos_nucleos_identicos_producen_ASK_no_una_eleccion(self):
        with Workspace("core-two") as ws:
            make_core(ws, "a/nucleo")
            make_core(ws, "b/nucleo")
            out = find_cores([ws.root], max_depth=4)
            self.assertEqual(out["outcome"], "ASK")
            self.assertIsNone(out["chosen"])
            self.assertIn("empatados", out["question"])

    def test_sin_ninguno_devuelve_NONE_y_dice_donde_miro(self):
        with Workspace("core-none") as ws:
            out = find_cores([ws.root], max_depth=3)
            self.assertEqual(out["outcome"], "NONE")
            self.assertTrue(out["searched"])


class TestRepositorio(unittest.TestCase):
    def test_el_repo_que_contiene_el_cwd_gana_sin_discusion(self):
        """Es un hecho, no una señal: no compite con las demás, las gana."""
        with Workspace("repo-cwd") as ws:
            a = make_repo(ws, "a")
            make_repo(ws, "b")
            sub = a / "src"
            sub.mkdir()
            out = find_repositories([ws.root], cwd=sub)
            self.assertEqual(out["outcome"], "AUTO")
            self.assertEqual(Path(out["chosen"]["subject"]).resolve(), a.resolve())
            self.assertIn("dentro de este repositorio", out["note"])

    def test_sin_cwd_dentro_y_con_empate_pregunta(self):
        with Workspace("repo-tie") as ws:
            make_repo(ws, "a")
            make_repo(ws, "b")
            out = find_repositories([ws.root], cwd=ws.root)
            self.assertEqual(out["outcome"], "ASK")

    def test_un_repo_gobernado_puntua_por_encima(self):
        with Workspace("repo-gov") as ws:
            make_repo(ws, "plain")
            gov = make_repo(ws, "gov")
            (gov / ".harness").mkdir()
            a = _cheap_repo_scan(gov, None)
            b = _cheap_repo_scan(ws.root / "plain", None)
            self.assertGreater(a.raw, b.raw)

    def test_un_directorio_sin_git_se_descarta(self):
        with Workspace("repo-nogit") as ws:
            (ws.root / "x").mkdir()
            from core.discovery import inspect_repository
            self.assertEqual(inspect_repository(ws.root / "x").level, DESCARTADO)

    def test_declara_lo_que_no_inspecciono(self):
        with Workspace("repo-many") as ws:
            for i in range(6):
                make_repo(ws, f"r{i}")
            out = find_repositories([ws.root], cwd=ws.root, enrich_top=2)
            self.assertEqual(out["inspected_with_git"], 2)
            self.assertIn("NO inspeccionados", out["truncated"])


class TestEntorno(unittest.TestCase):
    def test_no_revela_el_contenido_de_ninguna_credencial(self):
        """El descubrimiento reporta PRESENCIA. Leer el archivo sería exfiltración."""
        env = scan_environment()
        blob = json.dumps(env)
        for leak in ("aws_secret_access_key", "BEGIN RSA PRIVATE KEY", "ghp_", "AKIA"):
            self.assertNotIn(leak, blob)
        self.assertTrue(all(isinstance(v, bool) for v in env["credential_presence"].values()))

    def test_toda_herramienta_declara_para_que_sirve(self):
        """«Falta X» sin decir para qué es una queja, no un diagnóstico."""
        for t in scan_tools(with_versions=False):
            self.assertTrue(t.why, f"{t.name} no declara para qué se necesita")

    def test_una_herramienta_ausente_se_declara_ausente(self):
        facts = {t.name: t for t in scan_tools(["git", "no-existe-esta-herramienta"],
                                               with_versions=False)}
        self.assertFalse(facts["no-existe-esta-herramienta"].present)


class TestConfianza(unittest.TestCase):
    def test_raw_ordena_y_score_muestra(self):
        """Acotar antes de ordenar empataba a 251 repositorios en 1.00."""
        a = Scored("a").add("x", .6).add("y", .6).add("z", .6)
        b = Scored("b").add("x", .6).add("y", .6)
        self.assertEqual(a.score, 1.0)
        self.assertEqual(b.score, 1.0)
        self.assertGreater(a.raw, b.raw)

    def test_un_hecho_decisivo_gana_a_una_puntuacion_mayor(self):
        alto = Scored("alto").add("x", 1.0).add("y", 1.0)
        decisivo = Scored("dec").add("x", 0.3).settle("es el que contiene el cwd")
        out = resolve([alto, decisivo], what="X")
        self.assertEqual(out["outcome"], "AUTO")
        self.assertEqual(out["chosen"]["subject"], "dec")

    def test_dos_decisivos_no_deciden_nada(self):
        a = Scored("a").add("x", .9).settle("razón")
        b = Scored("b").add("x", .9).settle("razón")
        self.assertEqual(resolve([a, b], what="X")["outcome"], "ASK")

    def test_nunca_elige_por_debajo_de_CIERTO(self):
        p = Scored("p").add("x", 0.4)
        self.assertEqual(p.level, POSIBLE)
        self.assertEqual(resolve([p], what="X")["outcome"], "ASK")
