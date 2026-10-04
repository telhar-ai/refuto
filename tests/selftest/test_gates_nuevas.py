# -*- coding: utf-8 -*-
"""Auto-prueba de las puertas de plataforma: trazabilidad, seguridad, PR, revisión y roles.

Mismo contrato que el resto: positivo, negativo, entrada corrupta y dependencia ausente.
"""

from __future__ import annotations

import json
import os
import subprocess
from pathlib import Path

from core.model import BLOCKED, FAIL, NOT_EXECUTABLE, PASS
from gates.base import run_gate
from tests.fixtures import AKIA_SINTETICA, Workspace
from tests.selftest.test_gates import GateCase


def git_repo(ws: Workspace, branch: str = "trabajo") -> Path:
    r = ws.root
    env = {**os.environ, "GIT_AUTHOR_NAME": "a", "GIT_AUTHOR_EMAIL": "a@b",
           "GIT_COMMITTER_NAME": "a", "GIT_COMMITTER_EMAIL": "a@b"}
    subprocess.run(["git", "init", "-q", "-b", "main"], cwd=r, capture_output=True, env=env)
    (r / "README.md").write_text("# x\n", encoding="utf-8")
    subprocess.run(["git", "add", "-A"], cwd=r, capture_output=True, env=env)
    subprocess.run(["git", "commit", "-qm", "inicial"], cwd=r, capture_output=True, env=env)
    if branch != "main":
        subprocess.run(["git", "checkout", "-qb", branch], cwd=r, capture_output=True, env=env)
    return r


def commit(ws: Workspace, message: str) -> None:
    env = {**os.environ, "GIT_AUTHOR_NAME": "a", "GIT_AUTHOR_EMAIL": "a@b",
           "GIT_COMMITTER_NAME": "a", "GIT_COMMITTER_EMAIL": "a@b"}
    subprocess.run(["git", "add", "-A"], cwd=ws.root, capture_output=True, env=env)
    subprocess.run(["git", "commit", "-qm", message], cwd=ws.root, capture_output=True, env=env)


# ── G-TRACE ──────────────────────────────────────────────────────────────────────────
class TestGateTrace(GateCase):
    def _spec(self, ws, ids=("REQ-001", "REQ-002")):
        body = "\n".join(f"### {i}\nCuando ocurra X el sistema hará Y.\n" for i in ids)
        ws.file("requirements.md", f"# Requisitos\n\n{body}")

    def test_positivo(self):
        with Workspace("tr-ok") as ws:
            ws.manifest()
            self._spec(ws)
            ws.file("app/x.js", "// REQ-001 REQ-002\nexport const x = 1;\n")
            ws.file("tests/x.test.js", "it('[REQ-001] hace X', () => {});\n"
                                       "it('[REQ-002] hace Y', () => {});\n")
            self.assert_status(run_gate("G-TRACE", ws.context()), PASS)

    def test_negativo_cita_fantasma(self):
        """El defecto medido en un repositorio real: pruebas que citan REQ-022/023/024,
        que no existen."""
        with Workspace("tr-ghost") as ws:
            ws.manifest()
            self._spec(ws, ["REQ-001"])
            ws.file("tests/x.test.js", "it('[REQ-001] a', ()=>{});\nit('[REQ-099] b', ()=>{});\n")
            r = run_gate("G-TRACE", ws.context())
            self.assert_status(r, FAIL)
            self.assertTrue(any("REQ-099" in f.as_text() for f in r.findings))

    def test_negativo_requisito_sin_prueba(self):
        with Workspace("tr-untested") as ws:
            ws.manifest()
            self._spec(ws, ["REQ-001", "REQ-002"])
            ws.file("tests/x.test.js", "it('[REQ-001] a', ()=>{});\n")
            r = run_gate("G-TRACE", ws.context())
            self.assert_status(r, FAIL)
            self.assertTrue(any("REQ-002" in f.as_text() for f in r.findings))

    def test_no_indexa_las_fixtures_del_propio_verificador(self):
        """`verificacion/` contiene identificadores falsos a propósito. Indexarlos hacía que el
        juez encontrara sus propias fixtures y las declarara citas fantasma del proyecto."""
        with Workspace("tr-fixture") as ws:
            ws.manifest()
            self._spec(ws, ["REQ-001"])
            ws.file("tests/x.test.js", "it('[REQ-001] a', ()=>{});\n")
            ws.file("verificacion/pruebas.py", '"**REQ-099** · requisito de prueba"\n')
            self.assert_status(run_gate("G-TRACE", ws.context()), PASS)

    def test_dependencia_ausente(self):
        with Workspace("tr-none") as ws:
            ws.manifest()
            self.assert_status(run_gate("G-TRACE", ws.context()), BLOCKED)


# ── G-HUMAN ──────────────────────────────────────────────────────────────────────────
class TestGateHuman(GateCase):
    def _review(self, ws, kind, subject, **over):
        from core import humanreview as HR
        p = HR.request(ws.root, kind, subject, generated_by="agente@x")
        d = json.loads(p.read_text(encoding="utf-8"))
        d.update(over)
        p.write_text(json.dumps(d, ensure_ascii=False, indent=2), encoding="utf-8")
        return p

    def test_positivo(self):
        from core import humanreview as HR
        with Workspace("hr-ok") as ws:
            ws.manifest(roles=["visual-validator"])
            self._review(ws, HR.VISUAL, "pantalla", decision="APPROVED",
                         reviewer="Persona Dos", reviewer_email="dos@x")
            self.assert_status(run_gate("G-HUMAN", ws.context()), PASS)

    def test_negativo_auto_aprobacion(self):
        """Quien revisa no puede ser quien generó. Es una firma, no una revisión."""
        from core import humanreview as HR
        with Workspace("hr-self") as ws:
            ws.manifest(roles=["visual-validator"])
            self._review(ws, HR.VISUAL, "pantalla", decision="APPROVED",
                         reviewer="El Mismo", reviewer_email="agente@x")
            r = run_gate("G-HUMAN", ws.context())
            self.assert_status(r, FAIL)
            self.assertTrue(any("quien generó" in f.as_text() for f in r.findings))

    def test_negativo_aprobada_sin_nombre(self):
        from core import humanreview as HR
        with Workspace("hr-anon") as ws:
            ws.manifest(roles=["visual-validator"])
            self._review(ws, HR.VISUAL, "pantalla", decision="APPROVED")
            self.assert_not_pass(run_gate("G-HUMAN", ws.context()))

    def test_falta_una_revision_obligatoria_bloquea_no_aprueba(self):
        with Workspace("hr-missing") as ws:
            ws.manifest(roles=["visual-validator"])
            self.assert_status(run_gate("G-HUMAN", ws.context()), BLOCKED)

    def test_entrada_corrupta(self):
        from core import humanreview as HR
        with Workspace("hr-corrupt") as ws:
            ws.manifest(roles=["visual-validator"])
            ws.file(f".harness/{HR.DIR}/human_visual_review--x.json", "{{{ no json")
            self.assert_not_pass(run_gate("G-HUMAN", ws.context()))

    def test_dependencia_ausente(self):
        with Workspace("hr-norole") as ws:
            ws.manifest(roles=["technical-writer"])       # no exige revisión humana
            self.assert_status(run_gate("G-HUMAN", ws.context()), BLOCKED)


# ── G-PR ─────────────────────────────────────────────────────────────────────────────
class TestGatePr(GateCase):
    def test_negativo_trabajando_sobre_la_rama_por_defecto(self):
        with Workspace("pr-main") as ws:
            ws.manifest()
            git_repo(ws, branch="main")
            r = run_gate("G-PR", ws.context())
            self.assert_status(r, FAIL)
            self.assertTrue(any("directamente sobre" in f.as_text() for f in r.findings))

    def test_negativo_ningun_commit_cita_un_requisito(self):
        with Workspace("pr-notrace") as ws:
            ws.manifest()
            git_repo(ws, branch="trabajo")
            ws.file("app/x.js", "1")
            commit(ws, "arreglos varios")
            r = run_gate("G-PR", ws.context())
            self.assert_status(r, FAIL)
            self.assertTrue(any("cita un requisito" in f.as_text() for f in r.findings))

    def test_positivo_rama_propia_y_commit_trazado(self):
        with Workspace("pr-ok") as ws:
            ws.manifest()
            git_repo(ws, branch="folio/REQ-001")
            ws.file("app/x.js", "1")
            commit(ws, "feat: implementa REQ-001")
            r = run_gate("G-PR", ws.context())
            # PASS o BLOCKED según haya o no revisión humana registrada; nunca FAIL.
            self.assertIn(r.status, (PASS, BLOCKED), r.measure)

    def test_dependencia_ausente(self):
        with Workspace("pr-nogit") as ws:
            ws.manifest()
            self.assert_status(run_gate("G-PR", ws.context()), BLOCKED)


# ── G-SECURITY ───────────────────────────────────────────────────────────────────────
class TestGateSecurity(GateCase):
    def test_negativo_secreto_en_el_arbol(self):
        with Workspace("sec-leak") as ws:
            ws.manifest()
            ws.file("app/config.js", f"const k = '{AKIA_SINTETICA}';\n")
            r = run_gate("G-SECURITY", ws.context())
            self.assert_status(r, FAIL)
            self.assertTrue(any("secreto" in f.as_text() for f in r.findings))

    def test_sin_herramientas_bloquea_no_aprueba(self):
        """La regla que da sentido a esta puerta: sin escáner, BLOCKED. Un pipeline en verde
        porque el escáner no estaba es peor que no tener pipeline."""
        with Workspace("sec-clean") as ws:
            ws.manifest()
            ws.file("app/x.js", "export const x = 1;\n")
            r = run_gate("G-SECURITY", ws.context())
            self.assertIn(r.status, (PASS, BLOCKED, NOT_EXECUTABLE))
            if r.status in (BLOCKED, NOT_EXECUTABLE):
                self.assertTrue(any("BLOCKED" in o or "NO está" in o or "NOT_EXECUTABLE" in o for o in r.observations))

    def test_no_confunde_un_binario_con_texto(self):
        with Workspace("sec-bin") as ws:
            ws.manifest()
            (ws.root / "app").mkdir(parents=True, exist_ok=True)
            (ws.root / "app" / "logo.png").write_bytes(b"\x89PNG\r\n" + AKIA_SINTETICA[:4].encode() * 200)
            r = run_gate("G-SECURITY", ws.context())
            self.assertFalse(any("logo.png" in f.as_text() for f in r.findings))


# ── G-ROLES ──────────────────────────────────────────────────────────────────────────
class TestGateRoles(GateCase):
    def test_positivo_el_registro_real_valida(self):
        with Workspace("rol-ok") as ws:
            ws.manifest()
            self.assert_status(run_gate("G-ROLES", ws.context()), PASS)

    def test_negativo_restriccion_que_el_harness_no_sabe_aplicar(self):
        """Una restricción declarada y no aplicable se cita como si protegiera. No protege."""
        import tempfile
        from core.roles import validate_registry
        doc = json.loads((Path("roles/registry.json")).read_text(encoding="utf-8"))
        doc["roles"][0]["constraints"].append("no_hacer_el_mal")
        with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False, encoding="utf-8") as fh:
            json.dump(doc, fh, ensure_ascii=False)
            tmp = fh.name
        problems = validate_registry(tmp)
        os.unlink(tmp)
        # Se fija la PROPIEDAD —la restricción inventada se detecta y se nombra— y no el texto
        # del mensaje. Fijaba la cadena «no sabe aplicar», y al corregir el criterio del 2026-09-25
        # —de `KNOWN_CONSTRAINTS`, que es prosa, a `capabilities.CONOCIDAS`, que es aplicación—
        # la prueba cayó teniendo el control MÁS fuerte que antes. Una prueba que se rompe al
        # arreglar lo que vigila estaba fijando la implementación, no el contrato.
        self.assertTrue(any("no_hacer_el_mal" in p for p in problems), problems)

    def test_negativo_traspaso_a_un_rol_inexistente(self):
        import tempfile
        from core.roles import validate_registry
        doc = json.loads((Path("roles/registry.json")).read_text(encoding="utf-8"))
        doc["roles"][0]["handoff"] = ["rol-que-no-existe"]
        with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False, encoding="utf-8") as fh:
            json.dump(doc, fh, ensure_ascii=False)
            tmp = fh.name
        problems = validate_registry(tmp)
        os.unlink(tmp)
        self.assertTrue(any("no es un rol" in p for p in problems), problems)

    def test_entrada_corrupta(self):
        import tempfile
        from core.roles import validate_registry
        with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False, encoding="utf-8") as fh:
            fh.write("{{{ roto")
            tmp = fh.name
        problems = validate_registry(tmp)
        os.unlink(tmp)
        self.assertTrue(problems)
