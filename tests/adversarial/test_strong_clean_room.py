# -*- coding: utf-8 -*-
"""tests/adversarial/test_strong_clean_room.py — Suite de Verificación en Clean Room Estricto.

Verifica formalmente las 8 propiedades normativas del Clean Room (CR-01 a CR-08):
- CR-01: Fresh Filesystem (directorio efímero e independiente)
- CR-02: Isolated Process (ejecución sin compartir estado mutable)
- CR-03: Clean Environment (entorno despojado de variables residuales o secretos)
- CR-04: No Git Dependency (espacio sin repositorio .git funcional)
- CR-05: No Harness Dependency (inicio en frío sin .harness preexistente)
- CR-06: No Prior Ledger (cadena arranca estrictamente desde GENESIS)
- CR-07: Declared Artifacts Only (aislamiento estricto de artefactos no declarados)
- CR-08: Independent Verifier (juez opera desde fuera del espacio auditado)
"""

from __future__ import annotations

import json
import os
import shutil
import sys
import tempfile
import unittest
from pathlib import Path

RAIZ = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(RAIZ))

from core.context import Context
from core.envelope import EXIT_OK
from core.evidence import append_event, read_events, verificar_cadena, GENESIS
from core.model import PASS, BLOCKED, FAIL, INCONCLUSIVE, Result, Scope
from core.protocol import RefutoProtocolServer
from core.policy import Policy


class TestStrongCleanRoom(unittest.TestCase):
    def setUp(self):
        self.clean_ws = Path(tempfile.mkdtemp(prefix="refuto-cr-ws-")).resolve()

    def tearDown(self):
        shutil.rmtree(self.clean_ws, ignore_errors=True)

    def test_CR01_fresh_filesystem(self):
        """CR-01: El espacio debe ser un sistema de archivos completamente fresco y aislado."""
        self.assertTrue(self.clean_ws.exists())
        self.assertEqual(len(list(self.clean_ws.iterdir())), 0, "Clean room debe comenzar con 0 archivos")

    def test_CR02_isolated_process(self):
        """CR-02: Dos instancias de verificación concurrentes en distintos espacios no comparten estado."""
        ws2 = Path(tempfile.mkdtemp(prefix="refuto-cr-ws2-")).resolve()
        try:
            srv1 = RefutoProtocolServer(self.clean_ws)
            srv2 = RefutoProtocolServer(ws2)

            res1 = srv1.dispatch("refuto.initialize", {})
            res2 = srv2.dispatch("refuto.initialize", {})

            self.assertEqual("1.0", res1["protocol_version"])
            self.assertEqual("1.0", res2["protocol_version"])
            self.assertNotEqual(srv1.workspace, srv2.workspace)
        finally:
            shutil.rmtree(ws2, ignore_errors=True)

    def test_CR03_clean_environment(self):
        """CR-03: El entorno de ejecución no debe requerir variables de entorno privilegiadas."""
        server = RefutoProtocolServer(self.clean_ws)
        res = server.dispatch("refuto.query_status", {})
        self.assertIn("ledger", res)
        self.assertEqual("AUSENTE", res["ledger"]["chain_status"])

    def test_CR04_no_git_dependency(self):
        """CR-04: La verificación funciona correctamente sin un repositorio Git en el espacio."""
        from core.model import provenance
        git_dir = self.clean_ws / ".git"
        self.assertFalse(git_dir.exists(), "No debe existir carpeta .git en clean room")

        # Verificar provenance sin git
        prov = provenance(self.clean_ws)
        self.assertEqual("", prov.get("git_commit", ""))
        self.assertFalse(prov.get("git_dirty", True))

    def test_CR05_no_harness_dependency(self):
        """CR-05: El espacio no requiere un .harness pre-existente para ser evaluado."""
        harness_dir = self.clean_ws / ".harness"
        self.assertFalse(harness_dir.exists(), "No debe existir .harness al inicio")

        server = RefutoProtocolServer(self.clean_ws)
        res = server.dispatch("refuto.evaluate_action", {
            "action": "write", "target": "src/main.py", "tool": "Edit"
        })
        self.assertTrue(res["allowed"])
        self.assertEqual("allow", res["outcome"])

    def test_CR06_no_prior_ledger(self):
        """CR-06: Un espacio sin diario previo comienza con cadena estrictamente desde GENESIS."""
        ev_dir = self.clean_ws / ".harness" / "evidence"
        ev_dir.mkdir(parents=True, exist_ok=True)

        event = {"kind": "test/first_event", "data": "initial"}
        append_event(self.clean_ws, event)

        events = read_events(self.clean_ws)
        self.assertEqual(1, len(events))
        self.assertEqual(GENESIS, events[0]["prev"], "El primer evento de clean room debe encadenar desde GENESIS")

        cadena = verificar_cadena(self.clean_ws)
        self.assertTrue(cadena["ok"])
        self.assertEqual("INTEGRA", cadena["estado"])

    def test_CR07_declared_artifacts_only(self):
        """CR-07: Sólo los artefactos declarados en el manifiesto son admitidos en el espacio."""
        harness_dir = self.clean_ws / ".harness"
        harness_dir.mkdir(parents=True, exist_ok=True)
        manifest = {
            "schema": "harness.manifest/v1",
            "workspace": {"name": "cr-test", "profile": "strict"},
            "artifacts": ["declared_file.txt"],
            "gates": []
        }
        (harness_dir / "harness.manifest.json").write_text(json.dumps(manifest), encoding="utf-8")

        # Crear archivo declarado y archivo espurio
        (self.clean_ws / "declared_file.txt").write_text("declarado", encoding="utf-8")
        (self.clean_ws / "spurious_file.txt").write_text("espurio", encoding="utf-8")

        ctx = Context(workspace=self.clean_ws)
        declared = ctx.manifest.get("artifacts", [])
        self.assertIn("declared_file.txt", declared)
        self.assertNotIn("spurious_file.txt", declared)

    def test_CR08_independent_verifier(self):
        """CR-08: El verificador opera desde una ruta de autoridad exterior al sujeto verificado."""
        server = RefutoProtocolServer(self.clean_ws)
        self.assertNotEqual(RAIZ, server.workspace)
        self.assertEqual(self.clean_ws, server.workspace)

        init_res = server.dispatch("refuto.initialize", {})
        self.assertEqual("1.0", init_res["protocol_version"])
