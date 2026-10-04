# -*- coding: utf-8 -*-
"""Higiene del permiso. Cada prueba fija una forma concreta de podar mal.

Podar de menos deja el agujero. Podar de más rompe permisos legítimos y empuja a la persona a
volver a aprobarlo todo a lo ancho, que termina en un agujero mayor. Las dos importan.
"""

from __future__ import annotations

import json
import unittest
from pathlib import Path

from core.hygiene import (
    HUECO, INERTE, MUERTA, analizar, es_inerte, esta_muerta, podar, tiene_hueco,
)
from tests.fixtures import Workspace

VIVO = "/private/tmp/claude-0/-Users-x-repo/11111111-1111-1111-1111-111111111111"
MUERTO = "/private/tmp/claude-0/-Users-x-repo/22222222-2222-2222-2222-222222222222"


def existe(p: Path) -> bool:
    return str(p) == VIVO


class TestHueco(unittest.TestCase):

    def test_el_sufijo_dos_puntos_asterisco_es_legitimo(self):
        """`Bash(git push:*)` acota un prefijo. Es la forma correcta y no se toca."""
        self.assertFalse(tiene_hueco("Bash(git push:*)"))
        self.assertFalse(tiene_hueco("Bash(kubectl get:*)"))

    def test_sin_comodin_no_hay_hueco(self):
        self.assertFalse(tiene_hueco("Bash(git status)"))

    def test_comodin_en_medio_SI_es_hueco(self):
        self.assertTrue(tiene_hueco("Bash(tar --exclude=*/target -czf x.tgz .)"))

    def test_el_caso_real_mas_grave(self):
        """Aprobaba cualquier orden ejecutada con privilegios por SSH contra un host real."""
        self.assertTrue(tiene_hueco("Bash(sudo -u operador -H ssh host-de-pruebas ' *)"))

    def test_los_globs_de_lectura_NO_son_huecos(self):
        """En `Read`/`Edit` el contenido es una ruta: el comodín es un glob y significa lo que parece.

        Tratarlos como órdenes y podarlos sería introducir un defecto mientras se arregla otro.
        """
        self.assertFalse(tiene_hueco("Read(docs/**)"))
        self.assertFalse(tiene_hueco("Read(//home/x/*.md)"))
        self.assertFalse(tiene_hueco("Edit(docs/architecture/*)"))

    def test_regla_sin_parentesis_no_revienta(self):
        self.assertFalse(tiene_hueco("WebFetch"))


class TestMuerta(unittest.TestCase):

    def test_scratchpad_inexistente(self):
        self.assertTrue(esta_muerta(f"Bash(cat {MUERTO}/x.json)", existe=existe))

    def test_scratchpad_vivo_se_conserva(self):
        self.assertFalse(esta_muerta(f"Bash(cat {VIVO}/x.json)", existe=existe))

    def test_sin_scratchpad_no_aplica(self):
        self.assertFalse(esta_muerta("Bash(git status)", existe=existe))

    def test_forma_no_reconocida_se_deja_en_paz(self):
        """Podar por sospecha es podar de más."""
        self.assertFalse(esta_muerta("Bash(cat /private/tmp/otra-cosa/x)", existe=existe))


class TestInerte(unittest.TestCase):

    def test_write_es_inerte(self):
        self.assertTrue(es_inerte("Write(docs/architecture/*)"))

    def test_edit_no_lo_es(self):
        self.assertFalse(es_inerte("Edit(docs/architecture/*)"))


class TestAnalizar(unittest.TestCase):

    def test_clasifica_y_conserva_lo_sano(self):
        reglas = [
            "Bash(git status)",                       # sana
            "Bash(git push:*)",                       # sana (prefijo)
            "Read(docs/**)",                          # sana (glob)
            "Bash(sudo -u x -H ssh h ' *)",           # hueco
            f"Bash(cat {MUERTO}/x)",                  # muerta
            f"Bash(cat {VIVO}/x)",                    # sana
            "Write(docs/a/*)",                        # inerte
        ]
        inf = analizar(reglas, existe=existe)

        self.assertEqual(7, inf.total)
        self.assertEqual(3, inf.retiradas)
        self.assertEqual(4, len(inf.conserva))
        self.assertEqual(HUECO, inf.retira["Bash(sudo -u x -H ssh h ' *)"])
        self.assertEqual(MUERTA, inf.retira[f"Bash(cat {MUERTO}/x)"])
        self.assertEqual(INERTE, inf.retira["Write(docs/a/*)"])
        self.assertIn("Bash(git push:*)", inf.conserva)
        self.assertIn("Read(docs/**)", inf.conserva)

    def test_una_regla_se_retira_por_un_solo_motivo(self):
        """Una regla con hueco Y scratchpad muerto cuenta una vez, no dos."""
        reglas = [f"Bash(cat {MUERTO}/* )"]
        inf = analizar(reglas, existe=existe)
        self.assertEqual(1, inf.retiradas)
        self.assertEqual(HUECO, list(inf.retira.values())[0])
        self.assertEqual({HUECO: 1}, inf.por_motivo_crudo())

    def test_lista_vacia(self):
        inf = analizar([], existe=existe)
        self.assertEqual(0, inf.total)
        self.assertEqual(0, inf.retiradas)



class TestPodar(unittest.TestCase):

    def _settings(self, ws: Workspace, reglas: list) -> Path:
        return ws.json(".claude/settings.local.json",
                       {"permissions": {"allow": reglas, "deny": []}, "hooks": {"PreToolUse": []}})

    def test_en_seco_no_escribe(self):
        with Workspace("pod-seco") as ws:
            p = self._settings(ws, ["Bash(sudo ssh h ' *)", "Bash(git status)"])
            antes = p.read_text(encoding="utf-8")

            res = podar(p, dry_run=True, existe=existe)

            self.assertEqual(antes, p.read_text(encoding="utf-8"))
            self.assertEqual(1, res["retiradas"])
            self.assertEqual("", res["copia"])

    def test_poda_de_verdad_y_deja_copia(self):
        with Workspace("pod-real") as ws:
            p = self._settings(ws, ["Bash(sudo ssh h ' *)", "Bash(git status)",
                                    f"Bash(cat {MUERTO}/x)"])

            res = podar(p, dry_run=False, existe=existe)

            doc = json.loads(p.read_text(encoding="utf-8"))
            self.assertEqual(["Bash(git status)"], doc["permissions"]["allow"])
            self.assertEqual(2, res["retiradas"])
            self.assertTrue(Path(res["copia"]).is_file())
            copia = json.loads(Path(res["copia"]).read_text(encoding="utf-8"))
            self.assertEqual(3, len(copia["permissions"]["allow"]))

    def test_no_toca_lo_que_no_es_permissions(self):
        """Podar permisos no puede tirar los ganchos: el guardián vive ahí."""
        with Workspace("pod-hooks") as ws:
            p = self._settings(ws, ["Bash(sudo ssh h ' *)"])
            podar(p, dry_run=False, existe=existe)
            doc = json.loads(p.read_text(encoding="utf-8"))
            self.assertIn("hooks", doc)
            self.assertIn("PreToolUse", doc["hooks"])
            self.assertIn("deny", doc["permissions"])

    def test_nada_que_podar_no_deja_copia(self):
        with Workspace("pod-limpio") as ws:
            p = self._settings(ws, ["Bash(git status)"])
            res = podar(p, dry_run=False, existe=existe)
            self.assertEqual(0, res["retiradas"])
            self.assertEqual("", res["copia"])


if __name__ == "__main__":
    unittest.main()
