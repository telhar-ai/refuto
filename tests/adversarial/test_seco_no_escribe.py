# -*- coding: utf-8 -*-
"""`--dry-run` no escribe, y lo que haría lo declara.

El defecto, medido el 2026-10-04
--------------------------------
`launcher.install` se llamaba ANTES de cualquier comprobación de `dry_run`, en los tres
`wire_*`. Así que `refuto policy wire --dry-run` escribía
`.harness/bin/{guard,guard.cmd,installed.json}` —reapuntando el guardián de un espacio a otro
motor— y la salida sólo hablaba de `.claude/settings.local.json`.

Se descubrió intentando una simulación sobre dos espacios instalados y comprobando después que
su lanzador había cambiado de puntero. No lo encontró una prueba: lo encontró la sorpresa de una
medición, que es la forma cara de encontrarlo.

**Una simulación que escribe es peor que no tener simulación**: es el único modo en que alguien
prueba un cambio en producción creyendo que no lo está aplicando. Y hay un segundo error, el
contrario y más fácil de cometer al arreglar el primero: que el seco deje de MENCIONAR el
fichero. Una lista que omite un efecto se lee como una lista completa. Las dos mitades se fijan
aquí.

Por qué se mide el sistema de archivos y no la lista devuelta
-------------------------------------------------------------
La lista era correcta antes del defecto: decía «simulación» mientras el disco cambiaba. Afirmar
sobre la lista es afirmar sobre lo que el código DICE que hizo. Estas pruebas hacen una huella
del árbol antes y después y comparan; es lo único que distingue «declaró que no escribía» de «no
escribió».
"""

from __future__ import annotations

import hashlib
import json
import unittest
from pathlib import Path

from core import wire
from tests.fixtures import Workspace


def _huella(raiz: Path) -> dict:
    """`{ruta: sha256}` de todo fichero bajo `raiz`. Detecta creación, borrado y edición."""
    out = {}
    for p in sorted(raiz.rglob("*")):
        if p.is_file():
            out[str(p.relative_to(raiz))] = hashlib.sha256(p.read_bytes()).hexdigest()
    return out


class _Base(unittest.TestCase):
    def _espacio(self, ws):
        ws.json(".harness/policy.json",
                {"schema": "harness.policy/v1", "name": "e", "version": "1"})
        return Path.home() / ".local" / "share" / "refuto" / "engine" / "current"


class TestElSecoNoTocaElDisco(_Base):

    def test_wire_claude_en_seco(self):
        with Workspace("seco-claude") as ws:
            motor = self._espacio(ws)
            antes = _huella(ws.root)
            res = wire.wire_claude(ws.root, harness_root=motor, dry_run=True)
            self.assertEqual(antes, _huella(ws.root),
                             "`--dry-run` escribió en el disco")
            self.assertTrue(res, "un seco que no devuelve nada no se puede revisar")

    def test_wire_kiro_en_seco(self):
        with Workspace("seco-kiro") as ws:
            motor = self._espacio(ws)
            (ws.root / ".kiro" / "agents").mkdir(parents=True)
            ws.json(".kiro/agents/a.json", {"name": "a", "hooks": {}})
            antes = _huella(ws.root)
            wire.wire_kiro_agents(ws.root, harness_root=motor, dry_run=True)
            self.assertEqual(antes, _huella(ws.root), "`--dry-run` escribió en el disco")

    def test_wire_antigravity_en_seco(self):
        with Workspace("seco-antigravity") as ws:
            motor = self._espacio(ws)
            antes = _huella(ws.root)
            wire.wire_antigravity(ws.root, harness_root=motor, dry_run=True)
            self.assertEqual(antes, _huella(ws.root), "`--dry-run` escribió en el disco")

    def test_y_el_lanzador_en_concreto_NO_aparece(self):
        """El fichero exacto que el defecto creaba."""
        with Workspace("seco-lanzador") as ws:
            motor = self._espacio(ws)
            wire.wire_claude(ws.root, harness_root=motor, dry_run=True)
            for nombre in ("guard", "guard.cmd", "installed.json"):
                with self.subTest(fichero=nombre):
                    self.assertFalse((ws.root / ".harness" / "bin" / nombre).exists(),
                                     f"el seco creó .harness/bin/{nombre}")


class TestElSecoDeclaraLoQueHaria(_Base):
    """La otra mitad: callar el efecto es el error contrario, y es el fácil de cometer."""

    def test_el_lanzador_se_menciona(self):
        with Workspace("declara-lanzador") as ws:
            motor = self._espacio(ws)
            res = wire.wire_claude(ws.root, harness_root=motor, dry_run=True)
            rutas = [r.path for r in res]
            self.assertIn(wire.BIN_LANZADOR, rutas,
                          f"el seco no declara que tocaría el lanzador; dijo {rutas}")
            self.assertTrue(any("simulaci" in (r.detail or "").lower() for r in res),
                            "nada en la salida dice que es una simulación")

    def test_y_el_real_lo_menciona_tambien(self):
        """Si sólo lo dijera el seco, la salida del real seguiría siendo incompleta."""
        with Workspace("declara-real") as ws:
            motor = self._espacio(ws)
            res = wire.wire_claude(ws.root, harness_root=motor)
            self.assertIn(wire.BIN_LANZADOR, [r.path for r in res])
            self.assertTrue((ws.root / ".harness" / "bin" / "guard").is_file())

    def test_y_tambien_cuando_el_gancho_ya_estaba(self):
        """La rama `already`, que es donde se escapó de verdad.

        Medido el 2026-10-04 cableando ocho espacios instalados: siete salieron
        «already .claude/settings.local.json» y en los siete el lanzador SÍ se reapuntó —
        `installed.json` pasó a otro motor en la misma llamada. El efecto ocurría y el informe lo
        callaba, que es la misma clase de defecto que una simulación que escribe: la salida no
        describe lo que pasó.
        """
        with Workspace("declara-already") as ws:
            motor = self._espacio(ws)
            wire.wire_claude(ws.root, harness_root=motor)           # primera vez
            res = wire.wire_claude(ws.root, harness_root=motor)     # ahora el gancho ya está
            acciones = {r.path: r.action for r in res}
            self.assertEqual("already", acciones.get(".claude/settings.local.json"),
                             f"el gancho debería estar al día; salió {acciones}")
            self.assertIn(wire.BIN_LANZADOR, acciones,
                          f"el lanzador se tocó y no se declaró; salió {acciones}")


class TestElRealSiEscribe(_Base):
    """La contraparte. Sin ella, «no escribe en seco» se satisface no escribiendo nunca."""

    def test_wire_claude_de_verdad(self):
        with Workspace("real-claude") as ws:
            motor = self._espacio(ws)
            antes = _huella(ws.root)
            wire.wire_claude(ws.root, harness_root=motor)
            despues = _huella(ws.root)
            self.assertNotEqual(antes, despues, "el real no escribió nada")
            nuevos = set(despues) - set(antes)
            self.assertIn(".claude/settings.local.json", nuevos)
            self.assertTrue({".harness/bin/guard", ".harness/bin/installed.json"} <= nuevos,
                            f"faltó el lanzador; se escribió {sorted(nuevos)}")

    def test_y_el_lanzador_apunta_al_motor_pedido(self):
        with Workspace("real-puntero") as ws:
            motor = self._espacio(ws)
            wire.wire_claude(ws.root, harness_root=motor)
            texto = (ws.root / ".harness" / "bin" / "guard").read_text(encoding="utf-8")
            self.assertIn(str(motor), texto)
            meta = json.loads((ws.root / ".harness" / "bin" / "installed.json")
                              .read_text(encoding="utf-8"))
            self.assertEqual(str(motor), meta["harness_home"])


if __name__ == "__main__":
    unittest.main()
