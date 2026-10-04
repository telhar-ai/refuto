# -*- coding: utf-8 -*-
"""Una decisión que no se pudo registrar no es una decisión aprobada.

El defecto que estas pruebas fijan, medido el 2026-09-25
--------------------------------------------------------
Con el diario inescribible y una escritura que de otro modo sería `allow`, el guardián daba
tres respuestas distintas al mismo hecho:

    claude                     allow   ← la escritura ocurre
    kiro · gemini · opencode   exit 2  ← bloquea
    antigravity                ask

`core/guard.py::_emit_event` argumenta exactamente este caso —«en una decisión `allow` con
respuesta estructurada, stderr no llega a ninguna parte: una aprobación sin registrar quedaba
idéntica a una registrada»— y concluye que el fallo «viaja dentro de la propia decisión».
Viajaba en el TEXTO; la decisión seguía siendo `allow`. El arreglo estaba en
`_main_antigravity` y no en `main()`: se aplicó a un dialecto estructurado y no al otro, siendo
el que faltaba el runtime principal del producto.

Ninguna prueba cubría este camino antes de este fichero.

Por qué `ask` y no `deny`
-------------------------
Porque el trabajo no se pierde y la decisión la toma quien puede arreglar el diario. Un `deny`
convertiría un diario en manos de root —la causa habitual— en un espacio inutilizable, y un
control que deja a alguien sin salida se rodea. Es el mismo criterio que `decide_command` aplica
a la lectura de credenciales.
"""

from __future__ import annotations

import json
import subprocess  # nosec B404 — lanzar el guardián real ES lo que hay que medir
import sys
import tempfile
import unittest
from pathlib import Path

from core.proc import TEXT_IO

RAIZ = Path(__file__).resolve().parents[2]

#: Cómo se lee la respuesta de cada dialecto, y qué cuenta como «deja pasar».
DIALECTOS = ("claude", "kiro", "gemini", "opencode", "antigravity")


def _carga(runtime: str, ws: Path) -> dict:
    """La misma escritura inocua, en la forma que cada runtime entrega."""
    destino, contenido = str(ws / "nota.txt"), "hola"
    if runtime == "antigravity":
        return {"toolCall": {"name": "write_file", "args": {"path": destino,
                                                            "content": contenido}},
                "workspacePaths": [str(ws)], "conversationId": "c1"}
    return {"tool_name": "Write",
            "tool_input": {"file_path": destino, "content": contenido}, "cwd": str(ws)}


def _decidir(runtime: str, ws: Path):
    """`(codigo, decision, motivo)`. `decision` vacía si el dialecto no la emite en stdout."""
    p = subprocess.run(  # nosec B603
        [sys.executable, "-m", "core.guard", "--runtime", runtime, "--stdin",
         "--workspace", str(ws)],
        input=json.dumps(_carga(runtime, ws)), capture_output=True,
        cwd=str(RAIZ), timeout=120, **TEXT_IO)
    decision, motivo = "", p.stderr
    if p.stdout.strip():
        try:
            doc = json.loads(p.stdout)
            decision = (doc.get("hookSpecificOutput", {}).get("permissionDecision")
                        or doc.get("decision", ""))
            motivo = (doc.get("hookSpecificOutput", {}).get("permissionDecisionReason")
                      or doc.get("reason", "")) or motivo
        except json.JSONDecodeError:
            pass
    return p.returncode, decision, motivo


class _ConDiarioRoto(unittest.TestCase):
    """El diario se vuelve inescribible poniendo un DIRECTORIO donde va el fichero.

    Y no con permisos: como root —o en un contenedor que corra como root— `chmod 000` no
    impide escribir, así que la prueba aprobaría por el motivo equivocado en la mitad de los
    entornos de CI. Un directorio no lo puede escribir nadie, sea quien sea.
    """

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.ws = Path(self._tmp.name)
        (self.ws / ".harness" / "evidence" / "ledger.jsonl").mkdir(parents=True)

    def tearDown(self):
        self._tmp.cleanup()


class TestNingunDialectoDejaPasarSinRegistrar(_ConDiarioRoto):
    def test_ningun_runtime_responde_allow(self):
        for runtime in DIALECTOS:
            with self.subTest(runtime=runtime):
                codigo, decision, _ = _decidir(runtime, self.ws)
                paso = decision == "allow" or (not decision and codigo == 0)
                self.assertFalse(
                    paso,
                    f"«{runtime}» aprobó una escritura que no pudo registrar: el rastro se "
                    f"corta y nadie lo echa en falta, que es lo que `_emit_event` existe para "
                    f"impedir (codigo={codigo}, decision={decision!r})")

    def test_y_el_motivo_dice_que_fue_la_auditoria(self):
        """Retener sin decir por qué manda a arreglar lo que no está roto."""
        for runtime in DIALECTOS:
            with self.subTest(runtime=runtime):
                _, _, motivo = _decidir(runtime, self.ws)
                self.assertIn("AUDITORÍA INTERRUMPIDA", motivo)

    def test_los_dialectos_estructurados_preguntan_en_vez_de_rechazar(self):
        """El trabajo no se pierde: lo decide quien puede arreglar el diario."""
        for runtime in ("claude", "antigravity"):
            with self.subTest(runtime=runtime):
                _, decision, _ = _decidir(runtime, self.ws)
                self.assertEqual("ask", decision)


class TestConElDiarioSanoNoCambiaNada(unittest.TestCase):
    """El control negativo. Sin él, un guardián que retuviera SIEMPRE pasaría lo de arriba."""

    def test_una_escritura_inocua_se_sigue_permitiendo(self):
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            (ws / ".harness").mkdir()
            for runtime in DIALECTOS:
                with self.subTest(runtime=runtime):
                    codigo, decision, _ = _decidir(runtime, ws)
                    paso = decision == "allow" or (not decision and codigo == 0)
                    self.assertTrue(paso, f"«{runtime}» retiene con el diario sano: entonces "
                                          f"la prueba de arriba no mide la auditoría")


if __name__ == "__main__":
    unittest.main()
