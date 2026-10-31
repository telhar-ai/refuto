# -*- coding: utf-8 -*-
"""El guardián REAL, lanzado como proceso, contestando el dialecto de cada runtime.

Por qué por subproceso y no importando `responder`
--------------------------------------------------
`tests/unit/test_dialecto.py` fija el contrato de la traducción. Eso no demuestra que el
guardián la USE: el defecto que estas pruebas existen para impedir fue exactamente ése —la
traducción estaba bien y corría en el orden equivocado—. Aquí se mide lo que sale por el
descriptor 1 del proceso que el gancho invoca de verdad, que es lo único que Codex lee.

Lo que estas pruebas siguen sin demostrar
-----------------------------------------
Que Codex ACEPTE esa salida. Eso no se puede afirmar desde Python: se midió el 2026-10-31
contra Codex 0.166.0 lanzando `codex exec` con una herramienta de efecto observable y
comprobando si el fichero aparecía. La tabla está en `core/dialect.py`. Un verde aquí con
aquella medición caducada sería un verde falso, así que la fecha y la versión viajan con la
afirmación, no con el código.
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

PERMITIDA = '{"tool_name":"Bash","tool_input":{"command":"ls -la"}}'
CONSULTA = '{"tool_name":"Bash","tool_input":{"command":"git push origin main"}}'
PROTEGIDA = '{"tool_name":"Write","tool_input":{"file_path":"gates/base.py","content":"x"}}'


class _Salida:
    """Lo que el runtime ve: código, stdout crudo y la decisión que viaja en el sobre."""

    def __init__(self, proc):
        self.rc = proc.returncode
        self.stdout = proc.stdout
        self.stderr = proc.stderr
        self.wire = None
        if proc.stdout.strip():
            self.wire = json.loads(proc.stdout)["hookSpecificOutput"]["permissionDecision"]

    @property
    def motivo(self):
        return json.loads(self.stdout)["hookSpecificOutput"]["permissionDecisionReason"]


def _guardian(raw: str, runtime: str, diario_roto: bool = False) -> _Salida:
    with tempfile.TemporaryDirectory() as tmp:
        ws = Path(tmp)
        (ws / ".harness").mkdir()
        if diario_roto:
            # Un DIRECTORIO donde va el fichero: la escritura del diario falla de verdad,
            # sin parchear nada en memoria. Es el fallo de auditoría más barato de montar
            # que no depende de permisos de root ni de llenar el disco.
            (ws / ".harness" / "evidence" / "ledger.jsonl").mkdir(parents=True)
        return _Salida(subprocess.run(  # nosec B603
            [sys.executable, "-m", "core.guard", "--runtime", runtime, "--stdin",
             "--workspace", str(ws)],
            input=raw, capture_output=True, cwd=str(RAIZ), timeout=120, **TEXT_IO))


class CodexAprobarEsCallarse(unittest.TestCase):

    def test_una_orden_permitida_no_produce_salida(self):
        s = _guardian(PERMITIDA, "codex")
        self.assertEqual("", s.stdout.strip(),
                         "un `allow` dicho en voz alta es «Hook Failed» en Codex")
        self.assertEqual(0, s.rc)

    def test_el_silencio_es_exclusivo_de_la_aprobacion(self):
        """Callarse aprueba, así que nada que no apruebe puede callarse."""
        for carga, etiqueta in ((CONSULTA, "requiere persona"), (PROTEGIDA, "protegida")):
            with self.subTest(etiqueta):
                s = _guardian(carga, "codex")
                self.assertTrue(s.stdout.strip(), "callarse aquí sería aprobar")
                self.assertEqual("deny", s.wire)


class CodexNoPuedePreguntar(unittest.TestCase):

    def test_la_consulta_se_traduce_a_bloqueo(self):
        s = _guardian(CONSULTA, "codex")
        self.assertEqual("deny", s.wire, "`ask` en Codex ejecuta igual")
        self.assertIn("persona", s.motivo, "hay que decir por qué se bloqueó algo aprobable")

    def test_auditoria_interrumpida_bloquea_y_no_pregunta(self):
        """El fallo abierto de fondo: escalar a `ask` en Codex es escalar a `allow`.

        Antes del 2026-10-31 la traducción del dialecto corría antes que esta escalada, así
        que una escritura PERMITIDA con el diario roto salía como `ask` — «Hook Failed» — y
        ocurría igual, sin rastro. El control más caro del guardián era inerte justo aquí.
        """
        s = _guardian(PERMITIDA, "codex", diario_roto=True)
        self.assertEqual("deny", s.wire, "sin rastro no se aprueba, y en Codex `ask` aprueba")
        self.assertIn("AUDITORÍA INTERRUMPIDA", s.motivo)

    def test_ninguna_carga_consigue_un_ask_en_el_cable(self):
        for carga in (PERMITIDA, CONSULTA, PROTEGIDA, "{}", '{"tool_name":"Write"}'):
            for roto in (False, True):
                with self.subTest(carga=carga[:40], diario_roto=roto):
                    s = _guardian(carga, "codex", roto)
                    self.assertIn(s.wire, (None, "deny"))


class CodexBloqueaDeFormaValida(unittest.TestCase):

    def test_el_motivo_nunca_viaja_vacio(self):
        """«permissionDecision:deny without a non-empty permissionDecisionReason» ejecuta."""
        for carga in (CONSULTA, PROTEGIDA, '{"tool_name":"Write","tool_input":"/x"}'):
            with self.subTest(carga[:40]):
                s = _guardian(carga, "codex")
                if s.wire == "deny":
                    self.assertTrue(s.motivo.strip())

    def test_el_sobre_solo_lleva_lo_que_codex_admite(self):
        doc = json.loads(_guardian(PROTEGIDA, "codex").stdout)
        self.assertEqual({"hookSpecificOutput"}, set(doc),
                         "`continue`, `stopReason` y `suppressOutput` son «unsupported»")

    def test_carga_que_no_es_json_bloquea(self):
        s = _guardian("esto no es json", "codex")
        self.assertNotEqual(0, s.rc, "un gancho que sale 2 SÍ bloquea en Codex (medido)")


class ElDiarioDistingueDecidirDeDecir(unittest.TestCase):
    """`outcome` es lo que se decidió; `wire` es lo que se dijo. No son la misma columna.

    El defecto de Codex vivía justo en esa diferencia: se decidía `ask` y se emitía algo que
    ese runtime ejecuta. Con una sola columna, una auditoría del diario no podía detectarlo
    sin reproducir la corrida entera.
    """

    def _ultimo_evento(self, raw: str, runtime: str) -> dict:
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            (ws / ".harness").mkdir()
            subprocess.run(  # nosec B603
                [sys.executable, "-m", "core.guard", "--runtime", runtime, "--stdin",
                 "--workspace", str(ws)],
                input=raw, capture_output=True, cwd=str(RAIZ), timeout=120, **TEXT_IO)
            diario = ws / ".harness" / "evidence" / "ledger.jsonl"
            return [json.loads(l) for l in diario.open(encoding="utf-8") if l.strip()][-1]

    def test_un_ask_degradado_no_se_cuenta_como_un_deny_de_la_politica(self):
        e = self._ultimo_evento(CONSULTA, "codex")
        self.assertEqual("ask", e["outcome"], "la decisión semántica no se reescribe")
        self.assertEqual("deny", e["wire"], "y lo que viajó por el cable fue un bloqueo")
        self.assertTrue(e["wire_degradada"], "sin esto los dos bloqueos son indistinguibles")

    def test_el_silencio_se_registra_como_silencio_y_no_como_allow(self):
        e = self._ultimo_evento(PERMITIDA, "codex")
        self.assertEqual("allow", e["outcome"])
        self.assertEqual("", e["wire"], "en Codex aprobar es no decir nada, y consta así")

    def test_en_claude_decidir_y_decir_coinciden(self):
        for carga, esperado in ((PERMITIDA, "allow"), (CONSULTA, "ask"), (PROTEGIDA, "deny")):
            with self.subTest(esperado):
                e = self._ultimo_evento(carga, "claude")
                self.assertEqual(esperado, e["outcome"])
                self.assertEqual(esperado, e["wire"])
                self.assertFalse(e["wire_degradada"])


class ClaudeNoSeEntera(unittest.TestCase):
    """Un cambio en el dialecto de Codex no puede mover el de Claude Code."""

    def test_las_tres_decisiones_siguen_siendo_las_de_antes(self):
        self.assertEqual("allow", _guardian(PERMITIDA, "claude").wire)
        self.assertEqual("ask", _guardian(CONSULTA, "claude").wire)
        self.assertEqual("deny", _guardian(PROTEGIDA, "claude").wire)

    def test_la_escalada_por_auditoria_sigue_siendo_ask(self):
        """Deliberado: en Claude `ask` NO ejecuta, así que ya era fail-closed.

        Endurecerlo a `deny` cambiaría la política de seguridad de un runtime que nunca
        tuvo el defecto, y perdería trabajo que una persona informada puede aprobar.
        """
        s = _guardian(PERMITIDA, "claude", diario_roto=True)
        self.assertEqual("ask", s.wire)
        self.assertIn("AUDITORÍA INTERRUMPIDA", s.motivo)


class RuntimesPlanos(unittest.TestCase):

    def test_la_decision_sigue_viajando_en_el_codigo_de_salida(self):
        for rt in ("kiro", "gemini", "opencode"):
            with self.subTest(rt):
                self.assertEqual(0, _guardian(PERMITIDA, rt).rc)
                self.assertEqual(2, _guardian(PERMITIDA, rt, diario_roto=True).rc)

    def test_no_se_les_imprime_json_que_nadie_lee(self):
        self.assertEqual("", _guardian(CONSULTA, "kiro").stdout.strip())


if __name__ == "__main__":
    unittest.main()
