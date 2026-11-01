# -*- coding: utf-8 -*-
"""Contrato de `core.dialect`: cómo se DICE cada decisión en cada runtime.

Estas pruebas son de unidad y por tanto NO demuestran compatibilidad operacional: que
`responder("codex", ALLOW)` devuelva silencio no prueba que Codex lo acepte. Lo que prueba
eso es `tests/adversarial/test_dialecto_codex.py` (guardián real) y la medición con efecto
observable del 2026-10-31 que documenta `core/dialect.py`. Aquí se fija el contrato interno
para que no se mueva sin que nadie se entere.
"""

from __future__ import annotations

import json
import unittest

from core import dialect
from core.dialect import responder
from core.policy import ALLOW, ASK, DENY


def _wire(resp):
    """La decisión que viaja de verdad, o `None` si no se serializó sobre alguno."""
    if not resp.stdout:
        return None
    return json.loads(resp.stdout)["hookSpecificOutput"]["permissionDecision"]


class DialectoClaude(unittest.TestCase):
    """Claude Code implementa el enum entero: la traducción es la identidad."""

    def test_las_tres_decisiones_viajan_tal_cual(self):
        for sem in (ALLOW, DENY, ASK):
            with self.subTest(sem):
                r = responder("claude", sem, "motivo")
                self.assertEqual(sem, _wire(r))
                self.assertEqual(0, r.exit_code)
                self.assertEqual("", r.degradada)

    def test_auditoria_rota_escala_allow_a_ask(self):
        r = responder("claude", ALLOW, "motivo", aviso="AUDITORÍA INTERRUMPIDA: …")
        self.assertEqual(ASK, _wire(r), "sin rastro no se aprueba")
        self.assertIn("AUDITORÍA INTERRUMPIDA", r.stdout)

    def test_auditoria_rota_no_ablanda_un_deny(self):
        self.assertEqual(DENY, _wire(responder("claude", DENY, "x", aviso="roto")))


class DialectoCodex(unittest.TestCase):
    """Codex declara `allow|deny|ask` e implementa `deny`. Ver la tabla de `core/dialect`."""

    def test_aprobar_es_callarse(self):
        r = responder("codex", ALLOW, "da igual el motivo")
        self.assertEqual("", r.stdout, "un `allow` dicho en voz alta es «Hook Failed»")
        self.assertEqual("", r.stderr)
        self.assertEqual(0, r.exit_code)
        self.assertEqual("", r.wire, "la aprobación de Codex es la ausencia de respuesta")

    def test_ask_se_degrada_a_deny_y_lo_declara(self):
        r = responder("codex", ASK, "esto lo decide una persona")
        self.assertEqual(DENY, _wire(r), "`ask` en Codex ejecuta: no puede quedarse en `ask`")
        self.assertEqual(ASK, r.semantica, "la decisión semántica no se reescribe")
        self.assertTrue(r.degradada, "una degradación que no se declara es una mentira")
        self.assertIn("esto lo decide una persona", r.stdout)

    def test_auditoria_rota_bloquea_en_vez_de_preguntar(self):
        """El defecto de fondo: escalar a `ask` en Codex es escalar a `allow`."""
        r = responder("codex", ALLOW, "escritura normal", aviso="AUDITORÍA INTERRUMPIDA: …")
        self.assertEqual(DENY, _wire(r))
        self.assertIn("AUDITORÍA INTERRUMPIDA", r.stdout)

    def test_un_deny_nunca_viaja_sin_motivo(self):
        """Codex trata `deny` con motivo vacío como fallo del gancho, y entonces ejecuta."""
        for motivo in ("", "   ", None):
            with self.subTest(motivo=motivo):
                r = responder("codex", DENY, motivo)
                self.assertEqual(DENY, _wire(r))
                reason = json.loads(r.stdout)["hookSpecificOutput"][
                    "permissionDecisionReason"]
                self.assertTrue(reason.strip())

    def test_el_sobre_no_lleva_campos_que_codex_rechaza(self):
        """`continue`, `stopReason`, `suppressOutput` y `updatedInput` son «unsupported»."""
        doc = json.loads(responder("codex", DENY, "x").stdout)
        self.assertEqual({"hookSpecificOutput"}, set(doc))
        self.assertEqual({"hookEventName", "permissionDecision", "permissionDecisionReason"},
                         set(doc["hookSpecificOutput"]))
        self.assertEqual("PreToolUse", doc["hookSpecificOutput"]["hookEventName"])


class DialectoPlano(unittest.TestCase):
    """Kiro, Gemini y OpenCode: la decisión viaja en el código de salida."""

    def test_allow_sale_en_silencio_y_lo_demas_sale_2(self):
        for rt in ("kiro", "gemini", "opencode"):
            with self.subTest(rt):
                self.assertEqual(0, responder(rt, ALLOW, "x").exit_code)
                self.assertEqual(2, responder(rt, DENY, "x").exit_code)
                self.assertEqual(2, responder(rt, ASK, "x").exit_code)

    def test_no_se_imprime_json_a_quien_no_lo_lee(self):
        r = responder("kiro", DENY, "x")
        self.assertEqual("", r.stdout)
        self.assertIn("BLOQUEADO", r.stderr)

    def test_auditoria_rota_no_deja_pasar(self):
        self.assertEqual(2, responder("kiro", ALLOW, "x", aviso="roto").exit_code)


class FallaCerrado(unittest.TestCase):
    """Lo que no se entiende no se aprueba. Es la regla que este programa aplica a todo."""

    def test_runtime_sin_dialecto_no_se_aproxima_al_mas_parecido(self):
        for rt in ("codex-next", "claude2", "", "CODEX", "antigravity"):
            with self.subTest(rt):
                r = responder(rt, ALLOW, "parece inocuo")
                self.assertEqual(2, r.exit_code, f"{rt!r} no puede aprobar por defecto")
                self.assertEqual("", r.stdout)
                self.assertEqual(DENY, r.wire)

    def test_decision_interna_desconocida_bloquea(self):
        for sem in ("approve", "block", "", None, "ALLOW"):
            with self.subTest(sem):
                r = responder("codex", sem, "x")
                self.assertEqual(2, r.exit_code)
                self.assertEqual(DENY, r.wire)

    def test_codex_no_puede_emitir_ask_ni_allow_por_ningun_camino(self):
        """La propiedad que cierra el defecto, y no el caso concreto que lo destapó.

        El fallo abierto original no era «falta traducir `ask`»: era que la traducción
        corría ANTES que la escalada por auditoría, así que una escalada posterior volvía a
        meter `ask` en el cable. Comprobar sólo «auditoría rota → deny» deja viva la
        siguiente variante del mismo error. Lo que se fija aquí es que **ningún**
        cruce de decisión × aviso pueda poner en el cable algo que Codex ejecute.
        """
        for sem in (ALLOW, DENY, ASK):
            for aviso in ("", "AUDITORÍA INTERRUMPIDA: …"):
                with self.subTest(semantica=sem, aviso=bool(aviso)):
                    r = responder("codex", sem, "motivo", aviso)
                    self.assertIn(_wire(r), (None, DENY),
                                  "en Codex, `allow` y `ask` son «Hook Failed» y ejecutan")
                    if _wire(r) is None:
                        self.assertEqual(ALLOW, sem,
                                         "sólo un `allow` sin aviso puede salir en silencio")
                        self.assertFalse(aviso)

    def test_ninguna_respuesta_aprueba_hablando(self):
        """Barrido: ningún runtime × decisión produce un `allow` serializado salvo Claude."""
        for rt in dialect.runtimes():
            for sem in (ALLOW, DENY, ASK):
                r = responder(rt, sem, "m")
                if _wire(r) == ALLOW:
                    self.assertEqual("claude", rt,
                                     f"{rt} no implementa `allow` y lo está emitiendo")
                    self.assertEqual(ALLOW, sem)


class TablasQueNoSePuedenSeparar(unittest.TestCase):
    """`core.guard._SHAPES` y `core.dialect._DIALECTOS` hablan de los mismos runtimes."""

    def test_todo_runtime_con_forma_tiene_dialecto(self):
        from core.guard import _SHAPES
        self.assertEqual(set(_SHAPES), set(dialect.runtimes()),
                         "un runtime que se sabe leer y no se sabe contestar es un fail-open "
                         "esperando: `responder` lo bloquearía, pero el gancho ya estaría "
                         "enganchado y el espacio inutilizable")


if __name__ == "__main__":
    unittest.main()
