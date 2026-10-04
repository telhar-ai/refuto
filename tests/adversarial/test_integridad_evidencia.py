# -*- coding: utf-8 -*-
"""La evidencia que justifica un veredicto, atacada.

La pregunta que ordena este fichero
------------------------------------
    ¿quién tiene autoridad para emitir el veredicto, y quién para modificar la evidencia
    que lo justifica?

Hasta el 2026-09-23 eran el mismo sujeto y no había nada que lo detectara. El diario era
JSON Lines plano —sin huella, sin firma, sin encadenar— y el artefacto de una corrida era un
JSON suelto. Medido: editando SÓLO el artefacto, conservando su `mtime`, `refuto status`
pasaba de «NO INTEGRABLE · 2 en rojo» a «INTEGRABLE · 0 en rojo». El diario conservaba
intacto el veredicto verdadero y **nadie los comparaba**.

Lo que estas pruebas fijan es tamper-EVIDENCIA, no tamper-proofing: un adversario que
reescriba la cadena entera y todas sus copias publicadas produce un diario coherente. Lo que
ya no puede es editar una línea y marcharse. La distinción está declarada en
`docs/assurance/FORMAL-MODEL.md` §3.5 y §8, y no se presenta como más de lo que es.
"""

from __future__ import annotations

import json
import os
import tempfile
import unittest
from pathlib import Path

from core.evidence import (append_event, cabeza, latest_verification, reconciliar,
                           verificar_cadena, write_run)
from core.model import FAIL, PASS, Result, Scope


def _corrida(ws: Path, run_id: str = "ver_" + "a" * 16, rojo: bool = True):
    rs = [Result("G-A", "a", PASS, scope=Scope(3, 0, "ficheros"))]
    if rojo:
        rs.append(Result("G-B", "b", FAIL, measure="dos problemas"))
    return write_run(ws, run_id, rs)


def _espacio(rojo: bool = True):
    ws = Path(tempfile.mkdtemp())
    p = _corrida(ws, rojo=rojo)
    for i in range(4):
        append_event(ws, {"kind": "policy/decision", "outcome": "deny", "n": i})
    return ws, p


class TestLaCadenaDelDiario(unittest.TestCase):
    def test_una_cadena_intacta_verifica(self):
        """Sin esta mitad, todo lo demás se satisface rompiendo siempre."""
        ws, _ = _espacio()
        r = verificar_cadena(ws)
        self.assertTrue(r["ok"], r["motivo"])
        self.assertEqual(5, r["eventos"])

    def test_editar_un_evento_en_su_sitio_rompe_la_cadena(self):
        ws, _ = _espacio()
        led = ws / ".harness" / "evidence" / "ledger.jsonl"
        ls = led.read_text(encoding="utf-8").splitlines()
        ev = json.loads(ls[2])
        ev["outcome"] = "allow"                       # el cambio que interesaría al sujeto
        ls[2] = json.dumps(ev, ensure_ascii=False)
        led.write_text("\n".join(ls) + "\n", encoding="utf-8", newline="\n")
        r = verificar_cadena(ws)
        self.assertFalse(r["ok"], "se editó un evento y la cadena siguió cerrando")
        self.assertIn("se editó después de escribirse", r["motivo"])

    def test_reordenar_un_evento_rompe_la_cadena(self):
        ws, _ = _espacio()
        led = ws / ".harness" / "evidence" / "ledger.jsonl"
        ls = led.read_text(encoding="utf-8").splitlines()
        ls[2], ls[3] = ls[3], ls[2]
        led.write_text("\n".join(ls) + "\n", encoding="utf-8", newline="\n")
        self.assertFalse(verificar_cadena(ws)["ok"], "se reordenaron dos eventos sin notarse")

    def test_borrar_un_evento_de_en_medio_rompe_la_cadena(self):
        ws, _ = _espacio()
        led = ws / ".harness" / "evidence" / "ledger.jsonl"
        ls = led.read_text(encoding="utf-8").splitlines()
        del ls[2]
        led.write_text("\n".join(ls) + "\n", encoding="utf-8", newline="\n")
        self.assertFalse(verificar_cadena(ws)["ok"], "se borró un evento sin notarse")

    def test_el_ancla_publicada_detecta_la_truncacion_de_cola(self):
        """El único ataque que la cadena por sí sola NO puede ver.

        Cortar la COLA deja los eslabones restantes consistentes entre sí: dentro de un
        fichero mutable no hay nada que diga cuántos eventos «debería» haber. Con una cabeza
        publicada fuera del árbol sí: si esa huella ya no está, el diario se cortó por detrás.
        """
        ws, _ = _espacio()
        ancla = cabeza(ws)                    # el operador la publica FUERA del espacio
        for i in range(3):
            append_event(ws, {"kind": "policy/decision", "outcome": "deny", "n": 100 + i})
        self.assertTrue(verificar_cadena(ws, ancla)["ok"], "sin tocar nada debe verificar")

        led = ws / ".harness" / "evidence" / "ledger.jsonl"
        ls = led.read_text(encoding="utf-8").splitlines()
        led.write_text("\n".join(ls[:3]) + "\n", encoding="utf-8", newline="\n")
        r = verificar_cadena(ws, ancla)
        self.assertFalse(r["ok"], "se truncó la cola por detrás del ancla sin notarse")
        self.assertIn("ancla publicada", r["motivo"])

    def test_sin_ancla_la_truncacion_de_cola_queda_NOT_PROVEN(self):
        """Se declara el límite en vez de fingir que no existe.

        Esta prueba documenta una propiedad que NO se tiene. Si alguien la cierra, cae, y
        ése es el momento de actualizar `FORMAL-MODEL.md` §8.
        """
        ws, _ = _espacio()
        led = ws / ".harness" / "evidence" / "ledger.jsonl"
        ls = led.read_text(encoding="utf-8").splitlines()
        led.write_text("\n".join(ls[:2]) + "\n", encoding="utf-8", newline="\n")
        self.assertTrue(verificar_cadena(ws)["ok"],
                        "el comportamiento documentado cambió: ¿hay ya ancla implícita?")


class TestLaReconciliacionArtefactoDiario(unittest.TestCase):
    def test_una_corrida_intacta_reconcilia(self):
        ws, p = _espacio()
        self.assertEqual("ok", reconciliar(ws, json.loads(p.read_text(encoding="utf-8")))["estado"])
        self.assertEqual("ok", latest_verification(ws)["integrity"]["estado"])

    def test_editar_el_artefacto_se_detecta(self):
        """El ataque exacto que se midió: sólo el artefacto, `mtime` conservado."""
        ws, p = _espacio()
        self.assertIn("NO INTEGRABLE", latest_verification(ws)["verdict"])

        st = os.stat(p)
        d = json.loads(p.read_text(encoding="utf-8"))
        d["verdict"] = "INTEGRABLE"
        for g in d["gates"]:
            g["status"] = PASS
            g["findings"] = []
        p.write_text(json.dumps(d, ensure_ascii=False, indent=2), encoding="utf-8",
                     newline="\n")
        os.utime(p, (st.st_atime, st.st_mtime))

        lv = latest_verification(ws)
        self.assertEqual("contradice", lv["integrity"]["estado"])
        self.assertIn("NO INTEGRABLE", lv["verdict"],
                      "el veredicto falsificado se reportó como bueno")
        self.assertNotIn("INTEGRABLE —", lv["verdict"].replace("NO INTEGRABLE", ""))

    def test_truncar_el_diario_entero_deja_el_artefacto_sin_respaldo(self):
        ws, p = _espacio()
        (ws / ".harness" / "evidence" / "ledger.jsonl").write_text("", encoding="utf-8")
        lv = latest_verification(ws)
        self.assertNotEqual("ok", lv["integrity"]["estado"])
        self.assertIn("NO INTEGRABLE", lv["verdict"])

    def test_un_artefacto_de_otra_corrida_no_se_da_por_bueno(self):
        """Traer un artefacto verde de otro sitio es más barato que falsificar uno."""
        ws, _ = _espacio(rojo=True)
        ajeno = Path(tempfile.mkdtemp())
        p2 = _corrida(ajeno, run_id="ver_" + "f" * 16, rojo=False)
        destino = ws / ".harness" / "evidence" / p2.name
        destino.write_text(p2.read_text(encoding="utf-8"), encoding="utf-8", newline="\n")
        lv = latest_verification(ws)
        self.assertNotEqual("ok", lv["integrity"]["estado"],
                            "un artefacto de otro espacio se aceptó como propio")


class TestElVeredictoNoAceptaUnPassSinPrueba(unittest.TestCase):
    def test_un_lock_sin_anclas_no_aprueba(self):
        """`core.lock.verify` comparaba cero huellas contra cero huellas y decía PASS."""
        from core.lock import LOCK_SCHEMA, verify
        from core.model import BLOCKED, NOT_APPLICABLE
        ws = Path(tempfile.mkdtemp())
        self.assertEqual(NOT_APPLICABLE,
                         verify(ws, {"schema": LOCK_SCHEMA, "sources": {}}).status)
        r = verify(ws, {"schema": LOCK_SCHEMA,
                        "sources": {"n": {"commit": "a" * 40, "ref": "v1", "files": {}}}})
        self.assertEqual(BLOCKED, r.status,
                         "un origen declarado con CERO ficheros anclados no ancla nada")

    def test_el_motor_de_veredicto_se_niega_a_contar_un_PASS_sin_cobertura(self):
        from core.evidence import verdict_of
        v = verdict_of([Result("G-X", "x", PASS)])
        self.assertIn("sin declarar qué observaron", v)
        self.assertTrue(v.startswith("NO INTEGRABLE"))


if __name__ == "__main__":
    unittest.main()
