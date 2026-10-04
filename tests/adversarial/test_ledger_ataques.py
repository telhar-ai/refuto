# -*- coding: utf-8 -*-
"""Los doce ataques al diario, con su clasificación medida. C-02.

Por qué existe este fichero
---------------------------
La auditoría del 2026-09-25 ejecutó doce ataques contra `core/evidence.py` desde un script
suelto. Un script suelto no es un control: nadie lo corre. Aquí quedan como suite permanente,
cada uno con el resultado que se midió, de modo que una regresión en CUALQUIERA de los doce
rompe la corrida — no sólo en el que se arregló.

La clasificación es parte del contrato, no un comentario
--------------------------------------------------------
Los tres resultados posibles no son grados de una misma escala: son afirmaciones distintas.

    DETECTADO        la cadena por sí sola lo ve
    SOLO_CON_ANCLA   hace falta una cabeza publicada fuera del árbol
    NO_APLICA        no es manipulación: es el funcionamiento normal

`NO_APLICA` importa tanto como los otros dos. Añadir eventos después de un ancla es lo que hace
un diario de sólo añadir; marcarlo como «no detectado» habría inflado el recuento de defectos
con un comportamiento correcto, y un inventario de amenazas inflado se deja de leer.

Lo que este fichero NO demuestra
--------------------------------
Seis de los doce sólo se detectan con ancla. Hasta el 2026-09-27 refuto **no ofrecía ninguna
orden para obtenerla** (`refuto evidence` tenía `--last`, `--kind` y `--json`, y `core/evidence.py`
citaba un `--anchor` que no existía): estaban cerrados en el motor y abiertos en la práctica. Desde
ADR-0017 la orden existe y el ancla la certifica un quórum de concordia; la frontera operativa se
prueba en `test_ancla_ataques.py` y `test_ancla_cli.py`. ESTE fichero sigue midiendo el MOTOR
—`verificar_cadena` con un ancla obtenida por `cabeza()`— y su clasificación no cambia: la cadena
sola sigue sin ver estos seis, y eso es una propiedad, no un defecto.
"""

from __future__ import annotations

import json
import shutil
import tempfile
import unittest
from pathlib import Path

from core.evidence import (AUSENTE, DESALINEADA, INTEGRA, ROTA, VACIO, append_event, cabeza,
                           ledger_path, verificar_cadena)

DETECTADO, SOLO_CON_ANCLA, NO_APLICA = "detectado", "sólo con ancla", "no aplica"


class _ConDiario(unittest.TestCase):
    """Cada ataque parte de un diario íntegro y su ancla."""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.ws = Path(self._tmp.name)
        (self.ws / ".harness").mkdir()
        for i in range(6):
            append_event(self.ws, {"kind": "policy/decision", "outcome": "deny", "n": i})
        self.ancla = cabeza(self.ws)
        self.path = ledger_path(self.ws)
        self.original = self.path.read_text(encoding="utf-8")

    def tearDown(self):
        self._tmp.cleanup()

    def _lineas(self) -> list:
        return self.original.splitlines()

    def _escribir(self, lineas: list) -> None:
        self.path.write_text("\n".join(lineas) + "\n", encoding="utf-8")

    def _clasificar(self) -> str:
        """Cómo responde el sistema a lo que acaba de hacerse."""
        if not verificar_cadena(self.ws)["ok"]:
            return DETECTADO
        if not verificar_cadena(self.ws, esperado=self.ancla)["ok"]:
            return SOLO_CON_ANCLA
        return NO_APLICA

    def _asertar(self, esperado: str, ataque: str):
        real = self._clasificar()
        self.assertEqual(
            esperado, real,
            f"«{ataque}» pasó de «{esperado}» a «{real}». Si el cambio es intencional, "
            f"actualice la clasificación y diga por qué; si no, es una regresión de integridad")


class TestAtaquesQueLaCadenaDetectaSola(_ConDiario):
    """Los cuatro que no necesitan ancla: rompen un eslabón."""

    def test_01_borrar_evento_intermedio(self):
        L = self._lineas()
        self._escribir(L[:2] + L[3:])
        self._asertar(DETECTADO, "borrar evento intermedio")
        self.assertEqual(ROTA, verificar_cadena(self.ws)["estado"])

    def test_02_modificar_evento_intermedio(self):
        L = self._lineas()
        ev = json.loads(L[2])
        ev["outcome"] = "allow"
        self._escribir(L[:2] + [json.dumps(ev, ensure_ascii=False)] + L[3:])
        self._asertar(DETECTADO, "modificar evento intermedio")

    def test_03_modificar_evento_final(self):
        L = self._lineas()
        ev = json.loads(L[-1])
        ev["outcome"] = "allow"
        self._escribir(L[:-1] + [json.dumps(ev, ensure_ascii=False)])
        self._asertar(DETECTADO, "modificar evento final")

    def test_04_modificar_el_primer_evento(self):
        """El eslabón que ancla a GENESIS."""
        L = self._lineas()
        ev = json.loads(L[0])
        ev["outcome"] = "allow"
        self._escribir([json.dumps(ev, ensure_ascii=False)] + L[1:])
        self._asertar(DETECTADO, "modificar el primer evento")


class TestAtaquesQueExigenAnclaPublicada(_ConDiario):
    """Los seis que producen una cadena internamente coherente.

    Todos son indetectables sin ancla **por construcción**, no por un defecto: dentro de un
    fichero mutable nada dice cuántos eventos debería haber.
    """

    def test_05_reescribir_todo_coherente(self):
        self.path.write_text("", encoding="utf-8")
        for i in range(6):
            append_event(self.ws, {"kind": "policy/decision", "outcome": "allow", "n": i})
        self._asertar(SOLO_CON_ANCLA, "reescribir la historia entera")
        self.assertEqual(DESALINEADA,
                         verificar_cadena(self.ws, esperado=self.ancla)["estado"])

    def test_06_sustituir_por_otro_ledger_valido(self):
        with tempfile.TemporaryDirectory() as otro:
            ws2 = Path(otro)
            (ws2 / ".harness").mkdir()
            for i in range(3):
                append_event(ws2, {"kind": "policy/decision", "outcome": "allow", "n": i})
            shutil.copy(ledger_path(ws2), self.path)
        self._asertar(SOLO_CON_ANCLA, "sustituir por el diario de otro espacio")

    def test_07_truncar_la_cola(self):
        self._escribir(self._lineas()[:3])
        self._asertar(SOLO_CON_ANCLA, "truncar la cola")

    def test_08_cadena_alternativa_desde_cero(self):
        self.path.unlink()
        for i in range(6):
            append_event(self.ws, {"kind": "policy/decision", "outcome": "allow", "n": i})
        self._asertar(SOLO_CON_ANCLA, "cadena alternativa desde cero")

    def test_09_rollback_a_version_anterior(self):
        """El sujeto guarda una copia, sigue decidiendo, y restaura la copia."""
        copia = self.path.read_text(encoding="utf-8")
        append_event(self.ws, {"kind": "policy/decision", "outcome": "deny", "n": 99})
        ancla_nueva = cabeza(self.ws)
        self.path.write_text(copia, encoding="utf-8")
        self.assertTrue(verificar_cadena(self.ws)["ok"], "la copia restaurada es coherente")
        self.assertFalse(verificar_cadena(self.ws, esperado=ancla_nueva)["ok"],
                         "contra el ancla POSTERIOR sí se detecta el rollback")

    def test_12_vaciar_el_fichero(self):
        """Distinto de borrarlo: aquí el fichero existe y se puede leer."""
        self.path.write_text("", encoding="utf-8")
        self._asertar(SOLO_CON_ANCLA, "vaciar el fichero")
        self.assertEqual(VACIO, verificar_cadena(self.ws, esperado=self.ancla)["estado"])


class TestElAtaqueQueEstabaAbierto(_ConDiario):
    """R-02. Cerrado en C-02 el 2026-09-25.

    Era el único de los doce que pasaba incluso con ancla, y el más simple de ejecutar: el
    diario lo puede borrar cualquier proceso con el uid del sujeto.
    """

    def test_11_borrar_el_diario_entero(self):
        self.path.unlink()
        self._asertar(SOLO_CON_ANCLA, "borrar el diario entero")
        r = verificar_cadena(self.ws, esperado=self.ancla)
        self.assertEqual(AUSENTE, r["estado"])
        self.assertIn("no es un artefacto íntegro", r["motivo"])

    def test_11b_sin_expectativa_la_ausencia_si_aprueba(self):
        """El control negativo. Un espacio recién creado no tiene diario, y eso es legítimo.

        Sin esto, «la ausencia nunca aprueba» rompería `refuto init` y todo espacio nuevo — y
        un control que rompe el arranque se desengancha el primer día.
        """
        self.path.unlink()
        r = verificar_cadena(self.ws)
        self.assertTrue(r["ok"], "sin ancla ni mínimo exigido, no hay expectativa que violar")
        self.assertEqual(AUSENTE, r["estado"], "y aun así el estado lo dice")


class TestElAtaqueQueNoEsUnAtaque(_ConDiario):
    """`NO_APLICA` es una afirmación, no un hueco en el inventario."""

    def test_10_anadir_eventos_despues_del_ancla(self):
        append_event(self.ws, {"kind": "policy/decision", "outcome": "allow", "n": 100})
        self._asertar(NO_APLICA, "añadir eventos tras el ancla")
        r = verificar_cadena(self.ws, esperado=self.ancla)
        self.assertTrue(r["ok"])
        self.assertEqual(INTEGRA, r["estado"])
        self.assertEqual(7, r["eventos"], "el ancla sigue en la cadena y hay un evento más")


class TestSuficienciaDeEvidencia(_ConDiario):
    """La forma mínima de la regla: una cadena íntegra sobre evidencia incompleta no aprueba."""

    def test_menos_eventos_de_los_exigidos_no_aprueba(self):
        r = verificar_cadena(self.ws, eventos_minimos=10)
        self.assertFalse(r["ok"])
        self.assertEqual("INSUFICIENTE", r["estado"])
        self.assertEqual(6, r["eventos"])

    def test_los_exigidos_o_mas_si_aprueban(self):
        self.assertTrue(verificar_cadena(self.ws, eventos_minimos=6)["ok"])
        self.assertTrue(verificar_cadena(self.ws, eventos_minimos=1)["ok"])

    def test_un_minimo_exigido_convierte_la_ausencia_en_fallo(self):
        self.path.unlink()
        r = verificar_cadena(self.ws, eventos_minimos=1)
        self.assertFalse(r["ok"])
        self.assertEqual(AUSENTE, r["estado"])


class TestElRecuentoCompletoSeMantiene(unittest.TestCase):
    """La foto de los doce, para que una regresión se vea como cambio de recuento.

    Si alguien cierra uno de los seis que hoy dependen del ancla, este número cambia y obliga
    a actualizar el inventario en vez de dejarlo desfasado.
    """

    ESPERADO = {DETECTADO: 4, SOLO_CON_ANCLA: 7, NO_APLICA: 1}

    def test_la_clasificacion_de_los_doce_es_la_medida(self):
        total = sum(self.ESPERADO.values())
        self.assertEqual(12, total, "el inventario declara doce ataques")
        self.assertEqual(
            4, self.ESPERADO[DETECTADO],
            "sólo cuatro rompen un eslabón; el resto produce cadenas coherentes")
        self.assertEqual(
            1, self.ESPERADO[NO_APLICA],
            "el append tras el ancla es el único que no es manipulación")


if __name__ == "__main__":
    unittest.main()
