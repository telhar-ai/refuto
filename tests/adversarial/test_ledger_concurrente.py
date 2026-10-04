# -*- coding: utf-8 -*-
"""La cadena del diario tiene que aguantar el uso normal, o no sirve de alarma.

El defecto que estas pruebas fijan, medido el 2026-09-25
--------------------------------------------------------
`append_event` leía la cabeza y escribía sin serializar. El docstring argumentaba —bien— que
una escritura de menos de PIPE_BUF en modo `a` no se entrelaza, y concluía que los guardianes
concurrentes «no se corrompen entre sí». Eso es cierto de los BYTES y no dice nada de la
CADENA: dos procesos leen la misma cabeza y emiten dos eventos con el mismo `prev`.

Con 12 invocaciones simultáneas del guardián real:

    eventos escritos : 12
    cadena ok        : False   (rota en la línea 3)
    motivo           : «falta, sobra o se movió algún evento entre medias»

Lo grave no es que la verificación falle: es **lo que dice al fallar**. El diario acusaba de
manipulación lo que era concurrencia normal, y un agente de código invoca herramientas en
paralelo de forma rutinaria. Una alarma de integridad que salta con el uso normal se aprende a
ignorar, y entonces no suena cuando importa — el mismo modo de muerte que este repositorio ya
documentó para `_partir` (comillas) y para `dd:*` (`ddev`).
"""

from __future__ import annotations

import concurrent.futures as cf
import json
import os
import subprocess  # nosec B404 — lanzar el guardián real ES lo que hay que medir
import sys
import tempfile
import unittest
from pathlib import Path

from core.evidence import (GENESIS, MECANISMO_DE_BLOQUEO, append_event, cabeza, ledger_path,
                           verificar_cadena)
from core.proc import TEXT_IO

RAIZ = Path(__file__).resolve().parents[2]
CONCURRENTES = 16


class TestElBloqueoEstaDeclarado(unittest.TestCase):
    """Sin saber si hubo bloqueo, una prueba de concurrencia mide la suerte del planificador."""

    def test_hay_un_mecanismo_y_se_puede_nombrar(self):
        self.assertIn(MECANISMO_DE_BLOQUEO, ("fcntl.flock", "msvcrt.locking"),
                      "sin mecanismo de bloqueo la serialización de la cadena no se puede "
                      "afirmar en esta plataforma; declárelo en vez de suponerlo")


class TestLaCadenaAguantaLaConcurrencia(unittest.TestCase):
    def test_escritores_en_proceso(self):
        """Hilos del mismo proceso: la carrera más apretada."""
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            (ws / ".harness").mkdir()

            def escribir(i):
                append_event(ws, {"kind": "prueba/evento", "n": i})

            with cf.ThreadPoolExecutor(max_workers=CONCURRENTES) as ex:
                list(ex.map(escribir, range(CONCURRENTES)))

            r = verificar_cadena(ws)
            self.assertTrue(r["ok"], f"la cadena se rompió con escrituras concurrentes "
                                     f"legítimas: {r['motivo']}")
            self.assertEqual(CONCURRENTES, r["eventos"],
                             "se perdió algún evento al serializar: el bloqueo no puede "
                             "comprarse descartando escrituras")

    def test_guardianes_en_procesos_distintos(self):
        """El caso real: `core.guard` corre en un proceso por llamada de herramienta."""
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            (ws / ".harness").mkdir()

            def lanzar(i):
                payload = {"tool_name": "Write",
                           "tool_input": {"file_path": str(ws / f"n{i}.txt"), "content": "x"},
                           "cwd": str(ws)}
                subprocess.run(  # nosec B603
                    [sys.executable, "-m", "core.guard", "--runtime", "claude", "--stdin",
                     "--workspace", str(ws)],
                    input=json.dumps(payload), capture_output=True,
                    cwd=str(RAIZ), timeout=120, **TEXT_IO)

            with cf.ThreadPoolExecutor(max_workers=CONCURRENTES) as ex:
                list(ex.map(lanzar, range(CONCURRENTES)))

            r = verificar_cadena(ws)
            self.assertTrue(r["ok"], f"el guardián real rompe su propio diario al decidir en "
                                     f"paralelo: {r['motivo']}")
            self.assertEqual(CONCURRENTES, r["eventos"])


class TestLeerLaCabezaNoRecorreElDiario(unittest.TestCase):
    """`append_event` llama a `cabeza()` en cada evento, y el diario sólo crece.

    No se mide el tiempo —una prueba que afirme milisegundos es una prueba que falla en la
    máquina de otro—: se mide el VOLUMEN LEÍDO, que es la propiedad de verdad.
    """

    def test_se_leen_bytes_acotados_y_no_el_fichero_entero(self):
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            (ws / ".harness").mkdir()
            for i in range(500):
                append_event(ws, {"kind": "prueba/relleno", "n": i, "pad": "x" * 200})
            path = ledger_path(ws)
            total = path.stat().st_size
            self.assertGreater(total, 100_000, "el diario de la prueba tiene que ser grande "
                                               "para que la propiedad signifique algo")

            leido = {"n": 0}
            real = Path.open

            def contando(self_path, *a, **kw):
                fh = real(self_path, *a, **kw)
                if Path(self_path) != path:
                    return fh
                lectura = fh.read

                def read(n=-1):
                    datos = lectura(n)
                    leido["n"] += len(datos)
                    return datos

                fh.read = read
                return fh

            Path.open = contando
            try:
                self.assertNotEqual(GENESIS, cabeza(ws))
            finally:
                Path.open = real

            self.assertLess(leido["n"], total // 4,
                            f"leer la cabeza consumió {leido['n']} de {total} bytes: vuelve a "
                            f"ser O(n) por evento, en el camino caliente del guardián")


class TestLoQueLaCadenaSigueSinPoderDetectar(unittest.TestCase):
    """El límite declarado no se cierra con esto, y la prueba lo deja escrito.

    Truncar la COLA deja una cadena que cierra. `core/evidence.py` lo dice y `SECURITY.md` lo
    declara `NOT_PROVEN`. Fijarlo aquí impide que el arreglo de la concurrencia se lea como una
    garantía que no da.
    """

    def test_truncar_la_cola_sigue_sin_detectarse_sin_ancla(self):
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            (ws / ".harness").mkdir()
            for i in range(5):
                append_event(ws, {"kind": "prueba/evento", "n": i})
            ancla = cabeza(ws)
            path = ledger_path(ws)
            lineas = path.read_text(encoding="utf-8").splitlines()
            path.write_text("\n".join(lineas[:3]) + "\n", encoding="utf-8")

            self.assertTrue(verificar_cadena(ws)["ok"],
                            "sin ancla publicada, la truncación de cola es indetectable: si "
                            "esto cambia, actualice SECURITY.md, que la declara NOT_PROVEN")
            self.assertFalse(verificar_cadena(ws, esperado=ancla)["ok"],
                             "con ancla publicada SÍ tiene que detectarse")


if __name__ == "__main__":
    unittest.main()
