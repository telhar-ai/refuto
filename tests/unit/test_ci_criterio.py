# -*- coding: utf-8 -*-
"""El criterio con el que CI juzga una corrida de puertas.

La tentación que estas pruebas cierran
--------------------------------------
El trabajo de CI sobre el espacio de ejemplo salía en rojo en TODA corrida, porque un ejecutor
sin agentes instalados no puede comprobar `G-AGENT` ni las que dependen de ella. Un rojo
permanente se deja de leer, y entonces el día que haya un rojo de verdad nadie lo mira.

Había tres salidas y sólo una es honesta:

    forzar verde        convertir BLOCKED en PASS. Es el fraude que este repositorio existe
                        para impedir, cometido por su propia tubería.
    dejarlo en rojo     honesto y **inútil**: la señal deja de significar nada.
    declarar el bloqueo  ← elegida. El trabajo afirma algo MÁS ESTRECHO y comprobable: «lo
                        único bloqueado es lo declarado de antemano, con su motivo». Un
                        bloqueo nuevo sigue parando la integración, porque es información.

Lo que estas pruebas impiden es que la tercera degenere en la primera.
"""

from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from core.proc import TEXT_IO

RAIZ = Path(__file__).resolve().parents[2]
GUION = RAIZ / "scripts" / "gate_summary.py"


def _cargar():
    spec = importlib.util.spec_from_file_location("gate_summary", GUION)
    mod = importlib.util.module_from_spec(spec)
    sys.modules["gate_summary"] = mod
    spec.loader.exec_module(mod)
    return mod


def _corrida(gates: list, verdict: str = "NO INTEGRABLE TODAVÍA") -> Path:
    doc = {"schema": "harness.run/v1", "run_id": "ver_0123456789abcdef",
           "verdict": verdict,
           "gates": [{"id": i, "status": s, "measure": m} for i, s, m in gates]}
    f = Path(tempfile.mkstemp(suffix=".json")[1])
    f.write_text(json.dumps(doc, ensure_ascii=False), encoding="utf-8", newline="\n")
    return f


def _ejecutar(ruta: Path, declarado: bool) -> tuple[int, str]:
    argv = [sys.executable, str(GUION)]
    if declarado:
        argv.append("--bloqueo-esperado")
    argv.append(str(ruta))
    p = subprocess.run(argv, capture_output=True, cwd=str(RAIZ), **TEXT_IO)
    return p.returncode, (p.stdout or "") + (p.stderr or "")


class TestUnBloqueoDeclaradoNoEsUnAprobado(unittest.TestCase):

    def test_solo_bloqueos_declarados_deja_seguir(self):
        f = _corrida([("G-AGENT", "BLOCKED", "sin agentes en el ejecutor"),
                      ("G-ROLES", "PASS", "22 roles")])
        rc, salida = _ejecutar(f, declarado=True)
        self.assertEqual(0, rc, salida)
        self.assertIn("Esto NO es un aprobado", salida,
                      "se dejó seguir sin declarar que el veredicto sigue sin ser integrable")
        self.assertIn("NO INTEGRABLE", salida, "el veredicto real dejó de imprimirse")

    def test_un_bloqueo_NO_declarado_para_la_integracion(self):
        """La mitad que impide que esto degenere en «forzar verde».

        Si bastara con pasar `--bloqueo-esperado` para que cualquier BLOCKED se perdonara,
        la bandera sería un `|| true` con nombre largo.
        """
        f = _corrida([("G-SECURITY", "BLOCKED", "herramientas: ninguna"),
                      ("G-ROLES", "PASS", "22 roles")])
        rc, salida = _ejecutar(f, declarado=True)
        self.assertNotEqual(0, rc, "un bloqueo no declarado pasó")
        self.assertIn("BLOQUEO NO DECLARADO", salida)
        self.assertIn("G-SECURITY", salida)

    def test_un_rojo_para_la_integracion_aunque_se_declare(self):
        """`--bloqueo-esperado` habla de BLOCKED. Un FAIL no se perdona jamás."""
        f = _corrida([("G-AGENT", "BLOCKED", "sin agentes"),
                      ("G-PR", "FAIL", "se trabaja sobre main")], verdict="NO INTEGRABLE")
        rc, _ = _ejecutar(f, declarado=True)
        self.assertEqual(1, rc)

    def test_un_no_ejecutable_tampoco_se_perdona(self):
        f = _corrida([("G-AGENT", "BLOCKED", "sin agentes"),
                      ("G-MCP", "NOT_EXECUTABLE", "config ilegible")], verdict="NO INTEGRABLE")
        rc, _ = _ejecutar(f, declarado=True)
        self.assertEqual(1, rc)

    def test_todo_bloqueado_y_nada_aprobado_no_pasa(self):
        """Ámbito vacío no aprueba, tampoco por esta vía.

        Sin este caso, un espacio donde NINGUNA puerta encontrara sujeto saldría en verde
        porque todos sus bloqueos estaban declarados — que es exactamente un aprobado vacuo.
        """
        f = _corrida([("G-AGENT", "BLOCKED", "sin agentes"),
                      ("G-TRACE", "BLOCKED", "sin requisitos")])
        rc, salida = _ejecutar(f, declarado=True)
        self.assertNotEqual(0, rc, "ninguna puerta aprobó y aun así pasó")
        self.assertIn("Ámbito vacío", salida)

    def test_sin_la_bandera_el_criterio_estricto_se_mantiene(self):
        """Quien no pide la excepción no la recibe. El comportamiento por omisión no cambió."""
        f = _corrida([("G-AGENT", "BLOCKED", "sin agentes"),
                      ("G-ROLES", "PASS", "22 roles")])
        rc, salida = _ejecutar(f, declarado=False)
        self.assertEqual(2, rc)
        self.assertIn("BLOCKED no es aprobado", salida)

    def test_cada_bloqueo_declarado_trae_su_motivo(self):
        """Una lista de excepciones sin motivo es una lista de perdones.

        El motivo es lo que permite revisarla: sin él, añadir una puerta a
        `BLOQUEO_ESPERADO` sería indistinguible de silenciarla.
        """
        mod = _cargar()
        self.assertTrue(mod.BLOQUEO_ESPERADO, "la lista está vacía")
        for puerta, motivo in mod.BLOQUEO_ESPERADO.items():
            self.assertTrue(motivo.strip(), f"{puerta} se declara sin motivo")
            self.assertGreater(len(motivo), 25, f"{puerta}: el motivo no explica nada")

    def test_G_SECURITY_no_esta_perdonada(self):
        """La causa de G-SECURITY se puede eliminar instalando escáneres, y se eliminó.

        Si alguien la añade a la lista, esta prueba lo para: declararla «esperada» sería
        aceptar para siempre un pipeline que no puede decir si hay secretos en el árbol.
        """
        mod = _cargar()
        self.assertNotIn("G-SECURITY", mod.BLOQUEO_ESPERADO,
                         "G-SECURITY se perdonó en vez de instalar los escáneres")


if __name__ == "__main__":
    unittest.main()
