# -*- coding: utf-8 -*-
"""El sobre que toda orden de refuto emite. Un vocabulario, tres consumidores.

Qué se fija aquí, y por qué cada mitad hace falta
------------------------------------------------
1. **La proyección de estado a código de salida es total y no se elige a mano.** El defecto que
   esto cierra se midió el 2026-09-24: `refuto context --json` devolvía **2** —«no se pudo
   comprobar»— con la salida completa y válida en stdout. Para una persona es invisible; para
   CI, `cmd && siguiente` no encadena nunca, y para un agente el éxito es indistinguible de un
   fallo del arnés.
2. **Un estado que no aprueba trae al menos un `next`.** Es la mitad de asistencia, y sin ella
   el resto es un formato más. La lección viene medida: un agente al que se denegó su
   directorio de entregables, sin que nadie le dijera cuál usar, se llevó 9,2 GB a `/tmp` —
   fuera de git y en una ruta que el sistema borra a los tres días. Un control que deniega sin
   nombrar la alternativa no protege, desvía.
3. **Las instancias reales validan contra el esquema publicado.** `scripts/check_schemas.py`
   comprueba que un esquema cae en el subconjunto soportado y **no valida ni una instancia**:
   sin esta clase, `schemas/envelope.schema.json` podría describir un sobre que nadie emite.
"""

from __future__ import annotations

import json
import unittest
from pathlib import Path

RAIZ = Path(__file__).resolve().parents[2]

from core.envelope import (AGENTE, EXIGEN_SIGUIENTE, EXIT_BLOCKED, EXIT_FAIL, EXIT_OK, MAQUINA,
                           PERSONA, QUIENES, SCHEMA, Siguiente, envelope, exit_for)
from core.model import (BLOCKED, FAIL, INCONCLUSIVE, NON_PASSING, NOT_APPLICABLE,
                        NOT_EXECUTABLE, PASS, STATUSES)
from core.schema import load_schema, validate


def _sobre(**kw):
    base = dict(command="doctor", status=PASS, workspace="/ruta/al/espacio", payload={})
    base.update(kw)
    return envelope(**base)


class TestLaProyeccionDeEstadoACodigo(unittest.TestCase):
    def test_los_seis_estados_tienen_codigo(self):
        """Total por construcción: `core.envelope` no se importa si falta alguno."""
        for status in STATUSES:
            with self.subTest(status=status):
                self.assertIn(exit_for(status), (EXIT_OK, EXIT_FAIL, EXIT_BLOCKED))

    def test_un_estado_inventado_no_tiene_codigo_por_omision(self):
        with self.assertRaises(ValueError):
            exit_for("VERDE")

    def test_lo_que_no_se_pudo_comprobar_no_sale_con_cero(self):
        """`BLOCKED` no aprueba, y el código de salida tampoco puede decir que sí."""
        for status in (BLOCKED, NOT_EXECUTABLE, INCONCLUSIVE):
            with self.subTest(status=status):
                self.assertEqual(EXIT_BLOCKED, exit_for(status))

    def test_un_informativo_correcto_sale_con_cero(self):
        """El defecto medido: `context --json` salía con 2 con la salida válida en stdout."""
        self.assertEqual(EXIT_OK, _sobre(command="context", status=PASS)["exit"])

    def test_no_aplica_no_es_un_fallo(self):
        """«Esta orden no tiene sujeto aquí» no es algo que arreglar.

        No contradice «un ámbito vacío nunca aprueba»: esa regla gobierna el veredicto de una
        PUERTA. Aquí se responde «¿hay algo que arreglar?», y mapearlo a 1 haría fallar el CI
        de todo espacio que legítimamente no declara MCP.
        """
        self.assertEqual(EXIT_OK, exit_for(NOT_APPLICABLE))
        self.assertNotEqual(exit_for(NOT_APPLICABLE), exit_for(FAIL))

    def test_el_codigo_del_sobre_es_el_derivado_y_no_otro(self):
        for status in STATUSES:
            extra = {} if status not in EXIGEN_SIGUIENTE else {
                "next": [Siguiente(why="x", do="y", who=MAQUINA)]}
            with self.subTest(status=status):
                self.assertEqual(exit_for(status), _sobre(status=status, **extra)["exit"])


class TestLaAsistenciaEsContratoNoIntencion(unittest.TestCase):
    def test_un_estado_que_no_aprueba_exige_paso_siguiente(self):
        for status in sorted(EXIGEN_SIGUIENTE):
            with self.subTest(status=status), self.assertRaises(ValueError):
                _sobre(status=status)

    def test_y_con_el_paso_declarado_se_acepta(self):
        """La contraparte: sin ella lo de arriba se satisface rechazando todo sobre."""
        for status in sorted(EXIGEN_SIGUIENTE):
            with self.subTest(status=status):
                s = _sobre(status=status,
                           next=[Siguiente(why="falta el lock", do="refuto lock init",
                                           who=PERSONA)])
                self.assertEqual(1, len(s["next"]))

    def test_no_aplica_no_exige_paso(self):
        self.assertEqual([], _sobre(status=NOT_APPLICABLE)["next"])
        self.assertIn(NOT_APPLICABLE, NON_PASSING)      # no aprueba, y aun así no deja tarea

    def test_los_turnos_son_tres_y_no_se_inventan(self):
        self.assertEqual((PERSONA, MAQUINA, AGENTE), QUIENES)
        with self.assertRaises(ValueError):
            Siguiente(why="x", who="robot")

    def test_un_paso_sin_motivo_se_rechaza(self):
        with self.assertRaises(ValueError):
            Siguiente(why="   ", do="refuto verify")

    def test_next_solo_admite_el_tipo(self):
        """Un dict crudo pasaría la validación del esquema y saltaría la del tipo."""
        with self.assertRaises(TypeError):
            _sobre(status=FAIL, next=[{"why": "x", "do": "y", "who": "persona"}])


class TestElSobreNoSeEmiteMalFormado(unittest.TestCase):
    def test_sin_orden_no_hay_sobre(self):
        with self.assertRaises(ValueError):
            _sobre(command="  ")

    def test_la_carga_util_viaja_intacta(self):
        """Lo que esta envoltura NO hace: normalizar los veinte contratos de carga útil.

        Un consumidor que ya leía la carga útil migra con un acceso: `["payload"]`.
        """
        carga = {"schema": "harness.context/v1", "provenance": {"x": 1}, "agents": []}
        self.assertEqual(carga, _sobre(payload=carga)["payload"])

    def test_una_lista_tambien_es_carga_util_valida(self):
        """`probe --json` y `memory list --json` emiten listas, no objetos."""
        self.assertEqual([1, 2], _sobre(payload=[1, 2])["payload"])


class TestLosSobresRealesValidanContraElEsquemaPublicado(unittest.TestCase):
    def _casos(self):
        yield "informativo", _sobre(command="context", status=PASS, run_id="ctx_abc",
                                   provenance={"harness_version": "0.3.0"})
        yield "con pasos de los tres turnos", _sobre(
            command="doctor", status=BLOCKED,
            next=[Siguiente(why="falta el lock", do="refuto lock init", who=PERSONA),
                  Siguiente(why="política por detrás del motor",
                            do="refuto policy reconcile --apply", who=MAQUINA),
                  Siguiente(why="la especificación no existe", do="", who=AGENTE)])
        yield "no aplica", _sobre(command="mcp", status=NOT_APPLICABLE)
        yield "carga de lista", _sobre(command="probe", payload=[{"a": 1}])

    def test_validan(self):
        esquema = load_schema("envelope.schema.json")
        for nombre, sobre in self._casos():
            with self.subTest(caso=nombre):
                self.assertEqual([], validate(sobre, esquema), f"«{nombre}» no valida")

    def test_el_validador_no_esta_mudo(self):
        """Sin esto, la prueba de arriba la satisface un validador que devuelve siempre []."""
        esquema = load_schema("envelope.schema.json")
        roto = _sobre()
        roto["status"] = "VERDE"
        self.assertNotEqual([], validate(roto, esquema),
                            "el validador aceptó un estado que el esquema no admite")
        roto2 = _sobre()
        del roto2["payload"]
        self.assertNotEqual([], validate(roto2, esquema),
                            "el validador aceptó un sobre sin carga útil")

    def test_el_esquema_declara_el_mismo_identificador_que_el_codigo(self):
        esquema = load_schema("envelope.schema.json")
        self.assertEqual(SCHEMA, esquema["properties"]["schema"]["const"])

    def test_el_esquema_enumera_los_seis_estados_y_no_cinco(self):
        """Si alguien añade un séptimo estado, el esquema tiene que enterarse."""
        esquema = load_schema("envelope.schema.json")
        self.assertEqual(set(STATUSES), set(esquema["properties"]["status"]["enum"]))

    def test_el_esquema_enumera_los_mismos_turnos_que_el_codigo(self):
        esquema = load_schema("envelope.schema.json")
        turnos = esquema["$defs"]["siguiente"]["properties"]["who"]["enum"]
        self.assertEqual(set(QUIENES), set(turnos))


class TestConJsonStdoutLlevaSoloElSobre(unittest.TestCase):
    """La mitad del protocolo que no se ve, y sin la cual no sirve.

    Se midió dos veces el mismo defecto en dos días, y la segunda con el arreglo de la primera
    ya escrito:

        2026-09-24  `refuto doctor --json` mezclaba 20 líneas de diagnóstico con el sobre.
                    `json.load(stdout)` → «Expecting value: line 2 column 1».
        2026-09-25  `scripts/preflight.py --json` hacía exactamente lo mismo, y lo encontró el
                    trabajo de CI que ejecuta el preflight: rc=0, preflight en verde, y el paso
                    siguiente reventando al parsear.

    Dos veces es un patrón, y un patrón se fija con una prueba y no con un comentario. Esto
    recorre las superficies `--json` como las recorre un consumidor: por subproceso, leyendo
    stdout y nada más.
    """

    #: Las superficies se lanzan UNA vez para toda la clase. Cada lanzamiento es un proceso
    #: completo de refuto, y la primera versión hacía seis para comprobar tres propiedades sobre
    #: dos salidas: 55 pruebas de contrato pasaron a tardar 62 s, y una suite lenta se deja de
    #: ejecutar. Lo que se fija es el CANAL, y el canal no cambia entre aserciones.
    SUPERFICIES = {
        "refuto": ["refuto.py", "status", "--json"],
        # `--solo esquemas` es el control más barato del preflight: lo que se prueba aquí es que
        # stdout lleve sólo el sobre, no el veredicto.
        "preflight": ["scripts/preflight.py", "--solo", "esquemas", "--json"],
    }

    @classmethod
    def setUpClass(cls):
        import subprocess
        import sys as _sys

        from core.proc import TEXT_IO

        cls.salidas = {}
        for nombre, argv in cls.SUPERFICIES.items():
            p = subprocess.run([_sys.executable, *argv], cwd=RAIZ, capture_output=True,
                               timeout=600, **TEXT_IO)
            cls.salidas[nombre] = p.stdout or ""

    def test_una_orden_de_refuto_emite_json_puro(self):
        sobre = json.loads(self.salidas["refuto"])    # revienta si se colara texto humano
        self.assertEqual(SCHEMA, sobre["schema"])

    def test_el_preflight_emite_json_puro(self):
        sobre = json.loads(self.salidas["preflight"])
        self.assertEqual(SCHEMA, sobre["schema"])
        self.assertEqual("preflight", sobre["command"])

    def test_y_el_sobre_de_cada_superficie_valida(self):
        esquema = load_schema("envelope.schema.json")
        for nombre, crudo in self.salidas.items():
            with self.subTest(superficie=nombre):
                self.assertEqual([], validate(json.loads(crudo), esquema))


if __name__ == "__main__":
    unittest.main()
