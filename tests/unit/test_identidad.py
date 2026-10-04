# -*- coding: utf-8 -*-
"""Identidad de ejecución: cuatro entidades, cuatro tipos, y el legado que se sigue leyendo.

Estas son las pruebas que [ADR-0012](../../docs/decisions/ADR-0012-identidad-de-ejecucion.md)
declaró y que estaban todas en `NOT_RUN`. Mientras lo estuvieron, el ADR describía una
intención; un ADR aceptado es una decisión tomada, no una propiedad del sistema.

El defecto que cierran, medido el 2026-09-22
--------------------------------------------
`core/model.py` tenía UN generador, `new_run_id() -> "run_<hex16>"`, y lo llamaban CUATRO
sitios para cuatro entidades con ciclos de vida distintos:

    core/run.py:168      ejecución orquestada  →  .harness/state/<id>.json
    core/session.py:879  sesión interactiva    →  eventos `session/*` del diario
    core/runcontext.py   contexto construido   →  .harness/context/
    refuto.py:888        verificación          →  .harness/evidence/<id>.json

De seis enlaces posibles existía uno. El síntoma visible: `refuto status` decía «no hay
ninguna ejecución registrada» justo después de un `verify` que había impreso la ruta de su
evidencia. Ninguno de los dos mentía: leían familias distintas con el mismo nombre.
"""

from __future__ import annotations

import unittest

from core.model import (KIND_CONTEXT, KIND_LEGACY, KIND_ORCHESTRATION, KIND_SESSION,
                        KIND_VERIFICATION, KINDS, kind_of, new_id, new_run_id)
from tests.fixtures import Workspace


class TestElTipoSeLeeDelIdentificador(unittest.TestCase):

    def test_cada_tipo_se_distingue_sin_mirar_el_directorio(self):
        """Un id suelto en un diario tiene que poder decir qué es.

        Si el tipo hubiera que deducirlo del directorio, un evento del ledger —que no está en
        ningún directorio— seguiría sin poder decir a qué entidad pertenece.
        """
        vistos = set()
        for kind in KINDS:
            ident = new_id(kind)
            self.assertEqual(kind, kind_of(ident), f"{ident} no se reconoce como {kind}")
            vistos.add(kind_of(ident))
        self.assertEqual(set(KINDS), vistos, "hay tipos que colapsan entre sí")

    def test_los_cuatro_acunadores_emiten_tipos_distintos(self):
        """La prueba que habría detectado el defecto original.

        Con `new_run_id()` en los cuatro sitios, este aserto fallaba: los cuatro daban `run`.
        """
        self.assertEqual(
            {KIND_SESSION, KIND_ORCHESTRATION, KIND_VERIFICATION, KIND_CONTEXT},
            {kind_of(new_id(k)) for k in KINDS},
            "dos entidades distintas comparten tipo de identidad")

    def test_no_se_puede_emitir_el_formato_legado(self):
        """`run_` se lee, no se escribe. Si se pudiera emitir, la puerta seguiría abierta."""
        with self.assertRaises(ValueError):
            new_id(KIND_LEGACY)
        with self.assertRaises(ValueError):
            new_id("inventado")

    def test_una_forma_ajena_no_se_confunde_con_legado(self):
        """Vacío significa «no lo reconozco», NO «es legado».

        Otro programa puede reclamar el mismo directorio —ya ocurrió con `.harness/policy.json`,
        ver `Policy.from_dict`—. Tratar un id ajeno como propio es cómo un documento de otro
        contrato acaba gobernando este.
        """
        for ajeno in ("", "run-20260922-152000-a1b2c3d4", "abc_0123456789abcdef",
                      "ses_NOHEX", "ses_0123", "otro"):
            self.assertEqual("", kind_of(ajeno), f"{ajeno!r} se reconoció como propio")


class TestCompatibilidadDelLegado(unittest.TestCase):

    def test_el_formato_legado_sigue_siendo_legible(self):
        self.assertEqual(KIND_LEGACY, kind_of(new_run_id()),
                         "un id escrito por una versión anterior dejó de reconocerse")

    def test_una_ejecucion_con_prefijo_legado_se_sigue_encontrando(self):
        """El riesgo de la migración, fijado.

        `latest()` globbeaba `run_*.json`. Si al emitir `orq_` no se hubiera ampliado el
        lector, un espacio instalado antes habría pasado a responder «no hay ninguna
        ejecución» teniéndolas — la misma respuesta falsa que esto vino a corregir.
        """
        from core.run import Run, latest
        with Workspace("id-legado") as ws:
            viejo = Run(run_id=new_run_id(), workspace=str(ws.root), goal="de antes")
            viejo.save()
            hallado = latest(ws.root)
            self.assertIsNotNone(hallado, "una ejecución con prefijo legado se volvió invisible")
            self.assertEqual(viejo.run_id, hallado.run_id)

    def test_conviven_los_dos_prefijos_y_gana_el_mas_reciente(self):
        import time
        from core.run import Run, latest
        with Workspace("id-mixto") as ws:
            Run(run_id=new_run_id(), workspace=str(ws.root), goal="viejo").save()
            time.sleep(0.02)
            nuevo = Run(run_id=new_id(KIND_ORCHESTRATION), workspace=str(ws.root), goal="nuevo")
            nuevo.save()
            self.assertEqual(nuevo.run_id, latest(ws.root).run_id)


class TestCadaEntidadUsaSuTipo(unittest.TestCase):
    """Que el generador exista no sirve si los llamadores siguen acuñando sin tipo."""

    def test_la_sesion_acuna_identidad_de_sesion(self):
        from core.session import plan
        from core.wire import wire_claude
        from pathlib import Path
        HARNESS = Path(__file__).resolve().parents[2]
        with Workspace("id-ses") as ws:
            ws.policy()
            wire_claude(ws.root, harness_root=HARNESS)
            self.assertEqual(KIND_SESSION, kind_of(plan(ws.root, runtime="claude").run_id))

    def test_la_orquestacion_acuna_identidad_de_orquestacion(self):
        from core.run import plan as plan_run
        with Workspace("id-orq") as ws:
            ws.manifest()
            run, _ = plan_run(ws.root, goal="x")
            self.assertEqual(KIND_ORCHESTRATION, kind_of(run.run_id))

    def test_el_contexto_acuna_identidad_de_contexto(self):
        from core.runcontext import build
        with Workspace("id-ctx") as ws:
            ws.manifest()
            self.assertEqual(KIND_CONTEXT, kind_of(build(ws.root).run_id))


class TestVerifyYStatusHablanDeLoMismo(unittest.TestCase):
    """La divergencia de §11, fijada.

    `verify` escribía en `.harness/evidence/` e imprimía la ruta; `status` leía
    `.harness/state/` y contestaba «no hay ninguna ejecución registrada» un segundo después.
    Dos fuentes, dos vocabularios, ninguna relación — y la respuesta más engañosa posible:
    no «no lo sé», sino «no hay».
    """

    @staticmethod
    def _resultados():
        from core.model import Result, PASS, blocked
        return [Result("G-A", "a", PASS), blocked("G-B", "b", "falta una herramienta")]

    def test_lo_que_verify_escribe_es_lo_que_status_lee(self):
        from core.evidence import latest_verification, write_run
        from core.model import KIND_VERIFICATION, new_id
        with Workspace("ev-status") as ws:
            rid = new_id(KIND_VERIFICATION)
            path = write_run(ws.root, rid, self._resultados())
            leido = latest_verification(ws.root)
            self.assertIsNotNone(leido, "status no ve la evidencia que verify acaba de escribir")
            self.assertEqual(rid, leido["run_id"], "distinta identidad")
            self.assertEqual(str(path), leido["path"], "distinta evidencia")
            self.assertEqual({"G-A": "PASS", "G-B": "BLOCKED"}, leido["gates"])
            self.assertIn("NO INTEGRABLE", leido["verdict"])

    def test_sin_ninguna_verificacion_dice_ninguna_no_se_inventa(self):
        from core.evidence import latest_verification
        with Workspace("ev-vacio") as ws:
            self.assertIsNone(latest_verification(ws.root))

    def test_una_evidencia_ilegible_se_declara_y_no_se_salta(self):
        """`BLOCKED` no es `PASS`, y aquí «no pude leerlo» no puede salir como «no hay».

        Saltarse en silencio un fichero corrupto dejaría a `status` diciendo «ninguna
        registrada» con la evidencia delante — la misma clase de mentira cómoda que el
        vocabulario de estados existe para impedir.
        """
        from core.evidence import latest_verification
        with Workspace("ev-roto") as ws:
            d = ws.root / ".harness" / "evidence"
            d.mkdir(parents=True, exist_ok=True)
            (d / "ver_0123456789abcdef.json").write_text("{{{ roto", encoding="utf-8")
            leido = latest_verification(ws.root)
            self.assertIsNotNone(leido, "una evidencia ilegible se tragó y pareció ausencia")
            self.assertEqual(1, len(leido["unreadable"]))
            self.assertEqual("", leido["run_id"], "no se puede afirmar una identidad que no se leyó")

    def test_la_identidad_de_la_verificacion_es_de_tipo_verificacion(self):
        from core.evidence import latest_verification, write_run
        from core.model import KIND_VERIFICATION, new_id
        with Workspace("ev-tipo") as ws:
            write_run(ws.root, new_id(KIND_VERIFICATION), self._resultados())
            self.assertEqual(KIND_VERIFICATION,
                             kind_of(latest_verification(ws.root)["run_id"]))


if __name__ == "__main__":
    unittest.main()
