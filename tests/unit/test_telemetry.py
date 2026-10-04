# -*- coding: utf-8 -*-
"""La lectura del diario, y la regla que la hace utilizable: **toda cifra con su cobertura**.

`duration_ms` y `entrada_digest` existen desde el 2026-09-28. Sobre los 52.131 eventos que ya
había, la cobertura de una mediana de latencia es del 0,2 %. Publicar «mediana 13 ms» sin ese
número al lado no es un resumen optimista: es una cifra distinta de la que aparenta.

Lo que más se vigila aquí no es que las cuentas salgan —eso es fácil— sino tres formas concretas
de mentir sin querer: contar un evento sin medir como si midiera cero, emparejar una decisión con
el resultado de otra herramienta que iba en paralelo, y leer un `ok` desconocido como un éxito.
"""

from __future__ import annotations

import json
import shutil
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

from core import telemetry as T

T0 = datetime(2026, 9, 28, 12, 0, 0, tzinfo=timezone.utc)


def dec(**kw) -> dict:
    e = {"ts": T0.isoformat(), "kind": T.KIND_DECISION, "runtime": "claude", "tool": "Bash",
         "outcome": "allow", "rule": "", "target": "x"}
    e.update(kw)
    return e


def res(**kw) -> dict:
    e = {"ts": T0.isoformat(), "kind": T.KIND_RESULTADO, "runtime": "claude", "tool": "Bash",
         "ok": True}
    e.update(kw)
    return e


def en(t: datetime) -> str:
    return t.isoformat()


class TestCoberturaDeCadaCifra(unittest.TestCase):

    def test_un_evento_sin_duracion_no_cuenta_como_cero(self):
        """El error que convertiría la mediana en ficción: tratar «no medido» como «0 ms»
        hundiría la mediana hacia cero justo mientras la cobertura es baja."""
        s = T.resumen([dec(duration_ms=100.0), dec(), dec(), dec()])
        self.assertEqual(1, s["guardian_ms"]["n"])
        self.assertEqual(4, s["guardian_ms"]["de"])
        self.assertEqual(100.0, s["guardian_ms"]["mediana"])
        self.assertEqual(25.0, s["guardian_ms"]["cobertura"])

    def test_sin_ninguna_medida_no_se_inventa_una_mediana(self):
        s = T.resumen([dec(), dec()])
        self.assertIsNone(s["guardian_ms"]["mediana"])
        self.assertEqual(0.0, s["guardian_ms"]["cobertura"])

    def test_un_booleano_no_es_una_duracion(self):
        """`True` es `1` en Python. Sin el filtro, una bandera entraría en la muestra como 1 ms."""
        s = T.resumen([dec(duration_ms=True), dec(duration_ms=10.0)])
        self.assertEqual(1, s["guardian_ms"]["n"])
        self.assertEqual(10.0, s["guardian_ms"]["mediana"])

    def test_la_friccion_sale_de_las_decisiones_y_no_de_los_eventos(self):
        s = T.resumen([dec(outcome="allow"), dec(outcome="deny"), dec(outcome="ask"), res()])
        self.assertEqual(3, s["decisiones"]["total"])
        self.assertAlmostEqual(66.7, s["decisiones"]["friccion_pct"], places=1)


class TestEmparejarDecisionConSuResultado(unittest.TestCase):

    def test_se_casan_por_digest_y_no_por_cercania(self):
        """Dos herramientas en vuelo, intercaladas. Emparejar por proximidad daría la duración
        de una a la otra; por `entrada_digest` cada una recibe la suya."""
        eventos = [
            dec(ts=en(T0), entrada_digest="aaa", tool="Bash"),
            dec(ts=en(T0 + timedelta(seconds=1)), entrada_digest="bbb", tool="Write"),
            res(ts=en(T0 + timedelta(seconds=2)), entrada_digest="bbb", tool="Write"),
            res(ts=en(T0 + timedelta(seconds=10)), entrada_digest="aaa", tool="Bash"),
        ]
        s = T.resumen(eventos)
        self.assertEqual(2, s["herramientas_s"]["emparejados"])
        por = {x["tool"]: x["mediana"] for x in s["lentas"]}
        self.assertAlmostEqual(10.0, por["Bash"], places=1)
        self.assertAlmostEqual(1.0, por["Write"], places=1)

    def test_un_resultado_sin_decision_previa_no_se_empareja(self):
        s = T.resumen([res(entrada_digest="huerfano")])
        self.assertEqual(0, s["herramientas_s"]["emparejados"])
        self.assertEqual(1, s["herramientas_s"]["sin_pareja"])

    def test_un_resultado_anterior_a_su_decision_no_se_empareja(self):
        """Relojes al revés o un diario reordenado: una duración negativa no es un dato lento,
        es un dato imposible, y colarlo bajaría la mediana de todos."""
        s = T.resumen([dec(ts=en(T0 + timedelta(seconds=5)), entrada_digest="x"),
                       res(ts=en(T0), entrada_digest="x")])
        self.assertEqual(0, s["herramientas_s"]["emparejados"])

    def test_con_varias_decisiones_del_mismo_digest_gana_la_mas_reciente_anterior(self):
        """El mismo comando ejecutado dos veces: su resultado pertenece a la última, no a la
        primera — con la primera, la duración incluiría el hueco entre ambas."""
        eventos = [dec(ts=en(T0), entrada_digest="r"),
                   dec(ts=en(T0 + timedelta(seconds=30)), entrada_digest="r"),
                   res(ts=en(T0 + timedelta(seconds=31)), entrada_digest="r")]
        s = T.resumen(eventos)
        self.assertAlmostEqual(1.0, s["herramientas_s"]["mediana"], places=1)

    def test_se_declara_cuantas_decisiones_no_tienen_resultado(self):
        s = T.resumen([dec(entrada_digest="a"), dec(entrada_digest="b")])
        self.assertEqual(2, s["herramientas_s"]["decisiones_sin_resultado"])
        self.assertEqual(0, s["herramientas_s"]["resultados"])


class TestDesenlace(unittest.TestCase):

    def test_desconocido_no_es_exito(self):
        s = T.resumen([res(ok=True), res(ok=None), res(ok=False)])
        self.assertEqual({"ok": 1, "sin determinar": 1, "fallo": 1}, s["desenlace"])

    def test_un_resultado_sin_campo_ok_cuenta_como_sin_determinar(self):
        e = res()
        del e["ok"]
        self.assertEqual({"sin determinar": 1}, T.resumen([e])["desenlace"])


class TestLecturaDeDiarios(unittest.TestCase):

    def setUp(self):
        self.base = Path(tempfile.mkdtemp(prefix="tele-")).resolve()

    def tearDown(self):
        shutil.rmtree(self.base, ignore_errors=True)

    def _diario(self, espacio: str, lineas: list) -> Path:
        p = T.ledger(self.base / espacio)
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text("\n".join(lineas) + "\n", encoding="utf-8")
        return p

    def test_una_linea_corrupta_se_cuenta_y_no_se_ignora(self):
        """Un diario medio roto leído como si estuviera entero da cifras más bajas y ninguna
        señal de que faltan."""
        self._diario("a", [json.dumps(dec()), "{ esto no es json", json.dumps(dec())])
        d = T.leer([T.ledger(self.base / "a")])
        self.assertEqual(2, len(d["eventos"]))
        self.assertEqual(1, d["ilegibles"])
        self.assertEqual(3, d["leidos"])

    def test_una_linea_que_es_json_pero_no_un_objeto_tambien(self):
        self._diario("a", [json.dumps(dec()), "[1,2,3]", '"texto"'])
        self.assertEqual(2, T.leer([T.ledger(self.base / "a")])["ilegibles"])

    def test_cada_evento_sabe_de_que_espacio_viene(self):
        self._diario("uno", [json.dumps(dec())])
        self._diario("dos", [json.dumps(dec()), json.dumps(dec())])
        d = T.leer([T.ledger(self.base / "uno"), T.ledger(self.base / "dos")])
        self.assertEqual({"uno": 1, "dos": 2}, T.resumen(d["eventos"])["por_espacio"])

    def test_la_ventana_deja_fuera_lo_viejo(self):
        viejo = (datetime.now().astimezone() - timedelta(days=30)).isoformat()
        nuevo = datetime.now().astimezone().isoformat()
        self._diario("a", [json.dumps(dec(ts=viejo)), json.dumps(dec(ts=nuevo))])
        d = T.leer([T.ledger(self.base / "a")], desde=T.ventana(7))
        self.assertEqual(1, len(d["eventos"]))

    def test_un_evento_sin_marca_de_tiempo_no_se_descarta_por_la_ventana(self):
        """No se sabe cuándo fue; descartarlo sería decidir que es viejo. Se conserva y se
        cuenta, que es lo único que se puede afirmar de él."""
        e = dec()
        del e["ts"]
        self._diario("a", [json.dumps(e)])
        self.assertEqual(1, len(T.leer([T.ledger(self.base / "a")], desde=T.ventana(1))["eventos"]))

    def test_encuentra_los_diarios_de_los_repos_anidados(self):
        self._diario("espacio", [json.dumps(dec())])
        self._diario("espacio/repo", [json.dumps(dec())])
        self._diario("espacio/area/repo", [json.dumps(dec())])
        self.assertEqual(3, len(T.diarios([self.base / "espacio"])))

    def test_un_ambito_sin_diarios_da_lista_vacia_y_no_revienta(self):
        self.assertEqual([], T.diarios([self.base / "no-existe"]))

    def test_no_se_lee_dos_veces_el_mismo_diario(self):
        """Dos raíces que se solapan no pueden duplicar los eventos: la fricción saldría igual
        y el volumen el doble."""
        self._diario("espacio/repo", [json.dumps(dec())])
        rutas = T.diarios([self.base / "espacio", self.base / "espacio"])
        self.assertEqual(1, len(rutas))


class TestResumenVacio(unittest.TestCase):

    def test_cero_eventos_no_afirma_nada(self):
        s = T.resumen([])
        self.assertEqual(0, s["eventos"])
        self.assertIsNone(s["decisiones"]["friccion_pct"])
        self.assertIsNone(s["guardian_ms"]["mediana"])
        self.assertEqual("", s["desde"])


if __name__ == "__main__":
    unittest.main()
