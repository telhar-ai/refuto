# -*- coding: utf-8 -*-
"""Al vigilante de las cifras del README lo vigila esto.

Por qué, y es la segunda mitad de una retractación
---------------------------------------------------
`scripts/check_mediciones.py` se añadió el 2026-09-25 porque las cifras de corrida del README
llevaban cinco commits desfasadas **con fecha del propio día** —declaraba 685 pruebas y 13
controles cuando eran 748 y 14—, y porque las cifras estructurales sí tenían quien las mirara
(`check_wiring`, `check_citas`) y éstas no.

Se entregó sin ninguna prueba. Es decir: el arreglo de «un control que nadie vigila» fue un
control que nadie vigilaba. Un guion de verificación que sólo se ha ejercitado en el caso bueno
—el README de hoy, que está al día— no ha demostrado lo único que importa de él: que **sabe
decir que no**.

Es el mismo criterio que `scripts/mutate_probe.py` aplica a sí mismo con sus controles
negativos `NC1`/`NC2`: sin demostrar que sabe informar `VIVA`, un 6/6 de mutaciones muertas es
`INCONCLUSIVE` y no un dato.
"""

from __future__ import annotations

import importlib.util
import sys
import unittest
from pathlib import Path

RAIZ = Path(__file__).resolve().parents[2]
GUION = RAIZ / "scripts" / "check_mediciones.py"


def _cargar():
    spec = importlib.util.spec_from_file_location("check_mediciones", GUION)
    mod = importlib.util.module_from_spec(spec)
    sys.modules["check_mediciones"] = mod
    spec.loader.exec_module(mod)
    return mod


CM = _cargar()

#: Comprobaciones de juguete, para ejercitar el criterio sin depender del README real.
FALSAS = (("una cifra", r"hay \*\*(\d+)\*\* cosas", lambda: 7),)


class TestSabeDecirQueNo(unittest.TestCase):
    """El control negativo. Sin él, un guion que devolviera 0 siempre pasaría por bueno."""

    def test_detecta_una_cifra_que_ya_no_da_eso(self):
        problemas, comprobadas = CM.revisar("hay **5** cosas", FALSAS)
        self.assertEqual(1, len(problemas), "una cifra falsa pasó por buena")
        self.assertEqual(1, comprobadas)
        self.assertIn("declara 5", problemas[0])
        self.assertIn("hoy son 7", problemas[0])

    def test_no_marca_una_cifra_que_sigue_dando_eso(self):
        problemas, comprobadas = CM.revisar("hay **7** cosas", FALSAS)
        self.assertEqual([], problemas)
        self.assertEqual(1, comprobadas)

    def test_una_afirmacion_que_desaparecio_no_se_da_por_buena(self):
        """El modo de fallo silencioso: si el patrón deja de casar, «no hay problema» sería
        indistinguible de «ya no se comprueba nada»."""
        problemas, comprobadas = CM.revisar("el README ya no dice eso", FALSAS)
        self.assertEqual(1, len(problemas))
        self.assertEqual(0, comprobadas, "no se comprobó ninguna y aun así habría aprobado")
        self.assertIn("no se encontró", problemas[0])


def _fila(pasan: int, total: int, fallan: int | None = None) -> str:
    """Una fila de la suite como la escribe el README, para ejercitar el criterio."""
    txt = f"| La suite | **E3** | `python3 refuto.py selftest` → **{pasan}/{total}, 5 omitidas**"
    if fallan is not None:
        txt += f". **{fallan} fallan**: `test_x` y `test_y`"
    return txt + " |"


class TestCoherenciaDelResultado(unittest.TestCase):
    """El hueco que tenía este control: exigía declarar que todo pasa.

    Comprobaba el NUMERADOR contra el total del árbol, así que con dos pruebas en rojo la única
    forma de dejarlo en verde era escribir una cifra falsa. Lo que se puede exigir sin ejecutar la
    suite no es cuántas pasan —eso lo dice la corrida— sino que lo declarado no se contradiga.
    """

    def test_todo_pasa_y_no_declara_fallos(self):
        self.assertEqual([], CM.coherencia_del_resultado(_fila(1373, 1373)))

    def test_declara_fallos_y_cuadran(self):
        self.assertEqual([], CM.coherencia_del_resultado(_fila(1371, 1373, 2)))

    def test_un_hueco_sin_declarar_no_pasa(self):
        """`1371/1373` a secas: hay dos en rojo y la tabla no dice cuáles."""
        p = CM.coherencia_del_resultado(_fila(1371, 1373))
        self.assertEqual(1, len(p))
        self.assertIn("no dice cuántas fallan", p[0])
        self.assertIn("**2 fallan**", p[0])

    def test_el_numero_de_fallos_tiene_que_cuadrar(self):
        p = CM.coherencia_del_resultado(_fila(1371, 1373, 5))
        self.assertEqual(1, len(p))
        self.assertIn("fallan 5", p[0])

    def test_decir_que_todo_pasa_mientras_se_declaran_fallos_es_contradictorio(self):
        """El camino por el que se colaría un verde: la cifra dice que no falla ninguna y el
        texto de al lado enumera dos."""
        p = CM.coherencia_del_resultado(_fila(1373, 1373, 2))
        self.assertEqual(1, len(p))
        self.assertIn("fallan 2", p[0])

    def test_no_pueden_pasar_mas_de_las_que_hay(self):
        p = CM.coherencia_del_resultado(_fila(1400, 1373))
        self.assertEqual(1, len(p))
        self.assertIn("más de las que hay", p[0])

    def test_si_la_fila_desaparece_no_se_da_por_buena(self):
        p = CM.coherencia_del_resultado("el README ya no declara el resultado de la suite")
        self.assertEqual(1, len(p))
        self.assertIn("no se encontró", p[0])

    def test_el_readme_real_es_coherente(self):
        readme = (RAIZ / "README.md").read_text(encoding="utf-8")
        self.assertEqual([], CM.coherencia_del_resultado(readme))

    def test_se_aplica_al_revisar_el_readme_real_y_no_a_un_juego_sintetico(self):
        """Con comprobaciones de juguete no se exige la fila de la suite: quien ejercita un
        patrón no debería tener que traer el README entero."""
        self.assertEqual([], CM.revisar("hay **7** cosas", FALSAS)[0])
        problemas, _ = CM.revisar("hay **7** cosas", FALSAS, coherencia=True)
        self.assertEqual(1, len(problemas))
        self.assertIn("no se encontró", problemas[0])

    def test_el_denominador_es_el_que_se_mide_contra_el_arbol(self):
        """Si se comparara el numerador, declarar un fallo volvería a ser imposible."""
        nombres = [c[0] for c in CM.COMPROBACIONES]
        self.assertIn("total de la suite", nombres)
        patron = [c[1] for c in CM.COMPROBACIONES if c[0] == "total de la suite"][0]
        import re
        m = re.search(patron, _fila(1371, 1373, 2))
        self.assertEqual("1373", m.group(1), "el control volvió a capturar el numerador")


class TestSobreElREADMEDeVerdad(unittest.TestCase):
    def test_las_afirmaciones_declaradas_siguen_estando_en_el_readme(self):
        """Cada patrón tiene que CASAR. Un patrón que no casa no aprueba: informa de que la
        tabla se reescribió y nadie actualizó el control."""
        readme = (RAIZ / "README.md").read_text(encoding="utf-8")
        problemas, comprobadas = CM.revisar(readme)
        # `+ 1` por `coherencia_del_resultado`, que no está en la tupla porque no compara una
        # cifra del README con el árbol: compara el README consigo mismo.
        esperadas = len(CM.COMPROBACIONES) + 1
        self.assertEqual(esperadas, comprobadas,
                         f"{esperadas - comprobadas} afirmación(es) del README ya "
                         f"no se localizan: {problemas}")

    def test_y_todas_dan_lo_que_declaran(self):
        readme = (RAIZ / "README.md").read_text(encoding="utf-8")
        problemas, _ = CM.revisar(readme)
        self.assertEqual([], problemas)

    def test_el_ambito_no_puede_estar_vacio(self):
        """Un control con cero comprobaciones aprobaría siempre, que es lo contrario de un
        control. `main()` devuelve 2 en ese caso; aquí se fija que no llegue a ocurrir."""
        self.assertGreater(len(CM.COMPROBACIONES), 0)

    def test_no_comprueba_tiempos_a_proposito(self):
        """Un umbral de milisegundos falla en la máquina de otro, y un control que falla por
        motivos que no son el defecto se desactiva. La decisión se fija para que no se
        reintroduzca sin discutirla."""
        for nombre, _, _ in CM.COMPROBACIONES:
            with self.subTest(afirmacion=nombre):
                self.assertNotIn("segundo", nombre.lower())
                self.assertNotIn(" ms", nombre.lower())


class TestLoQueMideEsElCargadorYNoUnGrep(unittest.TestCase):
    def test_el_recuento_coincide_con_quien_decide_que_se_ejecuta(self):
        """`grep -c "def test_"` daba uno de más: el texto aparece dentro de una cadena. El
        cargador de `unittest` es el que decide qué corre, así que es el que cuenta."""
        import unittest as ut

        por_suite = CM._pruebas_por_suite()                            # noqa: SLF001
        for suite, n in por_suite.items():
            with self.subTest(suite=suite):
                real = ut.TestLoader().discover(str(RAIZ / "tests" / suite),
                                                top_level_dir=str(RAIZ)).countTestCases()
                self.assertEqual(real, n)


if __name__ == "__main__":
    unittest.main()
