# -*- coding: utf-8 -*-
"""C-R07-R06 · El estado que `status` calcula, el que reporta y el código con que sale.

Qué se demuestra aquí
---------------------
Dos propiedades distintas, y conviene no fundirlas porque se rompen por separado:

    P-R07   Un consumidor automático NUNCA recibe código 0 cuando el estado reportado no es
            operacionalmente satisfactorio según el contrato.
    P-R06   La destrucción o ausencia de evidencia necesaria para establecer el estado
            permanece OBSERVABLE en la frontera operativa.

Qué NO se demuestra
-------------------
`P-R06` se cierra **con expectativa material** (hay artefactos de corrida, luego hubo eventos
que los escribieron). Sin ninguna expectativa —espacio sin artefactos— «no hay diario» y «no ha
pasado nada» siguen siendo indistinguibles dentro de un único fichero mutable, y eso es un
límite de información, no un defecto que se pueda parchear. Lo que sí se exige aquí es que deje
de ser SILENCIOSO: `test_R06_sin_expectativa_el_borrado_deja_de_ser_silencioso` fija esa mitad.
Cerrar la otra exige un ancla publicada fuera del árbol — es FG-4, y no se finge desde aquí.

No se confunde con C-02
-----------------------
C-02 cerró la semántica del MOTOR: `verificar_cadena` ya no aprueba una ausencia contra una
expectativa. Este fichero cierra la PROPAGACIÓN: que ese hecho llegue al código de salida de la
orden que lo comunica. Son capas distintas y se rompen por separado — de hecho, C-02 estaba
cerrado y `status` seguía devolviendo 0.
"""

from __future__ import annotations

import json
import subprocess  # nosec B404 — ejecutar el CLI real ES la medición
import sys
import tempfile
import unittest
from pathlib import Path

from core.envelope import EXIT_BLOCKED, EXIT_FAIL, EXIT_OK, exit_for
from core.evidence import (AUSENTE, DESALINEADA, INSUFICIENTE, INTEGRA, ROTA, VACIO,
                           append_event, write_run)
from core.model import (BLOCKED, FAIL, INCONCLUSIVE, NOT_APPLICABLE, NOT_EXECUTABLE, PASS,
                        STATUSES, Result)
from core.proc import TEXT_IO

RAIZ = Path(__file__).resolve().parents[2]


def _cli(ws: Path, *args: str) -> tuple[int, str, dict]:
    """Ejecuta el CLI REAL. Ni `unittest` ni importaciones: el binario, como en CI."""
    p = subprocess.run(  # nosec B603
        [sys.executable, str(RAIZ / "refuto.py"), "--workspace", str(ws), *args],
        capture_output=True, cwd=str(RAIZ), timeout=120, **TEXT_IO)
    doc: dict = {}
    if "--json" in args and p.stdout.strip():
        try:
            doc = json.loads(p.stdout)
        except json.JSONDecodeError:
            doc = {}
    return p.returncode, p.stdout, doc


def _espacio(eventos: int = 0, *, artefacto: bool = False) -> Path:
    """Fixture AISLADO. Nunca se mide contra el diario vivo del repositorio."""
    ws = Path(tempfile.mkdtemp(prefix="c-r07-r06-")).resolve()
    (ws / ".harness" / "evidence").mkdir(parents=True)
    for i in range(eventos):
        append_event(ws, {"kind": "policy/decision", "tool": "Bash",
                          "target": f"cmd{i}", "outcome": "deny"})
    if artefacto:
        write_run(ws, "ver_fixture",
                  [Result(id="G-X", name="ficticia", status=PASS, threshold="t")])
    return ws


def _ledger(ws: Path) -> Path:
    return ws / ".harness" / "evidence" / "ledger.jsonl"


# ── el contrato estado → código, como tabla exigible ─────────────────────────────────
class ContratoDeCodigoDeSalida(unittest.TestCase):
    """`core.envelope` ya derivaba el código del estado. Esto fija que siga haciéndolo."""

    #: La tabla que este cambio declara. Vive duplicada a propósito: si alguien cambia
    #: `_EXIT_POR_ESTADO`, esta prueba lo reporta en vez de heredar el cambio en silencio.
    ESPERADO = {PASS: EXIT_OK, NOT_APPLICABLE: EXIT_OK, FAIL: EXIT_FAIL,
                BLOCKED: EXIT_BLOCKED, NOT_EXECUTABLE: EXIT_BLOCKED,
                INCONCLUSIVE: EXIT_BLOCKED}

    def test_todo_estado_del_modelo_tiene_codigo(self):
        for s in STATUSES:
            self.assertIn(s, self.ESPERADO, f"{s} no tiene código declarado")
            self.assertEqual(self.ESPERADO[s], exit_for(s), f"el código de {s} cambió")

    def test_ningun_estado_no_satisfactorio_sale_con_exito(self):
        """El corazón de P-R07, en su forma más general."""
        for s in (FAIL, BLOCKED, NOT_EXECUTABLE, INCONCLUSIVE):
            self.assertNotEqual(EXIT_OK, exit_for(s),
                                f"{s} no es satisfactorio y saldría con éxito")

    def test_un_estado_inventado_no_recibe_codigo_por_omision(self):
        with self.assertRaises(ValueError):
            exit_for("DEGRADED")

    def test_DEGRADED_no_existe_en_el_modelo(self):
        """A-09 es `NOT_APPLICABLE` y consta por qué.

        El vocabulario de la misión incluye `DEGRADED`; el del programa, no. Añadirlo es una
        decisión de contrato —`_SIN_CODIGO` obliga a decidir su código al importar— y no se
        toma de paso dentro de otro cambio. Mientras no exista, un ataque que exija estado
        `DEGRADED` no aplica, y decirlo es más honesto que fabricar un séptimo estado.
        """
        self.assertNotIn("DEGRADED", STATUSES)


# ── A-01 … A-10 · los ataques obligatorios, por el CLI real ──────────────────────────
class AtaquesSobreLaFronteraOperativa(unittest.TestCase):
    """Cada prueba ejecuta `refuto status` de verdad y mide su código de salida."""

    def test_A01_diario_y_artefacto_presentes_salen_con_exito(self):
        """Control positivo. Sin él, «todo da FAIL» aprobaría el resto del fichero."""
        ws = _espacio(3, artefacto=True)
        rc, _out, doc = _cli(ws, "status", "--json")
        self.assertEqual(PASS, doc.get("status"))
        self.assertEqual(EXIT_OK, rc)

    def test_A02_diario_borrado_con_artefacto_que_lo_exige(self):
        ws = _espacio(5, artefacto=True)
        self.assertEqual(EXIT_OK, _cli(ws, "status", "--json")[0], "control")
        _ledger(ws).unlink()
        rc, _out, doc = _cli(ws, "status", "--json")
        self.assertEqual(FAIL, doc.get("status"))
        self.assertNotEqual(EXIT_OK, rc)

    def test_A03_diario_truncado(self):
        ws = _espacio(5, artefacto=True)
        lineas = _ledger(ws).read_text(encoding="utf-8").splitlines()
        _ledger(ws).write_text("\n".join(lineas[:-2]) + "\n", encoding="utf-8")
        rc, _out, doc = _cli(ws, "status", "--json")
        self.assertEqual(FAIL, doc.get("status"),
                         "la cabeza que ancló el artefacto ya no está en la cadena")
        self.assertNotEqual(EXIT_OK, rc)

    def test_A04_diario_modificado(self):
        ws = _espacio(5, artefacto=True)
        lineas = _ledger(ws).read_text(encoding="utf-8").splitlines()
        ev = json.loads(lineas[1])
        ev["target"] = "otra-cosa"
        lineas[1] = json.dumps(ev, ensure_ascii=False)
        _ledger(ws).write_text("\n".join(lineas) + "\n", encoding="utf-8")
        rc, _out, doc = _cli(ws, "status", "--json")
        self.assertEqual(FAIL, doc.get("status"), "un eslabón editado rompe la cadena")
        self.assertNotEqual(EXIT_OK, rc)

    def test_A05_artefacto_borrado(self):
        """Sin artefacto no queda expectativa: el estado es PASS y el `next` lo dice.

        No es un fallo encubierto. Es la respuesta correcta a «no hay nada que afirme que este
        espacio cumpla», y `next` enruta a `refuto verify`.
        """
        ws = _espacio(5, artefacto=True)
        for p in (ws / ".harness" / "evidence").glob("ver_*.json"):
            p.unlink()
        rc, _out, doc = _cli(ws, "status", "--json")
        self.assertEqual(PASS, doc.get("status"))
        self.assertEqual(EXIT_OK, rc)
        self.assertTrue(any("verify" in (n.get("do") or "") for n in doc.get("next", [])),
                        "un espacio sin verificación tiene que enrutar a `refuto verify`")

    def test_A06_artefacto_presente_y_diario_ausente(self):
        """El caso que R-06 destapó, en su forma con expectativa."""
        ws = _espacio(4, artefacto=True)
        _ledger(ws).unlink()
        rc, out, doc = _cli(ws, "status", "--json")
        self.assertEqual(FAIL, doc.get("status"))
        self.assertNotEqual(EXIT_OK, rc)
        rc2, texto, _ = _cli(ws, "status")
        self.assertIn(AUSENTE, texto, "el estado del diario tiene que ser visible")

    def test_A07_diario_valido_y_artefacto_ausente(self):
        ws = _espacio(5)
        rc, _out, doc = _cli(ws, "status", "--json")
        self.assertEqual(PASS, doc.get("status"))
        self.assertEqual(EXIT_OK, rc)

    def test_A08_BLOCKED_no_lo_emite_status_pero_su_codigo_no_es_exito(self):
        """A-08: `status` no tiene hoy ninguna ruta que emita `BLOCKED` —usa `INCONCLUSIVE`
        para «no pude determinarlo»—, así que el ataque no aplica a la orden. Lo que sí se
        exige es que el contrato no le dé éxito si algún día la emite."""
        self.assertEqual(EXIT_BLOCKED, exit_for(BLOCKED))
        self.assertNotEqual(EXIT_OK, exit_for(BLOCKED))

    def test_A10_evidencia_ilegible_da_INCONCLUSIVE(self):
        """A-10. «No pude leerlo» no es «está mal» ni «está bien», y no sale con 0."""
        ws = _espacio(3, artefacto=True)
        art = next((ws / ".harness" / "evidence").glob("ver_*.json"))
        art.write_text("{esto no es json", encoding="utf-8")
        rc, _out, doc = _cli(ws, "status", "--json")
        self.assertEqual(INCONCLUSIVE, doc.get("status"))
        self.assertEqual(EXIT_BLOCKED, rc)


# ── regresiones permanentes de las dos reproducciones ────────────────────────────────
class RegresionesDeCR07R06(unittest.TestCase):
    """Las dos reproducciones de STEP 1, fijadas. Si alguien revierte, esto se pone rojo."""

    def test_R07_evidencia_contradicha_no_puede_salir_con_exito(self):
        """R-07 reproducido el 2026-09-25: `status` imprimía «NO INTEGRABLE — la evidencia no
        se sostiene», calculaba `integrity='contradice'`, y devolvía PASS/0."""
        ws = _espacio(3, artefacto=True)
        lineas = _ledger(ws).read_text(encoding="utf-8").splitlines()
        _ledger(ws).write_text("\n".join(lineas[:-1]) + "\n", encoding="utf-8")
        rc, _out, doc = _cli(ws, "status", "--json")
        ver = (doc.get("payload") or {}).get("verification") or {}
        self.assertEqual("contradice", (ver.get("integrity") or {}).get("estado"),
                         "control: la contradicción se sigue detectando")
        self.assertEqual(FAIL, doc.get("status"),
                         "el estado calculado y el reportado tienen que coincidir")
        self.assertEqual(EXIT_FAIL, rc,
                         "un consumidor automático no puede leer esto como éxito")

    def test_R06_sin_expectativa_el_borrado_deja_de_ser_silencioso(self):
        """R-06 reproducido: 5 `deny` destruidos y salida IDÉNTICA byte a byte.

        Sin artefacto no hay expectativa, así que el estado sigue siendo PASS —y decir otra
        cosa rompería todo espacio recién creado—. Lo que ya no puede ser es SILENCIOSO.
        """
        ws = _espacio(5)
        _rc0, antes, _ = _cli(ws, "status")
        _ledger(ws).unlink()
        _rc1, despues, _ = _cli(ws, "status")
        self.assertNotEqual(antes, despues,
                            "la destrucción del diario no puede dejar la salida intacta")
        self.assertIn(INTEGRA, antes)
        self.assertIn(AUSENTE, despues,
                      "el estado del diario tiene que ser observable en la frontera")

    def test_el_estado_del_diario_viaja_en_el_sobre_para_maquinas(self):
        """Lo observable para una persona tiene que serlo también para un consumidor."""
        ws = _espacio(4, artefacto=True)
        _ledger(ws).unlink()
        _rc, _out, doc = _cli(ws, "status", "--json")
        self.assertTrue(doc.get("next"), "un estado que no aprueba está obligado a traer `next`")
        self.assertTrue(any("diario" in n.get("why", "") for n in doc["next"]))


# ── mutaciones: intentar reintroducir el defecto ─────────────────────────────────────
class MutacionesDeR07(unittest.TestCase):
    """Cada mutación reintroduce una forma del defecto. El testigo tiene que matarla.

    Se mutan ENTRADAS de `_estado_de_status`, que es una función pura de
    `(cadena, ver, ilegibles)`. Una mutación MUERE si existe al menos un escenario del
    catálogo en el que su veredicto difiere del original — es decir, si el catálogo la
    distingue. Si ninguno la distingue, está VIVA y el contrato no está protegido.
    """

    #: Catálogo de escenarios. Cada fila es `(nombre, cadena, ver, ilegibles, esperado)`.
    ESCENARIOS = (
        ("sano", {"estado": INTEGRA, "motivo": ""}, {"integrity": {"estado": "ok"}}, [], PASS),
        ("contradice", {"estado": INTEGRA, "motivo": ""},
         {"integrity": {"estado": "contradice"}}, [], FAIL),
        ("cadena rota", {"estado": ROTA, "motivo": "x"},
         {"integrity": {"estado": "ok"}}, [], FAIL),
        ("desalineada", {"estado": DESALINEADA, "motivo": "x"},
         {"integrity": {"estado": "ok"}}, [], FAIL),
        ("insuficiente", {"estado": INSUFICIENTE, "motivo": "x"},
         {"integrity": {"estado": "ok"}}, [], FAIL),
        ("ilegible", {"estado": INTEGRA, "motivo": ""}, None, [{"path": "p"}], INCONCLUSIVE),
        ("indeterminado", {"estado": INTEGRA, "motivo": ""},
         {"integrity": {"estado": "indeterminado"}}, [], INCONCLUSIVE),
        ("ausente sin expectativa", {"estado": AUSENTE, "motivo": ""}, None, [], PASS),
        ("vacio", {"estado": VACIO, "motivo": ""}, None, [], PASS),
    )

    def _original(self):
        import importlib.util
        spec = importlib.util.spec_from_file_location("_refuto_cli", RAIZ / "refuto.py")
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        return mod._estado_de_status

    def test_el_catalogo_describe_el_comportamiento_real(self):
        """Control. Si esto falla, las mutaciones de abajo miden contra una tabla falsa."""
        f = self._original()
        for nombre, cadena, ver, ileg, esperado in self.ESCENARIOS:
            self.assertEqual(esperado, f(cadena, ver, ileg), f"escenario «{nombre}»")

    def _matar(self, mutante, etiqueta: str) -> None:
        f = self._original()
        distinguen = [n for n, c, v, i, _e in self.ESCENARIOS if mutante(c, v, i) != f(c, v, i)]
        self.assertTrue(distinguen,
                        f"{etiqueta} VIVA: ningún escenario del catálogo la distingue del "
                        f"original, luego el contrato no está protegido frente a ella")

    def test_M_R07_01_forzar_exito_siempre(self):
        self._matar(lambda c, v, i: PASS, "M-R07-01 (force exit 0)")

    def test_M_R07_02_mapear_FAIL_a_exito(self):
        f = self._original()
        self._matar(lambda c, v, i: PASS if f(c, v, i) == FAIL else f(c, v, i),
                    "M-R07-02 (FAIL → 0)")

    def test_M_R07_04_ignorar_el_estado_del_verificador(self):
        from core.evidence import DESALINEADA as D, INSUFICIENTE as I, ROTA as Rt
        self._matar(lambda c, v, i: (FAIL if c["estado"] in (Rt, D, I)
                                     else (INCONCLUSIVE if i else PASS)),
                    "M-R07-04 (ignora `integrity`)")

    def test_M_R07_06_tragarse_la_excepcion_y_devolver_exito(self):
        def mutante(c, v, i):
            try:
                raise RuntimeError("fallo al verificar")
            except RuntimeError:
                return PASS
        self._matar(mutante, "M-R07-06 (except → PASS)")

    def test_M_R07_07_descartar_el_fallo_de_evidencia_antes_de_la_frontera(self):
        self._matar(lambda c, v, i: (INCONCLUSIVE if i else PASS),
                    "M-R07-07 (descarta cadena e integridad)")

    def test_M_R07_03_DEGRADED_no_aplica(self):
        """M-R07-03 mapea `DEGRADED`→0. No aplica: el estado no existe en el modelo."""
        self.assertNotIn("DEGRADED", STATUSES)

    def test_M_R07_05_imprimir_fallo_y_devolver_exito_se_mata_en_el_CLI(self):
        """M-R07-05 no es mutable en la función pura: imprime una cosa y devuelve otra, que es
        exactamente el defecto original. Su testigo es de runtime —`test_R07_…` compara el
        texto impreso con el código de salida del proceso real—, así que se comprueba que ese
        testigo existe y mide las dos caras."""
        ws = _espacio(3, artefacto=True)
        lineas = _ledger(ws).read_text(encoding="utf-8").splitlines()
        _ledger(ws).write_text("\n".join(lineas[:-1]) + "\n", encoding="utf-8")
        rc, texto, _ = _cli(ws, "status")
        self.assertIn("NO INTEGRABLE", texto, "imprime el fallo…")
        self.assertNotEqual(EXIT_OK, rc, "…y no puede salir con éxito")


if __name__ == "__main__":       # pragma: no cover
    unittest.main()
