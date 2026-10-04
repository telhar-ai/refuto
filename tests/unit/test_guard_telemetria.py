# -*- coding: utf-8 -*-
"""Lo que el diario NO sabía hasta el 2026-09-28, y ahora sí.

Medido ese día sobre 52.131 eventos reales de 13 espacios: se sabía **qué** se decidió y
**cuándo**, no **cuánto costó** ni **si funcionó**. Las consecuencias no eran teóricas:

- «el guardián es lento» no era una afirmación comprobable, así que tampoco lo era su contraria;
- un `allow` y una orden que reventó eran el mismo evento;
- la duración de una herramienta sólo se podía estimar por la distancia a su vecino en el
  diario, que con varias en vuelo es adivinar.

Tres piezas lo cierran, y cada una tiene aquí su prueba: `duration_ms` en la decisión,
`entrada_digest` en los dos extremos para poder casarlos, y `--post`, que registra el desenlace
**sin decidir nada**. La última propiedad es la que más importa y la más fácil de romper sin
enterarse: si el gancho posterior bloqueara, bloquearía DESPUÉS de que la herramienta actuara —
no desharía nada y sí rompería la sesión.
"""

from __future__ import annotations

import json
import shutil
import subprocess  # nosec B404
import sys
import tempfile
import unittest
from pathlib import Path

from core.guard import KIND_RESULTADO, digest_entrada, resultado_de
from core.proc import TEXT_IO

RAIZ = Path(__file__).resolve().parents[2]


def _hecho(**kw) -> dict:
    base = {"runtime": "claude", "tool": "Bash", "path": "", "command": "", "content": ""}
    base.update(kw)
    return base


class TestDigestDeEntrada(unittest.TestCase):
    """Identifica la OPERACIÓN, para poder casar la decisión con su resultado."""

    def test_el_mismo_hecho_da_el_mismo_digest(self):
        a, b = _hecho(command="ls -la"), _hecho(command="ls -la")
        self.assertEqual(digest_entrada(a), digest_entrada(b))

    def test_hechos_distintos_dan_digests_distintos(self):
        distintos = [_hecho(command="ls"), _hecho(command="ls -la"), _hecho(tool="Write"),
                     _hecho(path="/x/y.txt"), _hecho(runtime="kiro", command="ls"),
                     _hecho(content="algo")]
        self.assertEqual(len(distintos), len({digest_entrada(h) for h in distintos}))

    def test_no_confunde_campos_contiguos(self):
        """Concatenar sin separador haría iguales `path='ab', command=''` y `path='a', command='b'`.
        El separador nulo existe por eso."""
        self.assertNotEqual(digest_entrada(_hecho(path="ab")), digest_entrada(_hecho(path="a", command="b")))

    def test_es_estable_entre_procesos(self):
        """Si dependiera del `hash()` de Python, el `PYTHONHASHSEED` de cada proceso haría que la
        decisión y el resultado —que corren en procesos DISTINTOS— nunca casaran."""
        codigo = ("import sys; sys.path.insert(0, %r); from core.guard import digest_entrada; "
                  "print(digest_entrada({'runtime':'claude','tool':'Bash','path':'',"
                  "'command':'ls -la','content':''}))" % str(RAIZ))
        vistos = set()
        for _ in range(3):
            p = subprocess.run([sys.executable, "-c", codigo], capture_output=True,     # nosec B603
                               timeout=60, **TEXT_IO)
            vistos.add((p.stdout or "").strip())
        self.assertEqual(1, len(vistos), vistos)
        self.assertEqual({digest_entrada(_hecho(command="ls -la"))}, vistos)


class TestQueSePuedeAfirmarDelResultado(unittest.TestCase):
    """`ok` tiene tres valores, y el tercero es el que evita inventar aprobados."""

    def test_sin_forma_de_saberlo_es_none_y_no_true(self):
        for resp in ({"stdout": "hola", "stderr": ""}, "texto plano", None, 42, []):
            with self.subTest(resp=resp):
                self.assertIsNone(resultado_de({"tool_response": resp})["ok"])

    def test_codigo_cero_es_ok(self):
        r = resultado_de({"tool_response": {"exit_code": 0}})
        self.assertTrue(r["ok"])
        self.assertEqual(0, r["exit_code"])

    def test_codigo_distinto_de_cero_no_lo_es(self):
        r = resultado_de({"tool_response": {"exit_code": 3, "stderr": "no existe"}})
        self.assertFalse(r["ok"])
        self.assertEqual(3, r["exit_code"])
        self.assertEqual("no existe", r["stderr"])

    def test_un_booleano_no_se_lee_como_codigo_de_salida(self):
        """`{"code": true}` no es el código 1: en Python `True == 1` y sin el filtro de `bool`
        una bandera se convertía en un fallo que nadie tuvo."""
        self.assertIsNone(resultado_de({"tool_response": {"code": True}})["exit_code"])

    def test_is_error_sin_mensaje_usa_el_stderr(self):
        r = resultado_de({"tool_response": {"is_error": True, "stderr": "command not found: y"}})
        self.assertFalse(r["ok"])
        self.assertEqual("command not found: y", r["error"])

    def test_interrumpida_no_es_exitosa(self):
        r = resultado_de({"tool_response": {"interrupted": True}})
        self.assertFalse(r["ok"])
        self.assertTrue(r["interrupted"])

    def test_stderr_con_texto_no_convierte_en_fallo(self):
        """Hay programas que informan por stderr. Tratarlo como error inventaría fallos."""
        r = resultado_de({"tool_response": {"stderr": "aviso: usando caché"}})
        self.assertIsNone(r["ok"], "no se sabe si fue bien, y eso NO es que fuera mal")
        self.assertIn("caché", r["stderr"])

    def test_una_lista_de_bloques_se_examina(self):
        r = resultado_de({"tool_response": [{"exit_code": 1}]})
        self.assertFalse(r["ok"])
        self.assertEqual("lista", r["forma"])

    def test_el_mensaje_se_recorta_y_no_revienta_con_basura(self):
        r = resultado_de({"tool_response": {"is_error": True, "error": "x" * 5000}})
        self.assertLessEqual(len(r["error"]), 400)

    def test_se_registra_que_claves_trajo_la_respuesta(self):
        """Medido sobre 86 resultados reales: 82 quedaron en `ok=None` porque ninguna de las
        claves buscadas estaba, y el evento no guardaba con qué averiguar cuáles sí."""
        r = resultado_de({"tool_response": {"stdout": "x", "algoNuevo": 1, "interrupted": False}})
        self.assertEqual(["algoNuevo", "interrupted", "stdout"], r["claves"])

    def test_se_guardan_los_NOMBRES_y_nunca_el_contenido(self):
        """Un `stdout` en el diario sería filtrar el trabajo entero a un fichero que se lee
        dentro de un año. Los nombres bastan para arreglar la extracción; los valores, no."""
        secreto = "CONTRASEÑA-QUE-NO-PUEDE-SALIR"
        r = resultado_de({"tool_response": {"stdout": secreto, "token": secreto}})
        self.assertEqual(["stdout", "token"], r["claves"])
        self.assertNotIn(secreto, json.dumps(r, ensure_ascii=False))

    def test_ni_las_claves_pueden_crecer_sin_medida(self):
        r = resultado_de({"tool_response": {f"k{i}": i for i in range(50)}})
        self.assertLessEqual(len(r["claves"]), 16)
        r2 = resultado_de({"tool_response": {"x" * 500: 1}})
        self.assertLessEqual(len(r2["claves"][0]), 40)


class TestElGuardianMideYRegistra(unittest.TestCase):
    """De extremo a extremo, con el guardián real en un proceso aparte."""

    def setUp(self):
        self.ws = Path(tempfile.mkdtemp(prefix="guard-tele-")).resolve()
        (self.ws / ".harness" / "evidence").mkdir(parents=True)

    def tearDown(self):
        shutil.rmtree(self.ws, ignore_errors=True)

    def _guard(self, payload: dict, *extra: str):
        return subprocess.run(                                                  # nosec B603
            [sys.executable, "-m", "core.guard", "--runtime", "claude", "--stdin",
             "--workspace", str(self.ws), *extra],
            input=json.dumps(payload), cwd=str(RAIZ), capture_output=True, timeout=120, **TEXT_IO)

    def _eventos(self) -> list:
        p = self.ws / ".harness" / "evidence" / "ledger.jsonl"
        return [json.loads(l) for l in p.read_text(encoding="utf-8").splitlines() if l.strip()]

    def test_la_decision_dice_cuanto_costo(self):
        self._guard({"tool_name": "Bash", "tool_input": {"command": "echo hola"}})
        e = self._eventos()[-1]
        self.assertIsInstance(e["duration_ms"], (int, float))
        self.assertGreater(e["duration_ms"], 0)
        self.assertLess(e["duration_ms"], 30_000, "una decisión que tarda 30 s no es una medición")

    def test_una_denegacion_tambien_se_mide(self):
        """Si sólo se midieran los `allow`, el coste del guardián quedaría subestimado justo en
        los casos que más trabajo le cuestan."""
        self._guard({"tool_name": "Bash", "tool_input": {"command": "sudo rm -rf /"}})
        e = self._eventos()[-1]
        self.assertEqual("deny", e["outcome"])
        self.assertIsInstance(e["duration_ms"], (int, float))

    def test_la_decision_y_su_resultado_se_pueden_casar(self):
        entrada = {"tool_name": "Bash", "tool_input": {"command": "echo casar"}}
        self._guard(entrada)
        self._guard({**entrada, "tool_response": {"exit_code": 0}}, "--post")
        ev = self._eventos()
        decision = [e for e in ev if e["kind"] == "policy/decision"][-1]
        resultado = [e for e in ev if e["kind"] == KIND_RESULTADO][-1]
        self.assertEqual(decision["entrada_digest"], resultado["entrada_digest"])
        self.assertTrue(resultado["ok"])

    def test_la_duracion_de_la_herramienta_sale_de_los_dos_sellos(self):
        """La propiedad que hace útil el par: `ts(resultado) − ts(decisión)` ES lo que tardó."""
        from datetime import datetime
        entrada = {"tool_name": "Bash", "tool_input": {"command": "echo tiempo"}}
        self._guard(entrada)
        self._guard({**entrada, "tool_response": {"exit_code": 0}}, "--post")
        ev = self._eventos()
        d = [e for e in ev if e["kind"] == "policy/decision"][-1]
        r = [e for e in ev if e["kind"] == KIND_RESULTADO][-1]
        t0 = datetime.fromisoformat(d["ts"])
        t1 = datetime.fromisoformat(r["ts"])
        self.assertGreaterEqual((t1 - t0).total_seconds(), 0)

    def test_el_gancho_posterior_no_decide_nada(self):
        """Registrar no es decidir: `--post` no puede emitir una decisión ni bloquear."""
        p = self._guard({"tool_name": "Bash", "tool_input": {"command": "sudo rm -rf /"},
                         "tool_response": {"exit_code": 0}}, "--post")
        self.assertEqual(0, p.returncode, p.stderr)
        self.assertEqual("", p.stdout.strip(), "no emite decisión por stdout")
        self.assertEqual([KIND_RESULTADO], [e["kind"] for e in self._eventos()])

    def test_el_gancho_posterior_nunca_bloquea_ni_con_basura(self):
        """Sale 0 pase lo que pase: corre DESPUÉS de que la herramienta actuara, así que
        bloquear no desharía nada y sí rompería la sesión."""
        for crudo in ("no soy json", "[]", "null", "", '{"tool_response": 3}'):
            with self.subTest(crudo=crudo):
                p = subprocess.run(                                             # nosec B603
                    [sys.executable, "-m", "core.guard", "--runtime", "claude", "--stdin",
                     "--workspace", str(self.ws), "--post"],
                    input=crudo, cwd=str(RAIZ), capture_output=True, timeout=120, **TEXT_IO)
                self.assertEqual(0, p.returncode, p.stderr)

    def test_si_no_puede_registrar_lo_dice_y_sigue(self):
        """Un diario inescribible no puede costarle el trabajo a nadie, pero tampoco callarse."""
        d = self.ws / ".harness" / "evidence"
        shutil.rmtree(d)
        d.write_text("no soy un directorio", encoding="utf-8")
        p = self._guard({"tool_name": "Bash", "tool_input": {"command": "x"},
                         "tool_response": {"exit_code": 0}}, "--post")
        self.assertEqual(0, p.returncode)
        self.assertIn("no se pudo registrar", p.stderr)


if __name__ == "__main__":
    unittest.main()
