# -*- coding: utf-8 -*-
"""R-03 · Admisión: ninguna representación alternativa obtiene los privilegios de la canónica.

Relación con `test_brechas_de_assurance.py::G3`
----------------------------------------------
Aquél conserva la **reproducción histórica** —las cinco cargas con las que se midió el defecto
el 2026-09-25— y ya no lleva `@expectedFailure`. Éste es la **suite endurecida**: amplía a 16
representaciones, añade los caminos alternativos y las mutaciones. La primera demuestra la
historia; ésta, la frontera. Ninguna sustituye a la otra.

La propiedad
------------
    Para toda representación R no admisible:
        R → admisión → decisión → efecto
    NO produce el efecto protegido.

El mecanismo exacto (`deny`, `ask`, rechazo por código de salida) es indiferente. Lo que se
exige es que el efecto protegido **esté ausente** y que el estado quede observado.

El contrato de admisión, que antes no existía en ninguna parte
--------------------------------------------------------------
    ADMISIBLE   cadena no vacía bajo alguna clave declarada en `_SHAPES`
    AUSENTE     ninguna clave declarada presente          → legítimo (`Read`, `Grep`)
    ILEGIBLE    una clave declarada presente con valor inservible, o contenedor mal formado
    INADMISIBLE herramienta de escritura declarada sin ninguna ruta legible

Las dos últimas no se aprueban. La coerción está **prohibida**: sacar la ruta de un `dict` o de
una lista le daría a una representación ambigua los privilegios de la canónica, y entonces el
contrato lo fijaría quien elige la forma de la carga y no quien escribe la política.

Alcance declarado
-----------------
Medido contra el dialecto **claude**, que es el único con respuesta estructurada y el que la
máquina de medición usa. `_ESCRITURA` declara nombres para `kiro`, `gemini` y `opencode` tomados
de sus adaptadores, y se comprueban aquí en su forma básica; un runtime cuyo nombre de
herramienta de escritura no figure en esa tabla **queda fuera** de la comprobación de
`escritura-sin-ruta`. Es un PASS de alcance declarado, no universal.
"""

from __future__ import annotations

import json
import subprocess  # nosec B404 — ejecutar el guardián real ES la medición
import sys
import tempfile
import unittest
from pathlib import Path

import core.guard as G
from core.guard import evaluate, normalize
from core.policy import ALLOW, Policy
from core.proc import TEXT_IO

RAIZ = Path(__file__).resolve().parents[2]
PROTEGIDA = "gates/base.py"


def _ws() -> Path:
    ws = Path(tempfile.mkdtemp(prefix="r03-adm-")).resolve()
    (ws / ".harness" / "evidence").mkdir(parents=True)
    (ws / "gates").mkdir()
    (ws / "gates" / "base.py").write_text("juez", encoding="utf-8")
    return ws


def _guard(ws: Path, carga: dict, runtime: str = "claude") -> tuple[int, str]:
    p = subprocess.run(  # nosec B603
        [sys.executable, "-m", "core.guard", "--runtime", runtime, "--stdin",
         "--workspace", str(ws)],
        input=json.dumps(carga), capture_output=True, cwd=str(RAIZ), timeout=120, **TEXT_IO)
    dec = ""
    if p.stdout.strip():
        try:
            doc = json.loads(p.stdout)
            dec = (doc.get("hookSpecificOutput", {}).get("permissionDecision")
                   or doc.get("decision", ""))
        except json.JSONDecodeError:
            dec = ""
    return p.returncode, dec


def _carga(valor, clave: str = "file_path") -> dict:
    return {"tool_name": "Write", "tool_input": {clave: valor, "content": "ALTERADO"}}


#: A-R03-01 … A-R03-16. Cada fila: `(id, carga, admisible)`.
#: `admisible=True` significa que la carga es legítima y DEBE poder pasar; `False`, que el
#: efecto protegido tiene que quedar ausente. Una clasificación explícita por caso es el
#: requisito: no basta con que «no truene».
CATALOGO = (
    ("A-R03-01 string válida al juez", _carga(PROTEGIDA), False),
    ("A-R03-02 string vacía", _carga(""), False),
    ("A-R03-03 traversal", _carga("obra/../gates/base.py"), False),
    ("A-R03-04 dict simple", _carga({"path": PROTEGIDA}), False),
    ("A-R03-05 dict anidado", _carga({"a": {"b": PROTEGIDA}}), False),
    ("A-R03-06 list simple", _carga([PROTEGIDA]), False),
    ("A-R03-07 list anidada", _carga([[PROTEGIDA]]), False),
    ("A-R03-08 number", _carga(123), False),
    ("A-R03-09 float", _carga(1.5), False),
    ("A-R03-10 bool", _carga(True), False),
    ("A-R03-11 null", _carga(None), False),
    ("A-R03-12 list of dict", _carga([{"file_path": PROTEGIDA}]), False),
    ("A-R03-13 roundtrip JSON", _carga(json.loads(json.dumps({"path": PROTEGIDA}))), False),
    ("A-R03-14 contenedor no-objeto", {"tool_name": "Write", "tool_input": PROTEGIDA}, False),
    ("A-R03-15 contenedor lista", {"tool_name": "Write",
                                   "tool_input": [{"file_path": PROTEGIDA}]}, False),
    ("A-R03-16 ruta en clave no listada", {"tool_name": "Write",
                                           "arguments": {"path": PROTEGIDA}}, False),
    # ── los que demuestran POR QUÉ la coerción es peligrosa ──────────────────────────
    #
    # Éstos faltaban en la primera versión del catálogo, y los destapó la prueba de mutación:
    # con un contenedor de UN solo valor, coaccionar `{"path": "gates/base.py"}` a la cadena
    # acierta la ruta y sale `deny`, así que la mutación parecía inocua. Con SEÑUELO no: la
    # coerción elige un valor y la escritura real puede ser el otro, y entonces una ruta
    # protegida sale aprobada. Es la diferencia entre «no se coacciona» como escrúpulo y como
    # propiedad de seguridad.
    ("A-R03-17 dict con señuelo", _carga({"seguro": "obra.txt", "real": PROTEGIDA}), False),
    ("A-R03-18 lista con señuelo", _carga(["obra.txt", PROTEGIDA]), False),
    # Contenedor mal formado sobre una ORDEN. Aquí no hay regla de «escritura sin ruta» que
    # rescate la propiedad: si `_dig` confunde «el contenedor no es un objeto» con «la clave
    # no está», una orden entera deja de examinarse.
    ("A-R03-19 contenedor no-objeto en Bash",
     {"tool_name": "Bash", "tool_input": "rm -rf " + PROTEGIDA}, False),
    ("A-R03-20 orden con señuelo",
     {"tool_name": "Bash", "tool_input": {"command": {"a": "echo hola",
                                                      "b": "rm -rf " + PROTEGIDA}}}, False),
    # «Presente y vale null» ≠ «no está». Sobre una orden, porque sobre una escritura lo
    # rescataría `escritura-sin-ruta` y entonces la prueba no mediría lo que dice medir.
    ("A-R03-21 orden nula", {"tool_name": "Bash", "tool_input": {"command": None}}, False),
)

#: Cargas LEGÍTIMAS. Sin ellas, «denegarlo todo» aprobaría el catálogo de arriba y rompería
#: cualquier gancho que dispare en herramientas de lectura.
LEGITIMAS = (
    ("lectura sin ruta", {"tool_name": "Grep", "tool_input": {"pattern": "x"}}),
    ("escritura inocua", {"tool_name": "Write",
                          "tool_input": {"file_path": "obra.txt", "content": "x"}}),
    ("orden inocua", {"tool_name": "Bash", "tool_input": {"command": "echo hola"}}),
    ("carga vacía", {}),
    ("MultiEdit real", {"tool_name": "MultiEdit",
                        "tool_input": {"file_path": "obra.txt",
                                       "edits": [{"old_string": "a", "new_string": "b"}]}}),
    ("NotebookEdit real", {"tool_name": "NotebookEdit",
                           "tool_input": {"notebook_path": "n.ipynb", "new_source": "x"}}),
)


class AdmisionPorElGuardianReal(unittest.TestCase):
    """Las 16 representaciones, por el guardián real en subproceso."""

    def test_ninguna_representacion_inadmisible_produce_el_efecto(self):
        ws = _ws()
        for ident, carga, admisible in CATALOGO:
            if admisible:
                continue
            with self.subTest(caso=ident):
                codigo, decision = _guard(ws, carga)
                paso = decision == "allow" or (not decision and codigo == 0)
                self.assertFalse(paso, f"{ident}: admitida sin poder examinar su destino")

    def test_control_las_cargas_legitimas_siguen_pasando(self):
        """Control positivo imprescindible: sin él, «todo da ask» aprobaría la prueba anterior."""
        ws = _ws()
        for ident, carga in LEGITIMAS:
            with self.subTest(caso=ident):
                _codigo, decision = _guard(ws, carga)
                self.assertEqual("allow", decision, f"{ident}: se rompió una carga legítima")

    def test_la_forma_canonica_al_juez_sigue_denegandose(self):
        """`deny`, no `ask`: cuando la ruta SÍ se lee, la política decide de verdad."""
        ws = _ws()
        _c, decision = _guard(ws, _carga(str(ws / "gates" / "base.py")))
        self.assertEqual("deny", decision)

    def test_el_motivo_distingue_los_dos_mecanismos(self):
        """Un `ask` que no dice cuál de las dos cosas pasó no se puede arreglar."""
        ws = _ws()
        for carga, regla in ((_carga({"a": 1}), "campo-ilegible"),
                             ({"tool_name": "Write", "arguments": {"path": PROTEGIDA}},
                              "escritura-sin-ruta")):
            fact = normalize("claude", carga)
            d, _k = evaluate(Policy.default(), ws, fact)
            self.assertEqual(regla, d.rule)


class LaAdmisionQuedaEnLaEvidencia(unittest.TestCase):
    """R-03 no era sólo admisión: era una MENTIRA en el diario.

    El daño demostrable no es que el runtime fuera a escribir —no se puede afirmar que Claude
    Code ejecute una `Write` con un `dict` por ruta, y no se afirma—. Es que el diario anotaba
    `Write · allow · target=''`: una escritura que nadie examinó, registrada como examinada y
    aprobada, indistinguible de un `Read` inocuo. Eso es certeza falsa, la misma clase de
    defecto que `opaco=False` en R-01.
    """

    def _eventos(self, ws: Path) -> list:
        led = ws / ".harness" / "evidence" / "ledger.jsonl"
        return [json.loads(x) for x in led.read_text(encoding="utf-8").splitlines() if x.strip()]

    def test_una_escritura_inexaminable_no_se_registra_como_aprobada(self):
        ws = _ws()
        _guard(ws, _carga({"path": PROTEGIDA}))
        ev = self._eventos(ws)[-1]
        self.assertEqual("Write", ev["tool"])
        self.assertNotEqual("allow", ev["outcome"],
                            "el diario declaraba aprobada una escritura que no se examinó")
        self.assertEqual("campo-ilegible", ev.get("rule"))

    def test_el_evento_permite_reconstruir_por_que(self):
        ws = _ws()
        _guard(ws, {"tool_name": "Write", "arguments": {"path": PROTEGIDA}})
        ev = self._eventos(ws)[-1]
        self.assertEqual("escritura-sin-ruta", ev.get("rule"))
        self.assertTrue(ev.get("reason"), "una decisión sin motivo no es auditable después")


class CaminosAlternativos(unittest.TestCase):
    """§15 — ¿hay otra puerta por la que entre una representación inadmisible?"""

    def test_la_API_directa_no_aprueba_una_ruta_no_canonica(self):
        """`decide_write` con un `dict` levanta `TypeError`. Una excepción NO es un `allow`:
        el efecto protegido queda ausente. Se fija aquí para que siga siendo así — si alguien
        añadiera una coerción amable en `decide_write`, esto se pondría rojo."""
        from core.policy import decide_write
        ws = _ws()
        for valor in ({"path": PROTEGIDA}, [PROTEGIDA], 123, None, True):
            with self.subTest(valor=type(valor).__name__):
                with self.assertRaises((TypeError, ValueError)):
                    decide_write(Policy.default(), ws, valor)

    def test_la_carga_malformada_se_bloquea_antes_de_decidir(self):
        """JSON inválido o que no es un objeto: se bloquea con código 2, no se aprueba."""
        ws = _ws()
        for crudo in ("{no es json", json.dumps([1, 2]), json.dumps("hola"), json.dumps(None)):
            with self.subTest(carga=crudo[:20]):
                p = subprocess.run(  # nosec B603
                    [sys.executable, "-m", "core.guard", "--runtime", "claude", "--stdin",
                     "--workspace", str(ws)],
                    input=crudo, capture_output=True, cwd=str(RAIZ), timeout=120, **TEXT_IO)
                self.assertNotEqual(0, p.returncode)

    def test_ningun_dialecto_aprueba_una_escritura_sin_ruta(self):
        """Alcance declarado: los cuatro runtimes con `_ESCRITURA` poblada."""
        ws = _ws()
        cargas = {"claude": {"tool_name": "Write", "arguments": {"p": PROTEGIDA}},
                  "kiro": {"tool_name": "fs_write", "arguments": {"destino": PROTEGIDA}},
                  "gemini": {"tool_name": "write_file", "otro": {"p": PROTEGIDA}},
                  "opencode": {"tool": "edit", "otro": {"p": PROTEGIDA}}}
        for runtime, carga in cargas.items():
            with self.subTest(runtime=runtime):
                codigo, decision = _guard(ws, carga, runtime)
                paso = decision == "allow" or (not decision and codigo == 0)
                self.assertFalse(paso, f"{runtime}: escritura sin ruta admitida")


class MutacionesDeR03(unittest.TestCase):
    """Reintroducir el defecto por coerción. El catálogo tiene que distinguirlo.

    Se muta `core.guard._campo`, que es donde vive el contrato. Una mutación MUERE si con ella
    alguna carga del catálogo pasa a `ALLOW` — es decir, si el catálogo la detecta.
    """

    def _con(self, mutante, etiqueta: str) -> None:
        ws = _ws()
        original = G._campo                                             # noqa: SLF001
        vivas = []
        try:
            G._campo = mutante                                          # noqa: SLF001
            for ident, carga, admisible in CATALOGO:
                if admisible:
                    continue
                d, _k = evaluate(Policy.default(), ws, normalize("claude", carga))
                if d.outcome == ALLOW:
                    vivas.append(ident)
        finally:
            G._campo = original                                         # noqa: SLF001
        self.assertTrue(vivas, f"{etiqueta}: el catálogo no la distingue del original")

    def test_M_R03_01_sin_validacion_de_tipo(self):
        """La `_first` original: filtra por `isinstance(str)` y no declara nada."""
        def mutante(doc, keys):
            for k in keys:
                v = G._dig(doc, k)                                      # noqa: SLF001
                if isinstance(v, str) and v:
                    return v, False
            return "", False
        self._con(mutante, "M-R03-01")

    def test_M_R03_02_coaccionar_dict_a_cadena(self):
        def mutante(doc, keys):
            for k in keys:
                v = G._dig(doc, k)                                      # noqa: SLF001
                if isinstance(v, dict) and v:
                    return str(next(iter(v.values()))), False
                if isinstance(v, str) and v:
                    return v, False
            return "", False
        self._con(mutante, "M-R03-02")

    def test_M_R03_07_tomar_el_primer_elemento_de_la_lista(self):
        def mutante(doc, keys):
            for k in keys:
                v = G._dig(doc, k)                                      # noqa: SLF001
                if isinstance(v, list) and v and isinstance(v[0], str):
                    return v[0], False
                if isinstance(v, str) and v:
                    return v, False
            return "", False
        self._con(mutante, "M-R03-07")

    def test_M_R03_08_extraer_dict_path(self):
        def mutante(doc, keys):
            for k in keys:
                v = G._dig(doc, k)                                      # noqa: SLF001
                if isinstance(v, dict) and isinstance(v.get("path"), str):
                    return v["path"], False
                if isinstance(v, str) and v:
                    return v, False
            return "", False
        self._con(mutante, "M-R03-08")

    def test_M_R03_04_null_como_ruta_vacia(self):
        """`None` → tratado como ausente, que es el defecto exacto: JSON `null` es un valor
        PRESENTE. Su testigo es `A-R03-21` (una orden nula), no una escritura: sobre `Write`
        lo rescataría `escritura-sin-ruta` y la prueba no mediría lo que dice medir."""
        def mutante(doc, keys):
            ileg = False
            for k in keys:
                v = G._dig(doc, k, G._SIN_CLAVE)                        # noqa: SLF001
                if v is G._SIN_CLAVE or v is None:                      # noqa: SLF001
                    continue
                if isinstance(v, str) and v:
                    return v, False
                ileg = True
            return "", ileg
        self._con(mutante, "M-R03-04")

    def test_M_R03_06_numero_como_ruta(self):
        def mutante(doc, keys):
            for k in keys:
                v = G._dig(doc, k)                                      # noqa: SLF001
                if isinstance(v, (int, float)) and not isinstance(v, bool):
                    return str(v), False
                if isinstance(v, str) and v:
                    return v, False
            return "", False
        self._con(mutante, "M-R03-06")

    def test_M_R03_09_aplanar_estructuras_anidadas(self):
        def aplanar(v):
            if isinstance(v, str):
                return v
            if isinstance(v, dict):
                return next((aplanar(x) for x in v.values() if aplanar(x)), "")
            if isinstance(v, list):
                return next((aplanar(x) for x in v if aplanar(x)), "")
            return ""
        def mutante(doc, keys):
            for k in keys:
                plano = aplanar(G._dig(doc, k))                         # noqa: SLF001
                if plano:
                    return plano, False
            return "", False
        self._con(mutante, "M-R03-09")

    def test_M_R03_10_ignorar_que_la_herramienta_escribe(self):
        """No es una mutación de `_campo` sino de `evaluate`: si se deja de exigir ruta a una
        herramienta de escritura, `A-R03-16` vuelve a pasar."""
        ws = _ws()
        carga = {"tool_name": "Write", "arguments": {"path": PROTEGIDA}}
        fact = normalize("claude", carga)
        self.assertTrue(fact["escribe"], "control: se reconoce como escritura")
        fact_mutado = dict(fact, escribe=False)
        d, _k = evaluate(Policy.default(), ws, fact_mutado)
        self.assertEqual(ALLOW, d.outcome,
                         "M-R03-10: sin `escribe` el defecto vuelve — luego el campo es el "
                         "que sostiene la propiedad, y su testigo es A-R03-16")

    def test_M_R03_11_contenedor_mal_formado_como_ausente(self):
        """La `_dig` original: `not isinstance(node, dict)` → «no está». Es el bypass del
        contenedor, encontrado DURANTE esta remediación."""
        original = G._dig                                               # noqa: SLF001
        def mutante(doc, dotted, ausente=None):
            node = doc
            for part in dotted.split("."):
                if not isinstance(node, dict) or part not in node:
                    return ausente
                node = node[part]
            return node
        ws = _ws()
        vivas = []
        try:
            G._dig = mutante                                            # noqa: SLF001
            for ident, carga, adm in CATALOGO:
                if adm:
                    continue
                d, _k = evaluate(Policy.default(), ws, normalize("claude", carga))
                if d.outcome == ALLOW:
                    vivas.append(ident)
        finally:
            G._dig = original                                           # noqa: SLF001
        self.assertTrue(vivas, "M-R03-11: el catálogo no distingue el bypass del contenedor")
        # El testigo es la ORDEN, no la escritura, y merece decirse: `A-R03-14` —la misma
        # forma sobre `Write`— NO distingue esta mutación, porque `escritura-sin-ruta` la
        # rescata por otro camino. Es defensa en profundidad y se mide como tal: si alguien
        # revierte `_dig`, las escrituras siguen protegidas y las ÓRDENES no. Afirmar que el
        # arreglo de `_dig` es necesario para todo sería más de lo que esta medición sostiene.
        self.assertIn("A-R03-19 contenedor no-objeto en Bash", vivas)
        self.assertNotIn("A-R03-14 contenedor no-objeto", vivas,
                         "si esto cambia, la redundancia dejó de existir y hay que redecirlo")


if __name__ == "__main__":       # pragma: no cover
    unittest.main()
