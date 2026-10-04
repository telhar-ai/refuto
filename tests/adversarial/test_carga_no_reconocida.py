# -*- coding: utf-8 -*-
"""Una carga que el guardián no sabe leer no es una llamada inocua.

El defecto que estas pruebas fijan, medido el 2026-09-25
--------------------------------------------------------
`core.guard._SHAPES` mapea la carga de cada runtime por **adivinación de nombres de campo**:
`_first` prueba varias claves hasta que una casa. Es lo correcto para absorber variantes
menores, y tiene un modo de fallo que nadie miraba — si ninguna clave casa, el hecho sale con
todos los campos vacíos, y `evaluate` respondía:

    Decision(ALLOW, reason="la carga del gancho no trae ruta ni orden que evaluar")

Medido con la MISMA escritura a una ruta protegida:

    {"tool_name":"Write","tool_input":{"file_path":"gates/base.py"}}  →  deny
    {"toolName":"Write","input":{"filePath":"gates/base.py"}}         →  ALLOW
    {"evento":{"tipo":"write","destino":"gates/base.py"}}             →  ALLOW
    [1,2,3]                                                           →  ALLOW

`core/guard.py::main` ya declara el principio para el JSON malformado —«un guardián que aprueba
lo que no entiende no es un guardián»— y lo aplicaba a **uno** de los dos casos. Un JSON roto se
denegaba; un JSON válido que no se entiende, se aprobaba.

Por qué es estructural y no un caso suelto
-------------------------------------------
El runtime es un sistema EXTERNO que versiona su propio formato por su cuenta. Claude Code,
Gemini CLI y el resto se actualizan solos. El día que uno renombre `tool_input`, el guardián
deja de gobernar **en silencio y aprobando**, y nada lo detecta: no hay versión de contrato en
la carga, ni validación de esquema, ni prueba que lo cubriera.

Lo delicado del arreglo, y por qué no basta con denegar
-------------------------------------------------------
El gancho se dispara para TODAS las herramientas, no sólo para las que escriben. `Read` y
`Grep` producen legítimamente un hecho sin ruta ni orden que evaluar. Denegar «sin ruta» habría
roto el uso normal, y un control que rompe el uso normal se desengancha.

La distinción que sí funciona es otra: **carga vacía** (el gancho no trajo nada) frente a
**carga llena que no se reconoció**. La primera se permite; la segunda no es una aprobación,
es una ignorancia.
"""

from __future__ import annotations

import json
import subprocess  # nosec B404 — lanzar el guardián real ES lo que hay que medir
import sys
import tempfile
import unittest
from pathlib import Path

from core.guard import normalize
from core.proc import TEXT_IO

RAIZ = Path(__file__).resolve().parents[2]
PROTEGIDA = "gates/base.py"


def _decidir(raw: str, runtime: str = "claude"):
    """`(codigo, decision)` del guardián real sobre esa carga cruda."""
    with tempfile.TemporaryDirectory() as tmp:
        ws = Path(tmp)
        (ws / ".harness").mkdir()
        p = subprocess.run(  # nosec B603
            [sys.executable, "-m", "core.guard", "--runtime", runtime, "--stdin",
             "--workspace", str(ws)],
            input=raw, capture_output=True, cwd=str(RAIZ), timeout=120, **TEXT_IO)
        decision = ""
        if p.stdout.strip():
            try:
                doc = json.loads(p.stdout)
                decision = (doc.get("hookSpecificOutput", {}).get("permissionDecision")
                            or doc.get("decision", ""))
            except json.JSONDecodeError:
                pass
        return p.returncode, decision


def _paso(codigo: int, decision: str) -> bool:
    return decision == "allow" or (not decision and codigo == 0)


#: Cargas que SÍ traen cuerpo y de las que no se reconoce nada. Cada una lleva dentro una
#: escritura a una ruta protegida, para que aprobarlas sea inequívocamente un fallo.
NO_RECONOCIDAS = (
    ("el runtime renombró sus campos",
     {"toolName": "Write", "input": {"filePath": PROTEGIDA, "content": "x"}}),
    ("estructura de otro programa",
     {"evento": {"tipo": "write", "destino": PROTEGIDA}}),
    ("campos con el tipo equivocado",
     {"herramienta": 42, "datos": [PROTEGIDA]}),
)

#: Lo que tiene que seguir pasando. Sin esto, «retener siempre» aprobaría las pruebas de arriba
#: y dejaría el guardián inservible — que es como se desengancha un control.
LEGITIMAS = (
    ("Read", {"tool_name": "Read", "tool_input": {"file_path": "README.md"}}),
    ("Grep sin ruta ni orden", {"tool_name": "Grep", "tool_input": {"pattern": "x"}}),
    ("carga vacía", {}),
    ("escritura permitida",
     {"tool_name": "Write", "tool_input": {"file_path": "nota.txt", "content": "hola"}}),
)


class TestUnaCargaQueNoSeEntiendeNoAprueba(unittest.TestCase):
    def test_las_cargas_no_reconocidas_retienen(self):
        for nombre, carga in NO_RECONOCIDAS:
            with self.subTest(caso=nombre):
                codigo, decision = _decidir(json.dumps(carga))
                self.assertFalse(
                    _paso(codigo, decision),
                    f"«{nombre}» llevaba una escritura a «{PROTEGIDA}» y se aprobó: el guardián "
                    f"dejó de gobernar en silencio (codigo={codigo}, decision={decision!r})")

    def test_y_el_motivo_dice_que_fue_el_mapeo_de_campos(self):
        """Retener sin decir por qué manda a arreglar lo que no está roto.

        Aquí importa especialmente: el motivo tiene que apuntar a `_SHAPES`, porque la causa
        real es una deriva de esquema del runtime y no nada que el agente haya hecho mal.
        """
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            (ws / ".harness").mkdir()
            p = subprocess.run(  # nosec B603
                [sys.executable, "-m", "core.guard", "--runtime", "claude", "--stdin",
                 "--workspace", str(ws)],
                input=json.dumps(NO_RECONOCIDAS[0][1]), capture_output=True,
                cwd=str(RAIZ), timeout=120, **TEXT_IO)
            motivo = json.loads(p.stdout)["hookSpecificOutput"]["permissionDecisionReason"]
            self.assertIn("_SHAPES", motivo)

    def test_un_json_que_no_es_objeto_se_rechaza_en_todos_los_dialectos(self):
        """`_main_antigravity` ya lo hacía; los otros cuatro no. Mismo principio, un solo sitio."""
        for runtime in ("claude", "kiro", "gemini", "opencode", "antigravity"):
            with self.subTest(runtime=runtime):
                codigo, decision = _decidir("[1,2,3]", runtime)
                self.assertFalse(_paso(codigo, decision))

    def test_json_malformado_sigue_denegando(self):
        """El caso que ya estaba cubierto: no se pierde al añadir el nuevo."""
        codigo, decision = _decidir("{esto no es json")
        self.assertFalse(_paso(codigo, decision))


class TestLoLegitimoSigueePasando(unittest.TestCase):
    """El control negativo. Sin él, un guardián que retuviera SIEMPRE pasaría lo de arriba."""

    def test_las_llamadas_normales_no_se_ven_afectadas(self):
        for nombre, carga in LEGITIMAS:
            with self.subTest(caso=nombre):
                codigo, decision = _decidir(json.dumps(carga))
                self.assertTrue(
                    _paso(codigo, decision),
                    f"«{nombre}» se retuvo: el arreglo rompe el uso normal, y un control que "
                    f"rompe el uso normal se desengancha (codigo={codigo}, "
                    f"decision={decision!r})")

    def test_la_escritura_prohibida_se_sigue_denegando_por_su_motivo(self):
        """Y no por «no te entendí», que sería el arreglo tapando el control de verdad."""
        codigo, decision = _decidir(json.dumps(
            {"tool_name": "Write", "tool_input": {"file_path": PROTEGIDA, "content": "x"}}))
        self.assertEqual("deny", decision)


class TestLaDistincionEsExplicitaEnElHecho(unittest.TestCase):
    """`carga_vacia` es lo que hace separable el caso legítimo del peligroso.

    Se fija aquí para que no se pierda en una refactorización: sin ese campo, «no trajo nada» y
    «trajo algo que no entendí» vuelven a ser indistinguibles.
    """

    def test_normalize_marca_la_carga_vacia(self):
        self.assertTrue(normalize("claude", {})["carga_vacia"])
        self.assertFalse(normalize("claude", {"evento": 1})["carga_vacia"])

    def test_una_carga_reconocida_deja_al_menos_un_campo(self):
        f = normalize("claude", {"tool_name": "Read", "tool_input": {"file_path": "a.md"}})
        self.assertTrue(any(f[k] for k in ("tool", "path", "content", "command", "cwd")))

    def test_una_carga_ajena_no_deja_ninguno(self):
        f = normalize("claude", {"evento": {"tipo": "write", "destino": PROTEGIDA}})
        self.assertFalse(any(f[k] for k in ("tool", "path", "content", "command", "cwd")))


if __name__ == "__main__":
    unittest.main()
