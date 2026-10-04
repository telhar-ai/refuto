# -*- coding: utf-8 -*-
"""R-01 · La cadena de resolución: entrada → resolución → decisión → efecto → evidencia.

Por qué este fichero no prueba `bool → enum`
--------------------------------------------
Cambiar el tipo no es la propiedad. La propiedad es que la distinción **sobreviva a toda la
cadena**: si se pierde en cualquier salto, el último consumidor vuelve a ver una certeza que
nadie tiene. `test_brechas_de_assurance::G1` conserva la reproducción histórica —las cuatro
órdenes ciegas— y este fichero comprueba que cada transición conserva el estado.

Los cinco estados, y por qué son cinco
--------------------------------------
    SIN_SUJETO    no había nada que derivar
    RESUELTO      se derivó entero. La certeza es real
    DESCONOCIDO   el programa no está modelado      → se arregla añadiéndolo a la tabla
    NO_RESOLUBLE  está modelado y no se deriva      → no se arregla nunca; se declara
    AMBIGUO       se derivó algo que NO es una ruta → el único que MIENTE

Se separan porque **se arreglan distinto**, que es el mismo criterio con el que `core.evidence`
separó los seis estados del diario y `core.guard` los cuatro de la admisión. `DESCONOCIDO` y
`NO_RESOLUBLE` producen el mismo `opaco=True` y responden a preguntas distintas; colapsarlos
haría que «añade `mi-binario` a la tabla» y «esto no tiene arreglo» se leyeran igual.

Lo que NO existe en este salto
------------------------------
El catálogo de la misión incluye «recibido pero ILEGIBLE». En este módulo no puede ocurrir: la
orden llega ya como cadena, y el caso «vino un campo y no se pudo leer» vive un canal más
arriba, en `core.guard._campo` (regla `campo-ilegible`, cerrado en R-03). Se dice en vez de
inventar un sexto estado que ninguna entrada podría alcanzar.

La asimetría deliberada entre escrituras y lecturas
---------------------------------------------------
Un destino de ESCRITURA sin resolver sale de `escrituras` y entra en `sin_resolver`: afirmar
`escrituras={'$D'}` es afirmar un fichero llamado `$D`. Un token de LECTURA sin resolver **se
conserva**, porque es el nombre de la variable y `_lecturas_secretas` lo usa para detectar
credenciales por su forma. Filtrarlo convertía `echo $MI_SERVICIO_PASSWORD` de `ask` en
`allow` — medido al introducir este cambio, y es la razón de que la asimetría esté escrita.
"""

from __future__ import annotations

import json
import subprocess  # nosec B404 — ejecutar el guardián real ES la medición
import sys
import tempfile
import unittest
from pathlib import Path

import core.effects as E
from core.effects import (AMBIGUO, DESCONOCIDO, NO_RESOLUBLE, RESUELTO, SIN_SUJETO, Efectos,
                          efectos)
from core.policy import ALLOW, ASK, DENY, Policy, decide_command
from core.proc import TEXT_IO

RAIZ = Path(__file__).resolve().parents[2]
PROTEGIDA = "gates/base.py"

#: Las cuatro de `G1`, más las que amplían la clase. `(id, orden, resolución esperada)`.
CIEGAS = (
    ("variable de shell", f"D={PROTEGIDA}; echo x > $D", AMBIGUO),
    ("variable con llaves", f"D={PROTEGIDA}; echo x > ${{D}}", AMBIGUO),
    ("valor por omisión", f"echo x > ${{V:-{PROTEGIDA}}}", AMBIGUO),
    ("sustitución de orden", "echo x > $(mktemp)", AMBIGUO),
    ("comillas invertidas", "echo x > `mktemp`", AMBIGUO),
    ("find -exec", "find . -name base.py -exec truncate -s0 {} ;", NO_RESOLUBLE),
    ("find -delete", "find . -name base.py -delete", NO_RESOLUBLE),
    ("find -execdir", "find . -name base.py -execdir rm {} ;", NO_RESOLUBLE),
)

#: Controles positivos. Sin ellos, «todo es AMBIGUO» aprobaría el fichero entero.
CIERTAS = (
    ("redirección literal", f"echo x > {PROTEGIDA}", RESUELTO),
    ("copia", "cp a.txt b.txt", RESUELTO),
    ("borrado", "rm f.txt", RESUELTO),
    ("lector con ruta", "cat README.md", RESUELTO),
    ("lector sin ruta", "ls -la", RESUELTO),
    ("find sin acción", "find . -name '*.py'", RESUELTO),
    ("sed en sitio", "sed -i s/a/b/ f.txt", RESUELTO),
    ("orden vacía", "", SIN_SUJETO),
    ("intérprete", "python3 -c 'print(1)'", NO_RESOLUBLE),
    ("no modelado", "mi-binario --flag", DESCONOCIDO),
)


def _guard(cmd: str) -> tuple[str, dict]:
    """El guardián REAL, y el último evento que dejó en el diario."""
    ws = Path(tempfile.mkdtemp(prefix="r01-")).resolve()
    (ws / ".harness" / "evidence").mkdir(parents=True)
    (ws / "gates").mkdir()
    (ws / "gates" / "base.py").write_text("juez", encoding="utf-8")
    carga = {"tool_name": "Bash", "tool_input": {"command": cmd}}
    p = subprocess.run(  # nosec B603
        [sys.executable, "-m", "core.guard", "--runtime", "claude", "--stdin",
         "--workspace", str(ws)],
        input=json.dumps(carga), capture_output=True, cwd=str(RAIZ), timeout=120, **TEXT_IO)
    dec = json.loads(p.stdout)["hookSpecificOutput"]["permissionDecision"]
    lineas = (ws / ".harness" / "evidence" / "ledger.jsonl").read_text(encoding="utf-8")
    ev = [json.loads(x) for x in lineas.splitlines() if x.strip()][-1]
    return dec, ev


# ── salto 1 · entrada → resolución ───────────────────────────────────────────────────
class LaResolucionDistingueLosCincoEstados(unittest.TestCase):

    def test_ninguna_orden_ciega_queda_RESUELTA(self):
        """El corazón de R-01: no que se rechacen, sino que no se declaren ciertas."""
        for ident, orden, esperada in CIEGAS:
            with self.subTest(caso=ident):
                e = efectos(orden)
                self.assertNotEqual(RESUELTO, e.resolucion)
                self.assertEqual(esperada, e.resolucion)
                self.assertTrue(e.motivo_opaco, "un estado que no resuelve debe decir por qué")

    def test_control_lo_que_si_se_resuelve_lo_declara(self):
        for ident, orden, esperada in CIERTAS:
            with self.subTest(caso=ident):
                self.assertEqual(esperada, efectos(orden).resolucion)

    def test_ninguna_escritura_derivada_conserva_expansion(self):
        """Corolario barato que cubre la clase entera sin enumerarla."""
        for ident, orden, _r in CIEGAS + CIERTAS:
            for ruta in efectos(orden).escrituras:
                with self.subTest(caso=ident, ruta=ruta):
                    self.assertFalse(any(c in ruta for c in "$`"),
                                     f"«{ruta}» es una plantilla sin expandir, no una ruta")

    def test_lo_visto_y_no_resuelto_no_se_descarta(self):
        """Ni se coacciona ni se tira: se conserva aparte. Es la distinción entera."""
        e = efectos(f"D={PROTEGIDA}; echo x > $D")
        self.assertEqual(set(), e.escrituras)
        self.assertEqual({"$D"}, e.sin_resolver)

    def test_opaco_es_una_proyeccion_y_no_puede_contradecir_al_estado(self):
        for ident, orden, _r in CIEGAS + CIERTAS:
            with self.subTest(caso=ident):
                e = efectos(orden)
                self.assertEqual(e.resolucion in (DESCONOCIDO, NO_RESOLUBLE, AMBIGUO), e.opaco)

    def test_opaco_no_se_puede_fijar_a_mano(self):
        """Si volviera a ser un campo escribible, podría mentir otra vez sobre el estado."""
        with self.assertRaises(AttributeError):
            Efectos().opaco = False


class LaComposicionSeQuedaConLoPeor(unittest.TestCase):
    """Una cadena de segmentos vale lo que su segmento menos resuelto."""

    def test_un_segmento_ciego_contamina_la_cadena(self):
        e = efectos(f"cp a.txt b.txt && D={PROTEGIDA}; echo x > $D")
        self.assertEqual(AMBIGUO, e.resolucion)
        self.assertIn("b.txt", e.escrituras, "lo demostrado no se pierde por el camino")

    def test_el_motivo_describe_el_estado_que_gana(self):
        """Con `motivo or motivo` el estado era uno y la explicación otra."""
        izq, der = Efectos(resolucion=DESCONOCIDO, motivo_opaco="por desconocido"), \
            Efectos(resolucion=AMBIGUO, motivo_opaco="por ambiguo")
        self.assertEqual(AMBIGUO, (izq | der).resolucion)
        self.assertEqual("por ambiguo", (izq | der).motivo_opaco)
        self.assertEqual("por ambiguo", (der | izq).motivo_opaco)

    def test_el_orden_de_composicion_no_altera_el_resultado(self):
        for a in (SIN_SUJETO, RESUELTO, DESCONOCIDO, NO_RESOLUBLE, AMBIGUO):
            for b in (SIN_SUJETO, RESUELTO, DESCONOCIDO, NO_RESOLUBLE, AMBIGUO):
                with self.subTest(a=a, b=b):
                    x, y = Efectos(resolucion=a), Efectos(resolucion=b)
                    self.assertEqual((x | y).resolucion, (y | x).resolucion)


# ── salto 2 · resolución → decisión ──────────────────────────────────────────────────
class LaResolucionLlegaALaDecision(unittest.TestCase):

    def test_una_escritura_a_destino_sin_resolver_la_decide_una_persona(self):
        """`AMBIGUO` ≠ `NO_RESOLUBLE`, y por eso no se responden igual.

        Con `python3 -c` no se sabe SI escribe. Con `echo x > $D` se sabe QUE escribe y no
        ADÓNDE: hay una operación observada cuyo destino no se pudo examinar, que es el mismo
        hecho que `campo-ilegible` un canal más arriba.
        """
        for ident, orden, esperada in CIEGAS:
            if esperada != AMBIGUO:
                continue
            with self.subTest(caso=ident):
                d = decide_command(Policy.default(), orden, RAIZ)
                self.assertEqual(ASK, d.outcome)
                self.assertEqual("destino-sin-resolver", d.rule)

    def test_lo_no_resoluble_sigue_pasando_y_eso_es_correcto(self):
        """`find -exec` sale `allow`, como `python3 -c`. Denegar todo intérprete haría
        inusable la herramienta, y un control inusable se desactiva. Lo que cambió no es la
        decisión: es que ya no se registra como certeza."""
        for orden in ("find . -name base.py -exec truncate -s0 {} ;", "python3 -c 'print(1)'"):
            with self.subTest(orden=orden):
                d = decide_command(Policy.default(), orden, RAIZ)
                self.assertEqual(ALLOW, d.outcome)
                self.assertTrue(d.opaco)
                self.assertEqual(NO_RESOLUBLE, d.resolucion)

    def test_lo_resuelto_y_protegido_se_sigue_denegando(self):
        d = decide_command(Policy.default(), f"echo x > {PROTEGIDA}", RAIZ)
        self.assertEqual(DENY, d.outcome)
        self.assertEqual(RESUELTO, d.resolucion)
        self.assertFalse(d.opaco)

    def test_no_se_rompio_la_lectura_de_credenciales(self):
        """Regresión que introduje y detecté al medir: filtrar los tokens sin expandir de
        `lecturas` convertía esto de `ask` en `allow`. El nombre de la variable ES el dato."""
        d = decide_command(Policy.default(), "echo $MI_SERVICIO_PASSWORD", RAIZ)
        self.assertEqual(ASK, d.outcome)


# ── salto 3 · decisión → evidencia ───────────────────────────────────────────────────
class LaResolucionLlegaAlDiario(unittest.TestCase):

    def test_el_evento_registra_el_estado_y_no_solo_el_booleano(self):
        dec, ev = _guard(f"D={PROTEGIDA}; echo x > $D")
        self.assertEqual("ask", dec)
        self.assertEqual(AMBIGUO, ev.get("resolucion"))
        self.assertEqual(["$D"], ev.get("destinos_sin_resolver"))
        self.assertTrue(ev.get("opaco"), "la proyección tiene que seguir siendo coherente")

    def test_el_diario_distingue_los_dos_modos_de_ignorancia(self):
        _d1, amb = _guard(f"echo x > ${{V:-{PROTEGIDA}}}")
        _d2, nor = _guard("find . -name base.py -delete")
        _d3, des = _guard("mi-binario --flag")
        self.assertEqual({AMBIGUO, NO_RESOLUBLE, DESCONOCIDO},
                         {amb["resolucion"], nor["resolucion"], des["resolucion"]},
                         "tres ignorancias distintas no pueden quedar con el mismo registro")

    def test_una_certeza_real_se_registra_como_tal(self):
        dec, ev = _guard(f"echo x > {PROTEGIDA}")
        self.assertEqual("deny", dec)
        self.assertEqual(RESUELTO, ev.get("resolucion"))
        self.assertFalse(ev.get("opaco"))
        self.assertEqual([], ev.get("destinos_sin_resolver"))


# ── mutaciones ───────────────────────────────────────────────────────────────────────
class MutacionesDeR01(unittest.TestCase):
    """Reintroducir la certeza falsa. Cada mutación debe morir por su testigo."""

    def _matar(self, mutante, etiqueta: str) -> None:
        original = E._de_un_segmento                                    # noqa: SLF001
        vivas = []
        try:
            E._de_un_segmento = mutante                                 # noqa: SLF001
            for ident, orden, _esperada in CIEGAS:
                if not efectos(orden).opaco:
                    vivas.append(ident)
        finally:
            E._de_un_segmento = original                                # noqa: SLF001
        self.assertTrue(vivas, f"{etiqueta}: ningún caso ciego la distingue del original")

    def test_M_R01_01_no_comprobar_la_expansion_en_lo_derivado(self):
        """El `_de_un_segmento` anterior: deriva y no mira si lo derivado es una ruta."""
        self._matar(E._derivar_segmento, "M-R01-01")                    # noqa: SLF001

    def test_M_R01_02_conservar_la_ruta_cruda_como_si_fuera_real(self):
        """Coerción: `$D` se queda en `escrituras` y el estado dice RESUELTO."""
        def mutante(seg):
            ef = E._derivar_segmento(seg)                               # noqa: SLF001
            if ef.escrituras or ef.lecturas:
                ef.declarar(RESUELTO, "")
            return ef
        self._matar(mutante, "M-R01-02")

    def test_M_R01_03_descartar_en_silencio_lo_que_no_se_resuelve(self):
        """El otro extremo: tirar `$D` sin declararlo. Deja `escrituras` vacío y `opaco=False`
        — «sé que no escribe» sobre una orden que escribe."""
        def mutante(seg):
            ef = E._derivar_segmento(seg)                               # noqa: SLF001
            ef.escrituras = {p for p in ef.escrituras if not E._SIN_EXPANDIR.search(p)}
            if ef.resolucion == SIN_SUJETO and (ef.escrituras or ef.lecturas):
                ef.resolucion = RESUELTO
            return ef
        self._matar(mutante, "M-R01-03")

    def test_M_R01_04_find_vuelve_a_ser_un_lector(self):
        original = E._FIND_ACCIONES                                     # noqa: SLF001
        try:
            E._FIND_ACCIONES = set()                                    # noqa: SLF001
            ciegos = [i for i, o, r in CIEGAS if r == NO_RESOLUBLE and not efectos(o).opaco]
        finally:
            E._FIND_ACCIONES = original                                 # noqa: SLF001
        self.assertTrue(ciegos, "M-R01-04: el catálogo no cubre las acciones de `find`")

    def test_M_R01_05_la_composicion_se_queda_con_el_primero(self):
        """Si compone por `or` en vez de por severidad, un segmento limpio delante tapa al
        ciego de detrás."""
        izq, der = Efectos(resolucion=RESUELTO), Efectos(resolucion=AMBIGUO)
        self.assertEqual(AMBIGUO, (izq | der).resolucion,
                         "M-R01-05: la composición dejó de quedarse con lo peor")

    def test_M_R01_06_la_decision_ignora_sin_resolver(self):
        """Si `decide_command` deja de mirar `sin_resolver`, la orden vuelve a `allow`."""
        d = decide_command(Policy.default(), f"D={PROTEGIDA}; echo x > $D", RAIZ)
        self.assertNotEqual(ALLOW, d.outcome)
        self.assertTrue(d.sin_resolver,
                        "M-R01-06: sin este campo en la Decision no hay nada que mirar")

    def test_M_R01_07_el_diario_no_propaga_la_resolucion(self):
        """Testigo del último salto: si el evento pierde `resolucion`, la distinción muere
        justo donde se iba a auditar."""
        _dec, ev = _guard(f"D={PROTEGIDA}; echo x > $D")
        self.assertIn("resolucion", ev)
        self.assertIn("destinos_sin_resolver", ev)


if __name__ == "__main__":       # pragma: no cover
    unittest.main()
