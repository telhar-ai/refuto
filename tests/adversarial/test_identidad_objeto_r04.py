# -*- coding: utf-8 -*-
"""R-04 · Identidad de objeto y TOCTOU. Qué se alcanza, y qué NO.

Las cuatro respuestas posibles, y cuál sostiene esta arquitectura
----------------------------------------------------------------
    PREVENTION      impedir que la sustitución ocurra          NO ALCANZABLE
    DETECTION       notar que ocurrió                          BLOQUEADA en `E`
    ATTESTATION     dejar constancia de sobre qué se decidió   **ALCANZADA**
    RECONCILIATION  cruzar lo decidido con lo ocurrido         BLOQUEADA en `E`

`PREVENTION` no es alcanzable y no es un defecto pendiente: refuto es un gancho `PreToolUse`.
Decide, devuelve, y el proceso termina. Quien abre el fichero es **otro proceso, después**.
Entre las dos cosas no hay nada que refuto controle — no es que falte código, es que no hay
punto de programa donde ponerlo.

`DETECTION` y `RECONCILIATION` exigen un observador en T5, que es `E OBSERVATION`
(`DESIGNED_NOT_IMPLEMENTED`, 0 ganchos `PostToolUse`). Este fichero **no finge** cubrirlas:
`LoQueEstaArquitecturaNoAlcanza` las declara con su motivo y falla si alguien afirma lo
contrario.

Lo que sí se cierra es la precondición de las tres: hasta el 2026-09-25 la evidencia guardaba
el NOMBRE y un nombre es reapuntable. Dos eventos sobre «obra/salida.txt» podían ser sobre dos
ficheros distintos y nada lo decía. Ahora la identidad está atestiguada, y estas pruebas
demuestran que **basta para distinguir cada forma de sustitución** — que es exactamente la
afirmación que se puede sostener, ni una más.

Sobre `O_NOFOLLOW_ANY`, que NO se usa
-------------------------------------
Medido en esta máquina: `O_NOFOLLOW` deja pasar un enlace en componente intermedio,
`O_NOFOLLOW_ANY` lo rechaza con `ELOOP`, y un flag inventado se **acepta en silencio**. Todo
cierto, y todo irrelevante aquí: esas banderas protegen al ABRIR, y refuto nunca abre el
objetivo. `decide_write` usa `realpath`, que sigue los enlaces **a propósito**, porque un
enlace dentro del espacio apuntando al juez es un ataque que hay que ver. Añadir una sonda de
capacidad para una primitiva que el programa no usa sería complejidad sin ganancia de
assurance. La medición queda en el registro; el código no la necesita.
"""

from __future__ import annotations

import json
import os
import subprocess  # nosec B404 — ejecutar el guardián real ES la medición
import sys
import tempfile
import unittest
from pathlib import Path

from core.policy import (ALLOW, AUSENTE, DENY, EXISTE, IDENTIDAD_DISTINGUE_REUSO_DE_INODO,
                         INDETERMINADO, SIN_PADRE, Policy, decide_write, identidad_de)
from core.proc import TEXT_IO, euid

RAIZ = Path(__file__).resolve().parents[2]


def _ws() -> Path:
    ws = Path(tempfile.mkdtemp(prefix="r04-")).resolve()
    (ws / ".harness" / "evidence").mkdir(parents=True)
    (ws / "gates").mkdir()
    (ws / "gates" / "base.py").write_text("juez", encoding="utf-8")
    (ws / "obra").mkdir()
    return ws


class LaIdentidadSeAtestiguaEnLaDecision(unittest.TestCase):

    def test_los_cuatro_estados_se_distinguen(self):
        ws = _ws()
        (ws / "obra" / "hay.txt").write_text("x", encoding="utf-8")
        casos = {"obra/hay.txt": EXISTE, "obra/no-hay.txt": AUSENTE,
                 "obra/sin/padre/x.txt": SIN_PADRE}
        for target, esperado in casos.items():
            with self.subTest(target=target):
                self.assertEqual(esperado,
                                 decide_write(Policy.default(), ws, target).objeto["estado"])

    def test_no_poder_mirar_no_es_no_estar(self):
        """`INDETERMINADO` existe por la misma razón que en el diario y en la admisión."""
        ws = _ws()
        d = ws / "obra" / "cerrado"
        d.mkdir()
        (d / "dentro.txt").write_text("x", encoding="utf-8")
        d.chmod(0o000)
        try:
            ident = identidad_de(d / "dentro.txt")
        finally:
            d.chmod(0o755)
        if euid() == 0:                                                 # pragma: no cover
            self.skipTest("como root los permisos no bloquean: el caso no se puede provocar")
        self.assertEqual(INDETERMINADO, ident["estado"])
        self.assertTrue(ident.get("motivo"), "un estado que no sabe debe decir por qué")

    def test_toda_decision_sobre_ruta_trae_identidad(self):
        """Se adjunta en un solo sitio para que ninguna rama pueda salir sin ella."""
        ws = _ws()
        (ws / "obra" / "hay.txt").write_text("x", encoding="utf-8")
        for target in ("gates/base.py", "obra/hay.txt", "obra/nueva.txt", "../fuera.txt",
                       ".env", "obra/sin/padre/x.txt"):
            with self.subTest(target=target):
                self.assertTrue(decide_write(Policy.default(), ws, target).objeto,
                                "una rama de decide_write devolvió una decisión sin objeto")


class LaIdentidadDistingueCadaSustitucion(unittest.TestCase):
    """La afirmación que sí se puede sostener: la identidad SIRVE para notar el cambio.

    Cada prueba sustituye el objeto de una forma distinta y exige que la identidad cambie.
    Si alguna no cambiara, atestiguarla no serviría para nada y el campo sería decorado.
    """

    #: Lo que hace falta para que «otro objeto con el MISMO nombre» sea distinguible cuando el
    #: sistema de ficheros reutiliza el inodo. Ver `IDENTIDAD_DISTINGUE_REUSO_DE_INODO`: en ext4
    #: no lo hay, y declararlo es lo honesto — omitirlo dejaría cuatro `PASS` que en Linux serían
    #: falsos, que es justo el defecto que trajo esta prueba aquí.
    MOTIVO_SIN_REUSO = (
        "este sistema de ficheros reutiliza el número de inodo y `os.lstat` no expone hora de "
        "creación: la identidad NO puede distinguir una sustitución que reúsa el inodo. Es un "
        "límite declarado del mecanismo, no un aprobado (NOT_APPLICABLE)")

    def _ident(self, ws: Path, target: str) -> dict:
        return decide_write(Policy.default(), ws, target).objeto

    def test_borrar_y_recrear_con_el_mismo_nombre(self):
        """La forma de sustitución que ext4 hace invisible, y por la que R-04 se retracta.

        Medido en CI el 2026-09-30: mismo `ino` a los dos lados. En APFS el inodo no se reutiliza
        y además hay `st_birthtime`, así que ahí sí se distingue — y eso es precisamente lo que
        hizo creer que la propiedad valía en todas partes.
        """
        if not IDENTIDAD_DISTINGUE_REUSO_DE_INODO:
            self.skipTest(self.MOTIVO_SIN_REUSO)
        ws = _ws()
        f = ws / "obra" / "salida.txt"
        f.write_text("original", encoding="utf-8")
        antes = self._ident(ws, "obra/salida.txt")
        f.unlink()
        f.write_text("sustituido", encoding="utf-8")
        self.assertNotEqual(antes, self._ident(ws, "obra/salida.txt"))

    def test_el_predicado_dice_la_verdad_sobre_lo_que_la_identidad_LLEVA(self):
        """El otro lado de la retractación, y el que impide que el límite se olvide.

        Se mide el CAMPO, no el comportamiento del sistema de ficheros: «el inodo se reutiliza»
        no se puede forzar desde una prueba —en APFS no ocurre— y afirmarlo aquí ataría el
        control a algo que no controla. Lo que sí es comprobable en todas partes es si la
        identidad lleva hora de creación, que es de lo que depende distinguir el reúso.

        Así el límite queda medido en los dos sentidos: el día que Linux exponga la hora de
        creación por `os.lstat` —o alguien enlace `statx`— esta prueba y el `skipTest` de las de
        sustitución cambian juntos, y hay que venir a actualizar la retractación de R-04.
        """
        ws = _ws()
        (ws / "obra" / "salida.txt").write_text("x", encoding="utf-8")
        ident = self._ident(ws, "obra/salida.txt")
        self.assertEqual(IDENTIDAD_DISTINGUE_REUSO_DE_INODO, "nacimiento_us" in ident,
                         f"el predicado dice {IDENTIDAD_DISTINGUE_REUSO_DE_INODO} y la identidad "
                         f"lleva {sorted(ident)}: uno de los dos miente")

    def test_donde_no_hay_hora_de_creacion_solo_quedan_dev_ino_tipo_nlink(self):
        """Y entonces dos objetos que reúsan el inodo son indistinguibles. No es una hipótesis:
        es aritmética sobre los campos que quedan, y por eso el `skipTest` de arriba es honesto
        en vez de cómodo."""
        if IDENTIDAD_DISTINGUE_REUSO_DE_INODO:
            self.skipTest("esta plataforma expone hora de creación: el límite no aplica aquí")
        ws = _ws()
        (ws / "obra" / "salida.txt").write_text("x", encoding="utf-8")
        self.assertEqual({"estado", "dev", "ino", "tipo", "nlink"},
                         set(self._ident(ws, "obra/salida.txt")))

    def test_sustituir_el_fichero_por_un_enlace(self):
        ws = _ws()
        f = ws / "obra" / "salida.txt"
        f.write_text("original", encoding="utf-8")
        antes = self._ident(ws, "obra/salida.txt")
        f.unlink()
        os.symlink(ws / "obra" / "otro.txt", f)
        (ws / "obra" / "otro.txt").write_text("destino", encoding="utf-8")
        self.assertNotEqual(antes, self._ident(ws, "obra/salida.txt"))

    def test_sustituir_el_directorio_padre_de_una_creacion(self):
        """La forma de TOCTOU que aplica a un fichero que todavía no existe: no hay objeto
        que atestiguar, así que lo que se atestigua es DÓNDE va a aterrizar."""
        if not IDENTIDAD_DISTINGUE_REUSO_DE_INODO:
            self.skipTest(self.MOTIVO_SIN_REUSO + " — y un directorio recreado también lo reúsa")
        ws = _ws()
        d = ws / "obra" / "destino"
        d.mkdir()
        antes = self._ident(ws, "obra/destino/nuevo.txt")
        self.assertEqual(AUSENTE, antes["estado"])
        d.rmdir()
        d.mkdir()                       # mismo nombre, otro directorio
        self.assertNotEqual(antes, self._ident(ws, "obra/destino/nuevo.txt"))

    def test_un_objeto_que_no_cambia_da_la_misma_identidad(self):
        """Control negativo. Sin él, «la identidad siempre cambia» aprobaría lo anterior y
        haría la atestación inútil por el otro extremo: una alarma que salta siempre."""
        ws = _ws()
        (ws / "obra" / "quieto.txt").write_text("x", encoding="utf-8")
        a = self._ident(ws, "obra/quieto.txt")
        self.assertEqual(a, self._ident(ws, "obra/quieto.txt"))

    def test_reescribir_el_contenido_no_cambia_la_identidad(self):
        """Y es correcto: el objeto es el mismo. La identidad responde «¿es este fichero?»,
        no «¿tiene el mismo contenido?». Confundirlas sería otra certeza falsa."""
        ws = _ws()
        f = ws / "obra" / "quieto.txt"
        f.write_text("antes", encoding="utf-8")
        a = self._ident(ws, "obra/quieto.txt")
        with f.open("w", encoding="utf-8") as fh:
            fh.write("después")
        self.assertEqual(a, self._ident(ws, "obra/quieto.txt"))


class LaIdentidadLlegaAlDiario(unittest.TestCase):
    """Atestiguar en memoria no sirve: tiene que quedar donde alguien pueda mirarlo después."""

    def _evento(self, ws: Path, carga: dict) -> dict:
        p = subprocess.run(  # nosec B603
            [sys.executable, "-m", "core.guard", "--runtime", "claude", "--stdin",
             "--workspace", str(ws)],
            input=json.dumps(carga), capture_output=True, cwd=str(RAIZ), timeout=120, **TEXT_IO)
        self.assertEqual(0, p.returncode, p.stderr[:300])
        lineas = (ws / ".harness" / "evidence" / "ledger.jsonl").read_text(encoding="utf-8")
        return [json.loads(x) for x in lineas.splitlines() if x.strip()][-1]

    def test_el_evento_registra_sobre_que_objeto_se_decidio(self):
        ws = _ws()
        ev = self._evento(ws, {"tool_name": "Write",
                               "tool_input": {"file_path": str(ws / "gates" / "base.py"),
                                              "content": "x"}})
        self.assertEqual("deny", ev["outcome"])
        self.assertEqual(EXISTE, ev["objeto"]["estado"])
        self.assertIn("ino", ev["objeto"])

    def test_dos_eventos_sobre_el_mismo_NOMBRE_se_distinguen_por_objeto(self):
        """El hecho que la evidencia no podía expresar antes de R-04.

        Y que sigue sin poder expresar donde el inodo se reutiliza: el diario no puede distinguir
        lo que la identidad no distingue. Ver `IDENTIDAD_DISTINGUE_REUSO_DE_INODO`.
        """
        if not IDENTIDAD_DISTINGUE_REUSO_DE_INODO:
            self.skipTest("el inodo se reutiliza y no hay hora de creación: el diario registra la "
                          "identidad, pero en esta plataforma no basta para separar los dos "
                          "objetos (NOT_APPLICABLE, no PASS)")
        ws = _ws()
        f = ws / "obra" / "salida.txt"
        f.write_text("original", encoding="utf-8")
        carga = {"tool_name": "Write", "tool_input": {"file_path": str(f), "content": "x"}}
        e1 = self._evento(ws, carga)
        f.unlink()
        f.write_text("sustituido", encoding="utf-8")
        e2 = self._evento(ws, carga)
        self.assertEqual(e1["target"], e2["target"], "mismo nombre…")
        self.assertNotEqual(e1["objeto"], e2["objeto"], "…y el diario ya puede decir que no "
                                                        "es el mismo objeto")


class LoQueEstaArquitecturaNoAlcanza(unittest.TestCase):
    """Las fronteras, como aserciones. Si alguna dejara de ser cierta, hay que redecirlo.

    Estas pruebas existen para que el límite no se erosione en silencio: el día que alguien
    implemente `PostToolUse`, `test_no_hay_observador_en_T5` se pondrá roja y obligará a
    reescribir el contrato en vez de dejarlo diciendo menos de lo que el sistema ya hace.
    """

    def test_PREVENTION_no_es_alcanzable_y_consta_por_que(self):
        """refuto no abre el objetivo: no hay descriptor que sostener entre T1 y T5."""
        import inspect
        from core import policy
        fuente = inspect.getsource(policy.decide_write) + inspect.getsource(
            policy._decidir_escritura)                                  # noqa: SLF001
        for primitiva in ("os.open(", "O_NOFOLLOW", "fdopen"):
            self.assertNotIn(primitiva, fuente,
                             f"«{primitiva}» aparece en la decisión: si refuto ha empezado a "
                             f"abrir el objetivo, la frontera PREVENT/DETECT cambió y hay que "
                             f"volver a medirla, no heredar esta prueba")

    def test_no_hay_observador_en_T5(self):
        """`DETECTION` y `RECONCILIATION` dependen de `E`, que no está implementada."""
        from core import wire
        self.assertFalse(
            any("PostToolUse" in str(getattr(wire, n, "")) for n in dir(wire)
                if not n.startswith("__")),
            "hay algo que menciona PostToolUse en core.wire: si `E` se implementó, R-04 puede "
            "pasar de ATTESTATION a DETECTION y este fichero se queda corto")

    def test_la_ventana_dentro_de_la_decision_sigue_abierta(self):
        """Honestidad sobre el propio arreglo: `realpath()` y `lstat()` son DOS travesías del
        sistema de archivos. Entre ellas el objeto puede cambiar, así que la identidad
        atestiguada puede no ser la del objeto que se comparó contra la política.

        No se cierra aquí —haría falta resolver y medir en una sola operación, y `realpath`
        no la ofrece— y se declara en vez de callarse. La ventana es de microsegundos y
        requiere una carrera local; el resto del modelo asume un único uid, donde quien puede
        ganarla puede además borrar el diario.
        """
        import inspect
        from core import policy
        fuente = inspect.getsource(policy.decide_write)
        self.assertIn("realpath", fuente)
        self.assertIn("identidad_de", fuente)


if __name__ == "__main__":       # pragma: no cover
    unittest.main()
