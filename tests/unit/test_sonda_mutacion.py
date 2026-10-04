# -*- coding: utf-8 -*-
"""La sonda de mutación, medida a sí misma.

Un instrumento de assurance que no se comprueba es una afirmación más. Estas pruebas fijan
las tres propiedades sin las cuales `scripts/mutate_probe.py` produce cifras en vez de
evidencia.

El defecto que cierran, medido el 2026-09-23
--------------------------------------------
CI (ubuntu-latest, Python 3.13, corrida 35805060715) informó `M3 … MUERTA_INCIDENTAL`,
muerta por `test_no_aplica_exige_motivo_declarado` — que es el testigo de **M2**. En local
no se reproducía nunca.

La causa: Python invalida un `.pyc` comparando **(mtime, tamaño)** del fuente. M2 y M3
insertan la MISMA cadena (`"False and "`) en el MISMO fichero, así que los dos ficheros
mutados pesan **exactamente lo mismo**. En un ejecutor rápido las dos escrituras caen dentro
del mismo segundo, y el intérprete sirve el bytecode de la mutación anterior.

**La sonda estaba informando de una mutación mientras ejecutaba otra.** No es un fallo de
precisión: es atribuir una propiedad demostrada a quien no la demostró, que es exactamente el
falso aseguramiento que esta sonda existe para detectar — cometido por la sonda.
"""

from __future__ import annotations

import importlib.util
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from core.proc import TEXT_IO

RAIZ = Path(__file__).resolve().parents[2]


def _cargar_sonda():
    """La sonda es un guion, no un paquete. Se registra en `sys.modules` antes de ejecutarla
    porque `@dataclass` resuelve anotaciones mirando ahí, y sin registrar levanta
    `AttributeError: 'NoneType' object has no attribute '__dict__'`."""
    spec = importlib.util.spec_from_file_location("mutate_probe",
                                                  RAIZ / "scripts" / "mutate_probe.py")
    mod = importlib.util.module_from_spec(spec)
    sys.modules["mutate_probe"] = mod
    spec.loader.exec_module(mod)
    return mod


class TestLaSondaNoSeMideConBytecodeRancio(unittest.TestCase):

    def test_dos_mutaciones_del_mismo_fichero_producen_el_mismo_tamano(self):
        """La precondición del defecto, documentada.

        No se arregla haciendo que los tamaños difieran —sería frágil y accidental—: se
        arregla aislando la caché. Esta prueba deja constancia de por qué hace falta.
        """
        sonda = _cargar_sonda()
        por_fichero: dict = {}
        for m in sonda.MUTACIONES:
            original = (RAIZ / m.fichero).read_text(encoding="utf-8")
            if original.count(m.viejo) != 1:
                continue
            tam = len(original.replace(m.viejo, m.nuevo, 1).encode("utf-8"))
            por_fichero.setdefault(m.fichero, []).append((m.id, tam))
        colisiones = [(f, v) for f, v in por_fichero.items()
                      if len({t for _, t in v}) < len(v)]
        self.assertTrue(
            colisiones,
            "ya no hay colisión de tamaños: si es a propósito, esta prueba y el aislamiento "
            "de caché siguen siendo necesarios, porque depender de que los tamaños difieran "
            "es depender de una casualidad")

    def test_la_sonda_aisla_la_cache_de_bytecode_en_cada_ejecucion(self):
        """La propiedad que impide el defecto: cada corrida compila el fuente que hay en disco."""
        sonda = _cargar_sonda()
        visto = {}
        real = subprocess.run

        def espia(argv, **kw):
            visto["env"] = kw.get("env") or {}
            return real([sys.executable, "-c", "pass"], capture_output=True, **TEXT_IO)

        subprocess.run = espia
        try:
            sonda._correr(["contract"], etiqueta="PRUEBA")
        finally:
            subprocess.run = real
        prefijo = visto["env"].get("PYTHONPYCACHEPREFIX", "")
        self.assertTrue(prefijo, "sin PYTHONPYCACHEPREFIX la sonda puede servir bytecode rancio")
        self.assertIn("refuto-pyc", prefijo, "el prefijo no es un directorio propio de la sonda")

    def test_con_cache_aislada_se_observa_el_fuente_de_verdad(self):
        """La demostración, sobre un módulo desechable: mismo tamaño y mismo mtime.

        Sin aislar, el intérprete devuelve lo de la versión anterior. Con aislamiento,
        devuelve lo que hay escrito.
        """
        with tempfile.TemporaryDirectory() as d:
            raiz = Path(d)
            mod = raiz / "cobaya.py"
            # Dos versiones del MISMO tamaño: una letra por una letra.
            mod.write_text("VALOR = 'A'\n", encoding="utf-8", newline="\n")
            ts = mod.stat().st_mtime

            def leer(env_extra):
                env = dict(os.environ, PYTHONPATH=str(raiz), **env_extra)
                p = subprocess.run([sys.executable, "-c",
                                    "import cobaya; print(cobaya.VALOR)"],
                                   capture_output=True, cwd=str(raiz), env=env, **TEXT_IO)
                return p.stdout.strip()

            self.assertEqual("A", leer({}))                      # genera el .pyc
            mod.write_text("VALOR = 'B'\n", encoding="utf-8", newline="\n")
            os.utime(mod, (ts, ts))                              # mismo mtime y mismo tamaño

            rancio = leer({})
            with tempfile.TemporaryDirectory() as pyc:
                fresco = leer({"PYTHONPYCACHEPREFIX": pyc})

            self.assertEqual("B", fresco,
                             "con caché aislada debe leerse el fuente que hay en disco")
            if rancio == "A":
                # El defecto se reproduce en esta máquina: queda demostrado que el
                # aislamiento no es decorativo.
                self.assertNotEqual(rancio, fresco)
            # Si `rancio` ya daba "B", esta máquina no reproduce la condición (granularidad
            # de mtime distinta). No se concluye nada de ella: lo que se exige es `fresco`.


if __name__ == "__main__":
    unittest.main()
