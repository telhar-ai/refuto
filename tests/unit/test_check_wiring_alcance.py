# -*- coding: utf-8 -*-
"""`check_wiring` mide los módulos del PRODUCTO, no lo que haya en el directorio.

El defecto, medido el 2026-10-04
--------------------------------
`check_modules` recorre el árbol de trabajo con `ROOT.rglob("*.py")`, así que veía cualquier
cosa que alguien dejara en el directorio. Un guion de remediación bajo `artifacts/harness/`
—ignorado por git, nunca publicado, pensado para que lo ejecute una persona— dejaba el control en
rojo con «nadie lo importa», y con él el `pre-push` entero.

El control tenía razón en su REGLA y se estaba equivocando de SUJETO. Un fichero que git ignora
no forma parte del grafo de módulos: no se publica, no se importa y no puede estar conectado.
Exigirle un `import` es la misma clase de error que exigírselo a una puerta que se carga por
`importlib`, que ya estaba exenta por eso mismo.

Lo que NO es
------------
No es debilitar el control. En CI el árbol es un `checkout` limpio: no hay ficheros ignorados, el
conjunto excluido es **vacío** y el control mide exactamente lo que medía. Estas pruebas fijan las
dos mitades — que lo ignorado se excluya, y que lo NO ignorado siga delatándose — porque sin la
segunda la exclusión sería una puerta trasera.
"""

from __future__ import annotations

import importlib.util
import subprocess
import sys
import unittest
from pathlib import Path

RAIZ = Path(__file__).resolve().parents[2]
GUION = RAIZ / "scripts" / "check_wiring.py"


def _cargar():
    """Por ruta y no con `import check_wiring`, siguiendo la convención de
    `tests/unit/test_check_mediciones.py`.

    Un `import` a secas exigiría `scripts/` en el `sys.path`, y entonces
    `scripts/check_stdlib_only.py` lee el nombre como una dependencia de terceros: lo marcó en
    cuanto se escribió esta prueba. El guion es local, pero el control no puede saberlo desde el
    nombre, y tiene razón en no suponerlo.
    """
    spec = importlib.util.spec_from_file_location("check_wiring_bajo_prueba", GUION)
    mod = importlib.util.module_from_spec(spec)
    sys.modules["check_wiring_bajo_prueba"] = mod
    spec.loader.exec_module(mod)
    return mod


check_wiring = _cargar()


def _hay_git() -> bool:
    """¿El árbol de esta copia es un repositorio git?

    No siempre lo es, y eso NO es un defecto: `core.engine.publicar` materializa el motor con
    `git archive`, así que la copia que se prueba a sí misma antes de gobernar a nadie **no
    tiene `.git`**. Lo descubrió el propio `engine publish`, que se negó a publicar porque dos
    de estas pruebas fallaban ahí — en CI pasaban, porque CI es un `checkout`.

    Donde no hay git, la propiedad no es falsa: es **no medible**. Se declara `NOT_RUN` con su
    motivo en vez de fallar, que es el mismo trato que reciben las pruebas que necesitan
    `HICON_BIN`. Y el arreglo de `check_wiring` sigue siendo correcto ahí: sin git el conjunto
    de ignorados es vacío y el control mide el árbol entero, que es lo que debe hacer.
    """
    try:
        r = subprocess.run(["git", "-C", str(RAIZ), "rev-parse", "--git-dir"],
                           capture_output=True)
        return r.returncode == 0
    except (OSError, subprocess.SubprocessError):
        return False


SIN_GIT = "no es un repositorio git (p. ej. la copia que `engine publish` extrae con git archive)"


class TestLoIgnoradoNoCuenta(unittest.TestCase):

    @unittest.skipUnless(_hay_git(), SIN_GIT)
    def test_el_conjunto_de_ignorados_se_mide_de_git(self):
        ign = check_wiring._ignorados_por_git()
        self.assertIsInstance(ign, set)
        # `artifacts/harness/` está en `.gitignore` de este repositorio; si alguien lo quitara,
        # esta prueba lo diría en vez de que el control empezara a dar rojos por evidencia local.
        r = subprocess.run(["git", "-C", str(RAIZ), "check-ignore", "-q", "artifacts/harness/x"],
                           capture_output=True)
        self.assertEqual(0, r.returncode,
                         "`artifacts/harness/` ya no está ignorado: la evidencia local se "
                         "publicaría y este control volvería a medirla")

    @unittest.skipUnless(_hay_git(), SIN_GIT)
    def test_un_modulo_huerfano_IGNORADO_no_se_reporta(self):
        """El caso exacto que rompía el pre-push."""
        rel = "artifacts/harness/_sonda_huerfana_de_prueba.py"
        f = RAIZ / rel
        f.parent.mkdir(parents=True, exist_ok=True)
        f.write_text("# nadie me importa, y git me ignora\n", encoding="utf-8")
        try:
            self.assertIn(rel, check_wiring._ignorados_por_git(),
                          "git no lo declara ignorado; la premisa de la prueba no se cumple")
            problemas = check_wiring.check_modules()
            self.assertFalse([p for p in problemas if rel in p],
                             f"se reportó un módulo ignorado: {problemas}")
        finally:
            f.unlink(missing_ok=True)

    def test_pero_uno_NO_ignorado_si_se_reporta(self):
        """La contraparte. Sin ella, la exclusión sería una puerta trasera.

        Se crea en `core/`, que no está ignorado, y se comprueba que el control lo delata.
        """
        rel = "core/_sonda_huerfana_de_prueba.py"
        f = RAIZ / rel
        f.write_text("# nadie me importa, y git NO me ignora\n", encoding="utf-8")
        try:
            self.assertNotIn(rel, check_wiring._ignorados_por_git())
            problemas = check_wiring.check_modules()
            self.assertTrue([p for p in problemas if rel in p],
                            "el control dejó pasar un módulo huérfano del producto")
        finally:
            f.unlink(missing_ok=True)

    def test_sin_git_no_se_excluye_nada(self):
        """Ante la duda, se comprueba más: si git no responde, el conjunto es vacío."""
        original = check_wiring.subprocess.run

        def falla(*a, **k):
            raise OSError("git no está")

        check_wiring.subprocess.run = falla
        try:
            self.assertEqual(set(), check_wiring._ignorados_por_git())
        finally:
            check_wiring.subprocess.run = original

    def test_y_el_arbol_de_hoy_esta_conectado(self):
        """La medición de verdad: con la exclusión puesta, el producto no tiene huérfanos."""
        self.assertEqual([], check_wiring.check_modules())


if __name__ == "__main__":
    unittest.main()
