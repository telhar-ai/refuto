# -*- coding: utf-8 -*-
"""El motor publicado: la frontera entre «lo que estoy escribiendo» y «lo que está juzgando».

Medido el 2026-09-28: `.harness/bin/guard` hacía `cd $HARNESS_HOME && exec python3 -m core.guard`
con `HARNESS_HOME` apuntando al **árbol de trabajo de refuto**, y **12 espacios** apuntaban al
mismo árbol. Editar un fichero del motor cambiaba, en ese instante y sin aviso, el guardián de
los doce. Estas pruebas fijan las tres reglas que lo cierran:

    1. no se publica un árbol sucio — lo publicado tiene que poder reconstruirse desde un commit
    2. no se activa un motor que no se prueba a sí mismo, y saltarse la prueba queda ESCRITO
    3. cambiar de motor es un acto explícito, no el efecto de guardar un fichero

El repositorio de prueba es de mentira y mínimo: lo que se mide es el comportamiento de
`core.engine`, no el de refuto. Un fixture que copiara el repo real haría la suite lenta y, peor,
ataría estas pruebas a que el repo real siga pasando su propia suite.
"""

from __future__ import annotations

import json
import shutil
import subprocess  # nosec B404
import tempfile
import unittest
from pathlib import Path

from core import engine
from core.model import BLOCKED, FAIL, PASS
from core.proc import TEXT_IO

#: Un `refuto.py` que pasa o falla su «suite» según exista un fichero. Es lo que permite medir
#: qué hace `publicar` cuando la copia NO se prueba, sin tener que romper el repo real.
FALSO_REFUTO = '''\
import sys
from pathlib import Path
if Path(__file__).parent.joinpath("ROMPER").is_file():
    print("  0/1 pruebas pasan"); sys.exit(1)
print("  1/1 pruebas pasan"); sys.exit(0)
'''


def _git(repo: Path, *args: str):
    return subprocess.run(["git", *args], cwd=str(repo), capture_output=True,   # nosec B603 B607
                          timeout=60, **TEXT_IO)


class _ConRepo(unittest.TestCase):
    """Un repositorio de mentira con la forma mínima de un motor, y una raíz de publicación."""

    def setUp(self):
        self.base = Path(tempfile.mkdtemp(prefix="engine-")).resolve()
        self.repo = self.base / "repo"
        (self.repo / "core").mkdir(parents=True)
        for f in ("guard.py", "policy.py", "proc.py"):
            (self.repo / "core" / f).write_text(f"# {f}\nVALOR = 1\n", encoding="utf-8")
        (self.repo / "refuto.py").write_text(FALSO_REFUTO, encoding="utf-8")
        _git(self.repo, "init", "-q")
        _git(self.repo, "config", "user.email", "prueba@example-org")
        _git(self.repo, "config", "user.name", "prueba")
        _git(self.repo, "add", "-A")
        _git(self.repo, "commit", "-q", "-m", "inicial")
        self.raiz = self.base / "engine"

    def tearDown(self):
        shutil.rmtree(self.base, ignore_errors=True)

    def publicar(self, **kw):
        kw.setdefault("verificar", False)
        return engine.publicar(self.repo, destino=self.raiz, **kw)

    def ensuciar(self, texto: str = "# sucio\n"):
        (self.repo / "core" / "policy.py").write_text(texto, encoding="utf-8")


# ═══════════════════════════════════════════════════════════════════════════════════════
class TestNoSePublicaLoQueNoSePuedeReconstruir(_ConRepo):

    def test_arbol_sucio_no_se_publica(self):
        self.ensuciar()
        r = self.publicar()
        self.assertEqual(FAIL, r["estado"])
        self.assertIn("sin commitear", r["motivo"])
        self.assertIn("core/policy.py", r["motivo"])

    def test_y_no_deja_nada_a_medias(self):
        """Un FAIL que hubiera copiado medio motor sería peor que el problema que evita."""
        self.ensuciar()
        self.publicar()
        self.assertFalse((self.raiz / "current").exists())
        self.assertEqual([], engine.publicados(self.raiz))

    def test_un_commit_explicito_si_se_publica_con_el_arbol_sucio(self):
        """La regla protege de publicar lo que no está en ningún commit, no de publicar commits
        antiguos: pedir un SHA concreto es decir exactamente qué se quiere."""
        sha = _git(self.repo, "rev-parse", "HEAD").stdout.strip()
        self.ensuciar()
        r = self.publicar(commit=sha)
        self.assertEqual(PASS, r["estado"], r["motivo"])

    def test_la_copia_sale_del_commit_y_no_del_arbol(self):
        """La propiedad de fondo. Si la copia saliera del directorio, publicar sería exactamente
        lo que esta separación existe para impedir."""
        sha = _git(self.repo, "rev-parse", "HEAD").stdout.strip()
        self.ensuciar("# ESTO NO DEBE LLEGAR\n")
        r = self.publicar(commit=sha)
        copia = Path(r["path"]) / "core" / "policy.py"
        self.assertNotIn("NO DEBE LLEGAR", copia.read_text(encoding="utf-8"))
        self.assertIn("VALOR = 1", copia.read_text(encoding="utf-8"))

    def test_sin_repositorio_es_blocked_no_fail(self):
        """Falta una precondición externa; no hay ningún hecho en contra del motor."""
        suelto = self.base / "no-es-repo"
        suelto.mkdir()
        r = engine.publicar(suelto, destino=self.raiz, verificar=False)
        self.assertEqual(BLOCKED, r["estado"])

    def test_un_commit_que_no_trae_motor_no_es_un_motor(self):
        otro = self.base / "vacio"
        otro.mkdir()
        (otro / "LEEME.md").write_text("nada\n", encoding="utf-8")
        _git(otro, "init", "-q")
        _git(otro, "config", "user.email", "prueba@example-org")
        _git(otro, "config", "user.name", "prueba")
        _git(otro, "add", "-A")
        _git(otro, "commit", "-q", "-m", "vacío")
        r = engine.publicar(otro, destino=self.raiz, verificar=False)
        self.assertEqual(FAIL, r["estado"])
        self.assertIn("no es un motor", r["motivo"])


# ═══════════════════════════════════════════════════════════════════════════════════════
class TestSeAtestiguaLoQueSeProbo(_ConRepo):

    def test_la_copia_se_prueba_a_si_misma(self):
        r = self.publicar(verificar=True)
        self.assertEqual(PASS, r["estado"], r["motivo"])
        self.assertTrue(r["selftest"]["ok"])
        doc = json.loads((Path(r["path"]) / engine.MANIFIESTO).read_text(encoding="utf-8"))
        self.assertTrue(doc["verified"])
        self.assertEqual(r["commit"], doc["commit"])

    def test_una_copia_que_no_pasa_su_suite_no_se_activa(self):
        (self.repo / "ROMPER").write_text("x", encoding="utf-8")
        _git(self.repo, "add", "-A")
        _git(self.repo, "commit", "-q", "-m", "roto")
        r = self.publicar(verificar=True)
        self.assertEqual(FAIL, r["estado"])
        self.assertIn("no se prueba a sí misma", r["motivo"])
        self.assertIsNone(engine.vigente(self.raiz), "no puede quedar vigente un motor roto")

    def test_saltarse_la_prueba_se_puede_y_queda_escrito(self):
        """Publicar sin probar es una decisión legítima; esconderla no. `verified: false` es la
        diferencia entre una decisión declarada y un vacío que se lee como aprobado."""
        r = self.publicar(verificar=False)
        self.assertEqual(PASS, r["estado"], r["motivo"])
        doc = json.loads((Path(r["path"]) / engine.MANIFIESTO).read_text(encoding="utf-8"))
        self.assertFalse(doc["verified"])
        self.assertFalse(doc["selftest"]["ejecutada"])

    def test_el_manifiesto_dice_de_donde_salio(self):
        r = self.publicar()
        doc = json.loads((Path(r["path"]) / engine.MANIFIESTO).read_text(encoding="utf-8"))
        for campo in ("commit", "engine_digest", "published_at", "published_by", "source"):
            self.assertTrue(doc.get(campo) is not None, campo)
        self.assertEqual(64, len(doc["engine_digest"]))


# ═══════════════════════════════════════════════════════════════════════════════════════
class TestCambiarDeMotorEsUnActo(_ConRepo):

    def test_sin_publicar_nada_no_hay_motor_vigente(self):
        self.assertIsNone(engine.vigente(self.raiz))

    def test_publicar_activa_y_vigente_lo_dice(self):
        r = self.publicar()
        v = engine.vigente(self.raiz)
        self.assertIsNotNone(v)
        self.assertEqual(r["commit"], v["commit"])
        self.assertTrue(Path(v["home"], "core", "guard.py").is_file())

    def test_publicar_sin_activar_no_mueve_a_nadie(self):
        r = self.publicar(activar=False)
        self.assertEqual(PASS, r["estado"], r["motivo"])
        self.assertIsNone(engine.vigente(self.raiz), "publicar no puede mover el motor vigente")

    def test_usar_un_motor_que_no_existe_es_blocked(self):
        self.assertEqual(BLOCKED, engine.usar("deadbeef0000", destino=self.raiz)["estado"])

    def test_se_puede_volver_al_motor_anterior(self):
        """La propiedad que hace reversible todo esto: el motor viejo sigue en disco."""
        primero = self.publicar()
        (self.repo / "core" / "policy.py").write_text("# v2\nVALOR = 2\n", encoding="utf-8")
        _git(self.repo, "add", "-A")
        _git(self.repo, "commit", "-q", "-m", "v2")
        segundo = self.publicar()
        self.assertNotEqual(primero["commit"], segundo["commit"])
        self.assertEqual(segundo["commit"], engine.vigente(self.raiz)["commit"])
        self.assertEqual(PASS, engine.usar(primero["commit"][:12], destino=self.raiz)["estado"])
        self.assertEqual(primero["commit"], engine.vigente(self.raiz)["commit"])
        self.assertEqual(2, len(engine.publicados(self.raiz)))

    def test_republicar_el_mismo_commit_es_idempotente(self):
        a = self.publicar()
        b = self.publicar()
        self.assertEqual(a["commit"], b["commit"])
        self.assertEqual(a["digest"], b["digest"])
        self.assertEqual(1, len(engine.publicados(self.raiz)))


# ═══════════════════════════════════════════════════════════════════════════════════════
class TestADondeApuntaUnLanzador(_ConRepo):

    def test_sin_motor_publicado_apunta_al_arbol_y_lo_dice(self):
        d = engine.home_para_lanzadores(self.repo, self.raiz)
        self.assertFalse(d["publicado"])
        self.assertEqual(self.repo.resolve(), d["home"])
        self.assertIn("ÁRBOL DE TRABAJO", d["motivo"])
        self.assertIn("en caliente", d["motivo"],
                      "el aviso tiene que decir la consecuencia, no sólo el hecho")

    def test_con_motor_publicado_apunta_a_el_y_sin_aviso(self):
        r = self.publicar()
        d = engine.home_para_lanzadores(self.repo, self.raiz)
        self.assertTrue(d["publicado"])
        self.assertEqual(r["commit"], d["commit"])
        self.assertEqual("", d["motivo"])
        self.assertNotEqual(self.repo.resolve(), Path(d["home"]).resolve())

    def test_editar_el_arbol_ya_no_mueve_el_motor_vigente(self):
        """La propiedad entera, en una prueba: con motor publicado, tocar el árbol no cambia lo
        que ejecutan los lanzadores. Es justo lo que NO se cumplía el 2026-09-28."""
        self.publicar()
        antes = Path(engine.vigente(self.raiz)["home"], "core", "policy.py").read_text(encoding="utf-8")
        self.ensuciar("# el desarrollo sigue\nVALOR = 99\n")
        despues = Path(engine.vigente(self.raiz)["home"], "core", "policy.py").read_text(encoding="utf-8")
        self.assertEqual(antes, despues)
        self.assertNotIn("VALOR = 99", despues)


# ═══════════════════════════════════════════════════════════════════════════════════════
class TestElLanzadorApuntaAlEnlaceYNoAlCommit(_ConRepo):
    """Lo que hace reversible todo esto, y lo que estuvo roto hasta que se midió.

    `launcher.install` normalizaba con `resolve()`, que **sigue** los enlaces simbólicos: un
    `HARNESS_HOME` de `<raíz>/current` quedaba grabado como `<raíz>/<commit>`. Con eso,
    `refuto engine use` —cuyo trabajo es mover todos los espacios a la vez— no movía ninguno,
    porque cada lanzador llevaba el commit incrustado. El docstring afirmaba la propiedad y el
    código no la cumplía; se vio al cablear el primer espacio contra un motor publicado.
    """

    def setUp(self):
        super().setUp()
        self.ws = self.base / "espacio"
        (self.ws / ".harness").mkdir(parents=True)

    def _guard(self) -> str:
        from core import launcher
        return (self.ws / launcher.BIN / launcher.NAME).read_text(encoding="utf-8")

    def test_el_lanzador_conserva_el_enlace(self):
        from core import launcher
        r = self.publicar()
        launcher.install(self.ws, harness_home=engine.ruta_vigente(self.raiz), runtime="claude")
        texto = self._guard()
        self.assertIn(f'HARNESS_HOME="{engine.ruta_vigente(self.raiz)}"', texto)
        self.assertNotIn(r["commit"][:12], texto,
                         "el commit incrustado haría que `engine use` no moviera este espacio")

    def test_cambiar_el_motor_vigente_no_exige_recablear(self):
        """La propiedad operativa: si un motor sale malo, un comando devuelve a TODOS los
        espacios al anterior. Si hubiera que re-cablear uno a uno, no sería una reversión."""
        from core import launcher
        primero = self.publicar()
        launcher.install(self.ws, harness_home=engine.ruta_vigente(self.raiz), runtime="claude")
        antes = self._guard()

        (self.repo / "core" / "policy.py").write_text("# v2\nVALOR = 2\n", encoding="utf-8")
        _git(self.repo, "add", "-A")
        _git(self.repo, "commit", "-q", "-m", "v2")
        segundo = self.publicar()

        self.assertEqual(antes, self._guard(), "el lanzador no se toca al publicar")
        # Lo que el lanzador ejecutaría HOY sale de seguir el enlace, no del texto del guion.
        vigente = Path(engine.ruta_vigente(self.raiz)).resolve()
        self.assertEqual((self.raiz / segundo["commit"][:12]).resolve(), vigente)
        engine.usar(primero["commit"][:12], destino=self.raiz)
        self.assertEqual((self.raiz / primero["commit"][:12]).resolve(),
                         Path(engine.ruta_vigente(self.raiz)).resolve())
        self.assertEqual(antes, self._guard(), "volver atrás tampoco toca el lanzador")

    def test_installed_json_guarda_las_dos_rutas(self):
        """La que el lanzador usa y a dónde apuntaba al instalar. La segunda puede haber
        cambiado después, y saber cuál era es lo que permite explicar un veredicto viejo."""
        from core import launcher
        r = self.publicar()
        launcher.install(self.ws, harness_home=engine.ruta_vigente(self.raiz), runtime="claude")
        doc = json.loads((self.ws / launcher.BIN / "installed.json").read_text(encoding="utf-8"))
        self.assertEqual(str(engine.ruta_vigente(self.raiz)), doc["harness_home"])
        self.assertIn(r["commit"][:12], doc["harness_home_resuelto"])


if __name__ == "__main__":
    unittest.main()
