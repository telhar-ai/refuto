# -*- coding: utf-8 -*-
"""Portabilidad: lo que en POSIX no puede fallar, y en Windows sí.

Las cuatro llamadas que rompieron refuto en Windows —`os.geteuid`, `os.killpg`,
`signal.SIGKILL` y la decodificación por omisión de `subprocess`— comparten una propiedad
incómoda: **en la máquina donde se escribió el código no podían fallar**, así que nadie las
envolvió. Estas pruebas no comprueban Windows: comprueban que refuto ya no pregunta por
esas primitivas sin red, y corren igual en los tres sistemas.
"""

from __future__ import annotations

import ast
import os
import shutil
import subprocess
import sys
import unittest
from pathlib import Path

from core import launcher
from core.proc import (
    POSIX, TEXT_IO, euid, force_utf8_io, interpreter, owns_by_uid, spawn_kwargs, terminate,
)

ROOT = Path(__file__).resolve().parents[2]

#: Dónde se permite nombrar las primitivas POSIX. `core/proc.py` es el único sitio que puede,
#: porque es justo el módulo cuyo trabajo es decidir qué hacer cuando no existen.
EXENTOS = {"core/proc.py", "tests/unit/test_portabilidad.py"}

#: La deuda de `gates/**` se cerró en 0.3.0: las llamadas pasaron por `core/proc.py` y el parche
#: que las proponía se retiró. `PENDIENTE` queda vacío a propósito — si vuelve a haber deuda, se
#: declara aquí y la prueba de abajo exige de nuevo un parche que la describa.
PENDIENTE = ()
PARCHE = "docs/remediation/gates-portabilidad.patch"

#: Lo que no puede aparecer suelto por el árbol.
PROHIBIDO = ("os.geteuid(", "os.getpgid(", "os.killpg(", "signal.SIGKILL", "text=True",
             "start_new_session=True")


def fuentes():
    for path in sorted(ROOT.rglob("*.py")):
        rel = path.relative_to(ROOT).as_posix()
        if rel.startswith(".git/") or "__pycache__" in rel:
            continue
        yield rel, path.read_text(encoding="utf-8")


class TestNingunaLlamadaPosixSuelta(unittest.TestCase):
    def test_las_primitivas_posix_solo_se_nombran_donde_se_decide_que_hacer_sin_ellas(self):
        sueltas = []
        for rel, texto in fuentes():
            if rel in EXENTOS or rel.startswith(PENDIENTE):
                continue
            for token in PROHIBIDO:
                for n, linea in enumerate(texto.splitlines(), 1):
                    # Se ignoran las menciones en prosa: lo que importa es la llamada.
                    desnuda = linea.strip()
                    if token in linea and not desnuda.startswith(("#", "#:", '"""', "'''")):
                        sueltas.append(f"{rel}:{n} → {token}")
        self.assertEqual([], sueltas,
                         "una llamada POSIX sin red fuera de core/proc.py:\n  " +
                         "\n  ".join(sueltas))


    def test_lo_que_falta_en_el_juez_esta_propuesto_por_escrito(self):
        """`gates/**` no lo puede tocar un agente. Lo que no se puede aplicar, se propone.

        Sin esta prueba, excluir `gates/` del barrido de arriba sería taparlo. Con ella, el
        único modo de que la suite quede verde es que el parche exista y siga cubriendo
        exactamente los archivos que le faltan.
        """
        pendientes = sorted({rel for rel, texto in fuentes()
                             if rel.startswith(PENDIENTE)
                             and any(t in texto for t in PROHIBIDO)})
        if not pendientes:
            return                       # alguien ya aplicó el parche: no hay deuda que probar
        parche = ROOT / PARCHE
        self.assertTrue(parche.is_file(),
                        f"{len(pendientes)} archivos del juez siguen con llamadas POSIX y no "
                        f"hay parche propuesto en {PARCHE}")
        texto = parche.read_text(encoding="utf-8")
        for rel in pendientes:
            self.assertIn(rel, texto, f"{rel} tiene deuda y el parche no lo menciona")


class TestProc(unittest.TestCase):
    def test_euid_devuelve_None_donde_el_concepto_no_existe(self):
        # No se afirma un valor: se afirma que NO inventa un 0, que significaría «soy root».
        valor = euid()
        if hasattr(os, "geteuid"):
            self.assertEqual(os.geteuid(), valor)
        else:
            self.assertIsNone(valor, "sin `geteuid`, la respuesta honesta es None, no 0")

    def test_owns_by_uid_es_falso_donde_no_hay_chown(self):
        self.assertEqual(POSIX and hasattr(os, "chown"), owns_by_uid())

    def test_spawn_kwargs_aisla_el_grupo_en_todo_sistema(self):
        kw = spawn_kwargs()
        self.assertTrue(kw, "sin aislar el grupo, el hijo de Node sobrevive al padre")
        clave = "start_new_session" if POSIX else "creationflags"
        self.assertIn(clave, kw)

    def test_text_io_fija_la_codificacion_en_vez_de_heredarla(self):
        self.assertEqual("utf-8", TEXT_IO["encoding"])
        self.assertTrue(TEXT_IO["errors"], "sin política de errores, una tilde ajena aborta")

    def test_se_lee_utf8_aunque_la_consola_no_lo_sea(self):
        # El caso real: el guardián escribe «AUDITORÍA» y quien lo lee decodifica cp1252.
        argv = [sys.executable, "-c", "print('AUDITORÍA — ⚠')"]
        proc = subprocess.run(argv, capture_output=True, timeout=30, **TEXT_IO,
                              env={**os.environ, "PYTHONIOENCODING": "utf-8"})
        self.assertIn("AUDITOR", proc.stdout)

    def test_terminate_no_explota_con_un_proceso_ya_muerto(self):
        proc = subprocess.Popen([sys.executable, "-c", "pass"], **spawn_kwargs())
        proc.wait(timeout=30)
        terminate(proc)                     # no debe lanzar: el grupo ya no existe
        self.assertIsNotNone(proc.poll())

    def test_terminate_mata_al_que_sigue_vivo(self):
        proc = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(60)"],
                                **spawn_kwargs())
        terminate(proc)
        self.assertIsNotNone(proc.poll(), "el proceso debía estar muerto tras terminate()")

    def test_force_utf8_io_es_idempotente_y_no_se_cae(self):
        force_utf8_io()
        force_utf8_io()


class TestLoGeneradoSeEscribeEnLF(unittest.TestCase):
    """Este proyecto compara por huella. Un CRLF de más convierte «idéntico» en «deriva».

    El barrido de arriba mira primitivas POSIX; éste mira la otra mitad del mismo problema, y
    existe porque una escritura se escapó del barrido inicial y la encontró un `compile` real
    sobre un repositorio de verdad.
    """

    #: Sólo el código que refuto ejecuta y con el que GENERA artefactos. Las fixtures que
    #: declaran una huella ya la fijan por su cuenta, y una comprobación que grita sobre cada
    #: escritura de prueba se aprende a ignorar.
    ALCANCE = ("core/", "adapters/", "refuto.py", "scripts/")

    def test_ninguna_escritura_generada_hereda_el_salto_del_sistema(self):
        sueltas = []
        for rel, texto in fuentes():
            if rel in EXENTOS or rel.startswith(PENDIENTE):
                continue
            if not rel.startswith(self.ALCANCE):
                continue
            for n, linea in enumerate(texto.splitlines(), 1):
                if ".write_text(" not in linea or linea.strip().startswith("#"):
                    continue
                # Se mira el bloque, no la línea: la llamada puede seguir en la siguiente.
                bloque = "\n".join(texto.splitlines()[n - 1:n + 5])
                if "newline=" not in bloque:
                    sueltas.append(f"{rel}:{n}")
        self.assertEqual([], sueltas,
                         "write_text sin `newline=` explícito: en Windows escribe CRLF y la "
                         "huella del mismo documento deja de coincidir:\n  " +
                         "\n  ".join(sueltas))


class TestGuardianSinPrimitivasPosix(unittest.TestCase):
    """El fallo que dejó el espacio inoperante: euid rompía el registro, y el registro roto
    convertía TODA decisión en un bloqueo — incluidas las que debían permitirse."""

    def setUp(self):
        from tests.fixtures import Workspace
        self.ws = Workspace()
        self.addCleanup(shutil.rmtree, self.ws.root, ignore_errors=True)

    def _guard(self, payload: str) -> subprocess.CompletedProcess:
        return subprocess.run(
            [sys.executable, "-m", "core.guard", "--runtime", "kiro", "--stdin",
             "--workspace", str(self.ws.root)],
            input=payload, capture_output=True, timeout=60, cwd=str(ROOT), **TEXT_IO)

    def test_una_escritura_legitima_se_permite_y_el_diario_se_escribe(self):
        proc = self._guard('{"tool_name":"fs_write","path":"src/app.py","content":"x = 1"}')
        self.assertEqual(0, proc.returncode,
                         f"permitir no puede salir distinto de 0. stderr: {proc.stderr}")
        self.assertNotIn("AUDITOR", proc.stderr, "el diario debe haberse escrito de verdad")
        ledger = self.ws.root / ".harness" / "evidence" / "ledger.jsonl"
        self.assertTrue(ledger.is_file(), "sin diario no hay auditoría, y nadie lo echa en falta")

    def test_lo_protegido_sigue_bloqueado(self):
        proc = self._guard('{"tool_name":"fs_write","path":".harness/policy.json","content":"x"}')
        self.assertEqual(2, proc.returncode)

    def test_la_respuesta_estructurada_no_revienta_por_un_caracter(self):
        # `⚠` y `—` no existen en cp1252: imprimirlos sin fijar UTF-8 mataba al gancho ANTES
        # de emitir el JSON, y un gancho que no emite nada no comunica «permitido».
        import json
        proc = self._guard_claude('.harness/policy.json')
        self.assertEqual(0, proc.returncode, f"stderr: {proc.stderr}")
        doc = json.loads(proc.stdout)
        self.assertEqual("deny",
                         doc["hookSpecificOutput"]["permissionDecision"])

    def _guard_claude(self, path: str) -> subprocess.CompletedProcess:
        import json
        payload = json.dumps({"tool_name": "Write",
                              "tool_input": {"file_path": path, "content": "x"}})
        return subprocess.run(
            [sys.executable, "-m", "core.guard", "--runtime", "claude", "--stdin",
             "--workspace", str(self.ws.root)],
            input=payload, capture_output=True, timeout=60, cwd=str(ROOT), **TEXT_IO)


class TestLanzador(unittest.TestCase):
    def setUp(self):
        from tests.fixtures import Workspace
        self.ws = Workspace()
        self.addCleanup(shutil.rmtree, self.ws.root, ignore_errors=True)
        launcher.install(self.ws.root, harness_home=ROOT, runtime="claude")

    def test_se_instalan_los_dos_lanzadores_en_todo_sistema(self):
        for nombre in (launcher.NAME, launcher.NAME_CMD):
            self.assertTrue((self.ws.root / launcher.BIN / nombre).is_file(),
                            f"falta {nombre}: en Windows conviven cmd.exe y un shell POSIX")

    def test_el_cmd_lleva_finales_de_linea_de_windows(self):
        crudo = (self.ws.root / launcher.BIN / launcher.NAME_CMD).read_bytes()
        self.assertIn(b"\r\n", crudo, "un .cmd con LF se ejecuta mal y el síntoma no lo dice")

    def test_el_cmd_no_lleva_tildes(self):
        # Se lee con la página de códigos de la consola: una tilde vuelve ilegible justo el
        # mensaje que alguien lee cuando el guardián bloquea.
        texto = (self.ws.root / launcher.BIN / launcher.NAME_CMD).read_text(encoding="utf-8")
        self.assertTrue(texto.isascii(), "el .cmd debe ser ASCII puro")

    def test_el_cmd_bloquea_si_refuto_se_movio(self):
        p = self.ws.root / launcher.BIN / launcher.NAME_CMD
        p.write_text(p.read_text(encoding="utf-8").replace(str(ROOT), str(ROOT / "no-existe")),
                     encoding="utf-8", newline="\r\n")
        if os.name != "nt":
            self.skipTest("cmd.exe sólo existe en Windows; el contenido ya se comprobó")
        proc = subprocess.run([str(p)], input="{}", capture_output=True, timeout=60, **TEXT_IO)
        self.assertEqual(2, proc.returncode, "no encontrarse no puede ser aprobar")

    def test_el_gancho_usa_la_sintaxis_que_este_sistema_sabe_ejecutar(self):
        cmd = launcher.hook_command(self.ws.root, runtime="claude")
        if os.name == "nt":
            self.assertNotIn("HARNESS_GUARD_RUNTIME=", cmd,
                             "`VAR=x orden` es sintaxis POSIX: cmd.exe no la ejecuta")
            self.assertIn(launcher.NAME_CMD, cmd)
        else:
            self.assertIn("HARNESS_GUARD_RUNTIME=claude", cmd)


class TestElComandoDelRepositorio(unittest.TestCase):
    """`bin/refuto` prometía ser un comando y llegó al árbol sin el bit de ejecución.

    Medido al integrar la rama sobre 0.2.2: `git ls-tree` daba `100644`, así que
    `./bin/refuto verify` respondía `permission denied` y sólo funcionaba escribiendo
    `sh bin/refuto`, que es exactamente la traducción a mano que este lanzador existe para
    ahorrar. El contenido estaba bien; el modo no.
    """

    def test_el_lanzador_de_sh_se_puede_ejecutar_por_si_mismo(self):
        p = ROOT / "bin" / "refuto"
        self.assertTrue(p.is_file(), "falta bin/refuto")
        if os.name == "nt":
            self.skipTest("Windows no tiene bit de ejecución; allí manda bin/refuto.cmd")
        self.assertTrue(os.access(p, os.X_OK),
                        "sin `chmod +x`, `refuto` sigue sin ser un comando: "
                        "`./bin/refuto` responde «permission denied»")

    def test_el_lanzador_arranca_el_cli_y_propaga_el_codigo_de_salida(self):
        orden = [str(ROOT / "bin" / "refuto")] if os.name != "nt" else \
            [str(ROOT / "bin" / "refuto.cmd")]
        proc = subprocess.run(orden + ["--help"], capture_output=True, timeout=120, **TEXT_IO)
        self.assertEqual(0, proc.returncode, proc.stderr)
        self.assertIn("refuto", proc.stdout.lower())


class TestElInformeDePropiedadNoMienteDondeNoPuedeMirar(unittest.TestCase):
    def setUp(self):
        from tests.fixtures import Workspace
        self.ws = Workspace()
        self.addCleanup(shutil.rmtree, self.ws.root, ignore_errors=True)

    def test_sin_uid_se_declara_no_comprobado_en_vez_de_limpio(self):
        launcher.install(self.ws.root, harness_home=ROOT, runtime="claude")
        informe = launcher.ownership_report(self.ws.root)
        if owns_by_uid():
            self.assertTrue(informe["checked"])
        else:
            self.assertFalse(informe["checked"],
                             "sin uid no hay nada que comparar: decir «limpio» es afirmar "
                             "haber comprobado lo que no se comprobó")
            self.assertIn("uid", informe["reason"])


class TestElInformeNoPrometeLoQueNoExiste(unittest.TestCase):
    """El informe de sesión enumera comandos y afirma que funcionan. Que sea verdad."""

    def test_el_interprete_que_se_promete_resuelve_de_verdad(self):
        import shutil
        elegido = interpreter()
        if elegido.startswith('"'):
            ruta = Path(elegido.strip('"'))
            self.assertTrue(ruta.is_file(), "se prometió una ruta de intérprete que no existe")
            return
        self.assertTrue(shutil.which(elegido),
                        f"el informe prometería «{elegido}», que no resuelve en esta máquina. "
                        f"Un comando inexistente es peor que ninguno: el agente lo intenta.")

    def test_los_comandos_del_informe_arrancan(self):
        from core.session import resources
        from tests.fixtures import Workspace
        ws = Workspace()
        self.addCleanup(shutil.rmtree, ws.root, ignore_errors=True)
        comandos = [c for c, _ in resources(ws.root)["comandos"]]
        self.assertTrue(comandos, "el informe no prometió ningún comando")
        for cmd in comandos:
            argv = ([cmd.split(" ", 1)[0].strip('"')] +
                    [a for a in cmd.split(" ")[1:] if a] + ["--help"])
            proc = subprocess.run(argv, capture_output=True, timeout=60, **TEXT_IO)
            self.assertEqual(0, proc.returncode,
                             f"«{cmd}» no arranca: {proc.stderr[:200]}")


class TestElComandoQueLaDocumentacionPromete(unittest.TestCase):
    """`refuto verify` se escribe así en toda la documentación. Que exista de verdad.

    Sin esto, la primera orden del manual responde «The term 'refuto' is not recognized» en
    Windows y «command not found» en POSIX. Es la misma regla que el informe de sesión: un
    comando prometido y ausente es peor que no prometerlo.
    """

    def test_hay_lanzador_para_los_dos_vocabularios(self):
        for nombre in ("refuto", "refuto.cmd"):
            self.assertTrue((ROOT / "bin" / nombre).is_file(), f"falta bin/{nombre}")

    def test_el_cmd_lleva_CRLF_y_es_ascii(self):
        crudo = (ROOT / "bin" / "refuto.cmd").read_bytes()
        self.assertIn(b"\r\n", crudo, "un .cmd con LF se ejecuta mal en cmd.exe")
        self.assertTrue(crudo.decode("utf-8").isascii(),
                        "se lee con la página de códigos de la consola: ASCII puro")

    def test_el_lanzador_nativo_ejecuta_el_CLI_desde_otro_directorio(self):
        # Se invoca DESDE el espacio gobernado, que está en otro sitio: el lanzador tiene que
        # resolverse por su propia ubicación y no por el directorio actual.
        from tests.fixtures import Workspace
        ws = Workspace()
        self.addCleanup(shutil.rmtree, ws.root, ignore_errors=True)
        lanzador = ROOT / "bin" / ("refuto.cmd" if os.name == "nt" else "refuto")
        argv = [str(lanzador)] if os.name == "nt" else ["sh", str(lanzador)]
        proc = subprocess.run(argv + ["--help"], cwd=str(ws.root),
                              capture_output=True, timeout=120, **TEXT_IO)
        self.assertEqual(0, proc.returncode, proc.stderr[:300])
        self.assertIn("refuto", proc.stdout)

    def test_un_lanzador_sin_su_refuto_al_lado_falla_y_lo_dice(self):
        from tests.fixtures import Workspace
        ws = Workspace()
        self.addCleanup(shutil.rmtree, ws.root, ignore_errors=True)
        nombre = "refuto.cmd" if os.name == "nt" else "refuto"
        suelto = ws.root / nombre
        salto = "\r\n" if nombre.endswith(".cmd") else "\n"
        suelto.write_text((ROOT / "bin" / nombre).read_text(encoding="utf-8"),
                          encoding="utf-8", newline=salto)
        argv = [str(suelto)] if os.name == "nt" else ["sh", str(suelto)]
        proc = subprocess.run(argv + ["verify"], capture_output=True, timeout=120, **TEXT_IO)
        self.assertEqual(2, proc.returncode)
        self.assertIn("no encuentro refuto.py", proc.stderr)


class TestNadaSeImportaEnCirculo(unittest.TestCase):
    def test_core_proc_no_depende_de_nadie_del_harness(self):
        arbol = ast.parse((ROOT / "core" / "proc.py").read_text(encoding="utf-8"))
        for node in ast.walk(arbol):
            if isinstance(node, ast.ImportFrom) and (node.module or "").startswith(("core", "adapters", "gates")):
                self.fail(f"core/proc.py importa {node.module}: es la capa de abajo, no puede "
                          f"depender de nadie o cualquier módulo que la use se cicla")


if __name__ == "__main__":
    unittest.main()
