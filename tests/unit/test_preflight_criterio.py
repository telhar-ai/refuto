# -*- coding: utf-8 -*-
"""El criterio del preflight: qué perdona y qué no, y qué mira el control de datos personales.

Por qué estas pruebas existen, y es una retractación
-----------------------------------------------------
Los dos mecanismos de abajo se añadieron el 2026-09-25 para cerrar dos defectos, y se
verificaron **a mano**. Es decir: el trabajo consistió en señalar controles que nadie vigilaba
y se entregó añadiendo dos controles que nadie vigilaba. `scripts/check_mediciones.py` vigila
las cifras del README y no tenía quien lo vigilara a él; `DEUDA_DECLARADA` decide si un cambio
sale y se probó con una corrida en la máquina de quien lo escribió.

Lo que se fija aquí son los BORDES, que son los que no aparecen cuando uno quiere en una
corrida real: el ámbito vacío, la puerta nueva en rojo, la deuda ya saldada, el sobre ilegible.

Hermana de `test_ci_criterio.py`, que fija el mismo principio un escalón más arriba: «lo único
bloqueado es lo declarado de antemano, con su motivo», y que eso no degenere en forzar verde.
"""

from __future__ import annotations

import importlib.util
import shutil
import subprocess  # nosec B404 — enumerar el árbol rastreado con git ES la medición
import sys
import tempfile
import unittest
from pathlib import Path

from core.proc import TEXT_IO

RAIZ = Path(__file__).resolve().parents[2]
GUION = RAIZ / "scripts" / "preflight.py"


def _cargar():
    spec = importlib.util.spec_from_file_location("preflight", GUION)
    mod = importlib.util.module_from_spec(spec)
    sys.modules["preflight"] = mod
    spec.loader.exec_module(mod)
    return mod


PF = _cargar()


def _puertas(*pares) -> list:
    return [{"id": i, "status": s} for i, s in pares]


# ── el criterio de la deuda ──────────────────────────────────────────────────────────
class TestLaDeudaDeclaradaNoSeConvierteEnForzarVerde(unittest.TestCase):
    """La tercera salida de `test_ci_criterio.py`, aplicada al preflight: DECLARAR el bloqueo.

    Degenera en la primera —forzar verde— en cuanto la tabla perdona algo que no nombra.
    """

    def test_una_puerta_nueva_en_rojo_retiene_el_empujon(self):
        for estado in ("FAIL", "BLOCKED", "NOT_EXECUTABLE", "INCONCLUSIVE"):
            with self.subTest(estado=estado):
                codigo, salida = PF.clasificar_puertas(
                    _puertas(("G-SECURITY", "FAIL"), ("G-INVENTADA", estado)),
                    deuda={"G-SECURITY": "deuda de ejemplo"})
                self.assertEqual(1, codigo, "una puerta que nadie declaró salió en rojo y el "
                                            "preflight dejó pasar el cambio")
                self.assertIn("G-INVENTADA", salida)

    def test_lo_declarado_se_perdona_y_se_nombra(self):
        codigo, salida = PF.clasificar_puertas(
            _puertas(("G-SECURITY", "FAIL"), ("G-POLICY", "PASS")),
            deuda={"G-SECURITY": "deuda de ejemplo"})
        self.assertEqual(0, codigo)
        self.assertIn("G-SECURITY", salida, "perdonar sin decir QUÉ se perdona es forzar verde "
                                            "con otra sintaxis")

    def test_un_ambito_vacio_no_aprueba(self):
        codigo, salida = PF.clasificar_puertas([], deuda={"G-SECURITY": "x"})
        self.assertEqual(2, codigo, "cero puertas ejecutadas no es un aprobado: es que no se "
                                    "pudo comprobar")
        self.assertIn("ámbito vacío", salida)

    def test_not_applicable_no_cuenta_como_rojo(self):
        """`NOT_APPLICABLE` es «esta puerta no tiene sujeto aquí», y no deja tarea pendiente."""
        codigo, _ = PF.clasificar_puertas(
            _puertas(("G-MCP", "NOT_APPLICABLE"), ("G-POLICY", "PASS")), deuda={})
        self.assertEqual(0, codigo)

    def test_la_deuda_saldada_se_dice_en_vez_de_conservarse_en_silencio(self):
        """Una excepción que ya no describe nada es como envejecen los controles hasta ser
        adorno: se conserva el hueco y se pierde el motivo."""
        codigo, salida = PF.clasificar_puertas(
            _puertas(("G-POLICY", "PASS")),
            deuda={"G-SECURITY": "x", "G-PR": "y"})
        self.assertEqual(0, codigo, "que la deuda esté saldada no puede castigar a nadie")
        self.assertIn("saldada", salida)
        self.assertIn("G-SECURITY", salida)

    def test_toda_deuda_declarada_trae_su_motivo_escrito(self):
        """La misma regla que `Result` aplica a `NOT_APPLICABLE`: no se acepta sin `measure`."""
        for gate, motivo in PF.DEUDA_DECLARADA.items():
            with self.subTest(gate=gate):
                self.assertTrue(
                    motivo and len(motivo.strip()) > 30,
                    f"«{gate}» se perdona sin explicar por qué: una lista de excepciones sin "
                    f"motivos no se puede auditar ni vaciar")

    def test_la_deuda_solo_nombra_puertas_que_existen(self):
        """Una entrada que no corresponde a ninguna puerta perdona el vacío y nadie lo nota."""
        from gates.base import GATES

        ids = {g.id if hasattr(g, "id") else g for g in GATES} if GATES else set()
        if not ids:
            self.skipTest("no se pudo enumerar las puertas registradas")
        for gate in PF.DEUDA_DECLARADA:
            with self.subTest(gate=gate):
                self.assertIn(gate, ids, f"«{gate}» no es ninguna puerta registrada")

    def test_verify_es_bloqueante_y_no_informativo(self):
        """El defecto que motivó todo: un tier estático afirma para siempre lo medido una vez."""
        verify = next(c for c in PF._chequeos() if c.nombre == "verify")   # noqa: SLF001
        self.assertEqual(PF.BLOQUEA, verify.tier,
                         "`verify` volvió a ser informativo: entonces una puerta nueva en rojo "
                         "no retendría el empujón, que es el defecto de 2026-09-25")


# ── el control de datos personales ───────────────────────────────────────────────────
#: Los casos POSITIVOS se escriben partidos (`"…@" + "…"`) y la concatenación la hace Python al
#: cargar. No es manía: sin partirlos, **este fichero dispara el detector que prueba** y el
#: control se pone en rojo por su propia batería de pruebas.
#:
#: Hay dos salidas y ésta es la fuerte. La otra es declarar el fichero en
#: `_PERSONALES_PERMITIDOS`, cuyo comentario dice —con razón— que «cero excepciones es el estado
#: más fuerte que puede tener una lista de excepciones». Gastar la primera excepción de esa lista
#: en el fichero que comprueba el detector sería empezar a vaciarla por el sitio más tonto. Y hay
#: precedente en el repositorio: `tests/fixtures/__init__.py` parte sus literales por lo mismo, y
#: `.gitleaksignore` cuenta lo que cuesta no hacerlo — el árbol se limpia, el historial publicado
#: conserva la cadena para siempre.
def _partido(*trozos: str) -> str:
    """Une los trozos de un caso. El fichero guarda las partes; la prueba ve el todo."""
    return "".join(trozos)


#: `(qué es, texto, debe marcarlo)`. Los positivos son lo que `AGENTS.md` prohíbe literalmente;
#: los negativos son lo que la propia norma PRESCRIBE escribir, y marcarlos enseñaría a ignorar
#: el control — el modo de muerte que este repositorio documenta en `_partir` y en `dd:*`.
CASOS = (
    ("correo corporativo", _partido("escribir a alguien.apellido@", "unaempresa.com.mx"), True),
    ("ruta personal de macOS", _partido("vive en /Users/", "fulanito/repo/x.py"), True),
    ("dirección RFC 1918", _partido("el host 192.168.", "1.42 responde"), True),
    ("dirección 10.x", _partido("bind a 10.0.", "0.7"), True),
    ("enlace-local", _partido("metadatos en 169.254.", "169.254"), True),
    ("host interno", _partido("build.", "corp compiló el artefacto"), True),
    ("correo de ejemplo", "contacto: user@example.com", False),
    ("dominio de ejemplo", "admin@mi-empresa.example.org", False),
    ("noreply de agente", "Co-Authored-By: Claude <noreply@anthropic.com>", False),
    ("fichero .local", "no toque .claude/settings.local.json", False),
    ("otro fichero .local", "el patrón `**/.env.local` no aplica", False),
    ("dirección pública", "los resolutores 8.8.8.8 y 203.0.113.7", False),
    ("ruta genérica prescrita", "use /ruta/al/espacio o /home/persona/repo", False),
)


class TestDatosPersonalesCubreLaNormaQueCita(unittest.TestCase):
    """El control se llamaba `datos-personales` y miraba `/Users/…` y tres dominios de correo.

    `AGENTS.md` prohíbe además «correos, hosts internos, direcciones privadas». Un alcance
    declarado mayor que el medido no es un control incompleto: es un `PASS` que afirma más de lo
    que comprobó, y este repositorio existe para no emitir esos.
    """

    def _marca(self, texto: str) -> bool:
        return any(not PF._PERSONALES_INOCUOS.search(m.group(0))       # noqa: SLF001
                   for m in PF._PERSONALES.finditer(texto))            # noqa: SLF001

    def test_marca_lo_que_la_norma_prohibe_y_solo_eso(self):
        for nombre, texto, esperado in CASOS:
            with self.subTest(caso=nombre):
                self.assertEqual(esperado, self._marca(texto),
                                 f"«{texto}» → detectado={self._marca(texto)}, "
                                 f"esperado={esperado}")

    def test_el_arbol_rastreado_esta_limpio(self):
        """La medición de verdad. El repositorio es público desde el 2026-09-25.

        Sin repositorio no hay «árbol rastreado», así que la propiedad no es que no se cumpla:
        es que no aplica, y se declara `NOT_RUN` con su motivo. Distinguirlo importa desde el
        2026-09-28: un motor publicado es una copia de `git archive`, que no lleva `.git`, y
        ahí esta prueba salía en rojo diciendo «no se pudo comprobar» — con lo que una copia
        correcta quedaba sin poder activarse por una comprobación inaplicable. Donde sí hay
        repositorio —el repo, CI— sigue exigiendo exactamente lo mismo que antes.
        """
        if not (RAIZ / ".git").exists():
            self.skipTest("no hay repositorio git: sin árbol rastreado la propiedad no aplica "
                          "(NOT_RUN, no PASS)")
        codigo, salida = PF._datos_personales()                        # noqa: SLF001
        self.assertEqual(0, codigo, salida)

    def test_punto_local_se_queda_fuera_y_por_eso_no_marca_los_ficheros_del_repo(self):
        """Medido con `.local` dentro: 47 coincidencias y CERO hosts.

        Es la misma decisión que dejar `/home/…` fuera, y por el mismo motivo: `.local` es a la
        vez el TLD de mDNS y la convención para «variante local de este fichero». Si alguien lo
        reintroduce, ocho ficheros del repositorio se ponen en rojo por su nombre.
        """
        for nombre in ("settings.local.json", "hooks.local.json", ".env.local"):
            with self.subTest(fichero=nombre):
                self.assertFalse(self._marca(f"ruta: .claude/{nombre}"))


class TestElAlcanceDelControlEsLoQueSePublica(unittest.TestCase):
    """El control mide `_publicables()`, no el árbol rastreado — y la diferencia dejó pasar uno.

    Medido el 2026-09-29: el control dio `PASS` con «0 fichero(s) con coincidencia» mientras
    `tests/adversarial/test_elevacion.py` —un fichero nuevo, sin `git add`, camino del mismo
    commit— llevaba **16** veces el nombre de la cuenta de quien lo escribió. Dos huecos
    independientes lo permitieron, y hacían falta los dos arreglos:

      · el alcance era `git ls-files` a secas, que no ve lo no rastreado;
      · un nombre de cuenta no tiene FORMA, así que ninguna expresión regular puede describirlo.

    Avisar sólo de lo ya versionado es avisar cuando el dato está en el historial, que es cuando
    ya no sirve: un dato personal publicado no se retira con un commit.
    """

    def test_lo_no_rastreado_entra_en_el_alcance(self):
        if not (RAIZ / ".git").exists():
            self.skipTest("sin repositorio no hay «lo publicable» (NOT_RUN, no PASS)")
        codigo, rutas = PF._publicables()                              # noqa: SLF001
        self.assertEqual(0, codigo, rutas)
        rastreados = subprocess.run(                                   # nosec B603,B607
            ["git", "ls-files", "-z"], cwd=RAIZ, capture_output=True, timeout=60, **TEXT_IO)
        solo_rastreados = {r for r in (rastreados.stdout or "").split("\0") if r.strip()}
        self.assertGreaterEqual(set(rutas), solo_rastreados,
                                "lo publicable tiene que incluir, al menos, lo rastreado")

    def test_un_fichero_nuevo_con_la_cuenta_del_sistema_se_marca(self):
        """La falsación que importa: reintroducir el defecto y comprobar que AHORA se ve.

        Se escribe un fichero nuevo y no rastreado, que es exactamente la forma en la que el
        defecto original pasó, y con la cuenta LEÍDA del entorno — nunca escrita aquí.
        """
        if not (RAIZ / ".git").exists():
            self.skipTest("sin repositorio no hay «lo publicable» (NOT_RUN, no PASS)")
        cuentas = PF._identidad_local()                                # noqa: SLF001
        if not cuentas:
            self.skipTest("esta máquina no expone una cuenta personal en el entorno: la mitad "
                          "de «cuenta del sistema» no se puede medir aquí (NOT_RUN, no PASS)")
        señuelo = RAIZ / "tests" / "unit" / ".senuelo-datos-personales.txt"
        try:
            señuelo.write_text(f"ruta de trabajo de {cuentas[0]}\n", encoding="utf-8")
            codigo, salida = PF._datos_personales()                    # noqa: SLF001
            self.assertEqual(1, codigo, f"el señuelo no se detectó: {salida}")
            self.assertIn(señuelo.name, salida)
        finally:
            señuelo.unlink(missing_ok=True)
        # Y el árbol vuelve a estar limpio en cuanto el señuelo se va: si no, lo que detectó
        # fue otra cosa y la prueba no demuestra nada.
        self.assertEqual(0, PF._datos_personales()[0])                  # noqa: SLF001

    def test_la_cuenta_de_una_maquina_de_CI_no_se_confunde_con_una_persona(self):
        """`$USER` es `runner` en GitHub Actions y «runner» sale en 29 ficheros por motivos
        legítimos (`runs-on`, `tests/runner.py`). Un detector que marca lo normal enseña a
        ignorarlo, que es como mueren los controles."""
        for cuenta in ("runner", "root", "ubuntu", "codespace"):
            with self.subTest(cuenta=cuenta):
                self.assertIn(cuenta, PF._CUENTAS_NO_PERSONALES)       # noqa: SLF001

    def test_la_cuenta_no_esta_escrita_en_el_repositorio(self):
        """Escribir el nombre en el control para poder detectarlo sería filtrarlo.

        Es la lección de `_MARCAS_DE_CREDENCIAL`, aplicada aquí: la identidad se LEE del
        entorno en cada corrida y no se almacena en ninguna lista.
        """
        fuente = (RAIZ / "scripts" / "preflight.py").read_text(encoding="utf-8")
        for cuenta in PF._identidad_local():                           # noqa: SLF001
            with self.subTest(cuenta=cuenta):
                self.assertNotIn(cuenta, fuente)

    def test_el_control_declara_que_mitad_pudo_comprobar(self):
        """Un `PASS` que significa «también miré la cuenta» y uno que significa «no había cuenta
        que mirar» no son el mismo `PASS`. Confundirlos es el defecto que este control ya tuvo."""
        if not (RAIZ / ".git").exists():
            self.skipTest("sin repositorio no hay «lo publicable» (NOT_RUN, no PASS)")
        _, salida = PF._datos_personales()                             # noqa: SLF001
        self.assertIn("publicables", salida)
        self.assertRegex(salida, r"patrón \+ cuenta del sistema|patrón SOLO")


# ── el guion vigila, y aquí se vigila al guion ───────────────────────────────────────
class TestElPreflightSeDeclaraEntero(unittest.TestCase):
    def test_todo_control_tiene_nombre_unico(self):
        nombres = [c.nombre for c in PF._chequeos()]                   # noqa: SLF001
        self.assertEqual(sorted(set(nombres)), sorted(nombres),
                         "dos controles con el mismo nombre: `--solo` y `--excepto` elegirían "
                         "uno y el otro no se podría nombrar")

    def test_todo_control_declara_argv_o_funcion(self):
        for c in PF._chequeos():                                       # noqa: SLF001
            with self.subTest(control=c.nombre):
                self.assertTrue(c.argv or c.funcion is not None,
                                f"«{c.nombre}» no dice cómo se ejecuta")

    def test_los_guiones_que_invoca_existen(self):
        for c in PF._chequeos():                                       # noqa: SLF001
            for arg in c.argv or ():
                if arg.startswith("scripts/") or arg.endswith(".py"):
                    with self.subTest(control=c.nombre, arg=arg):
                        if "/" in arg:
                            self.assertTrue((RAIZ / arg).is_file(),
                                            f"«{c.nombre}» invoca «{arg}», que no existe")

    def test_todo_control_esta_rastreado_por_git(self):
        """Un control que no se publica no protege a quien clona el repositorio."""
        p = subprocess.run(["git", "ls-files"], cwd=RAIZ,   # nosec B603,B607
                           capture_output=True, timeout=60, **TEXT_IO)
        if p.returncode != 0:
            self.skipTest("no se pudo listar el árbol rastreado")
        rastreados = set((p.stdout or "").splitlines())
        for c in PF._chequeos():                                       # noqa: SLF001
            for arg in c.argv or ():
                if arg.startswith("scripts/"):
                    with self.subTest(control=c.nombre):
                        # `assertTrue` y no `assertIn`: el árbol rastreado son ~200 rutas, y
                        # volcarlas en el fallo esconde la frase que dice qué pasa.
                        self.assertTrue(
                            arg in rastreados,
                            f"«{c.nombre}» ejecuta «{arg}», que git no rastrea: quien clone el "
                            f"repositorio no lo tendrá, y el control no protege a nadie salvo "
                            f"a la máquina donde se escribió")


# ── el sujeto del control de secretos ────────────────────────────────────────────────
#: Un identificador con forma de credencial que `gitleaks` SÍ reconoce, construido en piezas.
#:
#: Dos restricciones lo obligan. La primera: la clave de ejemplo de AWS que usa el resto de la
#: suite está en la lista blanca de `gitleaks` y da «no leaks found», así que con ella esta
#: prueba sería vacua en el sentido peor: verde porque no mide. Medido el 2026-10-31.
#: La segunda: escribir la cadena entera y literal en un fichero del repositorio la convierte
#: en lo que esta prueba finge, y el propio guardián rechaza esa escritura, con razón — rechazó
#: una primera versión de este mismo comentario por citar la clave de ejemplo.
_PAT_SINTETICO = "glpat-" + "AbCdEfGhIjKlMnOpQrSt"


class TestElControlDeSecretosMideElRepositorioYNoElClon(unittest.TestCase):
    """`gitleaks detect --source <ruta>` recorre **todas** las refs del almacén de objetos.

    Un clon con un segundo remoto —otro proyecto, un fork, una base de la que se derivó— trae
    su historia entera a ese almacén. El control decía «un secreto en el árbol» y en realidad
    respondía «un secreto en algún objeto de este clon», que no es lo mismo y no es lo que se
    publica.

    Medido el 2026-10-31 en este repositorio: 20 commits alcanzables desde `HEAD`, 241 desde
    todas las refs, 189 de ellos de otro proyecto. El control retuvo el empujón por un secreto
    de ese otro proyecto — real, pero ajeno a lo que refuto publica, y por tanto imposible de
    arreglar desde aquí. Un control que no se puede cerrar se acaba saltando, y entonces no
    protege de nada.

    La prueba de abajo lleva su propio control positivo: sin acotar, el secreto ajeno SÍ
    aparece. Sin esa mitad, un `gitleaks` que dejara de detectar cualquier cosa haría pasar la
    otra mitad sin medir nada.
    """

    def _git(self, repo: Path, *args: str):
        return subprocess.run(["git", *args], cwd=str(repo),            # nosec B603,B607
                              capture_output=True, timeout=60, **TEXT_IO)

    def _repo_con_ref_ajena(self, base: Path) -> Path:
        """Un repositorio limpio en `HEAD` y un secreto colgando de una ref de otro remoto."""
        repo = base / "clon"
        repo.mkdir()
        self._git(repo, "init", "-q", "-b", "main")
        self._git(repo, "config", "user.email", "prueba@example-org")
        self._git(repo, "config", "user.name", "prueba")
        (repo / "limpio.txt").write_text("nada que ocultar\n", encoding="utf-8")
        self._git(repo, "add", "-A")
        self._git(repo, "commit", "-q", "-m", "propio")
        # La historia ajena cuelga de `refs/remotes/ajeno/dev` y NO es alcanzable desde `HEAD`,
        # igual que las 189 del otro proyecto en el clon real.
        self._git(repo, "checkout", "-q", "--orphan", "ajeno")
        self._git(repo, "rm", "-rq", "--cached", ".")
        (repo / "limpio.txt").unlink()
        (repo / "config.py").write_text(f'TOKEN = "{_PAT_SINTETICO}"\n', encoding="utf-8")
        self._git(repo, "add", "-A")
        self._git(repo, "commit", "-q", "-m", "importación inicial de otro proyecto")
        sha = (self._git(repo, "rev-parse", "HEAD").stdout or "").strip()
        self._git(repo, "update-ref", "refs/remotes/ajeno/dev", sha)
        self._git(repo, "checkout", "-q", "main")
        self._git(repo, "branch", "-q", "-D", "ajeno")
        return repo

    def _gitleaks(self, repo: Path, argv_extra: list) -> int:
        p = subprocess.run(["gitleaks", "detect", "--no-banner", "--redact",   # nosec B603,B607
                            "--source", str(repo), *argv_extra],
                           cwd=str(repo), capture_output=True, timeout=300, **TEXT_IO)
        return p.returncode

    def _preparar(self) -> Path:
        if shutil.which("gitleaks") is None:
            self.skipTest("`gitleaks` no está en el PATH: NOT_EXECUTABLE, que no es PASS")
        base = Path(tempfile.mkdtemp(prefix="refuto-gl-"))
        self.addCleanup(shutil.rmtree, base, ignore_errors=True)
        return self._repo_con_ref_ajena(base)

    def test_sin_acotar_el_secreto_AJENO_retiene_el_empujon(self):
        """Control positivo. Si esto deja de encontrarlo, la prueba de abajo no mide nada."""
        repo = self._preparar()
        self.assertNotEqual(0, self._gitleaks(repo, []),
                            "sin acotar, `gitleaks` tiene que ver la ref ajena; si no la ve, "
                            "el control positivo de esta prueba está roto")

    def test_acotado_al_sujeto_del_empujon_el_secreto_ajeno_no_cuenta(self):
        repo = self._preparar()
        self.assertEqual(0, self._gitleaks(repo, list(PF.ACOTADO_AL_EMPUJON)),
                         "con el sujeto acotado a lo que se empuja, un secreto que cuelga de "
                         "la ref de otro proyecto no puede retener este empujón")

    def test_y_un_secreto_PROPIO_sigue_reteniendo_el_empujon(self):
        """El acotamiento no puede degenerar en apagar el control."""
        repo = self._preparar()
        (repo / "mio.py").write_text(f'TOKEN = "{_PAT_SINTETICO}"\n', encoding="utf-8")
        self._git(repo, "add", "-A")
        self._git(repo, "commit", "-q", "-m", "esto sí es mío")
        self.assertNotEqual(0, self._gitleaks(repo, list(PF.ACOTADO_AL_EMPUJON)),
                            "acotar el sujeto no es apagar el control: un secreto alcanzable "
                            "desde `HEAD` tiene que seguir parando el empujón")

    def test_en_HEAD_desprendido_el_ambito_no_se_queda_vacio(self):
        """La trampa del propio arreglo, y la razón de que `HEAD` vaya delante.

        `actions/checkout` deja HEAD desprendido en los eventos `pull_request`: no hay ninguna
        rama local. Acotar sólo con `--branches --tags` haría que el control escaneara 0 bytes
        y declarara «no leaks found» — verde porque no mira, que es la forma de fallo que este
        repositorio existe para impedir.
        """
        if shutil.which("gitleaks") is None:
            self.skipTest("`gitleaks` no está en el PATH: NOT_EXECUTABLE, que no es PASS")
        base = Path(tempfile.mkdtemp(prefix="refuto-gl-"))
        self.addCleanup(shutil.rmtree, base, ignore_errors=True)
        repo = base / "ci"
        repo.mkdir()
        self._git(repo, "init", "-q", "-b", "main")
        self._git(repo, "config", "user.email", "prueba@example-org")
        self._git(repo, "config", "user.name", "prueba")
        (repo / "config.py").write_text(f'TOKEN = "{_PAT_SINTETICO}"\n', encoding="utf-8")
        self._git(repo, "add", "-A")
        self._git(repo, "commit", "-q", "-m", "con secreto")
        self._git(repo, "checkout", "-q", "--detach", "HEAD")
        self._git(repo, "branch", "-q", "-D", "main")

        solo_ramas = ["--log-opts", "--branches --tags"]
        self.assertEqual(0, self._gitleaks(repo, solo_ramas),
                         "si esto dejara de salir verde, el ámbito ya no estaría vacío y esta "
                         "prueba habría perdido su sujeto")
        self.assertNotEqual(0, self._gitleaks(repo, list(PF.ACOTADO_AL_EMPUJON)),
                            "el acotamiento que usa el preflight TIENE que seguir mirando algo "
                            "cuando no hay ramas locales: un ámbito vacío nunca aprueba")

    def test_el_control_declarado_lleva_el_acotamiento(self):
        """Que la constante exista no sirve si el control registrado no la usa."""
        gl = [c for c in PF._chequeos() if c.nombre == "gitleaks"]     # noqa: SLF001
        self.assertEqual(1, len(gl), "no hay exactamente un control llamado «gitleaks»")
        argv = list(gl[0].argv or ())
        for pieza in PF.ACOTADO_AL_EMPUJON:
            with self.subTest(pieza=pieza):
                self.assertIn(pieza, argv,
                              "el control de secretos no acota su sujeto: volverá a medir el "
                              "almacén de objetos del clon en vez del repositorio")


if __name__ == "__main__":
    unittest.main()
