# -*- coding: utf-8 -*-
"""Lanzador del guardián, instalado en el espacio de trabajo.

Por qué no basta con poner el comando en el gancho
--------------------------------------------------
La primera versión incrustaba rutas absolutas en cada gancho:

    cd /ruta/a/refuto && python3 -m core.guard --runtime claude --workspace /ruta/al/espacio

Eso funciona exactamente en una máquina, con un intérprete, con refuto en un sitio. Se rompe
al mover refuto, al abrir el espacio desde otro usuario, al ejecutar con `sudo` —donde el
`PATH` y el `python3` pueden ser otros— y al abrirlo desde una aplicación de escritorio, que no
hereda el entorno del shell.

Aquí se instala **un guion en el propio espacio** (`.harness/bin/guard`). Los ganchos lo invocan
por ruta relativa al espacio, y él resuelve el resto:

    1. localiza el espacio subiendo desde su propia ubicación — no depende del directorio actual
    2. localiza refuto por la ruta registrada al instalar, y si se movió, lo dice
    3. elige un intérprete que exista, en vez de asumir que `python3` está en el PATH
    4. si corre bajo `sudo`, devuelve al usuario original la propiedad de lo que cree

El punto 4 no es cosmético: un guardián que corre como root deja archivos de root en el espacio
de la persona, y a partir de ahí **el diario de auditoría deja de poder escribirse** sin que
nada falle a la vista. Un rastro que se corta en silencio es peor que no tenerlo, porque nadie
lo echa en falta.
"""

from __future__ import annotations

import json
import os
import stat
import sys
from pathlib import Path

from core.model import now, write_json
from core.proc import euid, owns_by_uid

BIN = ".harness/bin"
NAME = "guard"
#: El mismo lanzador en el vocabulario de Windows. Se escriben **los dos** en todo sistema: en
#: Windows conviven un shell POSIX (Git Bash, WSL) y `cmd.exe`, y cuál de los dos invoca el
#: gancho lo decide el runtime, no nosotros. Un lanzador de más cuesta 40 líneas; el que falta
#: cuesta un espacio que parece gobernado y no lo está.
NAME_CMD = "guard.cmd"

TEMPLATE = '''#!/bin/sh
# GENERADO por `refuto policy wire`. No editar: se sobrescribe.
#
# Lanzador del guardián de refuto. Se invoca desde los ganchos de cualquier runtime y se
# resuelve solo: no depende del directorio actual, ni de que `python3` esté en el PATH, ni de
# que refuto siga donde estaba cuando se instaló.
set -eu

# El espacio de trabajo es dos niveles por encima de este guion (.harness/bin/guard).
BIN_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
WORKSPACE=$(CDPATH= cd -- "$BIN_DIR/../.." && pwd)

HARNESS_HOME="__HARNESS_HOME__"
if [ ! -f "$HARNESS_HOME/core/guard.py" ]; then
  echo "harness-guard: refuto ya no está en $HARNESS_HOME." >&2
  echo "harness-guard: vuelva a ejecutar 'refuto policy wire' desde su nueva ubicación." >&2
  echo "harness-guard: se BLOQUEA la operación: un guardián que no se encuentra no aprueba." >&2
  exit 2
fi

# Un intérprete que exista de verdad. Bajo sudo o desde una aplicación de escritorio, el PATH
# no es el del shell del usuario.
PY=""
for candidate in "__PYTHON__" python3 /usr/bin/python3 /opt/homebrew/bin/python3 \\
                 /usr/local/bin/python3; do
  if [ -x "$candidate" ] 2>/dev/null || command -v "$candidate" >/dev/null 2>&1; then
    PY="$candidate"; break
  fi
done
if [ -z "$PY" ]; then
  echo "harness-guard: no hay intérprete de Python. Se BLOQUEA." >&2
  exit 2
fi

cd "$HARNESS_HOME"
# Los argumentos del gancho se REENVÍAN: es lo que permite que el mismo lanzador sirva al
# control preventivo (sin argumentos) y al registro del resultado (`--post`), sin instalar dos.
exec "$PY" -m core.guard --runtime "${HARNESS_GUARD_RUNTIME:-__RUNTIME__}" --stdin \\
     --workspace "$WORKSPACE" "$@"
'''


#: El mismo contrato que TEMPLATE, en el vocabulario de cmd.exe. Deliberadamente **sin tildes**:
#: un .cmd se lee con la pagina de codigos activa de la consola, que no es UTF-8 por defecto, y
#: un mensaje ilegible en el unico momento en que alguien lo lee —cuando bloquea— no sirve.
TEMPLATE_CMD = r"""@echo off
REM GENERADO por `refuto policy wire`. No editar: se sobrescribe.
REM
REM Lanzador del guardian de refuto para cmd.exe. Se resuelve solo: no depende del
REM directorio actual, ni de que python este en el PATH, ni de que refuto siga donde
REM estaba cuando se instalo. Si no se encuentra, BLOQUEA.
setlocal

REM El espacio de trabajo es dos niveles por encima de este guion (.harness\bin\guard.cmd).
for %%I in ("%~dp0..\..") do set "WORKSPACE=%%~fI"

set "HARNESS_HOME=__HARNESS_HOME__"
if not exist "%HARNESS_HOME%\core\guard.py" (
  echo harness-guard: refuto ya no esta en %HARNESS_HOME%. 1>&2
  echo harness-guard: vuelva a ejecutar 'refuto policy wire' desde su nueva ubicacion. 1>&2
  echo harness-guard: se BLOQUEA la operacion: un guardian que no se encuentra no aprueba. 1>&2
  exit /b 2
)

REM Un interprete que exista de verdad. El PATH de un proceso lanzado por una aplicacion de
REM escritorio no es el del shell del usuario.
set "PY=__PYTHON__"
if not exist "%PY%" set "PY=python"
where "%PY%" >nul 2>&1 || if not exist "%PY%" (
  echo harness-guard: no hay interprete de Python. Se BLOQUEA. 1>&2
  exit /b 2
)

REM El runtime llega como argumento; la variable de entorno sigue mandando si esta puesta.
set "RUNTIME=%~1"
if "%RUNTIME%"=="" set "RUNTIME=__RUNTIME__"
if not "%HARNESS_GUARD_RUNTIME%"=="" set "RUNTIME=%HARNESS_GUARD_RUNTIME%"

REM La fase llega como segundo argumento (vacia = control preventivo). Se reenvia tal cual:
REM el mismo lanzador sirve para decidir antes y para registrar el resultado despues.
set "FASE=%~2"

cd /d "%HARNESS_HOME%"
"%PY%" -m core.guard --runtime "%RUNTIME%" --stdin --workspace "%WORKSPACE%" %FASE%
exit /b %ERRORLEVEL%
"""


def native_name() -> str:
    """Cómo se llama el lanzador que este sistema sabe ejecutar por sí solo."""
    return NAME_CMD if os.name == "nt" else NAME


def launcher_path(workspace: Path) -> Path:
    return workspace / BIN / native_name()


def install(workspace: Path, *, harness_home: Path, runtime: str = "claude") -> Path:
    """Instala el lanzador en el espacio. Devuelve la ruta del nativo de este sistema."""
    d = workspace / BIN
    d.mkdir(parents=True, exist_ok=True)
    # `abspath` y NO `resolve()`: hay que normalizar la ruta sin seguir los enlaces simbólicos.
    # Con `resolve()`, un `HARNESS_HOME` que apuntaba a `<raíz>/current` quedaba grabado como
    # `<raíz>/<commit>`, y entonces `refuto engine use` —cuyo trabajo es mover TODOS los
    # espacios a la vez cambiando ese enlace— no movía a ninguno: cada lanzador llevaba el
    # commit incrustado. Medido el 2026-09-28, al cablear el primer espacio contra un motor
    # publicado. La capacidad de volver atrás de golpe es justo lo que hace reversible esto.
    destino = Path(os.path.abspath(str(harness_home)))
    sustituir = lambda plantilla: (plantilla                              # noqa: E731
                                   .replace("__HARNESS_HOME__", str(destino))
                                   .replace("__PYTHON__", sys.executable)
                                   .replace("__RUNTIME__", runtime))
    path = d / NAME
    path.write_text(sustituir(TEMPLATE), encoding="utf-8", newline="\n")
    path.chmod(path.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)

    # CRLF explícito: un .cmd con finales de línea de Unix se ejecuta mal en cmd.exe, y el
    # síntoma no apunta al fichero. Es el mismo mordisco que el CRLF en `gradlew`, al revés.
    cmd_path = d / NAME_CMD
    cmd_path.write_text(sustituir(TEMPLATE_CMD), encoding="utf-8", newline="\r\n")
    path = cmd_path if os.name == "nt" else path

    write_json(d / "installed.json", {
        "schema": "harness.launcher/v1",
        "_que_es": ("De donde salio este lanzador y contra que harness apunta. Si refuto se "
                    "mueve, el lanzador BLOQUEA en vez de aprobar por no encontrarse."),
        # Lo que el lanzador usa de verdad (sin resolver enlaces) y, si es un enlace, a dónde
        # apuntaba al instalar: las dos cosas, porque la segunda puede haber cambiado después
        # y saber cuál era es lo que permite explicar un veredicto viejo.
        "harness_home": str(destino),
        "harness_home_resuelto": str(destino.resolve()),
        "python": sys.executable,
        "default_runtime": runtime,
        "installed_at": now(),
        # `USER` es POSIX; en Windows la variable se llama `USERNAME`. Preguntar sólo por la
        # primera dejaba el campo vacío justo donde más se mira: al auditar quién instaló esto.
        "installed_by": (os.environ.get("SUDO_USER") or os.environ.get("USER")
                         or os.environ.get("USERNAME", "")),
    })
    restore_ownership(workspace)
    return path


def hook_command(workspace: Path, *, runtime: str) -> str:
    """El comando que va en el gancho. Corto, relativo y estable.

    En Windows el runtime viaja como ARGUMENTO, no como variable de entorno: `VAR=x orden` es
    sintaxis de shell POSIX, y `cmd.exe` la lee como el nombre de un programa que no existe. El
    gancho no fallaría ruidosamente — sencillamente no se ejecutaría, que es la peor de las dos
    formas de fallar para un control.
    """
    if os.name == "nt":
        return f'"{workspace}/{BIN}/{NAME_CMD}" {runtime}'
    return f'HARNESS_GUARD_RUNTIME={runtime} "{workspace}/{BIN}/{NAME}"'


def is_installed(workspace: Path) -> bool:
    return launcher_path(workspace).is_file()


def check(workspace: Path) -> dict:
    """¿El lanzador está y apunta a un harness que existe?"""
    path = launcher_path(workspace)
    meta = workspace / BIN / "installed.json"
    if not path.is_file():
        return {"ok": False, "reason": "no está instalado. Ejecute `refuto policy wire`."}
    if not os.access(path, os.X_OK):
        return {"ok": False, "reason": f"{path} no es ejecutable"}
    try:
        doc = json.loads(meta.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {"ok": False, "reason": "falta o es ilegible .harness/bin/installed.json"}
    home = Path(doc.get("harness_home", ""))
    if not (home / "core" / "guard.py").is_file():
        return {"ok": False, "harness_home": str(home),
                "reason": f"apunta a {home}, donde ya no está refuto. "
                          f"Vuelva a ejecutar `refuto policy wire`."}
    return {"ok": True, "harness_home": str(home), "python": doc.get("python", "")}


# ── propiedad de los archivos ────────────────────────────────────────────────────────
def workspace_owner(workspace: Path) -> tuple[int, int] | None:
    """A quién pertenece el espacio. Es la respuesta correcta a «¿de quién deben ser los
    archivos que refuto escribe aquí?».

    Se prefiere esto a `SUDO_UID` porque `SUDO_UID` miente en el caso que más duele: si quien
    lanza `sudo` ya era root, vale 0 y la restauración se convierte en una operación vacía —
    justo cuando más falta hace. El dueño del directorio siempre dice la verdad.
    """
    try:
        st = workspace.stat()
        return st.st_uid, st.st_gid
    except OSError:
        return None


def invoking_user() -> tuple[int, int] | None:
    """Quién invocó de verdad, cuando se corre con `sudo`. `None` si no aplica."""
    uid, gid = os.environ.get("SUDO_UID"), os.environ.get("SUDO_GID")
    if uid and gid and euid() == 0:
        try:
            return int(uid), int(gid)
        except ValueError:
            return None
    return None


def ownership_report(workspace: Path) -> dict:
    """Archivos de refuto que no pertenecen a quien va a usarlos.

    Es el daño colateral de una sesión con `sudo`: el agente y el guardián corren como root,
    dejan el diario en manos de root, y a partir de ahí la persona **pierde su propio rastro de
    auditoría sin que nada falle a la vista**.
    """
    base = workspace / ".harness"
    if not base.exists():
        return {"checked": False, "reason": "no hay .harness/ en este espacio"}
    if not owns_by_uid():
        # Windows no tiene `uid`: `st_uid` vale 0 para todo y comparar dueños no detectaría
        # nada. Declararlo es la respuesta correcta; devolver una lista vacía de ajenos sería
        # decir «comprobado y limpio» sin haber comprobado nada.
        return {"checked": False,
                "reason": "este sistema no expresa la propiedad por uid: no hay nada que "
                          "comparar. `sudo` tampoco existe aquí, que es el riesgo que esta "
                          "comprobación cubre."}
    dueño = workspace_owner(workspace)
    owner = dueño[0] if dueño else os.getuid()
    ajenos = []
    for p in [base, *base.rglob("*")]:
        try:
            if p.stat().st_uid != owner:
                ajenos.append(str(p.relative_to(workspace)))
        except OSError:
            continue
    return {
        "checked": True,
        "expected_uid": owner,
        "foreign": ajenos,
        "count": len(ajenos),
        "fix": f"sudo chown -R $USER '{workspace / '.harness'}'" if ajenos else "",
    }


def restore_ownership(workspace: Path) -> int:
    """Devuelve `.harness/` al dueño del espacio, si esto corre como root.

    Sin esto, una sola sesión con `sudo` deja el diario en manos de root y la persona pierde su
    propio rastro de auditoría — sin que nada falle a la vista.

    El destinatario es el dueño del DIRECTORIO, no `SUDO_UID`: el segundo vale 0 cuando quien
    lanzó `sudo` ya era root, y entonces la restauración no restaura nada.
    """
    # Sólo tiene sentido —y sólo es posible— si esto corre como root. Donde no hay `euid`
    # tampoco hay `sudo` ni `chown`: no hay nada que devolver a nadie.
    if not owns_by_uid() or euid() != 0:
        return 0
    who = workspace_owner(workspace)
    if who is None or who[0] == 0:
        return 0
    uid, gid = who
    base = workspace / ".harness"
    changed = 0
    if not base.exists():
        return 0
    for p in [base, *base.rglob("*")]:
        try:
            st = p.stat()
            if st.st_uid != uid:
                os.chown(p, uid, gid)
                changed += 1
        except OSError:
            continue
    return changed
