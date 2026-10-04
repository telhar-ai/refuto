# -*- coding: utf-8 -*-
"""Engancha el guardián en la ruta que el runtime usa de verdad.

Por qué esto es un módulo aparte y no parte de la compilación
-------------------------------------------------------------
Compilar la política produce ARTEFACTOS NUEVOS: archivos que refuto genera y puede
sobrescribir sin pensar. Engancharla toca ARCHIVOS AJENOS: los agentes que alguien escribió a
mano. Son dos operaciones con riesgos distintos y merecen dos verbos distintos.

H-03 existió porque la guardia estaba enganchada en `.kiro/hooks/*.json` —que lee el IDE— y el
orquestador siempre llama a `kiro-cli chat`, que lee `hooks{}` del propio agente. Generar sólo
el archivo del IDE repetiría el error con un archivo más moderno.

Reglas de este módulo, y las tres existen por lo mismo:
    1. **Copia de seguridad antes de tocar** (`.harness/backup/`), siempre.
    2. **Idempotente**: el gancho lleva marca; volver a engancharlo no lo duplica.
    3. **Reversible**: `unwire()` deja los archivos como estaban.
"""

from __future__ import annotations

import json
import os
import shutil
from dataclasses import dataclass
from pathlib import Path

from core import launcher

#: La marca con la que se reconoce un gancho puesto por este motor. **No se renombra al
#: renombrar el producto**: está escrita dentro del `settings.local.json` y de los agentes de
#: Kiro de todos los espacios ya enganchados, y es lo único que permite reengancharlos sin
#: duplicar el gancho ni pisar el de otra persona. Cambiarla convertiría cada gancho existente
#: en «de nadie». Misma regla que `.harness/`, `HARNESS_*` y los esquemas `harness.*/v1`.
MARK = "harness-guard"
#: Cómo se reconoce un gancho de refuto. Se busca la INVOCACIÓN del módulo, no la marca de
#: cortesía: `audit()` buscaba `harness-guard` dentro de `command`, y el comando real dice
#: `python3 -m core.guard`, así que declaraba 0/5 enganchados justo después de engancharlos.
#: Un chequeo que no comprueba lo que cree es peor que no tenerlo.
GUARD_MODULE = "core.guard"
GUARD_LAUNCHER = ".harness/bin/guard"

#: Lo que `_instalar_lanzador` reporta como ruta tocada. Es el mismo fichero que
#: `GUARD_LAUNCHER`, nombrado aparte para que la salida del seco sea legible.
BIN_LANZADOR = ".harness/bin/guard"

#: Las herramientas de Claude Code sobre las que corre el guardián.
#:
#: `Bash` está aquí porque sin él la mitad de la política era decorativa: el guardián implementa
#: `command_deny`/`command_ask` —`rm -rf`, `sudo`, `git push --force`, `glab mr`— y nadie lo
#: llamaba nunca, porque el matcher sólo cubría las herramientas de escritura. Medido en un
#: espacio real: 15 reglas de rechazo y 8 de consulta declaradas, 0 aplicadas. Una orden
#: cualquiera por Bash rodeaba el control entero.
#:
#: `Read` NO está, y es deliberado: el guardián no distingue leer de escribir sobre
#: `protected_paths`, así que engancharlo denegaría leer `.harness/**` — la evidencia y el
#: diario que el propio agente necesita consultar. Se prefiere `secret_read_deny` sin aplicar a
#: un agente que no puede leer lo que lo juzga.
CLAUDE_MATCHER = "Bash|Write|Edit|MultiEdit|NotebookEdit"

#: Variable con la que una sesión gobernada se anuncia a sí misma.
#:
#: La escribe `refuto chat` en el entorno del agente (`core.session`), y el gancho de abajo la
#: lee. El nombre empieza por `HARNESS_` como el resto de las variables del motor: son un
#: contrato con los espacios ya instalados y no se renombran al renombrar el producto.
#:
#: Esto estaba atado al lanzador PRIVADO de quien escribió el módulo: el gancho preguntaba por
#: una variable que sólo existía en su máquina y, si faltaba, mandaba reabrir la sesión con un
#: comando que no forma parte de este producto. Ese texto se escribe en el
#: `.claude/settings.local.json` de **cada repositorio enganchado de cada adoptante**, así que
#: fuera de esa máquina el aviso remitía a una orden inexistente — y el aviso más importante
#: del arranque terminaba en «command not found».
SESSION_ENV = "HARNESS_SESSION"

#: Aviso al arrancar cuando la sesión corre como root, en dos variantes.
#:
#: La primera versión decía «root, luego NO lo abrió el lanzador», y esa inferencia dejó de ser
#: cierta cuando el lanzador dejó de negarse a correr con privilegios. Se negaba, y el rechazo
#: se esquivaba elevando el binario del agente a secas —root Y sin gobierno, que es
#: estrictamente peor—, así que la barrera empujaba al camino malo. Ahora admite privilegios y
#: repara: al salir devuelve la configuración del agente y el espacio a quien invocó
#: (`core.launcher.restore_ownership`).
#:
#: Lo que importa, pues, ya no es si la sesión es root: es si hay alguien que vaya a restaurar.
#: `HARNESS_SESSION` lo dice, y sobrevive a `provider.clean_env`, que sólo quita las variables
#: de enrutado. Sin la marca, el aviso duro sigue en pie: una sesión root a pelo deja el daño
#: puesto. Medido en un espacio real de ~336 000 ficheros: el espacio entero más 22 ficheros de
#: la configuración del agente quedaron en propiedad de root —incluidos los ajustes de la
#: persona y su registro de proyectos—, y el diálogo de confianza volvía a salir en cada
#: arranque porque ya no podía escribirse.
#:
#: Avisa, no bloquea: una sesión root a medias es peor que una sesión root que sabe que lo es.
#: Y la orden que sugiere es la del propio producto (`refuto chat`), no la de ningún lanzador
#: de nadie: un aviso que manda ejecutar algo que no se publica no es un aviso, es ruido.
ROOT_WARN_CMD = (
    "if [ \"$(id -u)\" -eq 0 ]; then if [ -n \"$HARNESS_SESSION\" ]; then printf '%s' '{\"hookSpecificOut"
    "put\": {\"hookEventName\": \"SessionStart\", \"additionalContext\": \"NOTA DE REFUTO: esta sesion corre"
    " con privilegios de root, pero la abrio una sesion gobernada, que al terminar devuelve la config"
    "uracion del agente y el espacio a la persona que invoco. NO le pidas que cierre la sesion. Si al"
    "go del trabajo no necesita privilegios, no los uses.\"}}'; else printf '%s' '{\"hookSpecificOutput"
    "\": {\"hookEventName\": \"SessionStart\", \"additionalContext\": \"AVISO DE REFUTO: esta sesion corre c"
    "omo root (uid 0) y NO la abrio una sesion gobernada, luego NADIE devolvera la propiedad al salir"
    ". Todo archivo que toques quedara en propiedad de root, incluidos los de la configuracion del ag"
    "ente, y dejaran de ser escribibles por la persona. Diselo en tu primera respuesta y pidele que c"
    "ierre esta sesion y la reabra con: refuto chat\"}}'; fi; fi; exit 0"
)


def _is_guard_hook(entry: dict) -> bool:
    cmd = str(entry.get("command", ""))
    return (GUARD_MODULE in cmd or GUARD_LAUNCHER in cmd
            or MARK in str(entry.get("_generado", "")))


def _es_aviso_de_sesion(entry: dict) -> bool:
    """¿Este `SessionStart` es el aviso de root de refuto?

    Se reconoce por la marca **o por el comando**. Sólo por la marca no bastaba: las versiones
    anteriores escribían el aviso sin `_generado`, así que al volver a enganchar no se limpiaba
    y se añadía otro igual — el aviso quedaba DUPLICADO. Medido el 2026-09-28 al cablear un
    espacio real que ya lo tenía: dos avisos idénticos donde había que ver uno. No crecía más
    allá de dos, porque la comprobación de «ya está» contaba sólo los marcados; pero un control
    que se imprime dos veces enseña a no leerlo.
    """
    if MARK in str(entry.get("_generado", "")):
        return True
    return any(str(h.get("command", "")).strip() == ROOT_WARN_CMD.strip()
               for h in entry.get("hooks", []))


def _uses_launcher(entry: dict) -> bool:
    """¿Este gancho ya usa el lanzador, o es de la forma antigua con rutas incrustadas?

    `already` tenía que distinguir «ya está» de «ya está, pero anticuado». Sin eso, volver a
    enganchar dejaba intactos los ganchos frágiles y decía que todo estaba en orden.
    """
    return GUARD_LAUNCHER in str(entry.get("command", ""))


def _matcher_al_dia(entry: dict) -> bool:
    """¿Este gancho cubre las herramientas que hoy hay que cubrir?

    `already` comparaba el comando y no el ALCANCE. Un gancho correcto enganchado sobre menos
    herramientas de las debidas es indistinguible de uno bien puesto si sólo se mira el comando:
    volver a enganchar decía «already» y dejaba el agujero intacto.
    """
    actual = {t for t in str(entry.get("matcher", "")).split("|") if t}
    return actual == set(CLAUDE_MATCHER.split("|"))


@dataclass
class WireResult:
    path: str
    action: str          # wired | already | skipped | restored
    detail: str = ""


def _instalar_lanzador(workspace: Path, harness_root: Path, *, runtime: str,
                       dry_run: bool, solo_si_falta: bool = False) -> list:
    """Materializa el lanzador, y en seco NO lo materializa: lo DECLARA.

    El defecto que esto arregla, medido el 2026-10-04
    ------------------------------------------------
    `launcher.install` se llamaba antes de cualquier comprobación de `dry_run`, en los tres
    `wire_*`. Resultado: `refuto policy wire --dry-run` **escribía**
    `.harness/bin/{guard,guard.cmd,installed.json}` y la salida sólo hablaba de
    `.claude/settings.local.json`. Se descubrió al intentar una simulación sobre dos espacios y
    comprobar después que su lanzador había cambiado de puntero.

    Una simulación que escribe es peor que no tener simulación: es el único modo en que alguien
    prueba un cambio en producción creyendo que no lo está aplicando. Y el error contrario
    —callar el efecto— también cuenta: el seco declara la acción del lanzador en vez de omitirla,
    porque una lista que no la menciona se lee como una lista completa.
    """
    ya = launcher.is_installed(workspace)
    if solo_si_falta and ya:
        return []
    al_dia = _lanzador_al_dia(workspace, harness_root)
    if al_dia:
        return [WireResult(BIN_LANZADOR, "already", f"apunta a {harness_root}")]
    if dry_run:
        return [WireResult(BIN_LANZADOR, "upgraded" if ya else "wired",
                           f"(simulación) apuntaría a {harness_root}")]
    launcher.install(workspace, harness_home=harness_root, runtime=runtime)
    return [WireResult(BIN_LANZADOR, "upgraded" if ya else "wired",
                       f"{'reapuntado' if ya else 'apunta'} a {harness_root}")]


def _lanzador_al_dia(workspace: Path, harness_root: Path) -> bool:
    """¿El lanzador ya apunta donde debe? Entonces no se reescribe.

    No se compara byte a byte: `installed.json` lleva `installed_at`, así que una comparación
    exacta nunca coincidiría y el lanzador se reescribiría en cada llamada — subiendo su `mtime`
    y su marca de instalación sin que nada hubiera cambiado. Se compara lo que DECIDE algo: el
    puntero al motor, en el guion y en el metadato, y que estén los tres ficheros.
    """
    d = workspace / ".harness" / "bin"
    guion, meta = d / launcher.native_name(), d / "installed.json"
    if not (guion.is_file() and meta.is_file()):
        return False
    try:
        anotado = json.loads(meta.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return False
    esperado = str(Path(os.path.abspath(str(harness_root))))
    if anotado.get("harness_home") != esperado:
        return False
    try:
        return f'HARNESS_HOME="{esperado}"' in guion.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return False


def _backup(workspace: Path, path: Path) -> Path:
    dest = workspace / ".harness" / "backup" / path.relative_to(workspace)
    dest.parent.mkdir(parents=True, exist_ok=True)
    if not dest.exists():
        shutil.copy2(path, dest)
    return dest


def wire_kiro_agents(workspace: Path, *, harness_root: Path, dry_run: bool = False) -> list:
    """Añade el gancho del guardián a `hooks.preToolUse` de cada agente de Kiro.

    El comando se ancla al directorio de refuto: los ganchos corren con el directorio de
    trabajo de quien invoca, y `python3 -m core.guard` desde el proyecto no encuentra el módulo.
    Este detalle exacto es el que hacía fallar la publicación de agentes en el espacio SDD.
    """
    out: list = []
    agents_dir = workspace / ".kiro" / "agents"
    if not agents_dir.is_dir():
        return [WireResult(str(agents_dir), "skipped", "no hay agentes de Kiro en este espacio")]

    out += _instalar_lanzador(workspace, harness_root, runtime="kiro", dry_run=dry_run)
    command = launcher.hook_command(workspace, runtime="kiro")
    for path in sorted(agents_dir.glob("*.json")):
        try:
            doc = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError) as exc:
            out.append(WireResult(str(path), "skipped", f"ilegible: {exc}"))
            continue

        hooks = doc.setdefault("hooks", {})
        pre = hooks.setdefault("preToolUse", [])
        previos = [h for h in pre if _is_guard_hook(h)]
        if previos and all(_uses_launcher(h) for h in previos):
            out.append(WireResult(str(path.relative_to(workspace)), "already"))
            continue
        accion = "upgraded" if previos else "wired"
        pre[:] = [h for h in pre if not _is_guard_hook(h)]
        entry = {"matcher": "fs_write", "command": command,
                 "_generado": f"{MARK}: control preventivo de refuto en la ruta del CLI. "
                              f"Ver H-03."}
        pre.append(entry)
        if dry_run:
            out.append(WireResult(str(path.relative_to(workspace)), accion,
                                  "(simulación: no se escribió)"))
            continue
        _backup(workspace, path)
        path.write_text(json.dumps(doc, ensure_ascii=False, indent=2) + "\n", encoding="utf-8", newline="\n")
        out.append(WireResult(str(path.relative_to(workspace)), accion))
    launcher.restore_ownership(workspace)
    return out


def repos_del_espacio(workspace: Path, *, profundidad: int = 3) -> list:
    """Los repositorios git del espacio. Son los PUNTOS DE ENTRADA reales.

    Claude Code resuelve sus ajustes a la raíz del repositorio git, no al directorio actual —
    lo dice su documentación: «If you start Claude Code in a subdirectory of a git repository,
    it reads and writes that file at the repository root». Así que un espacio que contiene
    repositorios tiene tantos puntos de entrada como repositorios, y enganchar sólo la raíz
    cubre uno de ellos.

    Medido en un espacio real de 215 repositorios: 38 ficheros de ajustes y 2 con guardián.
    """
    from core.context import container_dirs

    base = workspace.resolve()
    # Dentro de un repositorio ya no se baja más, SALVO a los directorios contenedores: ahí
    # viven los árboles de trabajo (`git worktree add` usa `.worktrees/` por convención), que
    # son puntos de entrada propios. Cuáles son se declara en el manifiesto; `.worktrees` es
    # sólo el valor por omisión, no una ley del producto.
    contenedores = set(container_dirs(base))
    out, tope = [], len(base.parts) + profundidad
    import os as _os
    for dirpath, dirnames, filenames in _os.walk(base, followlinks=False):
        aqui = Path(dirpath)
        if len(aqui.parts) > tope:
            dirnames[:] = []
            continue
        dirnames[:] = [d for d in dirnames
                       if d not in {"node_modules", "target", ".venv", "dist", "build", ".git"}]
        if ".git" in dirnames or ".git" in filenames or (aqui / ".git").exists():
            if aqui != base:
                out.append(aqui)
            dirnames[:] = [d for d in dirnames if d in contenedores]
    return sorted(out)


def wire_claude_repos(workspace: Path, *, harness_root: Path, dry_run: bool = False) -> list:
    """Engancha en cada repositorio del espacio el guardián ÚNICO de ese espacio.

    Esto NO multiplica el gobierno: multiplica los punteros hacia él. Hay una política
    (`<espacio>/.harness/policy.json`), un guardián (`<espacio>/.harness/bin/guard`) y N
    referencias inertes. El guardián deduce el espacio de SU PROPIA ubicación —`$0/../..`—, no
    del directorio desde el que se le invoque, así que los N punteros dan exactamente la misma
    decisión y no pueden derivar entre sí.

    Es la diferencia entre repartir copias de una norma y repartir la dirección de donde está
    colgada. Lo segundo no crea versiones.

    Sigue sin cubrir un repositorio que nazca mañana: para eso hace falta resolver el espacio
    en tiempo de ejecución desde el nivel de usuario, y eso es otra decisión.
    """
    out = wire_claude(workspace, harness_root=harness_root, dry_run=dry_run)
    destinos = set(repos_del_espacio(workspace))

    # Y todo directorio que YA tenga `.claude/`: no es un repositorio, pero alguien abrió una
    # sesión ahí, y Claude Code usa los ajustes del directorio cuando no hay repositorio que
    # los reclame. Un punto de entrada probado por el uso es tan real como uno deducido de la
    # estructura. Medido en un espacio real: 23 de los 136 puntos eran de esta clase, y
    # recorrer sólo repositorios los dejaba fuera.
    for c in workspace.glob("*/.claude"):
        if c.is_dir() and c.parent != workspace:
            destinos.add(c.parent)
    for c in workspace.glob("*/*/.claude"):
        if c.is_dir():
            destinos.add(c.parent)

    for destino in sorted(destinos):
        out.extend(_enganchar_en(destino, workspace, dry_run=dry_run))
    return out


def _enganchar_en(repo: Path, workspace: Path, *, dry_run: bool) -> list:
    """Pone el gancho en un repositorio, apuntando al guardián del espacio que lo contiene."""
    path = repo / ".claude" / "settings.local.json"
    doc: dict = {}
    if path.is_file():
        try:
            doc = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError) as exc:
            return [WireResult(str(path), "skipped", f"ilegible: {exc}")]

    # El comando lo construye el lanzador, no esta función: en `cmd.exe`, `VAR=x orden` es el
    # nombre de un programa que no existe, y el gancho no fallaría — sencillamente no correría
    # (core/launcher.py:hook_command). El apuntado sigue siendo el guardián de ESTE espacio.
    command = launcher.hook_command(workspace, runtime="claude")
    guard = f"{workspace.as_posix()}/{launcher.BIN}/{launcher.NAME}"
    hooks = doc.setdefault("hooks", {})
    pre = hooks.setdefault("PreToolUse", [])
    # Se compara en barras de POSIX: el gancho escrito en Windows lleva `\\` y el mismo guardián
    # dejaría de reconocerse al reengancharse desde el otro sistema.
    ya = [h for e in pre for h in e.get("hooks", [])
          if guard in str(h.get("command", "")).replace("\\", "/")]
    if ya:
        return [WireResult(str(path), "already")]
    accion = "upgraded" if any(_is_guard_hook(h) for e in pre for h in e.get("hooks", [])) \
        else "wired"
    for e in pre:
        e["hooks"] = [h for h in e.get("hooks", []) if not _is_guard_hook(h)]
    pre[:] = [e for e in pre if e.get("hooks")]
    pre.append({"matcher": CLAUDE_MATCHER,
                "hooks": [{"type": "command", "command": command, "timeout": 30}],
                "_generado": f"{MARK}: guardián del espacio que contiene este repositorio."})
    if dry_run:
        return [WireResult(str(path), f"{accion} (en seco)")]
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(doc, ensure_ascii=False, indent=2) + "\n", encoding="utf-8", newline="\n")
    return [WireResult(str(path), accion)]


def wire_claude(workspace: Path, *, harness_root: Path, dry_run: bool = False) -> list:
    """Engancha el guardián en `.claude/settings.local.json`, fusionando con lo que ya hubiera.

    Se escribe en `settings.local.json` y no en `settings.json` a propósito: el segundo se
    versiona y suele estar escrito a mano. Pisar la configuración de alguien para instalar un
    control es empezar el control rompiendo algo.
    """
    out: list = []
    path = workspace / ".claude" / "settings.local.json"
    out += _instalar_lanzador(workspace, harness_root, runtime="claude", dry_run=dry_run)
    command = launcher.hook_command(workspace, runtime="claude")

    doc: dict = {}
    if path.is_file():
        try:
            doc = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError) as exc:
            return [WireResult(str(path), "skipped", f"ilegible: {exc}")]

    hooks = doc.setdefault("hooks", {})
    pre = hooks.setdefault("PreToolUse", [])
    post = hooks.setdefault("PostToolUse", [])
    ses = hooks.setdefault("SessionStart", [])
    previos = [(e, h) for e in pre for h in e.get("hooks", []) if _is_guard_hook(h)]
    post_previos = [h for e in post for h in e.get("hooks", []) if _is_guard_hook(h)]
    post_al_dia = (len(post_previos) == 1 and _uses_launcher(post_previos[0])
                   and str(post_previos[0].get("command", "")).rstrip().endswith("--post"))
    ses_previos = [e for e in ses if _es_aviso_de_sesion(e)]
    ses_al_dia = (len(ses_previos) == 1
                  and [h.get("command") for h in ses_previos[0].get("hooks", [])] == [ROOT_WARN_CMD])
    if (previos and all(_uses_launcher(h) and _matcher_al_dia(e) for e, h in previos)
            and ses_al_dia and post_al_dia):
        # `out` entero, no sólo esta línea. El gancho puede estar `already` y el LANZADOR
        # haberse reapuntado en la misma llamada: medido el 2026-10-04 cableando ocho espacios
        # instalados, donde `installed.json` pasó a otro motor y la salida sólo decía
        # «already .claude/settings.local.json». El efecto ocurría y el informe lo callaba, que
        # es la misma clase de defecto que una simulación que escribe.
        return out + [WireResult(str(path.relative_to(workspace)), "already")]
    accion = "upgraded" if previos else "wired"
    for e in pre:
        e["hooks"] = [h for h in e.get("hooks", []) if not _is_guard_hook(h)]
    pre[:] = [e for e in pre if e.get("hooks")]
    for e in post:
        e["hooks"] = [h for h in e.get("hooks", []) if not _is_guard_hook(h)]
    post[:] = [e for e in post if e.get("hooks")]
    ses[:] = [e for e in ses if not _es_aviso_de_sesion(e)]

    pre.append({
        "matcher": CLAUDE_MATCHER,
        "hooks": [{"type": "command", "command": command, "timeout": 30}],
        "_generado": f"{MARK}: control preventivo de refuto en la sesión de Claude Code.",
    })
    # El gancho POSTERIOR no decide nada: registra cómo acabó lo que el preventivo dejó pasar.
    # Sin él, el diario no distinguía un `allow` de una orden rota, y la duración de una
    # herramienta sólo se podía estimar por la distancia entre eventos vecinos. Con él, la
    # diferencia entre los dos `ts` de un mismo `entrada_digest` ES la duración.
    post.append({
        "matcher": CLAUDE_MATCHER,
        "hooks": [{"type": "command", "command": f"{command} --post", "timeout": 15}],
        "_generado": f"{MARK}: registra el resultado de la operación. No bloquea.",
    })
    ses.append({
        "hooks": [{"type": "command", "command": ROOT_WARN_CMD, "timeout": 10}],
        "_generado": f"{MARK}: avisa si la sesión se abrió como root, fuera del lanzador.",
    })
    if dry_run:
        # `out` ya trae la acción del lanzador: devolverlo entero es la otra mitad del arreglo
        # del 2026-10-04. Descartarlo hacía que el seco callara un efecto que el real sí tiene,
        # y una lista que omite un fichero se lee como una lista completa.
        return out + [WireResult(str(path.relative_to(workspace)), accion, "(simulación)")]
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.is_file():
        _backup(workspace, path)
    path.write_text(json.dumps(doc, ensure_ascii=False, indent=2) + "\n", encoding="utf-8", newline="\n")
    launcher.restore_ownership(workspace)
    out.append(WireResult(str(path.relative_to(workspace)), accion))
    return out


def unwire(workspace: Path) -> list:
    """Restaura desde la copia de seguridad. Todo lo que se engancha se puede desenganchar."""
    out: list = []
    backup = workspace / ".harness" / "backup"
    if not backup.is_dir():
        return [WireResult(str(backup), "skipped", "no hay copia de seguridad")]
    for src in sorted(backup.rglob("*")):
        if not src.is_file():
            continue
        dest = workspace / src.relative_to(backup)
        dest.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(src, dest)
        out.append(WireResult(str(dest.relative_to(workspace)), "restored"))
    return out


def audit_claude(workspace: Path) -> dict:
    path = workspace / ".claude" / "settings.local.json"
    if not path.is_file():
        return {"wired": False, "reason": "no hay .claude/settings.local.json"}
    try:
        doc = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        return {"wired": False, "reason": f"ilegible: {exc}"}
    for entry in (doc.get("hooks") or {}).get("PreToolUse") or []:
        for h in entry.get("hooks", []):
            if _is_guard_hook(h):
                return {"wired": True, "reason": "gancho PreToolUse presente"}
    return {"wired": False, "reason": "no hay gancho del guardián en PreToolUse"}


#: Antigravity: todas las herramientas pasan por el guardián, que distingue lectura de
#: escritura (core/antigravity.py). Una lista cerrada de herramientas de escritura deja pasar
#: la siguiente que el producto añada.
ANTIGRAVITY_MATCHER = "*"
ANTIGRAVITY_HOOK = MARK          # nombre del gancho dentro de `.agents/hooks.json`


def wire_antigravity(workspace: Path, *, harness_root: Path, dry_run: bool = False) -> list:
    """Engancha el guardián y el informe de sesión en `.agents/hooks.json`.

    Medido el 2026-09-21: un agente de Antigravity trabajó en un espacio gobernado sin ningún
    control. No por carencia del producto —Antigravity tiene `PreToolUse`— sino porque el
    harness sólo cableaba `.claude/` y `.kiro/`. Con este fichero recibe lo mismo que Claude:

        PreToolUse     el guardián, con la misma política canónica
        PreInvocation  el informe de sesión, una vez por conversación

    Antigravity lo busca en `<carpeta abierta>/.agents/hooks.json`: hay que abrir el espacio
    por su raíz. El fichero es un objeto de ganchos con nombre; se reemplaza SÓLO el nuestro.
    """
    path = workspace / ".agents" / "hooks.json"
    # El lanzador es común a todos los runtimes; su runtime por omisión no se toca aquí.
    previos = _instalar_lanzador(workspace, harness_root, runtime="claude", dry_run=dry_run,
                                 solo_si_falta=True)
    command = launcher.hook_command(workspace, runtime="antigravity")

    doc: dict = {}
    if path.is_file():
        try:
            doc = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError) as exc:
            return [WireResult(str(path), "skipped", f"ilegible: {exc}")]
        if not isinstance(doc, dict):
            return [WireResult(str(path), "skipped", "no es un objeto JSON")]

    nuevo = {
        "PreToolUse": [{"matcher": ANTIGRAVITY_MATCHER,
                        "hooks": [{"type": "command", "command": command, "timeout": 30}]}],
        "PreInvocation": [{"type": "command", "command": command, "timeout": 30}],
    }
    rel = str(path.relative_to(workspace))
    if doc.get(ANTIGRAVITY_HOOK) == nuevo:
        return [WireResult(rel, "already")]
    accion = "upgraded" if ANTIGRAVITY_HOOK in doc else "wired"
    doc[ANTIGRAVITY_HOOK] = nuevo
    if dry_run:
        return previos + [WireResult(rel, accion, "(simulación)")]
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.is_file():
        _backup(workspace, path)
    path.write_text(json.dumps(doc, ensure_ascii=False, indent=2) + "\n", encoding="utf-8", newline="\n")
    launcher.restore_ownership(workspace)
    return [WireResult(rel, accion)]


def audit_antigravity(workspace: Path) -> dict:
    path = workspace / ".agents" / "hooks.json"
    if not path.is_file():
        return {"wired": False, "reason": "no hay .agents/hooks.json"}
    try:
        doc = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        return {"wired": False, "reason": f"ilegible: {exc}"}
    spec = doc.get(ANTIGRAVITY_HOOK) if isinstance(doc, dict) else None
    if not isinstance(spec, dict) or spec.get("enabled") is False:
        return {"wired": False, "reason": "el gancho del guardián falta o está desactivado"}
    pre = [h for g in spec.get("PreToolUse") or [] for h in g.get("hooks", [])
           if _is_guard_hook(h)]
    mat = {g.get("matcher") for g in spec.get("PreToolUse") or []}
    inv = [h for h in spec.get("PreInvocation") or [] if _is_guard_hook(h)]
    if not pre:
        return {"wired": False, "reason": "no hay guardián en PreToolUse"}
    if ANTIGRAVITY_MATCHER not in mat and "" not in mat:
        return {"wired": False, "reason": f"el matcher {sorted(mat)} no cubre todas las herramientas"}
    if not inv:
        return {"wired": False, "reason": "falta PreInvocation: el agente no recibe el informe"}
    return {"wired": True, "reason": "PreToolUse (todas las herramientas) y PreInvocation"}


def audit(workspace: Path) -> dict:
    """¿Está el guardián enganchado en la ruta del CLI? Sin esto, H-03 vuelve en silencio."""
    agents_dir = workspace / ".kiro" / "agents"
    total = wired = 0
    detail = {}
    for path in sorted(agents_dir.glob("*.json")) if agents_dir.is_dir() else []:
        total += 1
        try:
            doc = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            detail[path.name] = "ilegible"
            continue
        pre = (doc.get("hooks") or {}).get("preToolUse") or []
        has = any(_is_guard_hook(h) for h in pre)
        wired += bool(has)
        detail[path.name] = "enganchado" if has else "SIN GUARDIÁN en la ruta del CLI"
    return {"agents": total, "wired": wired, "detail": detail}
