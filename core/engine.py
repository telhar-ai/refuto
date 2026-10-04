# -*- coding: utf-8 -*-
"""El motor PUBLICADO: la copia del juez contra la que corren los espacios.

El problema que cierra (medido el 2026-09-28)
---------------------------------------------
`.harness/bin/guard` no es una copia del motor: es un lanzador que hace
`cd $HARNESS_HOME && exec python3 -m core.guard`, y `HARNESS_HOME` era **el árbol de trabajo de
refuto**. Medido ese día: **12 espacios** apuntaban al mismo árbol. Consecuencia directa y poco
cómoda: cada decisión del guardián en cualquiera de ellos ejecutaba los ficheros que hubiera en
ese directorio en ese instante, sin commit, sin instalación y sin aviso.

Mientras alguien edita `core/policy.py`, los doce espacios están corriendo la versión a medias.
El lanzador falla cerrado —bloquea si no encuentra el motor—, así que el síntoma no es un
guardián permisivo: es doce espacios parados a la vez, o peor, doce espacios gobernados por una
política que nadie llegó a probar. No hay ninguna frontera ahí, y el árbol de trabajo es el
sitio donde menos garantías hay.

Aquí esa frontera existe. Un motor publicado es:

    <raíz>/<commit>/      una copia EXACTA de un commit (`git archive`), no del árbol
    <raíz>/current        a cuál de ellos apuntan los lanzadores ahora mismo

Tres reglas, y las tres importan
--------------------------------
1. **No se publica un árbol sucio.** Un motor que no está entero en ningún commit es
   irreproducible: nadie podría volver a construirlo para comprobar qué juzgó. `git archive`
   toma el commit, no el directorio, así que un fichero sin `git add` no llega — y eso, en vez
   de ser una sorpresa silenciosa, es un `FAIL` antes de copiar nada.
2. **No se activa un motor que no se prueba a sí mismo.** La copia ejecuta su propia suite antes
   de recibir a nadie. Se puede saltar, y entonces queda escrito `verified: false`: publicar sin
   probar es una decisión legítima, esconderla no.
3. **Cambiar de motor es un acto, no un efecto.** Editar un fichero ya no mueve a los doce
   espacios; hace falta `refuto engine publish` y `refuto engine use`, que dejan constancia de
   quién, cuándo y qué commit.

Lo que esto NO resuelve
-----------------------
El motor publicado vive con el mismo `uid` que el sujeto (FORMAL-MODEL §6.2): quien pueda
escribir en el árbol de trabajo puede escribir también en la copia. Esto no es aislamiento, es
**intencionalidad**: separa «lo que estoy escribiendo» de «lo que está juzgando», que es la
confusión que había. Para lo otro hace falta otro `uid`, y eso es otra decisión.
"""

from __future__ import annotations

import os
import shutil
import subprocess  # nosec B404 — `git archive` ES la medición: la copia sale del commit
import sys
import tempfile
from pathlib import Path

from core.model import BLOCKED, FAIL, PASS, now, write_json
from core.proc import TEXT_IO

#: Dónde viven los motores publicados. Se puede mover con la variable, que es lo que usan las
#: pruebas y lo que permite tener dos instalaciones en la misma máquina sin que se pisen.
ENV_RAIZ = "REFUTO_ENGINE_HOME"
NOMBRE_VIGENTE = "current"
MANIFIESTO = "published.json"
SCHEMA = "refuto.engine/v1"

#: Lo que se comprueba que existe en una copia antes de darla por buena. Si `git archive` dejó
#: fuera algo de esto, la copia no es un motor: es un directorio con ficheros de refuto.
IMPRESCINDIBLES = ("core/guard.py", "core/policy.py", "core/proc.py", "refuto.py")


def raiz() -> Path:
    """`$REFUTO_ENGINE_HOME`, o `$XDG_DATA_HOME/refuto/engine`, o `~/.local/share/refuto/engine`."""
    explicita = os.environ.get(ENV_RAIZ)
    if explicita:
        return Path(explicita).expanduser()
    xdg = os.environ.get("XDG_DATA_HOME")
    base = Path(xdg).expanduser() if xdg else Path.home() / ".local" / "share"
    return base / "refuto" / "engine"


def _git(repo: Path, *args: str, binario: bool = False):
    kw = {"capture_output": True, "timeout": 120, "cwd": str(repo)}
    if not binario:
        kw.update(TEXT_IO)
    return subprocess.run(["git", *args], **kw)                         # nosec B603 B607


def estado_del_arbol(repo: Path) -> dict:
    """`{limpio, sucios, commit}` del repositorio de origen. `commit` vacío = no es un repo."""
    r = _git(repo, "rev-parse", "HEAD")
    if r.returncode != 0:
        return {"limpio": False, "sucios": [], "commit": "",
                "motivo": f"no es un repositorio git utilizable: {(r.stderr or '').strip()[:120]}"}
    s = _git(repo, "status", "--porcelain=v1", "-uall")
    sucios = [ln[3:] for ln in (s.stdout or "").splitlines() if ln.strip()]
    return {"limpio": not sucios, "sucios": sucios, "commit": (r.stdout or "").strip(), "motivo": ""}


def _extraer(repo: Path, commit: str, destino: Path) -> None:
    """`git archive <commit> | tar -x` en `destino`. La copia sale del COMMIT, no del árbol."""
    destino.mkdir(parents=True, exist_ok=True)
    ar = _git(repo, "archive", "--format=tar", commit, binario=True)
    if ar.returncode != 0:
        raise RuntimeError(f"git archive falló: {ar.stderr[:200]!r}")
    tar = subprocess.run(["tar", "-x", "-C", str(destino)], input=ar.stdout,       # nosec B603 B607
                         capture_output=True, timeout=120)
    if tar.returncode != 0:
        raise RuntimeError(f"tar falló: {tar.stderr[:200]!r}")


def _selftest(copia: Path, *, timeout: float = 1800.0) -> dict:
    """La copia se prueba a sí misma, con SU intérprete y desde SU directorio."""
    try:
        p = subprocess.run([sys.executable, "refuto.py", "selftest"],             # nosec B603
                           cwd=str(copia), capture_output=True, timeout=timeout, **TEXT_IO)
    except subprocess.TimeoutExpired:
        return {"ok": False, "codigo": None, "resumen": f"la suite no terminó en {timeout:g} s"}
    salida = ((p.stdout or "") + (p.stderr or "")).strip().splitlines()
    return {"ok": p.returncode == 0, "codigo": p.returncode,
            "resumen": salida[-1].strip() if salida else "(sin salida)"}


def publicar(repo: Path, *, commit: str = "HEAD", verificar: bool = True,
             destino: Path | None = None, activar: bool = True) -> dict:
    """Publica un commit del repositorio como motor. Devuelve `{estado, motivo, …}`.

    `FAIL` si el árbol está sucio y se pidió `HEAD` —lo publicado tiene que poder reconstruirse—
    o si la copia no se prueba. `BLOCKED` si no hay repositorio del que sacar el commit.
    """
    from core.trust import digest_motor

    raiz_destino = Path(destino) if destino else raiz()
    est = estado_del_arbol(repo)
    if not est["commit"]:
        return {"estado": BLOCKED, "motivo": est["motivo"], "commit": "", "path": ""}
    if commit in ("HEAD", "") and not est["limpio"]:
        n = len(est["sucios"])
        return {"estado": FAIL, "commit": "", "path": "",
                "motivo": f"el árbol tiene {n} fichero(s) sin commitear "
                          f"({', '.join(est['sucios'][:3])}{'…' if n > 3 else ''}): lo que se "
                          f"publique así no está entero en ningún commit y nadie podría "
                          f"reconstruirlo para comprobar qué juzgó"}
    r = _git(repo, "rev-parse", commit if commit else "HEAD")
    if r.returncode != 0:
        return {"estado": BLOCKED, "commit": "", "path": "",
                "motivo": f"«{commit}» no resuelve a ningún commit"}
    sha = (r.stdout or "").strip()
    corto = sha[:12]
    final = raiz_destino / corto

    tmp = Path(tempfile.mkdtemp(prefix=f".publicando-{corto}-", dir=str(_preparar(raiz_destino))))
    try:
        _extraer(repo, sha, tmp)
        faltan = [f for f in IMPRESCINDIBLES if not (tmp / f).is_file()]
        if faltan:
            return {"estado": FAIL, "commit": sha, "path": "",
                    "motivo": f"la copia del commit no trae {faltan}: no es un motor"}
        digest = digest_motor(tmp)
        prueba = {"ejecutada": False, "ok": None, "resumen": "no se ejecutó (--sin-probar)"}
        if verificar:
            prueba = {"ejecutada": True, **_selftest(tmp)}
            if not prueba["ok"]:
                return {"estado": FAIL, "commit": sha, "path": "", "digest": digest,
                        "selftest": prueba,
                        "motivo": f"la copia no se prueba a sí misma: {prueba['resumen'][:160]}"}
        write_json(tmp / MANIFIESTO, {
            "schema": SCHEMA,
            "_que_es": ("De que commit salio este motor, que huella tiene y si se probo a si "
                        "mismo antes de recibir a nadie. verified=false NO impide usarlo: lo dice."),
            "commit": sha,
            "engine_digest": digest,
            "verified": bool(prueba.get("ok")),
            "selftest": prueba,
            "published_at": now(),
            "published_by": (os.environ.get("SUDO_USER") or os.environ.get("USER")
                             or os.environ.get("USERNAME", "")),
            "source": str(Path(repo).resolve()),
        })
        if final.exists():
            # Republicar el mismo commit es idempotente: la copia nueva sustituye a la vieja,
            # y son bit a bit la misma salvo el manifiesto.
            shutil.rmtree(final, ignore_errors=True)
        tmp.replace(final)
        tmp = None                                                      # ya no hay que limpiar
    except (OSError, RuntimeError) as exc:
        return {"estado": FAIL, "commit": sha, "path": "",
                "motivo": f"no se pudo publicar: {type(exc).__name__}: {exc}"}
    finally:
        if tmp is not None:
            shutil.rmtree(tmp, ignore_errors=True)

    activado = usar(corto, destino=raiz_destino) if activar else {"estado": PASS, "motivo": ""}
    if activado["estado"] != PASS:
        return {"estado": activado["estado"], "commit": sha, "path": str(final),
                "digest": digest, "selftest": prueba,
                "motivo": f"publicado, pero no activado: {activado['motivo']}"}
    return {"estado": PASS, "motivo": "", "commit": sha, "path": str(final), "digest": digest,
            "selftest": prueba, "activado": activar}


def _preparar(raiz_destino: Path) -> Path:
    raiz_destino.mkdir(parents=True, exist_ok=True)
    return raiz_destino


def ruta_vigente(destino: Path | None = None) -> Path:
    return (Path(destino) if destino else raiz()) / NOMBRE_VIGENTE


def usar(corto: str, *, destino: Path | None = None) -> dict:
    """Apunta `current` a ese motor. Es lo que mueve a TODOS los espacios a la vez."""
    raiz_destino = _preparar(Path(destino) if destino else raiz())
    objetivo = raiz_destino / corto
    if not (objetivo / "core" / "guard.py").is_file():
        return {"estado": BLOCKED, "motivo": f"no hay motor publicado «{corto}» en {raiz_destino}"}
    enlace = raiz_destino / NOMBRE_VIGENTE
    try:
        tmp = raiz_destino / f".{NOMBRE_VIGENTE}.nuevo"
        if tmp.is_symlink() or tmp.exists():
            _borrar(tmp)
        tmp.symlink_to(objetivo, target_is_directory=True)
        os.replace(tmp, enlace)                       # atómico: nadie ve un `current` a medias
    except (OSError, NotImplementedError) as exc:
        # Windows sin privilegios de enlace simbólico. Se copia, y se DICE que se copió: con
        # copia, `use` deja de ser atómico y republicar exige volver a copiar.
        try:
            _borrar(enlace)
            shutil.copytree(objetivo, enlace)
        except OSError as exc2:
            return {"estado": FAIL, "motivo": f"no se pudo apuntar a «{corto}»: {exc} / {exc2}"}
        return {"estado": PASS, "motivo": "", "corto": corto, "enlace": False,
                "aviso": "sin enlace simbólico: `current` es una COPIA, y cambiarla no es atómico"}
    return {"estado": PASS, "motivo": "", "corto": corto, "enlace": True}


def _borrar(p: Path) -> None:
    if p.is_symlink() or p.is_file():
        p.unlink()
    elif p.is_dir():
        shutil.rmtree(p)


def vigente(destino: Path | None = None) -> dict | None:
    """Qué motor están usando los lanzadores, o `None` si no hay ninguno publicado."""
    import json

    enlace = ruta_vigente(destino)
    if not (enlace / "core" / "guard.py").is_file():
        return None
    doc = {}
    try:
        doc = json.loads((enlace / MANIFIESTO).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        doc = {"schema": "", "commit": "", "verified": None,
               "_problema": "el motor vigente no tiene manifiesto legible"}
    doc["path"] = str(enlace.resolve() if enlace.is_symlink() else enlace)
    doc["home"] = str(enlace)
    return doc


def publicados(destino: Path | None = None) -> list:
    """Los motores disponibles, del más reciente al más antiguo por fecha de publicación."""
    import json

    raiz_destino = Path(destino) if destino else raiz()
    if not raiz_destino.is_dir():
        return []
    out = []
    for d in raiz_destino.iterdir():
        if not d.is_dir() or d.is_symlink() or d.name.startswith("."):
            continue
        try:
            doc = json.loads((d / MANIFIESTO).read_text(encoding="utf-8"))
        except (OSError, ValueError):
            doc = {"commit": "", "published_at": "", "verified": None,
                   "_problema": "sin manifiesto legible"}
        doc["corto"] = d.name
        out.append(doc)
    return sorted(out, key=lambda x: x.get("published_at") or "", reverse=True)


def home_para_lanzadores(repo: Path, destino: Path | None = None) -> dict:
    """A qué `HARNESS_HOME` debe apuntar un lanzador nuevo, y por qué.

    Si hay motor publicado, ése — es el que separa «lo que estoy escribiendo» de «lo que está
    juzgando». Si no lo hay, el árbol, **diciéndolo**: es el comportamiento anterior, y no se
    hereda en silencio.
    """
    v = vigente(destino)
    if v is not None:
        return {"home": Path(v["home"]), "publicado": True, "commit": v.get("commit", ""),
                "motivo": ""}
    return {"home": Path(repo).resolve(), "publicado": False, "commit": "",
            "motivo": ("no hay motor publicado: los lanzadores apuntarán al ÁRBOL DE TRABAJO, "
                       "y cualquier edición a medias gobierna los espacios en caliente. "
                       "Se cierra con `refuto engine publish`")}
