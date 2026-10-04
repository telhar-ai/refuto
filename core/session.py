# -*- coding: utf-8 -*-
"""Sesión interactiva gobernada. Abrir un agente en modo conversación, con las protecciones puestas.

Por qué esto no es «lanzar el CLI y ya»
---------------------------------------
Un agente abierto a pelo en un repositorio empieza sin saber tres cosas que refuto sí sabe:
qué se está construyendo, qué no puede tocar, y qué se le va a exigir al terminar. Sin eso,
descubre las restricciones chocando contra ellas —y cada choque es una vuelta perdida.

Lo que este módulo hace antes de abrir la sesión:

    1. comprueba que el guardián está enganchado en la ruta que ese runtime usa de verdad
    2. compone un informe de sesión: dónde está, qué specs hay, qué está protegido y qué puertas
       correrán
    3. lo inyecta como prompt de sistema, para que el agente empiece sabiéndolo
    4. registra la apertura y el cierre en el diario

Lo que NO hace: relajar nada. La sesión interactiva corre con la misma política que la
desatendida. Un modo «para trabajar cómodo» que apaga el guardián no es un modo: es una puerta
trasera con nombre amable.
"""

from __future__ import annotations

import json
import os
import re
import subprocess
from dataclasses import dataclass, field
from pathlib import Path

from core.evidence import append_event
from core.model import KIND_SESSION, new_id, now
from core import metodo as _metodo
from core.proc import TEXT_IO, interpreter


@dataclass
class SessionPlan:
    workspace: Path
    runtime: str
    run_id: str
    brief: str = ""
    argv: list = field(default_factory=list)
    warnings: list = field(default_factory=list)
    blockers: list = field(default_factory=list)
    brief_path: Path | None = None
    #: A dónde va a hablar esta sesión, y si eso es lo que la persona cree.
    routing: dict = field(default_factory=dict)
    clean_provider: bool = False


#: Dónde puede estar el documento de requisitos DENTRO de una especificación. La convención
#: SDD lo mete en `especificacion/`; las demás lo dejan en la raíz de la spec.
SPEC_DOC_DIRS = (".", "especificacion", "specification")


def _elegir_spec(specs: list, pedido: str, workspace: Path) -> tuple:
    """La especificación pedida, o el motivo de no poder elegir UNA. Nunca una al azar.

    Elegir la primera de varias homónimas es el peor resultado posible: el agente recibe una
    especificación, la trata como la autoridad del espacio, y nadie se entera de que había
    trece. Medido en un espacio real: de 20 especificaciones, 13 se llamaban igual —la misma,
    en trece árboles de trabajo del mismo repositorio— y otras 2 compartían otro nombre.
    Pedirla por su nombre devolvía la de un árbol de trabajo cualquiera, sin decir nada.

    Ante la duda no se elige: se declara la duda y se pide la ruta, que sí distingue.
    """
    candidatos = list(dict.fromkeys(
        s for s in specs if s.name == pedido or str(s).endswith(pedido)))
    if not candidatos:
        nombres = sorted({s.name for s in specs})
        return None, (f"no hay ninguna especificación llamada «{pedido}». "
                      f"Hay: {', '.join(nombres) or 'ninguna'}")
    if len(candidatos) > 1:
        rutas = "; ".join(str(c.relative_to(workspace)) for c in candidatos)
        return None, (f"«{pedido}» no identifica una sola especificación: coincide con "
                      f"{len(candidatos)}. Son homónimas y viven en repositorios distintos, "
                      f"así que el nombre no basta — desambigüe con la ruta. Son: {rutas}")
    return candidatos[0], ""


def _bajo_oculto(p: Path, workspace: Path, pattern: str = "") -> bool:
    """¿Llegó `p` a un directorio OCULTO que el patrón no nombraba?

    La distinción importa y antes no se hacía. `*` de pathlib casa también lo oculto, así que
    `*/*/sdd/…` alcanzaba `.worktrees/<rama>/sdd/…` y cada árbol de trabajo contaba como otra
    especificación. Pero descartar «todo segmento oculto» a secas descartaría también
    `.kiro/specs/…`, que es una convención legítima y está **escrita** en el patrón.

    La regla exacta: un segmento oculto alcanzado por un COMODÍN no cuenta; uno escrito
    literalmente en el patrón, sí. Como `*` casa exactamente un segmento, patrón y ruta
    relativa tienen el mismo número de partes y se comparan posición a posición.

    Sin patrón se conserva el comportamiento antiguo (cualquier segmento oculto descarta),
    que es lo que esperan quienes llaman sin patrón.
    """
    try:
        partes = p.relative_to(workspace).parts[:-1]
    except ValueError:
        return False
    if not pattern:
        return any(s.startswith(".") for s in partes)
    pat = Path(pattern).parts[:-1]
    if len(pat) != len(partes):
        return any(s.startswith(".") for s in partes)
    # `strict=True`: las dos secuencias se han comprobado del mismo largo tres líneas arriba,
    # así que un desajuste sería un defecto y no un caso a truncar en silencio.
    return any(s.startswith(".") and "*" in ps
               for s, ps in zip(partes, pat, strict=True))


#: Lo que NUNCA se versiona de `.harness/`, y por qué cada uno.
#:
#: Esta lista tenía dos entradas —`evidence/` y `state/`— y esa omisión es el defecto de
#: producto con la peor consecuencia medida de todo el motor: cada espacio gobernado versionaba
#: por omisión **la instantánea de la máquina de quien lo instaló y las notas de memoria del
#: proyecto**. En el propio repositorio de este motor acabaron, sin seguimiento y a un
#: `git add -A` de entrar, dos notas de memoria sobre el sistema de un cliente; y el informe de
#: sesión las incrustaba además en `state/session-brief.md`.
#:
#:     evidence/     diario de ejecución: órdenes reales, uid, rutas de $HOME. Se regenera.
#:     state/        el informe de sesión, reescrito en cada apertura. Dejaba el árbol sucio
#:                   para siempre, y lleva dentro la memoria y las rutas del espacio.
#:     context/      instantánea de ESTA máquina: binarios, remotos, rutas absolutas.
#:     memory/       lo que el agente aprendió del proyecto. Puede ser de un cliente; la
#:                   decisión de publicarlo es de una persona, no del valor por omisión.
#:     backup/       copias de los ficheros ajenos que `policy wire` tocó, con sus rutas.
#:     bin/          el lanzador generado, con `HARNESS_HOME` absoluto e `installed_by`.
#:     binding.json  generado: rutas absolutas y remotos, a veces privados.
#:
#: Lo que SÍ se versiona: `harness.manifest.json`, `harness.lock.json` y `policy.json` — lo
#: que el espacio DECLARA, que es justamente lo que otra persona necesita para reproducirlo.
GITIGNORE_ENTRIES = ("evidence/", "state/", "context/", "memory/", "backup/", "bin/",
                     "binding.json")


def ensure_gitignore(harness_dir: Path) -> bool:
    """Garantiza que `.harness/.gitignore` excluye todo lo generado o local. Idempotente.

    Las dos rutas de instalación escribían contenidos distintos —una `evidence/` y `state/`,
    la otra sólo `evidence/`— y ninguna corregía un `.gitignore` que ya existiera: el
    `state/session-brief.md`, que se reescribe en cada sesión, entraba en el commit y dejaba el
    árbol sucio para siempre. Se llama también al abrir sesión, para que los espacios ya
    instalados converjan sin reinstalar — que es cómo esta ampliación llega a los que ya
    estaban mal.

    Añade, nunca quita: una línea que alguien escribió a mano se respeta.

    Devuelve True si tuvo que escribir.
    """
    gi = harness_dir / ".gitignore"
    try:
        # Bytes, no texto: `read_text` traduce CRLF y la escritura devolvía el fichero entero
        # normalizado. Se añade con el fin de línea que ya use.
        actual = gi.read_bytes().decode("utf-8") if gi.exists() else ""
    except (OSError, UnicodeDecodeError):
        return False
    lineas = {ln.strip() for ln in actual.splitlines()}
    faltan = [e for e in GITIGNORE_ENTRIES if e not in lineas]
    if not faltan:
        return False
    fin = "\r\n" if "\r\n" in actual else "\n"
    sep = "" if not actual or actual.endswith("\n") else fin
    try:
        gi.write_bytes((actual + sep + "".join(f"{e}{fin}" for e in faltan)).encode("utf-8"))
    except OSError:
        return False
    return True


class Sesiones(list):
    """Las otras sesiones vivas, y —si no se pudo mirar— por qué no se pudo.

    Es una `list` para no romper a quien ya la recorre, pero lleva `ciego`: el motivo por el
    que la tabla de procesos no se pudo leer. Una lista vacía con `ciego` puesto significa «no
    lo sé», no «no hay nadie», y son cosas distintas: la primera no autoriza a concluir.

    Existe por el fallo que arregla. `sesiones_vivas` devolvía `[]` tanto cuando no había otra
    sesión como cuando `ps` no se podía ejecutar, y quien llamaba sólo avisaba si la lista
    traía algo. En un entorno donde inspeccionar procesos está restringido, la sesión abría
    declarando silenciosamente que estaba sola —que es justo la afirmación que este arnés
    existe para no dejar hacer sin medirla—.
    """

    def __init__(self, items=(), ciego: str = ""):
        super().__init__(items)
        self.ciego = ciego


def sesiones_vivas(workspace: Path) -> Sesiones:
    """Otras sesiones gobernadas abiertas AHORA sobre este mismo espacio: [(pid, orden)].

    Se mide en la tabla de procesos, no en el diario: una sesión que murió sin cerrar deja un
    `session/open` huérfano, y el diario diría que sigue viva. Lo que identifica a una sesión
    gobernada es que su orden lleva el informe de ESTE espacio.

    Por qué importa: dos sesiones sobre el mismo árbol se pisan sin saberlo. Medido en un
    espacio real: una cerró un plan a las 21:01 y a las 21:04 la otra añadió ficheros que lo
    dejaron sin validez; nadie lo vio hasta rehacer la medición.

    Si `ps` no se puede ejecutar, el resultado viene vacío **y con `ciego` puesto**. Vacío y
    ciego no es «está sola»: es «no se pudo comprobar», y quien llama tiene que decirlo.
    """
    # Anclada por delante: la ruta empieza un argumento (tras espacio o `=`). Como subcadena
    # suelta, `/b/x/pub/.harness/state/` contenía a `/x/pub/.harness/state/`.
    marca = re.compile(r"(?:^|[\s=])" + re.escape(str(workspace / ".harness" / "state") + os.sep))
    try:
        out = subprocess.run(["ps", "-Ao", "pid=,ppid=,command="], capture_output=True,
                             timeout=5, **TEXT_IO).stdout
    except (OSError, subprocess.SubprocessError) as exc:
        return Sesiones(ciego=f"no se pudo leer la tabla de procesos ({type(exc).__name__}: "
                              f"{exc}). Sin ella no se puede afirmar que esta sesión esté sola "
                              f"sobre el espacio.")
    tabla = {}
    for linea in out.splitlines():
        partes = linea.split(None, 2)
        if len(partes) == 3 and partes[0].isdigit() and partes[1].isdigit():
            tabla[int(partes[0])] = (int(partes[1]), partes[2])
    # Toda la ascendencia, no sólo el padre: `refuto chat --dry-run` lanzado DESDE una sesión
    # viva tiene a esa sesión de abuelo (agente → shell → python), y no es «otra».
    propias, pid = {os.getpid(), os.getppid()}, os.getppid()
    while pid in tabla and tabla[pid][0] > 1 and tabla[pid][0] not in propias:
        pid = tabla[pid][0]
        propias.add(pid)
    vivas = []
    for pid, (_, orden) in sorted(tabla.items()):
        if pid not in propias and "--append-system-prompt-file" in orden and marca.search(orden):
            vivas.append((pid, orden))
    return Sesiones(vivas)


def _spec_dir(doc: Path) -> Path:
    """El directorio de la especificación a la que pertenece este documento de requisitos.

    Hay dos formas, y se distinguen por el nombre del directorio que contiene al documento:

        specs/<nombre>/requirements.md                       → la spec es `<nombre>/`
        sdd/espacios/<nombre>/especificacion/requirements.md → la spec es `<nombre>/`

    Así un patrón nuevo declarado por un espacio no necesita además declarar cuántos niveles
    hay que subir: lo dice su propia estructura.
    """
    if doc.parent.name in SPEC_DOC_DIRS and doc.parent.name != ".":
        return doc.parent.parent
    return doc.parent


def _specs(workspace: Path, incluir_ocultos: bool = False) -> list:
    """Especificaciones del espacio, sea cual sea la convención que use.

    De dónde salen los patrones
    ---------------------------
    De `core.context.spec_globs`, que los lee del manifiesto (`specs.profiles` o
    `specs.globs`) y sólo si no hay nada declarado usa las tres convenciones conocidas.
    Estuvieron cableados a la distribución de UN espacio, y en cualquier otro el informe de
    sesión decía «No hay ninguna» teniendo especificaciones completas delante: el agente
    arrancaba sin la única autoridad que tenía, que es justo lo que el informe evita.

    `incluir_ocultos=True` sólo cuando se pide una por nombre (`--spec`): una copia en un
    directorio contenedor (`.worktrees/<rama>`) puede divergir, y elegir por nombre sin verla
    sería elegir a ciegas. Para contar y para elegir sola, no: allí una copia de trabajo no es
    otra especificación.

    `*` de pathlib SÍ casa directorios ocultos, así que `*/*/…` alcanzaba
    `.worktrees/<rama>/sdd/…` y cada árbol de trabajo contaba como otra especificación. Medido
    en un espacio real con 21 árboles de trabajo: 54 especificaciones contándolos y 7 sin
    ellos, es decir, el 87 % del recuento era una misma spec repetida.
    """
    from core.context import spec_globs

    found: list = []
    for pattern in spec_globs(workspace):
        for p in sorted(workspace.glob(pattern)):
            if p.is_file() and (incluir_ocultos or not _bajo_oculto(p, workspace, pattern)):
                found.append(_spec_dir(p))

    seen, out = set(), []
    for d in found:
        if d not in seen:
            seen.add(d)
            out.append(d)
    return out


def resources(workspace: Path) -> dict:
    """Qué hay **de verdad** en este espacio, y cómo se invoca desde aquí.

    El informe decía `python3 refuto.py verify`. En un espacio gobernado desde fuera, ese
    archivo no existe: refuto vive en otro sitio. El agente lo comprobó, no lo encontró, y
    gastó una vuelta averiguando qué ejecutar de verdad.

    Un informe que promete comandos inexistentes es peor que uno que no promete nada: el agente
    los intenta. Aquí sólo se enumera lo que existe, con la ruta con la que se invoca **desde
    este directorio**.
    """
    from core import launcher

    out: dict = {"comandos": [], "herramientas": [], "agentes": [], "skills": [],
                 "verificador": "", "harness_home": ""}

    # Cómo se invoca refuto DESDE AQUÍ. No se asume que esté al lado.
    meta = workspace / launcher.BIN / "installed.json"
    home = ""
    if meta.is_file():
        try:
            home = json.loads(meta.read_text(encoding="utf-8")).get("harness_home", "")
        except (OSError, ValueError):
            home = ""
    if not home:
        home = str(Path(__file__).resolve().parents[1])
    out["harness_home"] = home
    hp = Path(home) / "refuto.py"
    if hp.is_file():
        invocacion = f"{interpreter()} {hp}"
        out["comandos"] = [
            (f"{invocacion} verify", "ejecuta las puertas y emite evidencia"),
            (f"{invocacion} status", "qué falta y qué espera a una persona"),
            (f"{invocacion} plan", "qué haría, quién y con qué puertas"),
        ]

    # El verificador propio del espacio, si lo tiene. En un espacio SDD es EL juez.
    for cand in ("verificacion/verificar.py", "verification/verify.py"):
        if (workspace / cand).is_file():
            out["verificador"] = cand
            out["comandos"].insert(0, (f"{interpreter()} {cand}",
                                       "las puertas del núcleo SDD, aquí mismo"))
            break

    for d in ("herramientas", "scripts", "tools", "bin"):
        base = workspace / d
        if base.is_dir():
            out["herramientas"] += [f"{d}/{p.name}" for p in sorted(base.iterdir())
                                    if p.is_file() and p.suffix in (".py", ".sh")][:10]

    for d, patron in ((".kiro/agents", "*.json"), (".claude/agents", "*.md")):
        base = workspace / d
        if base.is_dir():
            out["agentes"] += [f"{d}/{p.name}" for p in sorted(base.glob(patron))]

    for d in (".kiro/skills", ".claude/skills"):
        base = workspace / d
        if base.is_dir():
            out["skills"] += [p.parent.name for p in sorted(base.glob("*/SKILL.md"))]
    return out


def _spec_summary(spec_dir: Path, workspace: Path) -> dict:
    """Qué hay en una especificación, sin leerla entera."""
    import re
    info = {"name": spec_dir.name if spec_dir != workspace else "(raíz)",
            "path": str(spec_dir.relative_to(workspace)) if spec_dir != workspace else ".",
            "documents": {}, "requirements": 0, "tasks_done": 0, "tasks_total": 0}
    for doc in ("requirements.md", "design.md", "tasks.md", "requisitos.md", "diseno.md",
                "tareas.md"):
        # El documento puede estar en la raíz de la spec o bajo `especificacion/` (SDD).
        p = next((spec_dir / d / doc for d in SPEC_DOC_DIRS if (spec_dir / d / doc).is_file()),
                 spec_dir / doc)
        if not p.is_file():
            continue
        text = p.read_text(encoding="utf-8", errors="ignore")
        info["documents"][doc] = len(text.splitlines())
        if doc.startswith(("requirements", "requisitos")):
            info["requirements"] = len(set(re.findall(r"\b(?:REQ|RF|RNF)-\d{1,4}\b", text)))
        if doc.startswith(("tasks", "tareas")):
            marks = re.findall(r"^\s*[-*]\s*\[([ xX])\]", text, re.M)
            info["tasks_total"] = len(marks)
            info["tasks_done"] = len([m for m in marks if m.lower() == "x"])
    return info


def task_context(workspace: Path, number: str, repo: str = "") -> tuple[dict, str]:
    """La tarea concreta que se va a trabajar, con su clasificación y su especificación.

    Es lo que convierte «abre una sesión» en «abre una sesión sobre ESTO». Sin ello, la primera
    vuelta de cada sesión se gasta explicando qué hay que hacer — que ya está escrito en la
    forja y en la spec del proyecto.
    """
    from core.classify import classify
    from core.forge import my_tasks, repo_of
    from core.roles import load as load_roles

    destino = repo or repo_of(workspace)
    if not destino:
        return {}, ("no se puede resolver el repositorio de esta tarea: use --repo owner/name")
    tareas, err = my_tasks(repo=destino, limit=60)
    if err:
        return {}, f"no se pudo consultar la forja: {err}"
    match = next((t for t in tareas if str(t.number) == str(number)), None)
    if match is None:
        disponibles = ", ".join(f"#{t.number}" for t in tareas) or "ninguna"
        return {}, (f"#{number} no está entre sus tareas abiertas en {destino}. "
                    f"Asignadas a usted: {disponibles}")
    c = classify(match, roles_disponibles=set(load_roles()))
    return {"task": match, "classification": c}, ""


def pending_summary(workspace: Path, *, limit: int = 8) -> tuple[list, str]:
    """Lo que está asignado en la forja, clasificado. Vacío si no hay sesión o no hay repo.

    Va en el informe porque abrir una sesión sin saber qué hay pendiente obliga a gastar la
    primera vuelta preguntándolo — y está escrito en un sitio que se puede consultar.
    """
    from core.classify import classify
    from core.forge import my_tasks, repo_of
    from core.roles import load as load_roles

    destino = repo_of(workspace)
    if not destino:
        return [], ""
    tareas, err = my_tasks(repo=destino, limit=limit)
    if err:
        return [], err
    disponibles = set(load_roles())
    return [(t, classify(t, roles_disponibles=disponibles)) for t in tareas], ""


def _memoria(workspace: Path, policy) -> list:
    """Lo que sesiones anteriores dejaron escrito, y cómo dejar más.

    Escribir memoria y no leerla es la mitad inútil del mecanismo, y era la mitad que había:
    `core.memory` sabe guardar notas por capas desde el principio, pero nada las traía de vuelta
    al arrancar. Una nota que nadie recupera es un fichero, no una memoria.

    Se traen las capas duraderas —`project`, `decision`, `domain`— y no `run`, que caduca en
    siete días y describe una ejecución que ya terminó. Las sustituidas no se traen: se
    conservan para saber qué se creyó, no para volver a creerlo.
    """
    from core.memory import DECISION, DIR, DOMAIN, PROJECT, Memory

    L: list = []
    try:
        notas = Memory(workspace).search(layers=[PROJECT, DECISION, DOMAIN])
    except OSError:
        return []

    escribible = bool(policy.is_writable(f"{DIR}/project/x.md"))

    if notas:
        L += ["## Lo que ya sabes de aquí", "",
              f"{len(notas)} nota(s) que dejaron sesiones anteriores en `{DIR}/`. No son "
              f"evidencia —se corrigen y envejecen— pero te ahorran volver a averiguarlo:", ""]
        for n in notas[:40]:
            cuerpo = " ".join(n.body.split())
            if len(cuerpo) > 300:
                cuerpo = cuerpo[:300] + "…"
            L.append(f"- **{n.key}** _({n.layer}"
                     + (f", {n.updated_at[:10]}" if n.updated_at else "") + ")_ — " + cuerpo)
            if n.why:
                L.append(f"    · _por qué_: {' '.join(n.why.split())[:200]}")
        if len(notas) > 40:
            L.append(f"- _(+{len(notas) - 40} nota(s) más; están en `{DIR}/`, sin recortar.)_")
        L.append("")
    elif escribible:
        L += ["## Tu memoria de este espacio", "",
              f"Está vacía: `{DIR}/` no tiene ninguna nota todavía. Todo lo que averigües en "
              f"esta sesión se perderá al cerrarla si no lo escribes.", ""]

    if escribible:
        L += ["**Cómo dejar memoria** — un fichero por nota, en la capa que le toca:", "",
              f"- `{DIR}/project/<clave>.md` — hechos del espacio que sobreviven a la sesión "
              f"(cómo se construye algo, qué rama está viva, dónde vive de verdad una pieza)",
              f"- `{DIR}/decision/<clave>.md` — qué se decidió y **por qué**. Lo más caro de "
              f"reconstruir, y lo que nadie vuelve a poder deducir del código",
              f"- `{DIR}/domain/<clave>.md` — conocimiento del negocio, con su fuente y su fecha",
              "",
              "Con encabezado `---` (`layer`, `key`, `why`, `source`, `updated_at`) y el cuerpo "
              "debajo. Escríbela **cuando lo averigües**, no al final: una sesión que se corta "
              "no deja nada. Y si descubres que una nota es falsa, no la borres — márcala "
              "`superseded_by`: perder la constancia de que alguien creyó eso es perder justo "
              "lo que evita volver a creerlo.", ""]
    return L


#: Runtimes en los que `refuto policy wire` sabe enganchar el guardián preventivo, con el
#: auditor que lo comprueba. Lo que NO está aquí no tiene guardián, y eso es una afirmación
#: sobre lo verificado: `gemini` genera `.gemini/hooks/harness-guard.json` pero nadie ha
#: comprobado que Gemini lea esa ruta, y el adapter de `opencode` declara él mismo que no
#: consta mecanismo de gancho previo a la escritura en la versión sondeada.
GUARDABLE = ("claude", "kiro", "antigravity")


def _guard_estado(workspace: Path, runtime: str) -> tuple[list, list, bool]:
    """¿Corre el guardián en esta sesión? Devuelve (bloqueos, avisos, sin_guardián).

    Qué se decidió aquí, y por qué
    ------------------------------
    La documentación afirma que `refuto chat` **se niega a abrir** si el guardián no está
    enganchado. El código sólo lo comprobaba para `claude`: en `kiro` bastaba con que el
    espacio no tuviera NINGÚN agente para que no se mirara nada (`if rep["agents"] and …`), y
    para `gemini` y `opencode` no se comprobaba absolutamente nada. Tres de los cuatro
    runtimes abrían una «sesión gobernada» sin gobierno mientras el manual decía lo contrario.

    Se elige **bloquear**, no avisar. Un aviso al abrir lo lee una persona una vez y la sesión
    sigue corriendo horas sin control; y sobre todo, una sesión sin guardián no es una sesión
    gobernada con una advertencia: es una sesión no gobernada, y llamarla de otro modo es la
    clase exacta de afirmación que este motor existe para impedir.

    Para los runtimes sin enganche verificado queda una salida, y es DECLARADA, no una
    bandera cómoda de línea de órdenes:

        "agents": {"gemini": {"required": false, "unguarded": true}}

    Declararlo no arregla nada: lo hace visible. Queda escrito en el manifiesto —que se
    versiona y se revisa—, sale como aviso en cada arranque, y el informe de sesión se lo
    dice al agente en su propia sección. Una excepción con nombre se puede leer y discutir;
    un agujero, no.
    """
    from core.context import read_manifest
    from core.wire import audit as wire_audit, audit_antigravity, audit_claude

    bloqueos, avisos = [], []
    if runtime == "claude":
        # Se delega en el auditor en vez de buscar una cadena a mano: la comprobación previa
        # buscaba `core.guard`, y al pasar al lanzador el gancho dejó de contener esa cadena.
        # Un chequeo que conoce sólo una forma del control caduca con el control.
        cl = audit_claude(workspace)
        if not cl["wired"]:
            bloqueos.append(f"el guardián no está enganchado para Claude Code: {cl['reason']}. "
                            f"Ejecute `refuto policy wire --agent claude`.")
        return bloqueos, avisos, bool(bloqueos)

    if runtime == "kiro":
        rep = wire_audit(workspace)
        if not rep["agents"]:
            # Cero agentes NO es «todo enganchado». El guardián de Kiro vive dentro de los
            # ficheros de `.kiro/agents/`: sin ninguno, no hay dónde ponerlo y la sesión
            # correría sin control. Antes esto pasaba como bueno por una condición que sólo
            # miraba la proporción.
            bloqueos.append(
                "no hay ningún agente en `.kiro/agents/`: el guardián de Kiro se engancha "
                "dentro de esos ficheros, así que no hay dónde ponerlo y esta sesión correría "
                "sin control preventivo. Cree un agente y ejecute `refuto policy wire`.")
        elif rep["wired"] < rep["agents"]:
            bloqueos.append(f"el guardián sólo está enganchado en {rep['wired']}/{rep['agents']} "
                            f"agentes de Kiro. Ejecute `refuto policy wire`.")
        return bloqueos, avisos, bool(bloqueos)

    if runtime == "antigravity":
        ag = audit_antigravity(workspace)
        if not ag["wired"]:
            bloqueos.append(f"el guardián no está enganchado para Antigravity: {ag['reason']}. "
                            f"Ejecute `refuto policy wire --agent antigravity`.")
        return bloqueos, avisos, bool(bloqueos)

    # Runtime sin enganche verificado.
    entrada = (read_manifest(workspace).get("agents") or {}).get(runtime) or {}
    if entrada.get("unguarded") is True:
        avisos.append(
            f"«{runtime}» abre SIN guardián preventivo: refuto no sabe enganchar un control "
            f"previo a la escritura en este runtime, y el manifiesto lo declara aceptado "
            f"(`agents.{runtime}.unguarded: true`). La política de este espacio NO se aplica "
            f"en esta sesión: se aplica la disciplina del agente, que es otra cosa.")
        return bloqueos, avisos, True

    bloqueos.append(
        f"«{runtime}» no tiene guardián enganchable en refuto: `policy wire` sólo sabe "
        f"enganchar {', '.join(GUARDABLE)}, y para {runtime} no consta un mecanismo de gancho "
        f"previo a la escritura verificado. Abrir aquí sería abrir una sesión SIN control "
        f"mientras se la llama gobernada. Use un runtime con guardián, o declare la excepción "
        f"en el manifiesto: `agents.{runtime}.unguarded: true` — queda escrita, se avisa en "
        f"cada arranque y el informe se lo dice al agente.")
    return bloqueos, avisos, True


def build_brief(workspace: Path, *, runtime: str, role_id: str = "",
                spec: str = "", task: dict | None = None,
                pending: list | None = None) -> tuple[str, list, list]:
    """Compone el informe de sesión. Devuelve (texto, avisos, bloqueos)."""
    from core.binding import read as read_binding
    from core.policy import PoliticaIlegible, Policy
    from core.roles import load as load_roles
    from core import launcher

    warnings, blockers = [], []
    bound = read_binding(workspace)
    policy_file = workspace / ".harness" / "policy.json"
    try:
        policy = Policy.load(policy_file) if policy_file.is_file() else Policy.default()
    except PoliticaIlegible as exc:
        policy = Policy.default()
        blockers.append(f"la política del espacio no es de este motor: {exc}")
    if not policy_file.is_file():
        warnings.append("no hay .harness/policy.json: se usa la política por defecto. "
                        "Ejecute `refuto init` para fijarla en el espacio.")

    guard_blockers, guard_warnings, sin_guardian = _guard_estado(workspace, runtime)
    blockers += guard_blockers
    warnings += guard_warnings

    # El lanzador tiene que existir y apuntar a un harness que siga ahí, sea cual sea el runtime.
    lz = launcher.check(workspace)
    if not lz["ok"]:
        blockers.append(f"el lanzador del guardián no está operativo: {lz['reason']}")

    specs = _specs(workspace)
    chosen = None
    if spec:
        chosen, porque = _elegir_spec(_specs(workspace, incluir_ocultos=True), spec,
                                      workspace)
        if chosen is None:
            blockers.append(porque)
    elif len(specs) == 1:
        chosen = specs[0]
    elif len(specs) > 1:
        # Listar 20 nombres con 13 repetidos no ayuda a elegir: agrupa, y marca cuáles exigen
        # la ruta porque su nombre no distingue.
        por_nombre: dict = {}
        for s_ in specs:
            por_nombre.setdefault(s_.name, []).append(s_)
        piezas = [n if len(v) == 1 else f"{n} (×{len(v)})"
                  for n, v in sorted(por_nombre.items())]
        ambiguos = sum(1 for v in por_nombre.values() if len(v) > 1)
        cola = (" Los marcados con «×» están repetidos en varios repositorios: para ésos el "
                "nombre no basta, hace falta la ruta." if ambiguos else "")
        warnings.append(f"hay {len(specs)} especificaciones bajo {len(por_nombre)} nombres: "
                        f"{', '.join(piezas)}. Elija con --spec.{cola}")

    roles = load_roles()
    # Si hay tarea y nadie pidió rol, el rol lo decide la clasificación. Ese es el punto: no
    # hace falta definirlo si el proyecto ya declaró la disciplina.
    if task and not role_id:
        c = task.get("classification")
        if c is not None and c.primary:
            role_id = c.primary
            if c.question:
                warnings.append(c.question)
    role = roles.get(role_id) if role_id else None
    if role_id and role is None:
        blockers.append(f"el rol «{role_id}» no existe. Hay: {', '.join(sorted(roles))}")

    L = ["# Sesión gobernada por refuto", ""]
    L += ["Estás trabajando dentro de un espacio gobernado. Lo que sigue no es contexto de "
          "cortesía: describe restricciones que se aplican de verdad, fuera de tu control.", ""]

    if task:
        t, c = task["task"], task["classification"]
        L += [f"## La tarea: {t.key or '#' + str(t.number)} — {t.title}", "",
              f"`{t.repo}#{t.number}` · {t.url}", ""]
        for campo in ("Tipo", "Épica", "Horas", "Estado spec", "Criterio de salida S0 que cierra",
                      "Depende de", "Alimenta a", "Verificación interna"):
            if t.fields.get(campo):
                L.append(f"- **{campo}**: {t.fields[campo][:200]}")
        if t.spec_path:
            existe = (workspace / t.spec_path).is_file()
            L += ["", f"- **Especificación**: `{t.spec_path}`"
                      + ("" if existe else "  ⚠ no está en este espacio; clone el repositorio "
                                           "correcto antes de trabajar")]
            if existe:
                hermanas = [n for n in ("plan.md", "tasks.md")
                            if (workspace / t.spec_path).parent.joinpath(n).is_file()]
                if hermanas:
                    L.append(f"- **Junto a ella**: {', '.join('`' + h + '`' for h in hermanas)}")
                L += ["", "**Léela entera antes de proponer nada.** Está refinada y es la "
                          "autoridad: si tu idea la contradice, la contradicción se declara — "
                          "no se resuelve escribiendo algo que la ignore."]
        if t.body_excerpt:
            L += ["", "> " + t.body_excerpt.split("\n")[0][:220]]
        L += ["", f"_Rol asignado por clasificación: **{c.primary or '—'}** "
                  f"({c.confidence} · {c.source} · evidencia {c.evidence}). "
                  f"Los demás roles implicados: {', '.join(c.roles[1:]) or 'ninguno'}._", ""]

    L += ["## Dónde estás", ""]
    core = bound.get("sdd_core") or {}
    repo = bound.get("repository") or {}
    if core:
        L.append(f"- **Núcleo SDD**: `{core.get('path')}` versión {core.get('version') or '?'}, "
                 f"anclado al commit `{(core.get('commit') or '')[:12]}`. Es el estándar "
                 f"exigible: **no se edita aquí**; un cambio se propone al núcleo.")
    if repo:
        L.append(f"- **Repositorio**: `{repo.get('path')}`")
    L.append(f"- **Espacio de trabajo**: `{workspace}`")
    L.append("")

    # QUÉ es el espacio, no sólo qué está prohibido en él. Va aquí arriba a propósito: es el
    # marco con el que se lee todo lo demás. Sin esto el informe describía un gobierno sin
    # objeto —reglas, puertas y evidencias sobre un proyecto del que no decía nada—, y el
    # agente empezaba cada sesión reconstruyendo a mano lo que ya estaba medido en el disco.
    # Si falla, se avisa y se sigue: quedarse sin sesión por no poder describirla sería peor.
    # CONTRA QUÉ se trabaja, antes que qué hay en el disco. Un inventario de código sin saber a
    # qué entorno apunta produce exactamente el fallo del 2026-09-06: medir producción creyendo
    # que es desarrollo, y firmar el diagnóstico. Va primero porque es el marco con el que se
    # lee todo sondeo posterior.
    try:
        from core import environments
        L += environments.seccion(workspace)
    except Exception as exc:                                            # noqa: BLE001
        warnings.append(f"no se pudieron leer los entornos declarados "
                        f"({type(exc).__name__}: {exc}); el informe no dice contra qué se "
                        f"trabaja. NO sondee nada hasta resolverlo.")

    try:
        from core import knowledge
        L += knowledge.seccion(workspace)
    except Exception as exc:                                            # noqa: BLE001
        warnings.append(f"no se pudo inventariar el espacio ({type(exc).__name__}: {exc}); "
                        f"el informe va sin la sección de arquitectura.")

    # El MÉTODO del espacio va tras el inventario y antes de la memoria: primero dónde estás
    # y qué hay, luego CÓMO se trabaja aquí, y sólo después lo que ya se sabe. Un agente que
    # recibe hechos sin disciplina los usa como quiera; medido en un espacio real, cuyo
    # informe de 104 líneas no mencionaba ni una vez las siete etapas que ese espacio declara
    # ni la escala de evidencia con la que se juzga su trabajo.
    try:
        from core import metodo
        L += metodo.seccion(workspace)
    except Exception as exc:                                            # noqa: BLE001
        warnings.append(f"no se pudo leer el método del espacio ({type(exc).__name__}: "
                        f"{exc}); el informe va sin la disciplina con la que se trabaja aquí.")

    L += _memoria(workspace, policy)

    if chosen is not None:
        s = _spec_summary(chosen, workspace)
        L += [f"## Especificación activa: `{s['name']}`", "",
              f"En `{s['path']}`:", ""]
        for doc, lines in sorted(s["documents"].items()):
            L.append(f"- `{doc}` — {lines} líneas")
        if s["requirements"]:
            L.append(f"- **{s['requirements']} requisitos** con identificador")
        if s["tasks_total"]:
            L.append(f"- **{s['tasks_done']}/{s['tasks_total']} tareas** marcadas como hechas")
        L += ["", "**Léela antes de proponer nada.** La especificación es la autoridad; si tu "
                  "idea la contradice, la contradicción se declara — no se resuelve escribiendo "
                  "código que la ignore.", ""]
    elif specs:
        repetidos: dict = {}
        for s_ in specs:
            repetidos.setdefault(s_.name, []).append(s_)
        L += ["## Especificaciones disponibles", ""]
        for s_ in specs:
            marca = " · **homónima**" if len(repetidos[s_.name]) > 1 else ""
            L.append(f"- `{s_.relative_to(workspace)}`{marca}")
        if any(len(v) > 1 for v in repetidos.values()):
            L += ["", "_Las marcadas como homónimas comparten nombre con otra: son la misma "
                      "especificación versionada en varios repositorios o árboles de trabajo, "
                      "y **no tienen por qué decir lo mismo**. Nombrarlas por su nombre a secas "
                      "no elige una; hace falta la ruta._"]
        L.append("")
    else:
        L += ["## Especificaciones", "",
              "No hay ninguna en este espacio. Si vas a construir algo, la especificación es lo "
              "primero, no la documentación de lo que ya hiciste.", ""]

    if role is not None:
        from core.roles import KNOWN_CONSTRAINTS
        L += [f"## Tu papel: `{role.id}`", "", f"{role.purpose}", ""]
        if role.output_contract:
            L.append(f"**Debes producir:** {', '.join(role.output_contract)}. Sin esos "
                     f"artefactos la fase no ha terminado, digas lo que digas.")
        if role.constraints:
            L += ["", "**No puedes:**"]
            L += [f"- {KNOWN_CONSTRAINTS.get(c, c)}" for c in role.constraints]
        if role.quality_gates:
            L += ["", f"**Al terminar se ejecutan:** {', '.join(role.quality_gates)}."]
        if role.human_review:
            L.append(f"**Requiere {role.human_review}**: tu salida no cierra la fase por sí sola.")
        L.append("")

    L += ["## Lo que no puedes tocar", ""]
    if sin_guardian:
        # El informe NO puede prometer un control que esta sesión no tiene. Decirle al agente
        # «hay un programa fuera de tu control» cuando no lo hay es enseñarle a confiar en una
        # barrera imaginaria, y la primera vez que la cruce sin resistencia aprenderá que el
        # resto del informe tampoco es fiable.
        L += ["**En esta sesión NO corre el guardián preventivo.** Este runtime no tiene un "
              "gancho de control previo a la escritura que refuto sepa enganchar, y el "
              "espacio lo ha declarado aceptado. Lo que sigue es la política del espacio, y "
              "aquí es una **instrucción tuya**, no un programa que te detenga: nadie va a "
              "interceptar la escritura si la intentas. Respétala igual, y si necesitas tocar "
              "algo de esta lista, dilo y pide la decisión en vez de escribirlo.", ""]
    else:
        L += ["Un guardián intercepta cada escritura **y cada orden** **antes** de que ocurra. "
              "No es una instrucción que puedas olvidar bajo presión de contexto: es un "
              "programa fuera de tu control, y cada intento bloqueado queda registrado.", ""]
    # SIN recortar. Estaba en `[:12]`, y en un espacio real eso escondía 13 de las 25 rutas
    # protegidas. Medido sobre una semana de diario: 28 rechazos cayeron sobre reglas ocultas,
    # exactamente los mismos que sobre la única regla visible. Es decir, la mitad de los
    # choques los causaba el recorte.
    # Una lista que se corta en silencio se lee como una lista completa.
    for pattern in policy.protected_paths:
        L.append(f"- `{pattern}`")
    L += ["", "Resuelve la ruta antes de compararla, así que `..` y los enlaces simbólicos no "
              "la sortean.", ""]
    if policy.writable_paths:
        L += ["Con estas excepciones, que **sí** puedes escribir aunque caigan dentro de lo "
              "anterior:", ""]
        L += [f"- `{p}`" for p in policy.writable_paths]
        L += ["", "Tu memoria está ahí, y está para usarla: lo que averigües sobre este espacio "
                  "—cómo se construye, qué falla, qué se decidió y por qué— escríbelo, y la "
                  "próxima sesión no tendrá que volver a averiguarlo.", ""]
    if policy.external_write_allow:
        L += ["Y fuera del espacio de trabajo sólo existen estos sitios, que son tuyos:", ""]
        L += [f"- `{p}`" for p in policy.external_write_allow]
        L += ["", "Cualquier otra ruta fuera del árbol se rechaza como travesía de directorios.",
              ""]
    L += ["Se bloquea además la escritura cuyo contenido tenga **forma** de credencial "
          "(`AKIA…`, `ghp_…`, una clave privada). Un literal sospechoso que no tenga esa forma "
          "no se rechaza: lo decide una persona. Referenciar un secreto —`std::env::var(\"X\")`, "
          "`${VAR}`— es la forma correcta y no dispara nada.", ""]
    # El guardián evalúa órdenes desde que cubre `Bash`. Antes lo hacía y nadie lo llamaba, así
    # que el informe callaba: prometer un control que no corre es peor que no prometerlo.
    if policy.command_deny or policy.command_ask:
        L += [f"También se evalúa lo que ejecutas: **{len(policy.command_deny)} órdenes "
              f"rechazadas** y **{len(policy.command_ask)} que decide una persona**. "
              f"No se rodean con otra sintaxis; se declara el bloqueo y se pide la decisión.", ""]
        # También sin recortar, y por la misma razón: `[:6]` ocultaba 10 de las 16 órdenes
        # rechazadas. Saber que existen 16 y ver 6 no permite evitar las otras 10.
        if policy.command_deny:
            L += ["- rechazo: " + " · ".join(f"`{c}`" for c in policy.command_deny)]
        if policy.command_ask:
            L += ["- consulta: " + " · ".join(f"`{c}`" for c in policy.command_ask)]
        L.append("")

    # Las concesiones de privilegio VIGENTES para este rol en esta máquina.
    #
    # Sin esto el mecanismo existe y nadie lo usa: un agente que no sabe que tiene una concesión
    # se comporta como si no la tuviera, y el camino declarado —acotado y con rastro— se queda sin
    # usar mientras el atajo opaco sigue ahí. Es la mitad de «parametrizar» que no es código.
    #
    # Se listan sólo las que APLICAN aquí y ahora. Enumerar las caducadas o las de otro host sería
    # prometer autoridad que no hay, y el informe de sesión es justo donde eso no puede pasar: lo
    # que dice se toma por cierto durante el resto de la sesión.
    try:
        from core.grants import cargar
        from datetime import date
        import platform as _plat

        anfitrion = _plat.node()
        rol_actual = role_id or ""
        vigentes = [c for c in cargar(policy)
                    if not c.problemas() and not c.caducada(date.today())
                    and any(p == "*" or p == anfitrion for p in c.hosts)
                    and any(p == "*" or p == rol_actual for p in c.roles)]
        if vigentes:
            L += ["**Concesiones de privilegio vigentes para ti en esta máquina.** Levantan un "
                  "rechazo concreto y nada más: fuera de la forma que declaran, la regla general "
                  "sigue en pie. Si la orden que necesitas no cae en ninguna, el camino es "
                  "pedirla, no rodearla.", ""]
            for c in vigentes:
                cual = "se ejecuta" if c.human_approval == "once-per-grant" \
                    else "lo confirma una persona cada vez"
                L += [f"- `{c.id}` — {' · '.join(c.commands)} · efectos `{c.effects}`"
                      + (" (verificados: si la orden escribe algo, la concesión NO aplica)"
                         if c.effects == "read-only" else "")
                      + f" · {cual} · vigente hasta {c.expires}"
                      + (f" · {c.evidence}" if c.evidence else "")]
            L.append("")
    except Exception:                                                   # noqa: BLE001
        # El informe NO se cae por no poder leer las concesiones. Omitir una capacidad que existe
        # cuesta una sesión menos capaz; caerse cuesta la sesión entera.
        pass

    # Lo que está asignado. Sólo cuando NO se abrió sobre una tarea concreta: si ya hay tarea,
    # repetir la lista entera distrae de la que se va a trabajar.
    if pending and not task:
        L += ["## Lo que tienes asignado", "",
              "Está en la forja, y ya viene enrutado. No hace falta que preguntes cuál es "
              "tu trabajo pendiente:", ""]
        for t, c in pending:
            clave = t.key or f"#{t.number}"
            L.append(f"- **{clave}** — {t.title}  ·  `{t.repo}#{t.number}`")
            detalles = []
            if t.fields.get("Tipo"):
                detalles.append(f"Tipo {t.fields['Tipo']}")
            if t.fields.get("Horas"):
                detalles.append(f"{t.fields['Horas']}")
            if c.primary:
                detalles.append(f"rol **{c.primary}**")
            if detalles:
                L.append(f"  {' · '.join(detalles)}")
            if t.spec_path:
                marca = "" if (workspace / t.spec_path).is_file() else "  ⚠ no está aquí"
                L.append(f"  spec: `{t.spec_path}`{marca}")
        L += ["", "Para trabajar una en concreto, la persona abre "
                  "`refuto chat --task <número>` y entonces recibes su especificación y el rol "
                  "que le corresponde. **No empieces por tu cuenta**: pregunta cuál quiere.", ""]

    # Los recursos, con las rutas con las que se invocan DESDE AQUÍ. Nada que no exista.
    res = resources(workspace)
    L += ["## Lo que tienes a mano", ""]
    if res["verificador"]:
        L.append(f"- **El juez de este espacio**: `{res['verificador']}`. Es el que decide si "
                 f"algo es integrable, y no lo puedes tocar.")
    if res["herramientas"]:
        L.append(f"- **Herramientas del espacio**: {', '.join('`' + h + '`' for h in res['herramientas'][:8])}")
    if res["agentes"]:
        L.append(f"- **{len(res['agentes'])} agentes declarados** en "
                 f"`{res['agentes'][0].rsplit('/', 1)[0]}/`")
    if res["skills"]:
        L.append(f"- **{len(res['skills'])} especialidades** disponibles: "
                 f"{', '.join(res['skills'][:8])}"
                 + ("…" if len(res["skills"]) > 8 else ""))
    L.append(f"- **Refuto** vive en `{res['harness_home']}` — **no en este directorio**. "
             f"Invócalo por su ruta completa; `python3 refuto.py` aquí no existe.")
    L.append("")

    # Quién decide aquí que algo está terminado: el método del espacio si lo declara, refuto
    # si no.
    #
    # Antes esto era un bloque fijo con las órdenes de refuto, siempre. En un espacio con motor
    # propio el informe salía contradiciéndose: la sección «Con qué se ejecuta» decía
    # `.harness/hz verify` y quince líneas después ésta mandaba `refuto.py verify`, con un
    # vocabulario de estados distinto —`PASS/FAIL/BLOCKED/NOT_EXECUTABLE` frente a la escala
    # `E0–E5` que el propio espacio acababa de declarar—. Medido el 2026-09-23 en un espacio
    # con instrumento propio: 171 líneas de informe y dos criterios de cierre incompatibles.
    #
    # El agente no elige entre los dos: los intenta. Y lo que decide si su trabajo cuenta es el
    # instrumento del espacio, no el de quien le abrió la sesión. Un motor que se declara juez
    # de un espacio que ya tiene el suyo no está gobernando: está pisando.
    metodo_propio = _metodo.leer(workspace)
    L += ["## Cómo se sabe que terminaste", ""]
    if metodo_propio.instrumento:
        L += [f"**Lo decide el instrumento de este espacio, no refuto.** `{workspace.name}` "
              f"declara su propio método en `.harness/` y su propio vocabulario de evidencia; "
              f"quien dice si una etapa cerró es:", "",
              "```bash",
              f"{metodo_propio.instrumento} verify     # verifica la cadena entera",
              f"{metodo_propio.instrumento} status     # último cierre por etapa",
              "```", "",
              "No declares nada terminado con otra herramienta. Refuto abrió esta sesión y "
              "aplica la política de escritura, pero **no es el juez de este espacio**: usar "
              "sus puertas aquí daría un veredicto en un vocabulario que este trabajo no usa.",
              ""]
        if res["comandos"]:
            L += ["<details><summary>refuto también está disponible, como herramienta, no como "
                  "criterio</summary>", "", "```bash"]
            L += [f"{cmd}  # {porque}" for cmd, porque in res["comandos"]]
            L += ["```", "</details>", ""]
    else:
        L += ["No por que lo digas. Se ejecutan puertas con cuatro estados —`PASS`, `FAIL`, "
              "`BLOCKED`, `NOT_EXECUTABLE`— y **`BLOCKED` no aprueba**: significa que algo no "
              "se pudo comprobar, que no es lo mismo que estar bien.", ""]
        if res["comandos"]:
            L += ["Comprobado con estos comandos, que existen y funcionan desde este "
                  "directorio:", "", "```bash"]
            ancho = max((len(c) for c, _ in res["comandos"]), default=0) + 2
            L += [f"{cmd:<{ancho}}# {porque}" for cmd, porque in res["comandos"]]
            L += ["```", ""]
        else:
            L += ["_(No se encontró ningún verificador invocable desde este espacio.)_", ""]

    if warnings:
        L += ["## Avisos", ""] + [f"- {w}" for w in warnings] + [""]
    return "\n".join(L), warnings, blockers


def plan(workspace: Path, *, runtime: str = "claude", role_id: str = "", spec: str = "",
         model: str = "", resume: bool = False, extra: list | None = None,
         provider: str = "auto", task: str = "", repo: str = "") -> SessionPlan:
    """Prepara la sesión sin abrirla. `argv` es exactamente lo que se ejecutaría."""
    from adapters.registry import ADAPTERS

    sp = SessionPlan(workspace=workspace, runtime=runtime, run_id=new_id(KIND_SESSION))
    spec_obj = ADAPTERS.get(runtime)
    if spec_obj is None:
        sp.blockers.append(f"no hay adapter para «{runtime}»; hay: {', '.join(sorted(ADAPTERS))}")
        return sp

    # Un espacio sin gobernar no es un error del usuario: es que falta un paso. Se dice cuál,
    # en vez de reventar con una traza. La primera versión lanzaba PermissionError desde
    # `mkdir` y quien lo veía no podía saber que sólo faltaba `refuto install`.
    if not (workspace / ".harness").is_dir():
        sp.blockers.append(
            f"«{workspace}» no está gobernado: no existe .harness/. "
            f"Ejecute `refuto install` aquí para dejarlo operativo, o `cd` al espacio que "
            f"quiera abrir.")
        return sp

    contexto_tarea = None
    if task:
        contexto_tarea, err = task_context(workspace, task, repo)
        if err:
            sp.blockers.append(err)
            return sp

    pendientes: list = []
    if not contexto_tarea:
        pendientes, err_p = pending_summary(workspace)
        if err_p:
            sp.warnings.append(f"no se pudieron listar sus pendientes: {err_p}")

    brief, warnings, blockers = build_brief(workspace, runtime=runtime, role_id=role_id,
                                            spec=spec, task=contexto_tarea,
                                            pending=pendientes)
    sp.brief, sp.warnings, sp.blockers = brief, warnings, blockers

    path = workspace / ".harness" / "state" / "session-brief.md"
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(brief, encoding="utf-8", newline="\n")
    except OSError as exc:
        sp.blockers.append(f"no se pudo escribir el informe de sesión en {path}: {exc}. "
                           f"Causa habitual: los archivos quedaron en manos de otro usuario "
                           f"tras una sesión con sudo. Ejecute `refuto doctor`.")
        return sp
    sp.brief_path = path
    ensure_gitignore(workspace / ".harness")

    vivas = sesiones_vivas(workspace)
    if vivas:
        sp.warnings.append(
            f"hay {len(vivas)} sesión(es) gobernada(s) abierta(s) sobre este mismo espacio "
            f"(pid {', '.join(str(p) for p, _ in vivas)}). Comparten árbol: lo que una mida, "
            f"la otra puede invalidarlo sin aviso. Ciérrela(s) o re-mida antes de concluir.")
    elif vivas.ciego:
        # Vacío por no haber mirado NO es vacío. Callar aquí es abrir la sesión afirmando
        # que está sola, que es precisamente la afirmación que no se ha medido.
        sp.warnings.append(
            f"no se pudo comprobar si hay otras sesiones gobernadas sobre este espacio: "
            f"{vivas.ciego} Trabaje como si pudiera haberlas: verifique a mano antes de "
            f"concluir nada que dependa de tener el árbol en exclusiva.")

    # A dónde va a hablar. Una sesión puede abrir bien, con todo puesto, y morir en el primer
    # mensaje porque una variable del shell la enruta a otro proveedor. Todo lo demás parece
    # correcto, y por eso hay que decirlo ANTES.
    from core import provider as prov
    r = prov.inspect()
    sp.routing = r.to_dict()
    esperado = prov.expected(workspace)
    sp.routing["expected"] = esperado
    if r.overridden:
        # `auto` limpia en dos casos, y los dos son «la sesión no va a hacer lo que se cree»:
        #   · la redirección está ROTA — fallaría en el primer mensaje
        #   · el espacio DECLARA otro proveedor — el entorno lo estaría contradiciendo
        # Adivinar cuál de los dos quiere la persona sería peor que dejarla declararlo.
        contradice = bool(esperado) and not prov.matches(esperado, r.provider)
        if contradice:
            sp.warnings.append(
                f"este espacio declara `provider.expect: {esperado}` y el entorno lo enruta a "
                f"«{r.provider}». Manda la declaración del espacio.")
        sp.clean_provider = (provider == "clean"
                             or (provider == "auto" and (bool(r.problems) or contradice)))
        # El aviso «NO usará su suscripción» describe el SHELL. Se emitía antes de decidir la
        # limpieza y nunca se retractaba: con `--provider clean` el arranque decía a la vez
        # «NO usará su suscripción» (amarillo) y «suscripción de Anthropic» (verde). Sólo se
        # avisa si la redirección va a llegar de verdad a la sesión.
        if not sp.clean_provider:
            sp.warnings.extend(r.warnings)
    elif provider == "clean":
        sp.clean_provider = True
    # Lo mismo para una redirección ROTA: «muere en el primer mensaje» es cierto del shell y
    # falso de una sesión que arranca limpia. Se dice qué está roto y que se ignora, porque
    # sigue habiendo que arreglarlo en el shell.
    if sp.clean_provider:
        sp.warnings.extend(
            f"{p.split('. ')[0]}. Esta sesión la ignora y arranca con la suscripción; sin "
            f"limpiar daría «API Error: Invalid URL». `refuto doctor` dice dónde se define."
            for p in r.problems)
    else:
        sp.warnings.extend(r.problems)

    etiqueta = role_id
    if contexto_tarea and not etiqueta:
        etiqueta = contexto_tarea["classification"].primary
    if contexto_tarea:
        etiqueta = f"{contexto_tarea['task'].key or task} · {etiqueta or 'sesión'}"
    sp.argv = _argv_for(runtime, workspace, brief_path=path, model=model, resume=resume,
                        role_id=etiqueta, extra=extra or [])
    if not sp.argv:
        sp.blockers.append(f"el adapter de «{runtime}» no sabe abrir una sesión interactiva")
    return sp


def _argv_for(runtime: str, workspace: Path, *, brief_path: Path, model: str,
              resume: bool, role_id: str, extra: list) -> list:
    """Línea de órdenes por runtime. Cada uno inyecta el informe a su manera.

    Aquí es donde la capa de adapter gana su sitio: la intención —«abre una sesión sabiendo
    esto»— es la misma; la bandera que la expresa, no.
    """
    if runtime == "claude":
        # El nombre lleva el ESPACIO: «harness · sesión» era idéntico en los once espacios, y
        # Claude Code lo renombraba al azar («sesión-dazzling-honey») en cuanto había dos.
        argv = ["claude", "--append-system-prompt-file", str(brief_path),
                "--name", f"{workspace.name} · {role_id or 'sesión'}"]
        if model:
            argv += ["--model", model]
        if resume:
            argv += ["--continue"]
        return argv + extra
    if runtime == "kiro":
        # Kiro no admite un prompt de sistema por bandera: el informe entra como primer mensaje.
        # kiro-cli chat sólo acepta UN posicional [INPUT]; si el usuario añade una pregunta
        # (en `extra`), se funde con el informe en ese único INPUT en vez de emitir un segundo
        # posicional —que kiro-cli rechaza con «unexpected argument».
        argv = ["kiro-cli", "chat", "--agent-engine", "v2"]
        if role_id:
            argv += ["--agent", role_id]
        if resume:
            argv += ["--resume"]
        brief_text = brief_path.read_text(encoding="utf-8")
        flags = [a for a in extra if a.startswith("-")]
        question = " ".join(a for a in extra if not a.startswith("-")).strip()
        input_text = f"{brief_text}\n\n---\n\n{question}" if question else brief_text
        return argv + flags + [input_text]
    if runtime == "gemini":
        argv = ["gemini", "-i", brief_path.read_text(encoding="utf-8")]
        if model:
            argv += ["-m", model]
        return argv + extra
    if runtime == "opencode":
        argv = ["opencode"]
        if resume:
            argv += ["--continue"]
        return argv + extra
    return []


def launch(sp: SessionPlan) -> int:
    """Abre la sesión. Bloquea hasta que el usuario la cierra."""
    from core.wire import SESSION_ENV as wire_SESSION_ENV

    if sp.clean_provider:
        from core.provider import clean_env
        env = clean_env()
    else:
        env = dict(os.environ)
    env.setdefault("CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC", "1")
    env.setdefault("KIRO_TELEMETRY_OPT_OUT", "1")
    env["HARNESS_WORKSPACE"] = str(sp.workspace)
    env["HARNESS_RUN_ID"] = sp.run_id
    # El SUJETO del monitor de referencia. Sin esto el guardián decide sobre
    # `(objeto, operación)` y todo rol tiene autoridad idéntica — ver `core/capabilities.py`.
    # Es una variable de entorno, luego el agente puede reescribirla en un subproceso: atenúa
    # por rol DECLARADO, no por principal criptográfico, y así se declara.
    if getattr(sp, "role", "") or getattr(sp, "rol", ""):
        env["HARNESS_ROLE"] = str(getattr(sp, "role", "") or getattr(sp, "rol", ""))
    # La marca que lee el gancho `SessionStart` para saber si HAY alguien que vaya a devolver
    # la propiedad de los ficheros al salir (`core.wire.ROOT_WARN_CMD`). La pone quien de
    # verdad lo va a hacer —esta función—, y no un lanzador externo: así el aviso dice la
    # verdad en cualquier máquina, no sólo en la del autor.
    env[wire_SESSION_ENV] = sp.run_id or "1"

    append_event(sp.workspace, {"kind": "session/open", "run_id": sp.run_id,
                                "runtime": sp.runtime, "argv": sp.argv[:4],
                                "opened_at": now()})
    try:
        code = subprocess.call(sp.argv, cwd=str(sp.workspace), env=env)
    except FileNotFoundError:
        append_event(sp.workspace, {"kind": "session/error", "run_id": sp.run_id,
                                    "runtime": sp.runtime, "error": "ejecutable no encontrado"})
        return 127
    except KeyboardInterrupt:
        code = 130
    append_event(sp.workspace, {"kind": "session/close", "run_id": sp.run_id,
                                "runtime": sp.runtime, "exit_code": code})
    return code
