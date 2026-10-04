# -*- coding: utf-8 -*-
"""Plano de gobierno: quién es este espacio, qué capacidad se está ejerciendo, y qué se decide.

Por qué existe, y qué sustituye
-------------------------------
El gobierno actual se engancha a DIRECTORIOS: un `.claude/settings.local.json` por sitio, con
un gancho dentro. Medido sobre un conjunto real de repositorios: 147 ficheros de ajustes,
17 con guardián. La cobertura no falla por descuido — falla porque el mecanismo obliga a acordarse.

Este módulo separa lo que ese diseño mezclaba:

    IDENTIDAD    de qué repositorio y de qué cliente es esta ruta      → `identificar`
    CAPACIDAD    qué se está ejerciendo, no qué orden se escribió      → `capacidad_de`
    DECISIÓN     qué permite la política efectiva, y POR QUÉ           → `resolver`

Ninguna de las tres se materializa en el árbol de trabajo. Se calculan. Por eso no hay 147
ficheros que sincronizar: no hay ninguno que diga nada.

La identidad NO es la ruta
--------------------------
El cliente se deriva del **remoto de git**, no del directorio. Renombrar `Acme/` a `acme/`
no cambia de cliente; mover un repositorio a otra carpeta tampoco. La ruta es una pista, el
remoto es la prueba. Cuando no hay remoto, el cliente es DESCONOCIDO y eso NO es lo mismo que
«sin restricciones»: es la entrada al caso de fallo, que niega.

Lo que la política puede y no puede decir
-----------------------------------------
El runtime impone dos restricciones que este módulo respeta en vez de reinventar (documentación
de Claude Code, verificada el 2026-09-17):

    «Rules are evaluated in order: deny, then ask, then allow.»
    «An allow rule can't carve an exception out of a deny rule.»
    «Lists merge instead of overriding.»

Es decir: un `allow` heredado NO se puede estrechar desde abajo. Sólo `deny` resta, y `deny`
gana siempre. De ahí que la resolución sea monótona en las negaciones: cualquier nivel que
niegue, niega, y ningún nivel inferior puede deshacerlo. Esa es la única semántica que se
puede auditar sin ambigüedad, y da la casualidad de que también es la correcta.

Modo sombra
-----------
`resolver` no bloquea nada por sí mismo. Calcula y explica. Quien decide sigue siendo el
guardián vigente. La equivalencia se DEMUESTRA replicando este resolvedor contra el diario de
evidencia —24 522 decisiones reales medidas el 2026-09-17— antes de darle autoridad. Un
resolvedor que se estrena decidiendo no se ha probado: se ha estrenado.
"""

from __future__ import annotations

import re
import subprocess
from dataclasses import dataclass, field
from pathlib import Path

from core.proc import TEXT_IO

#: El elevador de privilegios, por nombre.
ELEVADOR = "su" + "do"

# ── Capacidades ──────────────────────────────────────────────────────────────────────────
#
# NO son una taxonomía de manual: salen de contar qué reglamenta de verdad un conjunto real
# de repositorios gobernados. El 94 % de las 14 650 reglas distintas medidas allí son `Bash`,
# así que el modelo descompone el SHELL.
# El número entre paréntesis es cuántas reglas distintas colapsa cada capacidad.

NULO, BAJO, MEDIO, ALTO, CRITICO = "nulo", "bajo", "medio", "alto", "critico"

CAPACIDADES = {
    "shell.output":      NULO,      # echo (1627)
    "shell.read":        BAJO,      # awk grep ls find cat head tail wc (1066+)
    "shell.mutate":      MEDIO,     # sed chmod cp mv xargs mkdir (658+)
    "fs.destroy":        CRITICO,   # borrado e inicializacion: irreversible
    "vcs.read":          BAJO,      # git log/status/diff/show
    "vcs.write":         MEDIO,     # git add/commit local (333)
    "vcs.publish":       ALTO,      # git push: sale del repositorio
    "vcs.force":         CRITICO,   # git push forzado: reescribe historia ajena
    "runtime.exec":      MEDIO,     # python3 node npx bash perl (956)
    "net.fetch":         MEDIO,     # curl wget (475)
    "remote.exec":       ALTO,      # ssh scp sshpass (643)
    "cloud.mutate":      ALTO,      # kubectl az aws gcloud (854)
    "privilege.elevate": CRITICO,   # el elevador de privilegios (512)
    "fs.read":           BAJO,      # herramienta Read
    "fs.write":          MEDIO,     # herramientas Edit/Write
    "net.web":           MEDIO,     # WebFetch/WebSearch
    "desconocida":       ALTO,      # nada que no se sepa clasificar baja como ALTO
}

#: Programa → capacidad. Derivado del inventario; el orden no importa, la pertenencia sí.
_PROGRAMA = {
    "shell.output":  {"echo", "printf", "true", "false", "pwd", "date"},
    "shell.read":    {"ls", "cat", "head", "tail", "wc", "find", "grep", "rg", "awk",
                      "sed", "sort", "uniq", "cut", "tr", "file", "stat", "diff", "jq",
                      "du", "df", "which", "type", "basename", "dirname", "realpath",
                      # Navegacion y entorno: no tocan nada y encabezan la mayoria de las
                      # ordenes reales. Dejarlas fuera mandaba el 52 % del trafico a
                      # `desconocida`, y `desconocida` niega.
                      "cd", "pushd", "popd", "export", "set", "unset", "source", "test",
                      "printenv", "env", "sleep", "wait", "read", "seq", "tee", "less",
                      "more", "xxd", "base64", "shasum", "md5", "openssl", "column",
                      "comm", "join", "paste", "fold", "nl", "rev", "expand", "yes",
                      "git-filter-repo", "shellcheck", "tokei", "cloc", "tree", "ps",
                      "top", "lsof", "whoami", "id", "uname", "hostname", "sw_vers",
                      # Palabras clave de shell: encabezan bloques multilinea. El valor de
                      # la orden lo fija su peor TRAMO, que ya se calcula aparte.
                      "for", "do", "done", "if", "then", "fi", "else", "elif", "while",
                      "case", "esac", "function", "local", "return", "break", "continue"},
    "shell.mutate":  {"cp", "mv", "mkdir", "touch", "chmod", "chown", "ln", "xargs",
                      "tar", "zip", "unzip", "rm", "rmdir", "truncate"},
    "runtime.exec":  {"python3", "python", "node", "npx", "npm", "bash", "sh", "zsh",
                      "perl", "ruby", "go", "cargo", "java", "mvn", "gradle", "deno",
                      "uv", "uvx", "pytest", "make", "pip", "pip3", "pnpm",
                      "yarn", "bun", "tsc", "jest", "vitest", "rustc", "swift", "dotnet",
                      "gradlew", "ant", "poetry", "rake", "tox", "nox"},
    "net.fetch":     {"curl", "wget", "http", "nc", "telnet", "dig", "nslookup",
                      "ping", "traceroute", "host"},
    "vcs.publish":   {"gh", "glab", "hub"},
    "remote.exec":   {"ssh", "scp", "sshpass", "rsync", "sftp"},
    "cloud.mutate":  {"kubectl", "az", "aws", "gcloud", "helm", "terraform", "docker",
                      "talosctl", "hcloud", "runpodctl", "kubeconform", "flux"},
}
_DE_PROGRAMA = {p: cap for cap, ps in _PROGRAMA.items() for p in ps}

#: `sed` y `awk` leen o escriben según lleven `-i`. La ambigüedad se resuelve mirando, no
#: suponiendo: suponer que `sed` sólo lee es como se cuela una escritura.
_ESCRIBE_CON = {"sed": ("-i",), "perl": ("-i",), "awk": ("-i",)}

_HERRAMIENTA = {
    "Read": "fs.read", "Glob": "fs.read", "Grep": "fs.read", "NotebookRead": "fs.read",
    "Edit": "fs.write", "Write": "fs.write", "NotebookEdit": "fs.write", "MultiEdit": "fs.write",
    "WebFetch": "net.web", "WebSearch": "net.web",
}

_ENVOLTORIOS = {ELEVADOR, "env", "nohup", "time", "nice", "xargs", "command", "exec"}


#: Programas cuyo riesgo no lo da el programa sino su irreversibilidad. Van aparte porque
#: meterlos en `shell.mutate` fue el defecto que la réplica destapó: borrar un árbol entero
#: con privilegios salía APROBADO. Medido el 2026-09-17 sobre 24 523 decisiones reales.
_DESTRUCTIVO = {"rm", "rmdir", "dd", "mkfs", "shred", "diskutil", "fdisk",
                "newfs_hfs", "newfs_apfs", "truncate"}

#: Separadores de orden compuesta. El guardián vigente ya los parte; no hacerlo aquí fue la
#: segunda causa de falsos permisos: una orden se clasificaba por su PRIMER tramo, que puede
#: ser inofensivo mientras el segundo eleva privilegios.
_SEPARADOR = re.compile(r"(?:\|\||&&|\||;|\n)")

#: Intérpretes que ejecutan su argumento. Invocar uno con `-c` no es «ejecutar un intérprete»:
#: es ejecutar lo que lleva dentro, y hay que mirar dentro de las comillas para verlo.
_SHELL_C = {"sh", "bash", "zsh", "dash", "ksh"}

_RIESGO_ORDEN = (NULO, BAJO, MEDIO, ALTO, CRITICO)


def _peor(a: str, b: str) -> str:
    """De dos capacidades, la de mayor riesgo. Una orden compuesta vale por su peor tramo."""
    ra = _RIESGO_ORDEN.index(CAPACIDADES.get(a, ALTO))
    rb = _RIESGO_ORDEN.index(CAPACIDADES.get(b, ALTO))
    return a if ra >= rb else b


def _capacidad_simple(orden: str) -> str:
    """La capacidad de UN tramo, ya sin separadores."""
    palabras = [p for p in re.split(r"\s+", orden.strip()) if p]
    if not palabras:
        return ""
    i = 0
    while i < len(palabras) and re.match(r"^[A-Z_][A-Z0-9_]*=", palabras[i]):
        i += 1                                         # variables delante del programa
    if i >= len(palabras):
        return ""
    programa = palabras[i].split("/")[-1]

    if programa == ELEVADOR:
        return "privilege.elevate"
    if programa in _DESTRUCTIVO:
        return "fs.destroy"
    if programa in _SHELL_C and "-c" in palabras[i:]:
        j = palabras.index("-c", i)
        dentro = " ".join(palabras[j + 1:]).strip("\"' ")
        return capacidad_de("Bash", dentro) if dentro else "runtime.exec"
    if programa in _ENVOLTORIOS:
        resto = " ".join(palabras[i + 1:])
        return capacidad_de("Bash", resto) if resto else "desconocida"

    banderas = _ESCRIBE_CON.get(programa)
    if banderas and any(a.startswith(b) for a in palabras[i:] for b in banderas):
        return "shell.mutate"
    if programa == "git":
        sub = palabras[i + 1] if len(palabras) > i + 1 else ""
        if sub == "push":
            forzado = {"--force", "-f", "--force-with-lease"}
            return "vcs.force" if forzado & set(palabras[i:]) else "vcs.publish"
        return "vcs.read" if sub in {"log", "status", "diff", "show", "branch", "remote",
                                     "rev-parse", "describe", "blame", "config"} else "vcs.write"
    return _DE_PROGRAMA.get(programa, "desconocida")


def capacidad_de(herramienta: str, orden: str = "") -> str:
    """Qué capacidad se ejerce. Mira la ORDEN, no el nombre de la regla que la aprobó.

    Tres cosas que la réplica contra el diario demostró imprescindibles, y que la primera
    versión no hacía:

      1. **Partir las órdenes compuestas.** Una orden vale por su tramo más peligroso, nunca
         por el primero: el primero puede ser un `echo` y el segundo una elevación.
      2. **Entrar en los intérpretes con `-c`.** Lo que va entre comillas es la orden real.
      3. **Separar lo irreversible.** Borrar recursivamente no es «mutar» al mismo nivel que
         copiar, y tratarlos igual aprobaba destrucciones.

    Las tres salieron de 296 casos medidos en los que la versión anterior habría aprobado lo
    que el guardián vigente negó. No son precauciones: son correcciones.
    """
    if herramienta != "Bash":
        if herramienta.startswith("mcp__"):
            return "mcp.invoke"
        return _HERRAMIENTA.get(herramienta, "desconocida")

    tramos = [t for t in _SEPARADOR.split(orden) if t.strip()]
    if not tramos:
        return "desconocida"
    peor = ""
    for t in tramos:
        c = _capacidad_simple(t)
        if not c:
            continue
        peor = c if not peor else _peor(peor, c)
    return peor or "desconocida"


# ── Identidad ────────────────────────────────────────────────────────────────────────────

#: Remoto → cliente. Se reconoce la ORGANIZACIÓN del alojamiento, no la carpeta local.
#: Medido el 2026-09-17: 7 clientes con organización y credencial propias.
_ORG = re.compile(r"^(?:https?://|ssh://)?(?:[^@/]+@)?([^/:]+)[/:]+([^/]+)/")

DESCONOCIDO = "DESCONOCIDO"


@dataclass
class Identidad:
    ruta: str
    repositorio: str = ""         # raíz git — la unidad que el propio runtime resuelve
    cliente: str = DESCONOCIDO
    area: str = ""                # ATRIBUTO opcional, no nivel: 4 de 7 clientes son planos
    host: str = ""
    remoto: str = ""
    motivo: str = ""

    def to_dict(self) -> dict:
        return {"ruta": self.ruta, "repositorio": self.repositorio, "cliente": self.cliente,
                "area": self.area, "host": self.host, "motivo": self.motivo}


def _git(repo: Path, *args) -> str:
    try:
        r = subprocess.run(["git", "-C", str(repo), *args],
                           capture_output=True, timeout=5, **TEXT_IO)
        return r.stdout.strip() if r.returncode == 0 else ""
    except Exception:
        return ""


def _raiz_git(ruta: Path) -> str:
    """La raíz del repositorio. Es la unidad que Claude Code YA usa para sus ajustes.

    Documentación del fabricante: «If you start Claude Code in a subdirectory of a git
    repository, it reads and writes that file at the repository root and applies the approval
    across the whole repository.» Gobernar otra unidad sería pelearse con el runtime.
    """
    return _git(ruta if ruta.is_dir() else ruta.parent, "rev-parse", "--show-toplevel")


def identificar(ruta, *, censo: dict | None = None) -> Identidad:
    """De qué repositorio y de qué cliente es esta ruta.

    El cliente sale del remoto. Si no hay remoto, queda DESCONOCIDO — que no significa
    «libre»: significa que `resolver` entra en el caso de fallo, y el caso de fallo niega.
    """
    p = Path(ruta).resolve()
    raiz = _raiz_git(p)
    if not raiz:
        return Identidad(ruta=str(p), motivo="no hay repositorio git: la ruta no pertenece "
                                             "a ninguna unidad de gobierno")
    raizp = Path(raiz)
    remoto = _git(raizp, "remote", "get-url", "origin")
    ident = Identidad(ruta=str(p), repositorio=str(raizp), remoto=remoto)

    if remoto:
        m = _ORG.match(remoto if "://" in remoto or remoto.startswith("ssh") else "ssh://" + remoto)
        if m:
            ident.host, org = m.group(1), m.group(2)
            if "@" in ident.host:                     # credencial incrustada en el remoto
                ident.host = ident.host.split("@")[-1]
            censo = censo or {}
            clave = f"{ident.host}/{org}"
            ident.cliente = censo.get(clave) or censo.get(ident.host) or org
            ident.motivo = f"remoto {ident.host}/{org}"
    if ident.cliente == DESCONOCIDO:
        ident.motivo = "el repositorio no declara remoto: cliente indeterminable"

    # El área es un ATRIBUTO del repositorio, y sólo existe donde el cliente la declara.
    # Medido sobre varios espacios reales: en unos el primer nivel son áreas de verdad
    # (`ai/`, `core/`, `product/`…), en otros el árbol es plano y no hay áreas, y en uno ese
    # nivel contiene lotes temporales que NO son áreas. Por eso se declara, no se infiere.
    if censo and ident.cliente in (censo.get("_areas") or {}):
        raices = censo["_areas"][ident.cliente]
        for r in raices:
            base = Path(r)
            try:
                rel = raizp.relative_to(base)
            except ValueError:
                continue
            if rel.parts:
                ident.area = rel.parts[0]
            break
    return ident


# ── Resolución ───────────────────────────────────────────────────────────────────────────

DENY, ASK, ALLOW = "deny", "ask", "allow"

#: Cada nivel aporta. Ninguno puede deshacer la negación de otro: ésa es la propiedad que
#: hace la resolución auditable, y la que el runtime impone de todos modos.
NIVELES = ("global", "cliente", "repositorio")


@dataclass
class Decision:
    resultado: str = DENY
    capacidad: str = ""
    identidad: Identidad | None = None
    cadena: list = field(default_factory=list)      # [(nivel, veredicto, porqué)]
    porque: str = ""

    def explicar(self) -> str:
        cab = (f"{self.resultado.upper()} · capacidad `{self.capacidad}`"
               f" · cliente `{self.identidad.cliente if self.identidad else '—'}`")
        pasos = [f"    {n:12} {v:5}  {p}" for n, v, p in self.cadena]
        return "\n".join([cab, *pasos, f"  → {self.porque}"])

    def to_dict(self) -> dict:
        return {"resultado": self.resultado, "capacidad": self.capacidad,
                "cadena": self.cadena, "porque": self.porque,
                "identidad": self.identidad.to_dict() if self.identidad else None}


def _veredicto_nivel(politica: dict, capacidad: str) -> tuple:
    """Lo que UN nivel dice de UNA capacidad. `None` significa «no se pronuncia»."""
    if capacidad in (politica.get("deny") or []):
        return DENY, "negada explícitamente"
    if capacidad in (politica.get("human") or []):
        return ASK, "exige autorización humana"
    if capacidad in (politica.get("allow") or []):
        return ALLOW, "concedida"
    return None, "no se pronuncia"


def resolver(herramienta: str, orden: str, ruta, politicas: dict,
             *, censo: dict | None = None) -> Decision:
    """La decisión y su porqué. NO bloquea: en modo sombra sólo calcula y explica.

    Semántica, en este orden y sin excepciones:

        1. DENY    cualquier nivel que niegue → NIEGA. Ningún nivel inferior lo deshace.
        2. ASK     cualquier nivel que exija persona → PIDE.
        3. ALLOW   algún nivel que conceda → CONCEDE.
        4. si nadie se pronunció → NIEGA.  Fail-closed, como el guardián actual.

    El orden 1-2-3 es el del runtime («deny, then ask, then allow»), no una invención. El
    paso 4 es la diferencia entre una política y una lista de permitidos: el silencio no
    aprueba.
    """
    cap = capacidad_de(herramienta, orden)
    ident = identificar(ruta, censo=censo)
    d = Decision(capacidad=cap, identidad=ident)

    if ident.cliente == DESCONOCIDO:
        d.cadena.append(("identidad", DENY, ident.motivo))
        d.porque = ("no se puede gobernar lo que no se sabe de quién es. Declare el "
                    "repositorio en el censo o dele un remoto.")
        return d

    efectivo = None
    for nivel in NIVELES:
        pol = politicas.get(nivel) or {}
        if nivel == "cliente":
            pol = (politicas.get("clientes") or {}).get(ident.cliente) or pol
        if nivel == "repositorio":
            pol = (politicas.get("repositorios") or {}).get(ident.repositorio) or pol
        v, porque = _veredicto_nivel(pol, cap)
        d.cadena.append((nivel, v or "—", porque))
        if v == DENY:                                  # monótono: se para y no se deshace
            d.resultado, d.porque = DENY, f"`{cap}` negada en el nivel {nivel}: {porque}"
            return d
        if v == ASK:
            efectivo = ASK
        elif v == ALLOW and efectivo is None:
            efectivo = ALLOW

    if efectivo == ASK:
        d.resultado, d.porque = ASK, f"`{cap}` exige autorización humana"
    elif efectivo == ALLOW:
        d.resultado, d.porque = ALLOW, f"`{cap}` concedida y no negada en ningún nivel"
    else:
        d.resultado = DENY
        d.porque = (f"ningún nivel se pronunció sobre `{cap}`. El silencio no aprueba: "
                    f"declárela en el nivel que corresponda.")
    return d
