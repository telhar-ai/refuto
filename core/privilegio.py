# -*- coding: utf-8 -*-
"""Quién va a ejecutar esta orden: clasificar elevación, bajada e indeterminación.

El defecto que esto cierra (medido el 2026-09-29 con el guardián real)
---------------------------------------------------------------------
`command_deny` compara el TEXTO del segmento contra `sudo:*`, así que sólo caza el nombre
desnudo. De 23 formas de invocar privilegio, **12 pasaban sin freno**:

    deny   sudo id                     allow  /usr/bin/sudo id
    deny   command sudo id             allow  ../../usr/bin/sudo id
    deny   bash -c "sudo id"           allow  /usr/bin/env sudo id
    deny   echo hola; sudo id          allow  'sudo' id   "sudo" id   su'do' id   \\sudo id
                                       allow  $(which sudo) id
                                       allow  doas id · su root -c id · sudoedit /etc/hosts
                                       allow  osascript -e '… with administrator privileges'

Dos familias, y se arreglan distinto. Las ocho primeras son **el mismo programa escrito de otra
manera**: se normaliza el nombre y se acabó. Las cuatro últimas son **programas que la lista no
nombraba**: se nombran.

Elevar no es lo contrario de nada: bajar también existe
-------------------------------------------------------
De 3.624 invocaciones reales medidas en 13 espacios, **3.405 son `su <usuario> -c …`** — una
sesión con privilegios que ejecuta el trabajo como la persona para no dejar ficheros de root
detrás. Y 19 más son `sudo -u <usuario> -H env -i …`, que es lo mismo. Eso **no es escalar**: es
justo la buena práctica que el aviso de `SessionStart` pide, y tratarlo como una elevación
pondría en rojo el camino correcto — el modo exacto en que un control se acaba desactivando.

Por eso aquí hay cuatro respuestas y no dos:

    ELEVA           el programa pide privilegio (root, o un usuario sin declarar)
    BAJA            lo cede a un usuario concreto que no es root
    NINGUNO         no hay cambio de identidad
    INDETERMINADO   el nombre del programa se construye en tiempo de ejecución

`INDETERMINADO` no es `NINGUNO`. `$(which sudo) id` no se puede comprobar contra ninguna tabla,
y hasta hoy eso salía `allow`: una certeza falsa sobre un programa que nadie conocía.

Lo que esto NO es
-----------------
No es un analizador de shell, y comparte el límite que `_segmentos` ya declara: una ofuscación
decidida —armar el nombre en una variable, codificarlo— lo atraviesa. Es una barandilla contra
el resbalón. Lo que cubre es lo que de verdad ocurre a diario: rutas absolutas, envoltorios,
comillas y escapes.
"""

from __future__ import annotations

import re
import shlex

ELEVA = "ELEVA"
BAJA = "BAJA"
NINGUNO = "NINGUNO"
INDETERMINADO = "INDETERMINADO"

#: Programas que ejecutan OTRO programa sin cambiar de identidad. Se saltan para llegar al de
#: verdad: `env sudo id` es `sudo id` con un envoltorio delante, y la lista no puede depender de
#: cuántos envoltorios se apilen.
ENVOLTORIOS = frozenset({"env", "command", "exec", "builtin", "nohup", "nice", "ionice",
                         "stdbuf", "setsid", "time", "timeout", "eatmydata", "proxychains",
                         # `xargs` ejecuta lo que le sigue, así que es un envoltorio como los
                         # demás. Sin él, `xargs -I{} sh -c 'rm -rf /'` no llegaba a mirarse:
                         # el cuerpo de `-c` sólo se busca tras pelar, y el pelado se paraba
                         # en `xargs`. Medido el 2026-09-29.
                         "xargs"})

#: Los que piden privilegio. `su` está aquí **y** puede acabar en `BAJA`: lo decide su usuario.
ELEVADORES = frozenset({"sudo", "doas", "sudoedit", "pkexec", "su", "runas", "gosu", "setpriv"})

#: Banderas de `sudo`/`su`/`doas` que CONSUMEN el argumento siguiente. Sin esta tabla,
#: `sudo -g staff id` leería `staff` como el usuario destino y clasificaría mal.
_CON_VALOR = frozenset({"-u", "--user", "-g", "--group", "-p", "--prompt", "-U", "-C",
                        "--close-from", "-h", "--host", "-r", "--role", "-t", "--type",
                        "-T", "--command-timeout", "-s", "--shell"})
#: Las que toman usuario, en las que sí hay que mirar el valor.
_USUARIO = frozenset({"-u", "--user", "-U"})

#: Marca de sustitución de orden o expansión: el nombre del programa no está escrito.
_DINAMICO = re.compile(r"\$\(|\$\{|`|\$[A-Za-z_]")

#: macOS: `osascript … with administrator privileges` eleva sin nombrar a `sudo` en ninguna
#: parte. Medido: pasaba entero. `security` y `launchctl` NO están aquí — elevan sólo cuando se
#: invocan bajo `sudo`, y entonces ya los caza el elevador.
_APPLESCRIPT_ADMIN = re.compile(r"with\s+administrator\s+privileges", re.I)

ROOT = frozenset({"root", "0", "#0"})


class Clasificacion:
    """Qué identidad va a ejecutar el segmento, y con qué programa se pidió."""

    __slots__ = ("tipo", "programa", "usuario", "motivo", "resto")

    def __init__(self, tipo: str, programa: str = "", usuario: str = "", motivo: str = "",
                 resto: tuple = ()):
        self.tipo, self.programa, self.usuario = tipo, programa, usuario
        self.motivo, self.resto = motivo, tuple(resto)

    def __repr__(self) -> str:                                          # pragma: no cover
        return f"<{self.tipo} programa={self.programa!r} usuario={self.usuario!r}>"

    @property
    def eleva(self) -> bool:
        return self.tipo == ELEVA


def _tokenizar(segmento: str) -> list:
    try:
        return shlex.split(segmento)
    except ValueError:
        # Comillas sin cerrar. Partir a lo bruto es peor que no entender: se devuelve lo que
        # haya y quien llame decidirá con `INDETERMINADO` si el programa no se deja leer.
        return segmento.split()


def nombre_de_programa(token: str) -> str:
    """El programa que un token nombra, quitando ruta, comillas y escapes.

    `shlex` ya resuelve `'sudo'` y `"sudo"`; lo que no resuelve es `su'do'` —que concatena— ni
    `\\sudo`, y las dos formas pasaban enteras. El `basename` es lo que convierte
    `/usr/bin/sudo` y `../../usr/bin/sudo` en el mismo programa que `sudo`.

    Se devuelve **con su caja**, porque es lo que se imprime en el motivo. Para preguntar si
    nombra a un elevador se usa `clave_de_programa`, que la pliega: ver por qué allí.
    """
    t = token.replace("\\", "")
    if _DINAMICO.search(t):
        return ""
    t = t.replace("'", "").replace('"', "")
    if "/" in t:
        t = t.rsplit("/", 1)[-1]
    return t.strip()


def clave_de_programa(token: str) -> str:
    """El nombre con la caja plegada, que es la forma de preguntar «¿es este programa?».

    Medido el 2026-09-29 en macOS (APFS sin distinción de caja): `/usr/bin/SUDO` **existe y es
    ejecutable**, así que `SUDO id` eleva de verdad — y salía `NINGUNO` → `allow`, porque la
    comparación respetaba la caja. No es un caso teórico: es el mismo programa con otra caja, la
    misma familia que `su'do'` y `/usr/bin/sudo`, y se arregla igual.

    Plegar la caja sólo puede añadir rechazos, y únicamente para un programa que se llame igual
    que un elevador salvo por la caja. En un sistema que SÍ distingue caja, `SUDO` no existe y
    rechazarlo no cuesta nada; en uno que no la distingue, es el elevador. Las dos lecturas
    coinciden en que plegar es lo correcto.
    """
    return nombre_de_programa(token).lower()


def _saltar_envoltorios(toks: list) -> list:
    """Quita envoltorios y sus opciones hasta dejar el programa real delante.

    `VAR=valor` cuenta como asignación del shell o argumento de `env`: en los dos casos lo que
    viene después sigue siendo el programa.
    """
    i = 0
    vistos = 0
    while i < len(toks) and vistos < 8:                 # tope: `env env env …` no es un caso real
        crudo = toks[i]
        prog = clave_de_programa(crudo)
        if "=" in crudo and not crudo.startswith("-") and "/" not in crudo.split("=", 1)[0]:
            i += 1
            continue
        if prog in ENVOLTORIOS:
            i += 1
            vistos += 1
            # Las opciones del envoltorio no son el programa. `env -i`, `env -u VAR`,
            # `timeout 5`, `nice -n 10`.
            while i < len(toks) and (toks[i].startswith("-") or toks[i].replace(".", "").isdigit()):
                if toks[i] in ("-u", "--unset", "-n"):
                    i += 2
                else:
                    i += 1
            continue
        break
    return toks[i:]


def clasificar(segmento: str) -> Clasificacion:
    """Qué identidad ejecuta este segmento. Nunca lanza: una orden ilegible es INDETERMINADO."""
    if not segmento or not segmento.strip():
        return Clasificacion(NINGUNO)
    toks = _saltar_envoltorios(_tokenizar(segmento))
    if not toks:
        return Clasificacion(NINGUNO)

    prog = nombre_de_programa(toks[0])
    clave = clave_de_programa(toks[0])
    if not prog:
        return Clasificacion(INDETERMINADO, motivo=(
            f"el nombre del programa se construye en tiempo de ejecución («{toks[0][:40]}»): no "
            f"se puede comprobar contra ninguna tabla, así que no se puede afirmar que no eleve"))

    if clave == "osascript" and _APPLESCRIPT_ADMIN.search(segmento):
        return Clasificacion(ELEVA, programa=prog, usuario="root", motivo=(
            "`osascript … with administrator privileges` pide credenciales de administrador y "
            "ejecuta como root sin nombrar a `sudo` en ninguna parte"))

    if clave not in ELEVADORES:
        return Clasificacion(NINGUNO, programa=prog, resto=tuple(toks[1:]))

    # ── es un elevador: ¿a quién? ────────────────────────────────────────────────────
    usuario, i = "", 1
    posicional = None
    while i < len(toks):
        t = toks[i]
        if t == "--":
            i += 1
            break
        if t.startswith("-"):
            if t in _USUARIO and i + 1 < len(toks):
                usuario = nombre_de_programa(toks[i + 1]) or toks[i + 1]
                i += 2
                continue
            if "=" in t and t.split("=", 1)[0] in _USUARIO:
                usuario = t.split("=", 1)[1]
                i += 1
                continue
            if t in _CON_VALOR:
                i += 2
                continue
            i += 1
            continue
        posicional = t
        break

    if clave in ("su", "runas") and not usuario and posicional is not None:
        # `su alguien -c …`: en `su` el usuario es POSICIONAL, no una bandera. Confundirlo con
        # un programa a ejecutar es lo que haría pasar por elevación la bajada más común.
        usuario = nombre_de_programa(posicional) or posicional
        # …y entonces ese token es el USUARIO, no la orden. Dejarlo dentro de `resto` hacía que
        # `su persona rm -rf /` diera `resto=('persona','rm','-rf','/')`, donde `rm -rf` ya no
        # está en cabeza y por tanto no casa con `rm -rf:*`. Medido el 2026-09-29.
        i += 1

    #: Lo que este elevador va a EJECUTAR, ya sin sus banderas ni el usuario destino. Quien
    #: llama lo vuelve a pasar por la política: ceder o pedir privilegio no amnistía la orden.
    resto = tuple(toks[i:])

    if clave in ("sudoedit", "pkexec"):
        return Clasificacion(ELEVA, programa=prog, usuario=usuario or "root", resto=resto,
                             motivo=f"`{prog}` ejecuta con privilegios de administrador")

    if usuario and usuario not in ROOT:
        return Clasificacion(BAJA, programa=prog, usuario=usuario, resto=resto, motivo=(
            f"`{prog}` cede la identidad a «{usuario}», que no es root: la orden se ejecuta con "
            f"MENOS privilegio del que tiene quien la lanza"))
    return Clasificacion(ELEVA, programa=prog, usuario=usuario or "root", resto=resto,
                         motivo=f"`{prog}` ejecuta como {usuario or 'root'}")


def forma_normalizada(segmento: str) -> str:
    """El segmento con el programa reducido a su nombre, para comparar contra los patrones.

    Es lo que hace que `/usr/bin/sudo id` y `sudo id` casen la misma regla. Sólo se toca el
    PRIMER token: el resto se deja como está, porque las reglas hablan de él tal cual
    (`rm -rf`, `git push --force`) y normalizarlo cambiaría lo que significan.
    """
    toks = _saltar_envoltorios(_tokenizar(segmento))
    if not toks:
        return " ".join(segmento.split())
    prog = nombre_de_programa(toks[0])
    if not prog:
        return " ".join(segmento.split())
    # La caja se pliega SÓLO si el nombre plegado es un programa que la política nombra: así
    # `SUDO id` casa `sudo:*` y, a la vez, un programa cuyo nombre lleva mayúsculas de verdad
    # sigue comparándose tal cual. Ver `clave_de_programa`.
    if clave_de_programa(toks[0]) in (ELEVADORES | ENVOLTORIOS):
        prog = clave_de_programa(toks[0])
    return " ".join([prog, *toks[1:]])
