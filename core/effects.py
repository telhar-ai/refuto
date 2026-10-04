# -*- coding: utf-8 -*-
"""Modelo de EFECTOS de una orden de consola. Qué toca, no cómo se escribió.

Por qué existe
--------------
La política protege RUTAS. El guardián las aplicaba sólo cuando la herramienta declaraba una
ruta (`Write`, `Edit`), y decidía por la ORDEN cuando la herramienta era `Bash` — dos ramas
excluyentes en `core.guard.evaluate`. Medido el 2026-09-23 contra el guardián real, misma
ruta y misma política:

    Write  gates/base.py          →  deny
    Bash   echo x > gates/base.py →  allow, y el fichero se escribió

La política de rutas no se aplicaba al canal de órdenes. Este módulo existe para que la
decisión se tome sobre `Effects(orden)` y no sobre su sintaxis.

Lo que este módulo NO es, y conviene leerlo antes de confiar en él
------------------------------------------------------------------
`Effects` **no es computable**. Para cualquier máquina de Turing `M` y entrada `w`, la orden

    python3 -c 'if M(w) para: open("gates/base.py","w")'

escribe en el juez si y sólo si `M` para. Decidir el efecto decide la parada. Luego todo
analizador estático sobre órdenes es incorrecto (deja pasar) o incompleto (rechaza lo
inocuo), y un analizador correcto tendría que denegar `python3`, `make`, `npm` y cualquier
binario compilado — un control así se desactiva en una semana y entonces no protege de nada.

Por eso aquí se calcula `Ê`, una **sub-aproximación**: el conjunto de escrituras que se
pueden DEMOSTRAR desde la sintaxis.

    Ê(c) ⊆ Effects(c)

Lo que `Ê` afirma es sólido: si `Ê` dice que se escribe en `p`, se escribe en `p`. Lo que no
afirma es completitud: una orden opaca (`python3 -c …`, un binario propio) puede escribir
donde quiera y `Ê` devuelve `opaco=True` para que quien decida sepa que no sabe.

La garantía del producto NO descansa en este módulo. Descansa en `I6'` —«si el juez fue
modificado, ningún veredicto posterior es PASS»— que se sostiene con la atestación de
`core.trust`. Esto es reducción de superficie, y así se declara. Ver
`docs/assurance/FORMAL-MODEL.md` §6.
"""

from __future__ import annotations

import ast
import re
from dataclasses import dataclass, field

READ, WRITE = "READ", "WRITE"

#: Programas cuyo efecto sobre el sistema de archivos se puede derivar de sus argumentos.
#: Cada entrada dice QUÉ posiciones de argumento se escriben. No se añade ninguno «por si
#: acaso»: uno mal modelado es peor que uno ausente, porque afirma saber lo que no sabe.
#:
#: `destino`  la ÚLTIMA ruta no-opción es el destino escrito  (cp, mv, install, ln)
#: `todas`    toda ruta no-opción se escribe                  (touch, mkdir, rm, chmod, …)
#: `en_sitio` toda ruta no-opción se escribe SÓLO si aparece la bandera indicada; SIN ella el
#:            programa lee, y eso se puede afirmar porque su efecto está acotado por diseño
#: `en_sitio_opaco`  igual con la bandera, y SIN ella **no se deriva nada**: es un intérprete
#:            de propósito general y puede escribir por otros caminos que sus argumentos no
#:            declaran
#:
#: La distinción entre las dos últimas es el arreglo de un defecto medido el 2026-09-25, y la
#: forma del defecto importa más que el caso: `perl` estaba en esta tabla Y en `_OPACOS`, y como
#: esta tabla se consulta primero, ganaba la que afirma de más. Sin su `-i`, la rama `else`
#: clasificaba la orden como LECTURA y devolvía `opaco=False`:
#:
#:     perl -e 'open(F,">","gates/base.py")'      →  escrituras=[]  opaco=False
#:     awk 'BEGIN{print "x" > "gates/base.py"}'   →  escrituras=[]  opaco=False
#:     sed 's/a/b/w gates/base.py' README.md      →  escrituras=[]  opaco=False
#:     python3 -c 'open("gates/base.py","w")'     →  escrituras=[]  opaco=True   ← el correcto
#:
#: Es decir, `Ê` afirmaba «sé que no escribe» de tres lenguajes Turing-completos — exactamente
#: lo que el encabezado de este módulo promete no hacer, porque `Ê` sólo vale si lo que afirma
#: es sólido. Y la consecuencia no se quedaba aquí: `core/grants.py` descarta una concesión
#: `read-only` cuando la orden es opaca, así que el defecto **invertía** su criterio —
#: `sudo systemctl status` se denegaba (no modelado → opaco) y `sudo perl -e 'unlink …'` se
#: permitía (concesión aplicada).
#:
#: `gofmt` y `ruff` se quedan en `en_sitio` a propósito: formatean el fichero que se les nombra
#: y no ejecutan programa del usuario. La diferencia entre las dos clases es esa y no otra.
_ESCRITORES = {
    "cp": ("destino", None), "mv": ("destino", None), "install": ("destino", None),
    "ln": ("destino", None), "rsync": ("destino", None),
    "touch": ("todas", None), "mkdir": ("todas", None), "rmdir": ("todas", None),
    "rm": ("todas", None), "truncate": ("todas", None), "shred": ("todas", None),
    "chmod": ("todas", None), "chown": ("todas", None), "chflags": ("todas", None),
    "tee": ("todas", None),
    "sed": ("en_sitio_opaco", "-i"), "perl": ("en_sitio_opaco", "-i"),
    "awk": ("en_sitio_opaco", "-i"),
    "gofmt": ("en_sitio", "-w"), "ruff": ("en_sitio", "--fix"),
}

#: Programas cuyo efecto sobre el árbol es NINGUNO: leen o hablan por la salida estándar.
#:
#: Existe para que `opaco` signifique algo. Sin esta lista, `ls -la` y `echo hola` salían
#: marcados «no sé qué hace», y una señal que se dispara con todo no informa de nada — el
#: mismo defecto que `core/policy.py::_partir` documenta para los patrones de texto.
#: Una escritura por redirección se detecta aparte, ANTES de mirar el programa, así que
#: `echo x > f` sigue viéndose como escritura aunque `echo` esté aquí.
_LECTORES = {
    "echo", "printf", "true", "false", "pwd", "date", "sleep", "seq", "yes",
    "ls", "cat", "head", "tail", "wc", "find", "grep", "rg", "egrep", "fgrep",
    "sort", "uniq", "cut", "tr", "file", "stat", "diff", "jq", "du", "df",
    "which", "type", "basename", "dirname", "realpath", "readlink",
    "cd", "pushd", "popd", "test", "printenv", "column", "comm", "join",
    "paste", "fold", "nl", "rev", "expand", "less", "more", "xxd", "base64",
    "shasum", "sha256sum", "md5", "md5sum", "cksum", "tree", "ps", "top",
    "lsof", "whoami", "id", "uname", "hostname", "sw_vers", "env",
}

#: Intérpretes y ejecutores: lo que hagan no se deriva de sus argumentos.
#:
#: `perl` NO está aquí, y su ausencia es deliberada: vive en `_ESCRITORES` como
#: `en_sitio_opaco`, que ya produce `opaco=True` sin `-i` y además deriva las escrituras
#: cuando la trae. Estar en las dos tablas es lo que causó el defecto que documenta
#: `_ESCRITORES`, así que la coherencia se comprueba al importar (ver `_EN_LAS_DOS`).
_OPACOS = {
    "python", "python2", "python3", "node", "deno", "bun", "ruby", "php",
    "sh", "bash", "zsh", "dash", "ksh", "fish", "make", "cmake", "ninja",
    "npm", "npx", "pnpm", "yarn", "pip", "pip3", "uv", "uvx", "cargo", "go",
    "mvn", "gradle", "ant", "dotnet", "java", "swift", "rustc", "gcc", "clang",
    "ansible", "terraform", "docker", "kubectl", "git", "osascript",
}

#: Envoltorios que ejecutan OTRA orden CON SUS PROPIOS ARGUMENTOS. Se pelan antes de mirar
#: el programa.
#:
#: `xargs` **no** está aquí, y la ausencia es el arreglo de un agujero que encontró la
#: batería de falsación: `echo gates/base.py | xargs touch` escribía en el juez y el modelo
#: veía `touch` sin argumentos, porque las rutas de `xargs` llegan por la ENTRADA ESTÁNDAR.
#: Pelarlo como a los demás convertía una escritura demostrable en ninguna.
_ENVOLTORIOS = {"env", "nohup", "time", "nice", "ionice", "command", "builtin",
                "exec", "stdbuf", "timeout", "setsid", "sudo", "doas", "then", "do", "else"}

#: Los que reciben sus operandos por la entrada estándar. Lo que escriban no se deriva de
#: sus argumentos: se deriva de lo que les llegue por la tubería, que este módulo no ve.
_DESDE_STDIN = {"xargs", "parallel"}

#: Comprobado al importar: ningún programa puede estar en dos tablas a la vez.
#:
#: No es una precaución teórica. `perl` estaba en `_ESCRITORES` y en `_OPACOS`, y como
#: `_de_un_segmento` consulta la primera antes que la segunda, ganaba la que afirma de más —
#: `Ê` declaraba `opaco=False` sobre un intérprete. Una tabla que se consulta por orden y
#: admite duplicados no tiene un orden: tiene una preferencia que nadie escribió.
#:
#: Revienta al importar, y no en producción devolviendo una clasificación que nadie decidió.
#: Misma idea que `core.capabilities._EN_LAS_DOS` y `core.envelope._SIN_CODIGO`.
_EN_LAS_DOS = sorted((set(_ESCRITORES) & set(_LECTORES))
                     | (set(_ESCRITORES) & set(_OPACOS))
                     | (set(_LECTORES) & set(_OPACOS)))
if _EN_LAS_DOS:                                                       # pragma: no cover
    raise RuntimeError(
        f"programas en dos tablas de efectos a la vez: {', '.join(_EN_LAS_DOS)}. Las tablas se "
        f"consultan por orden, así que el duplicado no es redundante: decide en silencio cuál "
        f"gana. Clasifique cada programa en una sola.")

_ASIGNACION = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*=")
#: Sustitución de proceso y expansión: marcan opacidad.
_EXPANSION = re.compile(r"\$\(|`|\$\{[^}]*[?+=]|<\(|>\(")


#: Estado de RESOLUCIÓN del efecto. Reemplaza al `opaco: bool`, que colapsaba situaciones
#: opuestas en el mismo `False` y por eso registraba certezas falsas (R-01).
#:
#:     SIN_SUJETO    no hay nada que derivar: el segmento está vacío
#:     RESUELTO      el efecto se derivó ENTERO de los argumentos. La certeza es real
#:     DESCONOCIDO   el programa no está modelado. Se arregla añadiéndolo a la tabla
#:     NO_RESOLUBLE  el programa SÍ está modelado y su efecto no se deriva por naturaleza
#:                   (`python3 -c`, `xargs`, `find -exec`). No se arregla nunca: se declara
#:     AMBIGUO       se derivó algo que NO es una ruta: conserva expansión sin resolver
#:                   (`$D`, `${V:-x}`). Es el peor, porque es el único que produce un
#:                   artefacto con aspecto de certeza
#:
#: Las cinco se distinguen porque **se arreglan distinto**, que es el mismo criterio con el
#: que `core.evidence` separó los seis estados del diario y `core.guard` los de la admisión.
SIN_SUJETO, RESUELTO, DESCONOCIDO, NO_RESOLUBLE, AMBIGUO = (
    "SIN_SUJETO", "RESUELTO", "DESCONOCIDO", "NO_RESOLUBLE", "AMBIGUO")

#: Orden de severidad para componer segmentos. Lo menos accionable manda: `NO_RESOLUBLE` pesa
#: más que `DESCONOCIDO` porque el segundo se cierra añadiendo una línea a la tabla y el
#: primero no se cierra nunca. `AMBIGUO` encabeza porque es el único que MIENTE: los demás
#: declaran ignorancia y éste declara un hecho falso.
_ORDEN_RESOLUCION = {SIN_SUJETO: 0, RESUELTO: 1, DESCONOCIDO: 2, NO_RESOLUBLE: 3, AMBIGUO: 4}

#: Una ruta derivada que todavía contiene expansión del shell no es una ruta: es el texto que
#: el shell convertirá en una. `$D`, `${D}`, `${V:-x}`, `` `cmd` ``.
#:
#: Deliberadamente NO incluye los comodines de globbing (`*`, `?`, `[`): un glob se expande
#: contra ficheros que YA existen, así que el conjunto derivado sigue estando acotado por el
#: árbol, mientras que una variable puede valer cualquier cosa. Meterlos aquí marcaría
#: ambiguo medio `find` legítimo sin ganar ninguna propiedad. Es una frontera declarada.
_SIN_EXPANDIR = re.compile(r"\$|`")


@dataclass
class Efectos:
    """Lo que una orden hace sobre el sistema de archivos, hasta donde se puede demostrar."""

    escrituras: set = field(default_factory=set)
    lecturas: set = field(default_factory=set)
    #: Por qué no se pudo resolver, para poder explicarlo en el rastro.
    motivo_opaco: str = ""
    #: En cuál de los cinco estados quedó la derivación.
    resolucion: str = SIN_SUJETO
    #: Destinos de escritura que se vieron y NO se pudieron resolver a una ruta. No entran en
    #: `escrituras` a propósito: afirmar que se escribe en `$D` es afirmar una ruta que no
    #: existe. Tampoco se descartan, porque «vi una escritura y no sé adónde» es justo el
    #: hecho que hay que conservar. Mismo criterio que `core.guard`: no se coacciona, se
    #: declara.
    sin_resolver: set = field(default_factory=set)

    @property
    def opaco(self) -> bool:
        """Compatibilidad: `True` si la derivación no es de fiar.

        Se conserva porque está en el esquema del diario y en más de 2000 eventos ya escritos,
        y porque `core.policy` y `core.grants` lo consultan. Pero ya no es el tipo: es una
        PROYECCIÓN de `resolucion`, y por eso no puede volver a decir `False` sobre algo que no
        se resolvió. Quien necesite la distinción lee `resolucion`.
        """
        return self.resolucion in (DESCONOCIDO, NO_RESOLUBLE, AMBIGUO)

    def __or__(self, otro: "Efectos") -> "Efectos":
        peor = max(self.resolucion, otro.resolucion, key=lambda r: _ORDEN_RESOLUCION[r])
        # El motivo tiene que ser el del estado que GANA, no el primero que hubiera. Con
        # `self.motivo_opaco or otro.motivo_opaco` una orden con dos segmentos podía salir
        # `AMBIGUO` explicando por qué el otro segmento era `DESCONOCIDO`.
        motivo = self.motivo_opaco if peor == self.resolucion else otro.motivo_opaco
        return Efectos(self.escrituras | otro.escrituras,
                       self.lecturas | otro.lecturas,
                       motivo or self.motivo_opaco or otro.motivo_opaco,
                       peor,
                       self.sin_resolver | otro.sin_resolver)

    def declarar(self, estado: str, motivo: str) -> None:
        """Deja el efecto en `estado` si es más severo que el que ya tenía."""
        if _ORDEN_RESOLUCION[estado] > _ORDEN_RESOLUCION[self.resolucion]:
            self.resolucion, self.motivo_opaco = estado, motivo


def _sin_comillas(texto: str) -> str:
    """El texto con el contenido de las comillas en blanco, conservando la longitud.

    Sirve para buscar redirecciones sin confundir un `>` citado con una redirección real:
    `echo "a > b"` no redirige a ninguna parte.
    """
    out, simple, doble = [], False, False
    i, n = 0, len(texto)
    while i < n:
        c = texto[i]
        if c == "\\" and i + 1 < n:
            out.append(" ")
            out.append(" ")
            i += 2
            continue
        if c == "'" and not doble:
            simple = not simple
            out.append(c)
        elif c == '"' and not simple:
            doble = not doble
            out.append(c)
        else:
            out.append(" " if (simple or doble) else c)
        i += 1
    return "".join(out)


def _destinos_de_redireccion(segmento: str) -> list:
    """Las rutas a las que este segmento redirige la salida.

    Se escribió primero con una expresión regular sobre el texto «sin comillas», y tenía un
    agujero que encontró la batería de falsación: `echo x > "gates/base.py"` y su variante
    con comilla simple **se colaban**, porque el destino iba entre comillas y el borrado de
    literales lo dejaba en blanco justo antes de leerlo. Citar una ruta es lo más normal del
    mundo —cualquier ruta con espacios lo exige— así que el agujero no era exótico.

    Ahora se recorre el segmento carácter a carácter llevando el estado de las comillas: el
    OPERADOR sólo cuenta si está fuera de comillas (`echo "a > b"` no redirige a ninguna
    parte), y el DESTINO se lee después respetándolas.
    """
    destinos, i, n = [], 0, len(segmento)
    simple = doble = False
    while i < n:
        c = segmento[i]
        if c == "\\" and i + 1 < n:
            i += 2
            continue
        if c == "'" and not doble:
            simple = not simple
        elif c == '"' and not simple:
            doble = not doble
        elif c == ">" and not simple and not doble:
            j = i + 1
            while j < n and segmento[j] in ">|":      # `>>`, `>|`
                j += 1
            while j < n and segmento[j] in " \t":
                j += 1
            # El destino, respetando las comillas que lo envuelvan.
            destino, cita = [], ""
            while j < n:
                ch = segmento[j]
                if cita:
                    if ch == cita:
                        cita = ""
                    else:
                        destino.append(ch)
                elif ch in "'\"":
                    cita = ch
                elif ch in " \t;&|<>()\n":
                    # Los paréntesis cierran el destino: en `(echo x > a.lock.json)` el
                    # cierre del subshell se pegaba al nombre y producía `a.lock.json)`,
                    # que ya no casa con `*.lock.json`. Sólo fallaban las rutas SIN barra
                    # —las de la raíz— porque un patrón `dir/**` seguía casando con el
                    # nombre sucio. Lo encontró el producto cartesiano, no el diseño.
                    break
                else:
                    destino.append(ch)
                j += 1
            ruta = "".join(destino)
            if ruta and ruta not in ("/dev/null", "/dev/stdout", "/dev/stderr"):
                destinos.append(ruta)
            i = j
            continue
        i += 1
    return destinos


def _tokens(segmento: str) -> list:
    """Los tokens del segmento, sin comillas envolventes."""
    bruto = segmento.split()
    return [t.strip("'\"") for t in bruto]


def _pelar(tokens: list) -> list:
    """Quita envoltorios y asignaciones de entorno de la cabeza."""
    i = 0
    while i < len(tokens) and (tokens[i] in _ENVOLTORIOS or _ASIGNACION.match(tokens[i])):
        i += 1
    return tokens[i:]


def _rutas(tokens: list) -> list:
    """Los argumentos que parecen rutas: los que no empiezan por guion."""
    return [t for t in tokens if t and not t.startswith("-")]


#: Acciones de `find` que EJECUTAN o BORRAN. `find` vive en `_LECTORES` porque recorrer un
#: árbol es leerlo, y eso es cierto salvo con estas banderas, que convierten el recorrido en
#: un ejecutor de programa arbitrario sobre cada coincidencia.
#:
#: Medido el 2026-09-25: `find . -name base.py -exec truncate -s0 {} ;` salía
#: `escrituras=[] opaco=False`. Es decir, `Ê` afirmaba «sé que no escribe» de una orden que
#: trunca ficheros — la misma clase de afirmación falsa que `perl` sin `-i` ya había costado.
_FIND_ACCIONES = {"-exec", "-execdir", "-delete", "-ok", "-okdir"}


def _de_un_segmento(segmento: str) -> Efectos:
    """Efectos de UNA orden simple, con su estado de resolución ya normalizado."""
    ef = _derivar_segmento(segmento)

    # ── normalización: lo que se derivó, ¿es de fiar? ────────────────────────────────
    #
    # Una «ruta» que conserva expansión del shell no es una ruta: es el texto que el shell
    # convertirá en una. Afirmar `escrituras={'$D'}` con `opaco=False` era registrar una
    # certeza sobre un destino que nadie conoce (R-01). No se coacciona ni se descarta: se
    # mueve a `sin_resolver` y se declara `AMBIGUO`. Mismo criterio que `core.guard._campo`.
    crudas = {p for p in ef.escrituras if _SIN_EXPANDIR.search(p)}
    if crudas:
        ef.escrituras -= crudas
        ef.sin_resolver |= crudas
        ef.declarar(AMBIGUO,
                    f"el destino de escritura conserva expansión sin resolver "
                    f"({', '.join(sorted(crudas)[:3])}): su valor lo decide el shell en "
                    f"tiempo de ejecución, así que no se puede afirmar sobre qué ruta actúa")
    # Las LECTURAS no se filtran, y la asimetría es deliberada. Un destino de escritura sin
    # resolver es una afirmación falsa —`escrituras={'$D'}` dice que se escribe en un fichero
    # llamado `$D`—, pero un token de lectura sin resolver sigue siendo información útil: es el
    # NOMBRE DE LA VARIABLE, y `_lecturas_secretas` lo usa para detectar credenciales por su
    # forma. Filtrarlo aquí convertía `echo $MI_SERVICIO_PASSWORD` de `ask` en `allow` —medido
    # al introducir este cambio, y es una regresión de seguridad, no un detalle—. Un `$D`
    # espurio en `lecturas` es inerte: no se compara contra rutas protegidas.

    # Se derivó algo y nada lo puso en duda: la certeza es real y se dice.
    if ef.resolucion == SIN_SUJETO and (ef.escrituras or ef.lecturas):
        ef.resolucion = RESUELTO
    return ef


_RE_INLINE_CODE = re.compile(
    r"""(?x)
    (?:^|\s)(?:-c|-e|--eval|-r|-E)
    (?:\s*=\s*|\s+)
    (?:\"\"\"|\'\'\'|[\"\'])(.*?)(?:\"\"\"|\'\'\'|[\"\'])
    (?:\s|$)
    """,
    re.DOTALL
)
_RE_INLINE_UNQUOTED = re.compile(
    r"""(?x)
    (?:^|\s)(?:-c|-e|--eval|-r|-E)
    (?:\s*=\s*|\s+)
    (\S+)
    """
)

def _extraer_codigo_inline(segmento: str) -> str | None:
    m = _RE_INLINE_CODE.search(segmento)
    if m:
        return m.group(1)
    m2 = _RE_INLINE_UNQUOTED.search(segmento)
    if m2:
        return m2.group(1)
    return None


_RE_FS_MUTATION = re.compile(
    r"""(?x)
    (?:
        fs(?:\.promises)?\.(?:unlink|unlinkSync|rm|rmSync|rmdir|rmdirSync|writeFile|writeFileSync|appendFile|appendFileSync|truncate|truncateSync|rename|renameSync|copyFile|copyFileSync)
        |
        File\.(?:delete|unlink|write|truncate|rename)
        |
        FileUtils\.(?:rm|rm_rf|rm_r|remove_entry|cp|mv)
        |
        \bunlink\b
        |
        \b(?:unlink|file_put_contents|rmdir|rename)\b
        |
        os\.(?:remove|unlink|rmdir|rename|replace|truncate)
        |
        shutil\.(?:rmtree|move|copy|copy2|copyfile|copytree)
        |
        Path\([^)]*\)\.(?:unlink|rmdir|write_text|write_bytes|touch)
    )
    \s*\(?\s*['"`]([^'"`]+)['"`]
    """
)

_RE_EXEC_INNER = re.compile(
    r"""(?x)
    (?:
        child_process\.(?:exec|execSync|spawn|spawnSync)
        |
        os\.system
        |
        subprocess\.(?:run|Popen|call|check_call|check_output)
        |
        do\s+shell\s+script
    )
    \s*\(?\s*['"`]([^'"`]+)['"`]
    """
)

_RE_DYNAMIC_EVAL = re.compile(
    r"""(?x)
    \b(?:
        eval\s*\(
        |
        exec\s*\(
        |
        Function\s*\(
        |
        Buffer\.from\s*\([^,]+,\s*['"]base64['"]
        |
        atob\s*\(
        |
        b64decode
        |
        base64\.b64decode
    )
    """
)

_RE_REDIRECTION_INNER = re.compile(r'>\s*[\'"]([^\'"]+)[\'"]')


def _extraer_arg_cadena(node) -> str | None:
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    return None


def _analizar_python_ast(codigo: str, ef: Efectos) -> None:
    try:
        tree = ast.parse(codigo)
    except Exception:
        _analizar_lexico_inline("python", codigo, ef)
        return

    _OS_WRITES = {"remove", "unlink", "rmdir", "rename", "replace", "truncate"}
    _SHUTIL_WRITES = {"rmtree", "move", "copy", "copy2", "copyfile", "copytree", "chown"}
    _DYNAMIC_EVAL = {"eval", "exec", "compile", "__import__"}

    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            func_name = ""
            if isinstance(node.func, ast.Name):
                func_name = node.func.id
            elif isinstance(node.func, ast.Attribute):
                func_name = node.func.attr

            if func_name in _DYNAMIC_EVAL:
                ef.declarar(AMBIGUO, f"«python -c» ejecuta evaluación dinámica ({func_name})")
            elif func_name in ("b64decode", "decode"):
                ef.declarar(AMBIGUO, "«python -c» ejecuta decodificación dinámica")

            if func_name == "open" and node.args:
                target = _extraer_arg_cadena(node.args[0])
                mode = "r"
                if len(node.args) >= 2:
                    mode = _extraer_arg_cadena(node.args[1]) or "r"
                for kw in node.keywords:
                    if kw.arg == "mode":
                        mode = _extraer_arg_cadena(kw.value) or mode
                if any(m in mode for m in "wax+"):
                    if target:
                        ef.escrituras.add(target)
                    else:
                        ef.sin_resolver.add("open(dinamico)")
                else:
                    if target:
                        ef.lecturas.add(target)

            elif func_name in _OS_WRITES and node.args:
                target = _extraer_arg_cadena(node.args[0])
                if target:
                    ef.escrituras.add(target)
                else:
                    ef.sin_resolver.add(f"os.{func_name}(dinamico)")

            elif func_name in _SHUTIL_WRITES and node.args:
                target = _extraer_arg_cadena(node.args[0])
                if target:
                    ef.escrituras.add(target)
                if len(node.args) >= 2:
                    target2 = _extraer_arg_cadena(node.args[1])
                    if target2:
                        ef.escrituras.add(target2)

            elif func_name in ("unlink", "rmdir", "write_text", "write_bytes", "touch", "rename", "replace"):
                if isinstance(node.func, ast.Attribute) and isinstance(node.func.value, ast.Call):
                    inner = node.func.value
                    if inner.args:
                        target = _extraer_arg_cadena(inner.args[0])
                        if target:
                            ef.escrituras.add(target)
                elif node.args:
                    target = _extraer_arg_cadena(node.args[0])
                    if target:
                        ef.escrituras.add(target)

            elif func_name in ("system", "run", "Popen", "call", "check_call", "check_output"):
                if node.args:
                    inner_cmd = _extraer_arg_cadena(node.args[0])
                    if inner_cmd:
                        sub_ef = efectos(inner_cmd)
                        ef.escrituras.update(sub_ef.escrituras)
                        ef.lecturas.update(sub_ef.lecturas)
                        ef.sin_resolver.update(sub_ef.sin_resolver)


def _analizar_lexico_inline(programa: str, codigo: str, ef: Efectos) -> None:
    for target in _RE_FS_MUTATION.findall(codigo):
        ef.escrituras.add(target)
    for inner in _RE_EXEC_INNER.findall(codigo):
        sub = efectos(inner)
        ef.escrituras.update(sub.escrituras)
        ef.lecturas.update(sub.lecturas)
        ef.sin_resolver.update(sub.sin_resolver)
    for target in _RE_REDIRECTION_INNER.findall(codigo):
        ef.escrituras.add(target)
    if _RE_DYNAMIC_EVAL.search(codigo):
        ef.declarar(AMBIGUO, f"«{programa}» ejecuta código con evaluación dinámica o codificación")


def _derivar_segmento(segmento: str) -> Efectos:
    """La derivación cruda, antes de comprobar si lo derivado es de fiar."""
    ef = Efectos()
    visible = _sin_comillas(segmento)

    # 1 · Redirecciones. Es el caso que el guardián no veía y el más común de todos.
    ef.escrituras.update(_destinos_de_redireccion(segmento))

    # 2 · Expansión dinámica: el nombre del fichero puede construirse en tiempo de ejecución.
    if _EXPANSION.search(visible):
        ef.declarar(NO_RESOLUBLE,
                    "la orden construye parte de sí misma en tiempo de ejecución")

    tokens = _pelar(_tokens(segmento))
    if not tokens:
        return ef
    programa = tokens[0].rsplit("/", 1)[-1]
    resto = tokens[1:]

    # 3 · `xargs W`: las rutas le llegan por la tubería. Si `W` escribe, se escribe en algo
    # que este módulo no puede nombrar. Se declara opaco y NO se finge que no pasa nada.
    if programa in _DESDE_STDIN:
        envuelto = next((t.rsplit("/", 1)[-1] for t in resto if not t.startswith("-")), "")
        if envuelto in _ESCRITORES or envuelto in _OPACOS:
            ef.declarar(NO_RESOLUBLE,
                        f"«{programa} {envuelto}» recibe sus rutas por la entrada "
                        f"estándar: lo que escriba no se deriva de sus argumentos")
        elif envuelto:
            ef.lecturas.update(_rutas(resto))
        return ef

    # 4 · Programas con efecto derivable de sus argumentos.
    if programa in _ESCRITORES:
        clase, bandera = _ESCRITORES[programa]
        rutas = _rutas(resto)
        if clase == "destino" and len(rutas) >= 2:
            ef.escrituras.add(rutas[-1])
            ef.lecturas.update(rutas[:-1])
        elif clase == "destino" and len(rutas) == 1:
            ef.escrituras.add(rutas[0])
        elif clase == "todas":
            ef.escrituras.update(rutas)
        elif clase in ("en_sitio", "en_sitio_opaco"):
            if any(t == bandera or t.startswith(bandera) for t in resto):
                # `sed -i` puede llevar sufijo de respaldo como argumento suelto; se marcan
                # todas las rutas como escritas, que es el lado conservador.
                ef.escrituras.update(rutas)
            elif clase == "en_sitio_opaco":
                # Sin su bandera examinamos si trae código en línea (-e, -E) antes de descartar
                codigo = _extraer_codigo_inline(segmento)
                if codigo:
                    _analizar_lexico_inline(programa, codigo, ef)
                ef.declarar(NO_RESOLUBLE,
                            f"«{programa}» sin «{bandera}» ejecuta un programa que no se "
                            f"deriva de sus argumentos: puede escribir por otros caminos "
                            f"(`{programa} -e`, redirección interna, el comando `w`)")
                return ef
            else:
                ef.lecturas.update(rutas)
        ef.declarar(RESUELTO, "")
        return ef

    # 4 · Programas de sólo lectura: efecto conocido y vacío. No son opacos.
    if programa in _LECTORES:
        # …salvo que el «lector» traiga una acción que ejecuta o borra. `find -exec` recorre
        # leyendo y actúa escribiendo, y lo que ejecute no se deriva de estos argumentos.
        if programa == "find":
            accion = next((t for t in resto if t in _FIND_ACCIONES), "")
            if accion:
                ef.declarar(NO_RESOLUBLE,
                            f"«find {accion}» ejecuta una acción sobre cada coincidencia: lo "
                            f"que escriba o borre no se deriva de los argumentos de `find`, "
                            f"sino del árbol que recorra en tiempo de ejecución")
                return ef
        ef.lecturas.update(_rutas(resto))
        # Un lector reconocido SIN rutas en sus argumentos (`ls -la`, `pwd`) no es «no había
        # nada que derivar»: es «se derivó, y el efecto sobre el árbol es ninguno». Colapsar
        # las dos repetiría en pequeño el defecto que este cambio corrige.
        ef.declarar(RESUELTO, "")
        return ef

    # 5 · Opacos: se analiza el código en línea o script si existe.
    if programa in _OPACOS:
        codigo = _extraer_codigo_inline(segmento)
        if codigo:
            if programa in ("python", "python2", "python3"):
                _analizar_python_ast(codigo, ef)
            _analizar_lexico_inline(programa, codigo, ef)
        else:
            rutas = _rutas(resto)
            if rutas:
                ef.lecturas.add(rutas[0])
        ef.declarar(NO_RESOLUBLE,
                    f"«{programa}» ejecuta código que no se deriva de sus argumentos")
        return ef

    # 5 · Programa desconocido. Tampoco se sabe.
    if programa and not programa.startswith("-"):
        ef.declarar(DESCONOCIDO,
                    f"«{programa}» no está modelado: su efecto no se puede derivar")
    return ef


def _segmentar(orden: str) -> list:
    """Cada orden simple que esta cadena va a ejecutar.

    Se reutiliza el partidor de `core.policy`, que ya respeta comillas — duplicarlo sería
    tener dos analizadores que divergen, que es el defecto que `core.policy` documenta.
    """
    from core.policy import _partir, _sin_cuerpos_citados, _sin_literales

    # El cuerpo de un documento aquí citado no se ejecuta, así que tampoco escribe. Sin esto, la
    # prosa `redirige con > /etc/passwd` dentro de un `<<'EOF'` se derivaba como una escritura
    # REAL a `/etc/passwd`, y la orden se denegaba por «fuera-del-espacio»: medido el 2026-09-24.
    # La línea del operador se conserva, así que la redirección de verdad (`cat > destino`) se
    # sigue viendo. Ver `core.policy._sin_cuerpos_citados`.
    orden = _sin_cuerpos_citados(orden)
    fuera = []
    for sentencia in _partir(orden, tuberia=False):
        fuera.append(sentencia)
        fuera += _partir(sentencia)
    # Lo que va dentro de `$( … )` y de comillas invertidas también se ejecuta.
    for a, b in re.findall(r"\$\(([^()]*)\)|`([^`]*)`", _sin_literales(orden)):
        fuera += _partir(a) + _partir(b)
    # `sh -c "…"`: la orden real va dentro.
    for seg in list(fuera):
        t = seg.split()
        if len(t) >= 3 and t[0].rsplit("/", 1)[-1] in {"sh", "bash", "zsh", "dash"} \
                and "-c" in t[1:3]:
            fuera += _partir(seg.split("-c", 1)[1].strip().strip("'\""))
    return [s for s in fuera if s.strip()]


def efectos(orden: str) -> Efectos:
    """`Ê(orden)`: las escrituras que se pueden DEMOSTRAR, y si queda algo sin demostrar.

    Sólido en lo que afirma —si dice que escribe en `p`, escribe en `p`— e incompleto por
    construcción: ver el encabezado del módulo.
    """
    total = Efectos()
    for seg in _segmentar(orden):
        total = total | _de_un_segmento(seg)
    return total
