# -*- coding: utf-8 -*-
"""Refinamiento de política: `refuto → cliente → proyecto`.

Qué NO es esto, y por qué importa decirlo primero
-------------------------------------------------
No es `{**padre, **hijo}`. Una superposición de diccionarios deja que el hijo **sustituya**
cualquier clave del padre, y sustituir es relajar cuando la clave es una restricción. Bajo esa
semántica, una capa de cliente se convierte en el sitio donde se van a aflojar los controles —
y peor, en silencio, porque un `merge` no tiene nada que reportar.

Aquí el hijo **refina**: puede endurecer y puede añadir. Cualquier intento de aflojar no se
aplica a medias ni se avisa: **se rechaza la política entera**. Una política parcialmente
aplicada es indistinguible de una política, y esa indistinguibilidad es el fallo.

La invariante, en una línea
---------------------------
    restricciones(hijo)  ⊇  restricciones(padre)

Cada campo declara de qué lado cae y por qué. Un campo que no esté en `REGLAS` **no se
hereda y no se acepta**: añadir una clave nueva a `Policy` sin decidir su monotonía dejaría un
agujero por omisión, y los agujeros por omisión son los que nadie revisa.

Identidad
---------
Dos políticas con el mismo texto pero distinto padre **no son la misma política**. El digest
efectivo encadena la identidad del padre, así que un cambio en el cliente cambia la identidad
del proyecto aunque el proyecto no se haya tocado. Eso es exactamente lo que se quiere poder
detectar: que el significado de un proyecto cambió sin que el proyecto cambiara.
"""

from __future__ import annotations

import hashlib
import json
import os
from dataclasses import dataclass, field
from pathlib import Path

from core.policy import Policy, PoliticaIlegible

SCHEMA = "harness.refinement/v1"

# ── vocabulario de resultado ─────────────────────────────────────────────────────────
#
# Se reutilizan los estados del motor. No se inventan `NOT_DECLARED` ni `MISCONFIGURED`:
# `Result` ya obliga a que todo veredicto traiga su medida escrita, así que la distinción
# entre «no lo declaró», «lo declaró mal» y «no aplica» viaja en el motivo, que es donde se
# puede leer. Dos estados más partirían una dimensión ya expresada y romperían el
# `status_map` de cualquier consumidor externo.
from core.model import NOT_EXECUTABLE, PASS  # noqa: E402


@dataclass(frozen=True)
class Identidad:
    """Quién es una política, de forma verificable.

    `digest` es del documento canonicalizado; `efectivo` encadena al padre. Con sólo el
    primero, cambiar el cliente dejaría al proyecto con la misma identidad y otro
    significado — que es justo lo que hay que poder detectar.
    """

    nombre: str
    version: str
    digest: str
    efectivo: str = ""

    def to_dict(self) -> dict:
        return {"nombre": self.nombre, "version": self.version,
                "digest": self.digest, "efectivo": self.efectivo}


@dataclass
class Refinamiento:
    """El resultado de refinar. `status` es `PASS` o `NOT_EXECUTABLE`; nunca a medias."""

    status: str
    politica: Policy | None = None
    identidad: Identidad | None = None
    violaciones: list = field(default_factory=list)
    motivo: str = ""
    cadena: list = field(default_factory=list)

    def to_dict(self) -> dict:
        return {"schema": SCHEMA, "status": self.status, "motivo": self.motivo,
                "identidad": self.identidad.to_dict() if self.identidad else None,
                "violaciones": list(self.violaciones),
                "cadena": [i.to_dict() for i in self.cadena]}


# ── monotonía, campo por campo ───────────────────────────────────────────────────────
#
# `ACUMULA`   conjunto: el hijo hereda todo lo del padre y puede añadir. Quitar es violación.
# `REDUCE`    conjunto: el hijo hereda y **sólo puede quitar**. Añadir es violación.
# `ENDURECE`  booleano: `True` del padre no se puede poner a `False`.
# `PROPIO`    no se hereda; el valor del hijo manda. Reservado a lo que no es una restricción.
ACUMULA, REDUCE, ENDURECE, PROPIO = "acumula", "reduce", "endurece", "propio"
#: `MODO`   diccionario runtime→modo: el hijo no puede poner un modo MÁS PERMISIVO que el padre.
MODO = "modo"
#: `REDUCE_LISTA`  lista de registros: el hijo sólo puede QUITAR registros enteros.
#:
#: Hacía falta para `privilege_grants`, cuyos elementos son mapas y no cadenas, así que la
#: comparación de conjuntos de `REDUCE` no sirve. La regla es deliberadamente gruesa: el hijo
#: puede retirar una concesión completa y **no puede modificar una que conserva**. Estrechar
#: una concesión existente —acortar su caducidad, quitarle un host— se expresa retirándola y
#: escribiendo otra, y escribir otra es añadir, que es violación. Es más estricto de lo
#: necesario y es el lado correcto: comparar «anchura» entre dos concesiones exigiría decidir
#: inclusión entre globs de órdenes, que es justo lo que `_cubre` evita hacer (ADR-0014).
REDUCE_LISTA = "reduce_lista"

#: `ACUMULA_MAPA`  diccionario clave→conjunto: `ACUMULA` aplicado clave a clave.
#:
#: Hacía falta para `role_capabilities`, que es un mapa de rol a restricciones. La unión por
#: clave conserva la propiedad que importa —el hijo añade y no puede retirar— y, como en
#: `ACUMULA`, **no hay sintaxis para quitar**: retirar una restricción de un rol es
#: inexpresable, no una violación a detectar. Tratarlo como `PROPIO` habría dejado que un
#: proyecto vaciara las capacidades que su cliente impuso, en silencio y con un solo `{}`.
ACUMULA_MAPA = "acumula_mapa"

#: Orden de permisividad, de menos a más. Sólo se comparan modos que estén aquí.
#:
#: Un modo que no figure NO se compara: se exige igualdad con el padre. Si no se puede
#: demostrar que un cambio no es una relajación, no se autoriza — y eso incluye a
#: `declared-in-agent` y `unknown`, que vienen en los valores de fábrica y no son rankeables
#: porque su permisividad la decide otro fichero o no se sabe.
ORDEN_MODOS = ("ask", "default", "acceptEdits", "bypassPermissions")

REGLAS = {
    # Lo que protege. Más siempre se puede; menos, nunca.
    "protected_paths": ACUMULA,
    "secret_read_deny": ACUMULA,
    # Los nombres de variable con forma de credencial acumulan por el mismo motivo que las
    # rutas: marcar de más cuesta una consulta a una persona, y marcar de menos cuesta el
    # secreto. Y con la raíz NO vacía, `ACUMULA` no cae en la trampa de `REDUCE`.
    "secret_env_deny": ACUMULA,
    "command_deny": ACUMULA,
    # `command_ask` acumula por el mismo motivo: retirar una consulta convierte en automática
    # una decisión que alguien reservó a una persona.
    "command_ask": ACUMULA,
    "network_rules": ACUMULA,

    # Lo que ABRE un agujero en lo protegido. El hijo puede cerrar agujeros del padre, nunca
    # abrir otros: un agujero heredado en silencio a través de dos capas es indetectable en
    # revisión, y un agujero AÑADIDO por el hijo sería exactamente «relajar».
    "writable_paths": REDUCE,
    "external_write_allow": REDUCE,

    # Detectar secretos es una restricción: encenderla se puede, apagarla no.
    "block_secret_content": ENDURECE,

    # `default_modes` SÍ es una restricción de seguridad, y clasificarlo como `PROPIO` fue un
    # error mío. El razonamiento que escribí —«no es seguridad sino interacción»— quedó
    # falsado midiendo: `adapters/claude.py` compila este valor a `permissions.defaultMode`,
    # así que un hijo podía pasar de `ask` a `bypassPermissions` y la monotonía no lo miraba.
    #
    # El matiz que la medición también dio, y que conviene no perder: NO está comprobado que
    # `bypassPermissions` anule el gancho `PreToolUse`. Los ajustes compilados siguen
    # emitiendo sus reglas de consulta, así que el daño real es menor que «apaga la consulta a
    # la persona» — pero eso es comportamiento de Claude Code y aquí está `NOT_RUN`. La
    # reclasificación procede igual: lo que no se puede afirmar no se concede.
    "default_modes": MODO,

    # El SUJETO. Las capacidades por rol sólo APRIETAN, y por eso acumulan clave a clave. Se
    # expresan en negativo (`no_shell`) precisamente para que la unión sea la operación
    # correcta: una lista de concesiones tendría que ser `REDUCE` y volvería a la trampa que
    # documenta ADR-0014. Ver `core/capabilities.py`.
    "role_capabilities": ACUMULA_MAPA,

    # Una concesión de privilegio ABRE un agujero en el canal de órdenes, igual que
    # `writable_paths` lo abre en las rutas. Por eso reduce: el hijo cierra, nunca abre.
    "privilege_grants": REDUCE_LISTA,

    # Metadatos. No son política y por eso el hijo los fija: `schema` identifica el contrato
    # del documento y `version` la revisión de quien lo escribe. Que estén aquí y no
    # ausentes es deliberado — la regla es «todo campo de `Policy` declara su monotonía», y
    # un metadato sin declarar haría fallar a cualquier hijo legítimo.
    "schema": PROPIO,
    "version": PROPIO,
}

#: Comprobado al importar: ningún campo de `Policy` puede quedarse sin regla. Si alguien
#: añade uno y olvida decidir cómo se hereda, esto revienta aquí — al importar el módulo, no
#: en producción con una política a medias. Es la misma idea que `check_wiring.py`: un
#: componente que existe y que nadie conectó es peor que no tenerlo.
_SIN_REGLA = sorted(set(Policy.__dataclass_fields__) - set(REGLAS))   # noqa: SLF001
if _SIN_REGLA:                                                        # pragma: no cover
    raise RuntimeError(
        f"campos de Policy sin regla de monotonía: {', '.join(_SIN_REGLA)}. "
        f"Decida en `REGLAS` si acumulan, reducen, endurecen o son propios: heredarlos por "
        f"omisión sería un agujero que nadie revisa.")


def _canonico(doc: dict) -> str:
    """El texto del que se saca el digest. Las claves de comentario (`_que_es`, `_medido`…)
    se descartan: una nota que cambia no cambia la política, y si contara, editar un
    comentario invalidaría la identidad de todos los proyectos que heredan.

    Las listas de cadenas se ordenan por el mismo motivo. `protected_paths` es un CONJUNTO
    de patrones: el orden en que se tecleó no cambia nada de lo que protege. `sort_keys`
    sólo ordenaba las CLAVES, así que reordenar dos patrones —o que un paso intermedio los
    normalice— cambiaba la identidad del documento sin cambiar la política, e invalidaba
    todo `extends_digest` anclado a él. Medido el 2026-09-24: entre un documento y su
    composición con la norma base, la ÚNICA diferencia era el orden de cinco listas.

    Las listas que no son de cadenas (`network_rules`) se dejan como están: no se puede
    afirmar que su orden no signifique nada, y ordenar por afirmación no medida es
    justamente lo que este módulo existe para no hacer.
    """
    def _valor(v):
        if isinstance(v, list) and all(isinstance(x, str) for x in v):
            return sorted(v)
        return v

    limpio = {k: _valor(v) for k, v in sorted(doc.items()) if not k.startswith("_")}
    return json.dumps(limpio, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def digest_de(doc: dict) -> str:
    return hashlib.sha256(_canonico(doc).encode("utf-8")).hexdigest()


def identidad_de(doc: dict, *, padre: Identidad | None = None) -> Identidad:
    d = digest_de(doc)
    base = f"{padre.efectivo}|{d}" if padre else d
    return Identidad(
        nombre=str(doc.get("name") or doc.get("nombre") or "sin-nombre"),
        version=str(doc.get("version", "")),
        digest=d,
        efectivo=hashlib.sha256(base.encode("utf-8")).hexdigest())


def _viola(campo: str, regla: str, padre, hijo) -> list:
    """Qué ha intentado hacer el hijo que no puede. Lista vacía = refina bien."""
    if regla == MODO:
        fuera = []
        for runtime, modo_hijo in (hijo or {}).items():
            modo_padre = (padre or {}).get(runtime)
            if modo_padre is None or modo_padre == modo_hijo:
                continue
            if modo_padre in ORDEN_MODOS and modo_hijo in ORDEN_MODOS:
                if ORDEN_MODOS.index(modo_hijo) > ORDEN_MODOS.index(modo_padre):
                    fuera.append(f"`{campo}[{runtime}]`: el padre pide «{modo_padre}» y el "
                                 f"hijo pone «{modo_hijo}», que es más permisivo.")
            else:
                fuera.append(f"`{campo}[{runtime}]`: el padre pide «{modo_padre}» y el hijo "
                             f"pone «{modo_hijo}». Alguno de los dos no está en el orden de "
                             f"permisividad, así que no se puede demostrar que el cambio no "
                             f"sea una relajación — y lo que no se puede afirmar no se "
                             f"concede.")
        return fuera
    if regla == ENDURECE:
        if bool(padre) and not bool(hijo):
            return [f"`{campo}`: el padre lo exige (`true`) y el hijo lo apaga (`false`). "
                    f"Apagar una comprobación heredada es relajar."]
        return []
    # `REDUCE_LISTA` va ANTES de convertir a conjunto: sus elementos son mapas y un `dict` no es
    # hashable. Ponerlo después reventaba con `TypeError` en vez de decidir, que en una función de
    # monotonía es lo peor que puede pasar — un error de tipo se lee como «la política no se pudo
    # resolver» y el guardián deniega todo, así que un campo mal colocado parece un ataque.
    if regla == REDUCE_LISTA:
        def _canon(x):
            return json.dumps(x, ensure_ascii=False, sort_keys=True) if isinstance(x, dict) \
                else json.dumps(x, ensure_ascii=False)
        p_can = {_canon(x) for x in (padre or ())}
        sobran = sorted(_canon(x) for x in (hijo or ()) if _canon(x) not in p_can)
        if sobran:
            return [f"`{campo}`: el hijo declara {len(sobran)} registro(s) que el padre no "
                    f"tiene idénticos. Este campo ABRE un agujero, así que el hijo sólo puede "
                    f"retirar registros enteros; modificar uno se expresa retirándolo y "
                    f"escribiendo otro, y escribir otro es añadir. Primero: "
                    f"{sobran[0][:160]}"]
        return []
    if regla == ACUMULA_MAPA:
        # Como `ACUMULA` y por el mismo motivo: el efectivo es la unión por clave, así que
        # retirar una restricción de un rol no es una violación detectable — es inexpresable.
        # Lo único que se comprueba es la FORMA: un valor que no sea un mapa de listas no se
        # puede unir, y aceptarlo dejaría el campo silenciosamente vacío.
        if hijo is not None and not isinstance(hijo, dict):
            return [f"`{campo}`: se esperaba un mapa de rol a restricciones y llegó un "
                    f"{type(hijo).__name__}. Un valor que no se puede unir se aplicaría como "
                    f"vacío, y un campo de restricción vacío por error de forma es el peor "
                    f"modo de no tener control: el documento parece declararlo."]
        for rol, v in (hijo or {}).items():
            if not isinstance(v, (list, tuple)):
                return [f"`{campo}[{rol}]`: se esperaba una lista de restricciones y llegó un "
                        f"{type(v).__name__}."]
        return []
    # Desde aquí los campos son conjuntos de cadenas y sí se pueden hashear.
    p, h = set(padre or ()), set(hijo or ())
    if regla == ACUMULA:
        # Nunca hay violación, y es deliberado: el efectivo es la UNIÓN, así que el hijo no
        # tiene forma de retirar nada. Relajar aquí no se detecta — es INEXPRESABLE.
        #
        # La primera versión exigía que el hijo repitiera cada entrada del padre so pena de
        # «retirarla». Además de detectar mal (un hijo legítimo que añadía una ruta y no
        # repetía las heredadas se rechazaba), obligaba a la repetición exacta que la
        # herencia existe para eliminar: un cliente con veinte rutas protegidas forzaba a
        # copiarlas en cada proyecto, y a la tercera copia alguien recorta.
        #
        # No poder expresar la violación es más fuerte que detectarla. El único campo donde
        # sigue haciendo falta detección es `REDUCE`, porque ahí la unión SÍ ensancharía.
        return []
    if regla == REDUCE:
        sobran = sorted(x for x in h if not any(_cubre(pp, x) for pp in p))
        return [f"`{campo}`: el hijo añade {len(sobran)} entrada(s) que el padre no cubre: "
                f"{', '.join(sobran[:5])}. Este campo abre agujeros en lo protegido y sólo "
                f"puede encogerse."] if sobran else []
    return []


def _cubre(patron_padre: str, patron_hijo: str) -> bool:
    """¿Toda ruta que case con el patrón del hijo casa también con el del padre?

    Sólo devuelve `True` cuando la inclusión se puede DEMOSTRAR. Comparar globs en general no
    es decidible, así que ante la duda se responde `False` y el refinamiento lo trata como una
    entrada añadida — que es el lado seguro: rechazar un estrechamiento legítimo se nota y se
    arregla, aceptar un ensanchamiento no se nota nunca.

    El defecto que esto cierra
    --------------------------
    La comparación era por CADENA (`h - p`), y eso confunde «añadir un agujero» con
    «escribirlo de otra forma». `core.policy._path_matches` define `**/X` como «X en la raíz o
    a cualquier profundidad», luego `X ⊂ **/X` es una inclusión estricta y declarar `X` cuando
    el padre dice `**/X` es ESTRECHAR, no ensanchar.

    Medido el 2026-09-24: al corregir la asimetría de `DEFAULT_WRITABLE` —de
    `.harness/memory/**` a `**/.harness/memory/**`— toda política existente que declaraba el
    valor anterior dejó de resolverse:

        HerenciaIrresoluble: `writable_paths`: el hijo añade 1 entrada(s) que el padre no
        tiene: .harness/memory/**

    y una política que no resuelve hace que el guardián deniegue TODO. Es decir: la norma base
    no se podía corregir sin dejar ungobernables los espacios ya instalados, porque el
    instalador escribía justamente el valor antiguo. Un campo así no se puede mantener.
    """
    if patron_padre == patron_hijo:
        return True
    # `**/X` cubre `X`: es la misma relación que `_path_matches` aplica al comparar rutas, donde
    # para un patrón `**/…` se prueba además sin el prefijo. La dirección importa y no es
    # simétrica: el hijo puede pasar de `**/X` a `X` (estrecha), nunca de `X` a `**/X` (ensancha).
    if patron_padre.startswith("**/") and patron_padre[3:] == patron_hijo:
        return True
    return False


def refinar(padre_doc: dict, hijo_doc: dict, *,
            padre_id: Identidad | None = None) -> Refinamiento:
    """Refina `hijo` sobre `padre`. `PASS` con la política efectiva, o `NOT_EXECUTABLE`.

    No devuelve nunca una política «casi refinada». Si el hijo intenta relajar algo, la
    operación entera se rechaza: aplicar la mitad de una política y seguir sería peor que no
    aplicarla, porque el espacio parecería gobernado.
    """
    try:
        padre = Policy.from_dict(padre_doc)
    except PoliticaIlegible as exc:
        return Refinamiento(NOT_EXECUTABLE,
                            motivo=f"la política padre no se pudo interpretar: {exc}")
    try:
        Policy.from_dict(hijo_doc)
    except PoliticaIlegible as exc:
        return Refinamiento(NOT_EXECUTABLE,
                            motivo=f"la política hija no se pudo interpretar: {exc}")

    # Lo que el padre APLICA, no lo que ESCRIBE.
    #
    # Esto comparaba `padre_doc.get(campo)` — el documento crudo. Los valores de fábrica
    # (16 órdenes denegadas, `block_secret_content: True`, las rutas protegidas de serie)
    # sólo se materializan cuando `Policy.from_dict` rellena un campo AUSENTE, así que un
    # padre que no los escribe aportaba el conjunto vacío a la unión.
    #
    # Dos consecuencias medidas el 2026-09-23, y la segunda es la grave:
    #
    #   V1  padre sin `command_deny` + hijo con una orden  →  efectivo 1 entrada.
    #       `rm -rf /` y `sudo` pasaban a `allow`.
    #   V7  padre sin `block_secret_content` (fábrica True) + hijo con `false`  →  la cadena
    #       RESUELVE sin violación y la detección de secretos queda apagada. El invariante
    #       que este módulo declara en su docstring, falsado por OMISIÓN del padre.
    #
    # El agujero de V1 no lo introduce el refinamiento —un hijo sin `extends` que declara una
    # lista corta pierde igual las 16—: es la semántica de `from_dict`, donde declarar un
    # campo lo SUSTITUYE. Lo que la herencia aporta es convertirlo en el camino por defecto,
    # porque el propósito de un hijo es declarar sólo lo suyo.
    #
    # La asimetría es deliberada: el PADRE se resuelve (sus valores de fábrica son parte de lo
    # que aplica), el HIJO no. Para el hijo lo que importa es qué declaró EXPLÍCITAMENTE:
    # resolverlo también haría que un campo que calla trajera el valor de fábrica y, en
    # `REDUCE`, la intersección con el padre lo estrecharía a nada — rompiendo la herencia
    # legítima justo donde tiene que funcionar.
    padre_eff = padre.to_dict()

    desconocidas = [k for k in hijo_doc
                    if not k.startswith("_")
                    and k not in REGLAS
                    and k in Policy.__dataclass_fields__]       # noqa: SLF001
    if desconocidas:
        return Refinamiento(
            NOT_EXECUTABLE,
            motivo=f"el hijo declara campo(s) de política sin regla de monotonía: "
                   f"{', '.join(sorted(desconocidas))}. No se hereda lo que no se ha decidido "
                   f"cómo se hereda — un campo sin regla sería un agujero por omisión.")

    efectivo = dict(padre_eff)
    violaciones: list = []
    for campo, regla in REGLAS.items():
        if campo not in hijo_doc:
            continue
        violaciones += _viola(campo, regla, padre_eff.get(campo), hijo_doc.get(campo))
        if regla == REDUCE_LISTA:
            # La lista del HIJO, por el mismo motivo que en `REDUCE`: ya se demostró arriba que
            # cada registro suyo está idéntico en el padre, luego su lista ES el estrechamiento.
            efectivo[campo] = list(hijo_doc.get(campo) or ())
        elif regla == ACUMULA_MAPA:
            fusion = {k: list(v) for k, v in (padre_eff.get(campo) or {}).items()}
            for rol, v in (hijo_doc.get(campo) or {}).items():
                fusion[rol] = sorted(set(fusion.get(rol, ())) | set(v or ()))
            efectivo[campo] = {k: sorted(set(v)) for k, v in fusion.items()}
        elif regla == ACUMULA:
            efectivo[campo] = sorted(set(padre_eff.get(campo) or ()) |
                                     set(hijo_doc.get(campo) or ()))
        elif regla == REDUCE:
            # La lista del HIJO, no la intersección. Ya se ha demostrado arriba que cada
            # entrada suya está cubierta por el padre, así que su lista ES el estrechamiento —y
            # la intersección por cadena lo rompía: con el padre en `**/X` y el hijo en `X`, la
            # intersección daba el conjunto VACÍO, dejando al espacio sin ninguna excepción en
            # vez de con la que declaró. Para toda política que ya cumplía (hijo ⊆ padre por
            # igualdad) las dos formas coinciden, así que esto no cambia ningún efectivo previo.
            efectivo[campo] = sorted(set(hijo_doc.get(campo) or ()))
        elif regla == MODO:
            # El del padre como base: un runtime que el hijo no menciona conserva el suyo.
            efectivo[campo] = {**(padre_eff.get(campo) or {}), **(hijo_doc[campo] or {})}
        else:
            efectivo[campo] = hijo_doc[campo]

    if violaciones:
        return Refinamiento(
            NOT_EXECUTABLE, violaciones=violaciones,
            motivo=f"la política hija intenta relajar la del padre en "
                   f"{len(violaciones)} punto(s). No se aplica ninguna parte: una política a "
                   f"medias es indistinguible de una política.")

    pid = padre_id or identidad_de(padre_doc)
    ident = identidad_de(hijo_doc, padre=pid)
    try:
        resultante = Policy.from_dict(efectivo)
    except PoliticaIlegible as exc:                              # pragma: no cover
        return Refinamiento(NOT_EXECUTABLE,
                            motivo=f"la política efectiva no se pudo construir: {exc}")
    del padre
    return Refinamiento(PASS, politica=resultante, identidad=ident,
                        cadena=[pid, ident],
                        motivo="el hijo refina al padre: no retira nada y no abre nada nuevo")


#: Profundidad máxima de la cadena `refuto → cliente → proyecto`. Tres niveles y un margen.
#: El límite existe por el ciclo: un padre que se declara hijo de su hijo colgaría el
#: guardián en cada decisión, y un guardián colgado no deniega — deja de responder, que es
#: peor que denegar.
MAX_CADENA = 8


def politica_efectiva(ruta: Path, doc: dict) -> Policy:
    """La política efectiva del fichero `ruta`, con `extends` resuelto. La usa `Policy.load`.

    `extends` es una RUTA relativa al directorio del propio fichero de política, o absoluta.
    Deliberadamente no es un nombre contra el censo: resolver por nombre exige decidir dónde
    vive la capa de cliente, y esa decisión no está tomada. Un resolvedor que adivinara sería
    peor que uno que exige la ruta.

    Levanta `HerenciaIrresoluble` —subclase de `PoliticaIlegible`— si no se puede construir.
    El guardián ya deniega ante `PoliticaIlegible`, así que un fallo de herencia falla cerrado
    sin tocar una línea del guardián.
    """
    from core.policy import HerenciaIrresoluble

    vistos: list = []
    actual_ruta, actual_doc = ruta.resolve(), doc
    cadena: list = []                       # de hijo a ancestro
    while True:
        if actual_ruta in vistos:
            raise HerenciaIrresoluble(
                f"la cadena de `extends` tiene un ciclo: "
                f"{' → '.join(p.name for p in vistos + [actual_ruta])}. Una cadena circular "
                f"no tiene política efectiva.")
        vistos.append(actual_ruta)
        if len(vistos) > MAX_CADENA:
            raise HerenciaIrresoluble(
                f"la cadena de `extends` excede {MAX_CADENA} niveles. O hay un ciclo que no "
                f"se detectó, o la composición dejó de ser legible por una persona.")
        cadena.append((actual_ruta, actual_doc))
        ref = actual_doc.get("extends")
        if not ref:
            break
        if not isinstance(ref, str) or not ref.strip():
            raise HerenciaIrresoluble(
                f"«{actual_ruta.name}» declara `extends` y no es una referencia legible: "
                f"{ref!r}")
        padre_ruta = Path(ref)
        if not padre_ruta.is_absolute():
            padre_ruta = actual_ruta.parent / padre_ruta
        if not padre_ruta.is_file():
            raise HerenciaIrresoluble(
                f"«{actual_ruta.name}» declara `extends: {ref}` y ese padre no existe en "
                f"{padre_ruta}. NO se aplican los valores por omisión ni la política del hijo "
                f"a secas: un espacio que dice heredar y corre sin su padre parece gobernado "
                f"sin estarlo.")
        try:
            padre_doc = json.loads(padre_ruta.read_text(encoding="utf-8"))
        except (OSError, ValueError) as exc:
            raise HerenciaIrresoluble(
                f"el padre «{ref}» existe y no se pudo leer ({type(exc).__name__}: {exc}). "
                f"No poder leerlo no es no tenerlo: no se puede afirmar cuál es la política."
            ) from exc
        actual_ruta, actual_doc = padre_ruta.resolve(), padre_doc

    # De ancestro a hijo, refinando de dos en dos. El ancestro manda sobre todos.
    cadena.reverse()

    # …y sobre el ancestro manda la RAÍZ DEL MOTOR. Sin esto, la monotonía era relativa: se
    # demostraba `hijo ⊒ padre` en cada arista y nadie exigía que la CIMA atenuara nada, así
    # que bastaba con apuntar `extends` a una política laxa —escrita en cualquier sitio que
    # el espacio declare suyo— para vaciar el gobierno entero sin violar una sola arista.
    # Medido el 2026-09-23: tres comprobaciones pasaron de `deny` a `allow`.
    #
    # Componer y no sólo validar: en los campos que acumulan, el efectivo es la unión con la
    # norma base, y entonces vaciarlos no es una violación que haya que cazar — es algo que
    # no se puede escribir. Ver `core/trust.py`.
    from core.trust import componer_con_raiz

    ruta_cima, doc_cima = cadena[0]
    r_raiz = componer_con_raiz(doc_cima)
    if r_raiz.status != PASS:
        raise HerenciaIrresoluble(
            f"la cima de la cadena «{ruta_cima.name}» no atenúa la norma base de refuto: "
            f"{r_raiz.motivo} {' | '.join(r_raiz.violaciones)}")
    efectivo_doc = {**doc_cima, **{k: v for k, v in r_raiz.politica.to_dict().items()
                                   if k in REGLAS}}
    # La identidad de la cima es la de su documento DECLARADO, encadenada a la raíz del
    # motor. NO la del documento ya compuesto.
    #
    # Antes se digería `efectivo_doc`, y eso hacía que `digest` significara dos cosas según
    # la profundidad: en la cima, el documento compuesto; de ahí hacia abajo, `refinar`
    # devuelve `identidad_de(hijo_doc)`, que es el declarado. `documento_hijo` escribe el
    # ancla siempre con el declarado (`digest_de(padre_doc)`), así que un `extends_digest`
    # sobre una cima NO PODÍA coincidir nunca y `--anchor` quedaba roto para todo espacio
    # anclado, con un motivo que además mentía: decía «el padre cambió» sobre un padre
    # intacto. Medido el 2026-09-24 en un espacio real: ancla `41164aa7…`, comprobación
    # `7738a16e…`, fichero del padre sin tocar desde antes de escribirse el ancla.
    #
    # `efectivo` sigue encadenando —ahora también a la raíz—, que es donde vive «esta
    # política significa otra cosa que ayer». `digest` es quién declara ser.
    from core.trust import documento_raiz

    ident = identidad_de(doc_cima, padre=identidad_de(documento_raiz()))
    for ruta_hijo, hijo_doc in cadena[1:]:
        esperado = str(hijo_doc.get("extends_digest") or "")
        if esperado and esperado != ident.digest:
            raise HerenciaIrresoluble(
                f"«{ruta_hijo.name}» ancla `extends_digest` {esperado[:12]}… y su padre hoy "
                f"es {ident.digest[:12]}…. El padre cambió: el significado de este espacio "
                f"cambiaría sin que el espacio se haya tocado.")
        r = refinar(efectivo_doc, hijo_doc, padre_id=ident)
        if r.status != PASS:
            raise HerenciaIrresoluble(
                f"«{ruta_hijo.name}» no refina a su padre: {r.motivo} "
                f"{' | '.join(r.violaciones)}")
        efectivo_doc = {**efectivo_doc, **{k: v for k, v in r.politica.to_dict().items()
                                           if k in REGLAS}}
        ident = r.identidad
    politica = Policy.from_dict(efectivo_doc)
    # La identidad viaja CON la política, no en una variable de módulo.
    #
    # La primera versión la dejaba en `politica_efectiva.ultima_identidad`: estado mutable
    # compartido, acción a distancia, y un resultado que dependía de quién había llamado
    # antes. Con dos espacios resueltos en el mismo proceso —lo que hace `refuto verify`— la
    # segunda identidad pisaba a la primera, así que un evento podía citar la política de otro
    # espacio. Es un atributo fuera del contrato a propósito: NO es un campo de `Policy`,
    # porque entonces necesitaría regla de monotonía y aparecería en `to_dict()`, y un valor
    # DERIVADO que entra en el documento acaba entrando en su propio digest.
    politica.identidad_efectiva = ident
    return politica


def referencia_a(padre: Path, *, desde: Path) -> str:
    """Cómo escribir `extends` en una política que vive en el directorio `desde`.

    Relativa siempre que se pueda, y no por estética: un espacio de cliente y sus proyectos se
    mueven JUNTOS —se renombra la carpeta, se clona el árbol en otra máquina, se monta en otra
    ruta— y una referencia relativa sobrevive a eso mientras una absoluta no sobrevive a nada
    más. Sólo se cae a la absoluta cuando no hay ruta relativa posible (en Windows, dos
    unidades distintas), porque ahí la alternativa no es una referencia peor: es ninguna.
    """
    try:
        return Path(os.path.relpath(padre.resolve(), desde.resolve())).as_posix()
    except ValueError:
        return padre.resolve().as_posix()


def documento_hijo(nombre: str, extends: str, *, version: str = "1",
                   padre_doc: dict | None = None) -> dict:
    """La política de una capa que HEREDA: tres claves y, si se ancla, el digest del padre.

    Lo que este documento NO tiene es todo lo demás, y ése es el punto. `refuto install`
    escribía `Policy.default().to_dict()` —la norma entera, copiada— en cada espacio nuevo. Con
    once espacios eso son once copias que nadie vuelve a comparar, y la primera que alguien
    recorta deja de estar gobernada sin que ningún comando lo diga. Un hijo que sólo declara lo
    SUYO no puede divergir en lo que no declara.

    `padre_doc` ancla `extends_digest`. Es opcional y no se hace por omisión: anclado, cualquier
    cambio del padre deja de resolver hasta que alguien lo revise. Eso es lo que se quiere de
    una capa que no debe moverse sola, y demasiado rígido para una capa de cliente que
    evoluciona — así que lo decide quien crea la capa, no el instalador.
    """
    doc = {"schema": Policy.__dataclass_fields__["schema"].default,   # noqa: SLF001
           "name": nombre, "version": version, "extends": extends}
    if padre_doc is not None:
        doc["extends_digest"] = digest_de(padre_doc)
    return doc


def explicar(ruta: Path, doc: dict) -> Refinamiento:
    """Lo mismo que `politica_efectiva`, contado en vez de levantado.

    **Llama a `politica_efectiva`**, no reimplementa nada. Es la diferencia entre una segunda
    presentación y una segunda semántica: la primera es útil, la segunda es el defecto que
    este módulo existe para cerrar. Una versión anterior de `refuto policy refine` resolvía el
    padre contra el ESPACIO mientras `Policy.load` lo resolvía contra el directorio de la
    política, y las dos daban respuestas distintas sobre el mismo fichero.
    """
    from core.policy import PoliticaIlegible
    try:
        pol = politica_efectiva(ruta, doc)
    except PoliticaIlegible as exc:
        return Refinamiento(NOT_EXECUTABLE, motivo=str(exc))
    ident = getattr(pol, "identidad_efectiva", None)
    return Refinamiento(PASS, politica=pol, identidad=ident,
                        cadena=[ident] if ident else [],
                        motivo=("no declara `extends`: se aplica tal cual"
                                if not doc.get("extends")
                                else "la cadena de `extends` resuelve y cada hijo refina a su "
                                     "padre: no retira nada y no abre nada nuevo"))


def resolver(workspace: Path, doc: dict, *, buscar) -> Refinamiento:
    """Resuelve `extends` y refina. `buscar(ref) -> dict | None` localiza al padre.

    Un padre ausente NO produce la política del hijo ni los valores de fábrica: produce
    `NOT_EXECUTABLE`. Un manifiesto que dice `extends` y corre sin su padre **parece**
    gobernado y no lo está — el mismo fallo que `Policy.from_dict` ya cierra cuando no
    reconoce ninguna clave de un documento ajeno.
    """
    ref = doc.get("extends")
    if not ref:
        return Refinamiento(PASS, politica=Policy.from_dict(doc),
                            identidad=identidad_de(doc), cadena=[identidad_de(doc)],
                            motivo="no declara `extends`: se aplica tal cual")
    if not isinstance(ref, str) or not ref.strip():
        return Refinamiento(NOT_EXECUTABLE,
                            motivo=f"`extends` presente pero no es una referencia legible: "
                                   f"{ref!r}")
    try:
        padre_doc = buscar(ref)
    except Exception as exc:                                     # noqa: BLE001
        return Refinamiento(NOT_EXECUTABLE,
                            motivo=f"no se pudo resolver el padre «{ref}»: "
                                   f"{type(exc).__name__}: {exc}")
    if padre_doc is None:
        return Refinamiento(
            NOT_EXECUTABLE,
            motivo=f"declara `extends: {ref}` y ese padre no se encontró. NO se aplican los "
                   f"valores por omisión: un espacio que dice heredar y corre sin su padre "
                   f"parece gobernado sin estarlo.")
    esperado = str(doc.get("extends_digest") or "")
    pid = identidad_de(padre_doc)
    if esperado and esperado != pid.digest:
        return Refinamiento(
            NOT_EXECUTABLE,
            motivo=f"el padre «{ref}» cambió: el hijo ancla `extends_digest` "
                   f"{esperado[:12]}… y hoy es {pid.digest[:12]}…. El significado del "
                   f"proyecto cambiaría sin que el proyecto se haya tocado.")
    return refinar(padre_doc, doc, padre_id=pid)
