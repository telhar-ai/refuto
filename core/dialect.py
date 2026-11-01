# -*- coding: utf-8 -*-
"""Cómo se DICE una decisión en cada runtime. El motor decide; esto traduce.

Por qué existe este módulo
--------------------------
Hasta el 2026-10-31 la serialización vivía dentro de `core.guard.main`, mezclada con la
escalada por auditoría interrumpida. Mezclarlas costó un fallo abierto silencioso: la
traducción del dialecto de Codex corría **antes** que la escalada, así que una decisión
`allow` con el diario roto se convertía en `ask` *después* de haber pasado por el traductor,
y `ask` en Codex no pide nada —se ejecuta—. El control más caro del guardián, el que impide
que una escritura ocurra sin rastro, era inerte justo en el runtime que lo necesitaba.

De ahí la separación: **decidir** y **decirlo** son dos responsabilidades. El motor
(`core.policy.evaluate`) produce `allow`/`deny`/`ask` y no sabe qué es stdout. Este módulo
sabe de stdout, de JSON y de códigos de salida, y no sabe de políticas.

El protocolo de cada runtime, medido
------------------------------------
Codex 0.166.0 **declara** en su esquema embebido
`PreToolUsePermissionDecisionWire: enum ["allow","deny","ask"]` e **implementa uno**. Medido
el 2026-10-31 en macOS arm64 con efecto observable —un `touch` y la comprobación de que el
fichero existe—, no con un test unitario:

    respuesta del gancho                         Codex muestra      ¿se ejecuta?
    {"permissionDecision":"allow", …}            Hook Failed        SÍ
    stdout vacío, exit 0                         Hook Completed     SÍ
    {"permissionDecision":"deny","…Reason":"x"}  Hook Blocked       NO
    {"permissionDecision":"ask", …}              Hook Failed        SÍ   ← fallo abierto
    stderr + exit 2                              Hook Blocked       NO

Las dos consecuencias que dan forma al dialecto `codex`:

1. **Aprobar es callarse.** El silencio es la única aprobación que Codex entiende. Decirla
   en voz alta costaba un «Hook Failed» por cada llamada permitida, y eso enseña a ignorar
   al guardián justo cuando sí tiene algo que decir.
2. **`ask` no se puede representar.** No es que se vea distinto: es que *aprueba*. Se degrada
   a `deny` —fail-closed— y se dice por qué en el motivo, para que la persona lo ejecute.

El esquema declarado no es el protocolo implementado. Es el caso de libro de «sospecha del
instrumento antes que del sistema», sólo que el instrumento era la documentación del runtime.
Por eso ninguna fila de la tabla de arriba se apoya en el esquema ni en una cadena del
binario: se apoya en si el fichero apareció.

Lo que este módulo NO resuelve
------------------------------
Codex tiene un evento `PermissionRequest` aparte, con enum propio `["allow","deny"]`, que es
donde expresa de verdad la aprobación humana. Es la representación correcta de `ask` y
**refuto no lo implementa todavía**: mientras no lo haga, `ask` en Codex es `deny`, que
pierde trabajo pero no lo aprueba a espaldas de nadie. Degradar hacia el lado seguro y
declararlo es distinto de no tener el problema.
"""

from __future__ import annotations

import json
from dataclasses import dataclass

from core.policy import ALLOW, ASK, DENY

#: Motivo que se emite cuando la decisión no trae uno. Codex rechaza un `deny` con motivo
#: vacío («permissionDecision:deny without a non-empty permissionDecisionReason») y lo trata
#: como fallo del gancho, es decir: ejecuta. Un bloqueo sin motivo es un bloqueo que no
#: bloquea, así que el motivo no es decoración.
MOTIVO_POR_DEFECTO = "política de refuto"

_NOTA_ASK_EN_CODEX = (
    "(Esto requiere la decisión de una persona. Codex no implementa esa respuesta en "
    "`PreToolUse` —la trata como fallo del gancho y ejecuta igual—, así que aquí se traduce "
    "a un bloqueo: ejecútela usted.)"
)


@dataclass(frozen=True)
class Respuesta:
    """Lo que el guardián va a hacer de verdad, separado de lo que decidió.

    `wire` es la decisión **efectivamente serializada**, que no siempre es la semántica:
    vacía significa «no se dijo nada», y en Codex eso es precisamente la aprobación. La
    distinción entre `semantica` y `wire` es la que el diario necesita para que «decidí
    permitir» y «dije que permitía» dejen de ser la misma casilla.
    """

    stdout: str
    stderr: str
    exit_code: int
    semantica: str
    wire: str
    #: Vacío, o por qué la decisión semántica no se pudo representar tal cual.
    degradada: str = ""


def _sobre(decision: str, motivo: str) -> str:
    return json.dumps({
        "hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "permissionDecision": decision,
            "permissionDecisionReason": motivo,
        }
    }, ensure_ascii=False)


def _claude(semantica: str, motivo: str) -> Respuesta:
    """Claude Code implementa el enum entero. La traducción es la identidad."""
    return Respuesta(stdout=_sobre(semantica, motivo), stderr="", exit_code=0,
                     semantica=semantica, wire=semantica)


def _codex(semantica: str, motivo: str) -> Respuesta:
    """Codex implementa `deny` y nada más. Ver la tabla del encabezado."""
    if semantica == ALLOW:
        # Aprobar es callarse. Hablar aquí es «Hook Failed», que además ejecuta igual: se
        # pagaría ruido por una respuesta que no cambia nada.
        return Respuesta(stdout="", stderr="", exit_code=0, semantica=ALLOW, wire="")
    if semantica == ASK:
        return Respuesta(stdout=_sobre(DENY, f"{motivo}\n\n{_NOTA_ASK_EN_CODEX}"),
                         stderr="", exit_code=0, semantica=ASK, wire=DENY,
                         degradada="codex no implementa `ask` en PreToolUse: ejecutaría")
    return Respuesta(stdout=_sobre(DENY, motivo), stderr="", exit_code=0,
                     semantica=DENY, wire=DENY)


def _plano(semantica: str, motivo: str) -> Respuesta:
    """Kiro, Gemini y OpenCode: la decisión viaja en el código de salida.

    No hay respuesta estructurada que leer, así que `allow` es salir 0 en silencio y
    cualquier otra cosa es salir 2 con el motivo por stderr. `ask` y `deny` colapsan en el
    mismo efecto —no se ejecuta— y eso se declara en `degradada` en vez de fingir que el
    runtime distingue las dos.
    """
    if semantica == ALLOW:
        return Respuesta(stdout="", stderr="", exit_code=0, semantica=ALLOW, wire="")
    etiqueta = "BLOQUEADO" if semantica == DENY else "REQUIERE APROBACIÓN"
    return Respuesta(
        stdout="", stderr=f"harness-guard: {etiqueta} — {motivo}", exit_code=2,
        semantica=semantica, wire=DENY,
        degradada=("" if semantica == DENY else
                   "este runtime no distingue `ask` de `deny`: los dos no ejecutan"))


#: Un runtime se traduce con el dialecto que tenga declarado aquí y con ninguno por defecto.
#: Ver `responder`: lo que no está en esta tabla no se aproxima al más parecido.
_DIALECTOS = {
    "claude": _claude,
    "codex": _codex,
    "kiro": _plano,
    "gemini": _plano,
    "opencode": _plano,
}


def runtimes() -> tuple:
    """Los runtimes con dialecto declarado. `core.guard` la usa para no duplicar la lista."""
    return tuple(sorted(_DIALECTOS))


def responder(runtime: str, semantica: str, motivo: str = "", aviso: str = "") -> Respuesta:
    """Traduce una decisión del motor al protocolo de `runtime`.

    `aviso` no vacío significa que la decisión **no se pudo registrar**. Entonces `allow`
    deja de ser una opción: una operación que ocurre sin rastro es exactamente lo que el
    diario existe para impedir, y el aviso viaja en el texto —no sólo por stderr, que en un
    gancho estructurado no llega a ninguna parte—.

    A qué se escala, y por qué no es lo mismo en todas partes:

    * Codex → `deny`. Su `ask` ejecuta, así que escalar a `ask` sería escalar a `allow` con
      otro nombre. Es el defecto que este módulo existe para cerrar.
    * El resto → `ask`. Ahí `ask` **no ejecuta**: la operación queda detenida hasta que una
      persona la aprueba, y lo hace leyendo «AUDITORÍA INTERRUMPIDA» en el motivo. El trabajo
      no se pierde y la autorización es de la persona, informada. Se mantiene deliberadamente
      el comportamiento que ya tenía: cambiarlo a `deny` endurecería la política de seguridad
      de los runtimes que nunca tuvieron el defecto.

    Un runtime sin dialecto declarado **no se aproxima al más parecido**: se bloquea. Es el
    mismo principio que una política ilegible — no poder afirmar nada no es poder aprobar.
    """
    if semantica not in (ALLOW, DENY, ASK):
        # El motor sólo produce esas tres. Una cuarta significa que algo se corrompió entre
        # decidir y decirlo, y de un estado que no se entiende no sale una aprobación.
        return Respuesta(
            stdout="", stderr=f"harness-guard: decisión interna desconocida "
                              f"({semantica!r}); se bloquea por principio de precaución.",
            exit_code=2, semantica=str(semantica), wire=DENY,
            degradada="decisión semántica fuera del dominio del motor")

    dialecto = _DIALECTOS.get(runtime)
    if dialecto is None:
        return Respuesta(
            stdout="", stderr=f"harness-guard: no hay dialecto declarado para el runtime "
                              f"{runtime!r}; se bloquea por principio de precaución.",
            exit_code=2, semantica=semantica, wire=DENY,
            degradada="runtime sin dialecto: no se aproxima al más parecido")

    motivo = (motivo or "").strip() or MOTIVO_POR_DEFECTO
    if aviso:
        motivo = f"{motivo}\n\n⚠ {aviso}"
        if semantica == ALLOW:
            semantica = DENY if runtime == "codex" else ASK

    return _con_motivo_portante(dialecto(semantica, motivo))


def _con_motivo_portante(respuesta: Respuesta) -> Respuesta:
    """Garantiza que un `deny` serializado lleve motivo, reparándolo si no.

    No es un `assert`: `python -O` los borra, y una excepción aquí dejaría al guardián
    saliendo con traza y código 1, que es un estado de protocolo que nadie ha medido. El
    invariante —un `deny` sin motivo es «Hook failed», y «Hook failed» ejecuta— se repara
    hacia el lado seguro en vez de convertirse en una caída.
    """
    if respuesta.wire != DENY or not respuesta.stdout:
        return respuesta
    try:
        doc = json.loads(respuesta.stdout)
        motivo = doc["hookSpecificOutput"]["permissionDecisionReason"]
    except (ValueError, KeyError, TypeError):
        doc, motivo = None, ""
    if isinstance(motivo, str) and motivo.strip():
        return respuesta
    from dataclasses import replace
    return replace(respuesta, stdout=_sobre(DENY, MOTIVO_POR_DEFECTO),
                   degradada=(respuesta.degradada or
                              "motivo vacío en un `deny`: repuesto para que bloquee"))
