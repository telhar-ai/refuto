# -*- coding: utf-8 -*-
"""El guardián. Un solo programa; todos los ganchos de todos los runtimes lo invocan.

    python3 -m core.guard --runtime {kiro|claude|gemini|opencode|antigravity} --stdin

Lee por la entrada estándar la carga del gancho —que tiene forma distinta en cada runtime—, la
normaliza, aplica la política canónica y responde en el dialecto que ese runtime entiende.

Por qué un solo programa
------------------------
Porque la alternativa comprobada fue tener la regla escrita en dos vocabularios y aplicada en
uno (H-03). Traducir la CARGA es un problema de veinte líneas por runtime; traducir la REGLA es
un problema que diverge. Se traduce la carga.

Cómo responde cada runtime, verificado en su documentación instalada:

    claude    JSON en stdout con `hookSpecificOutput.permissionDecision` ∈ {allow, deny, ask}
              y salida 0. Salida 2 también bloquea, con stderr al modelo.
    kiro      salida ≠ 0 bloquea; stderr explica.
    gemini    salida ≠ 0 bloquea; stderr explica.
    antigravity  JSON en stdout `{"decision": allow|deny|ask, "reason"}`, salida 0 siempre
              (el código de salida no está documentado: ver core/antigravity.py).
    otros     salida ≠ 0 bloquea.

Cuando el dialecto exacto de un runtime NO consta verificado, se usa el mecanismo universal
—salida distinta de cero— y se registra en el evento que la respuesta fue genérica. Nunca se
inventa un campo.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys
import time
from pathlib import Path

from core.policy import (ALLOW, ASK, DENY, Decision, PoliticaIlegible, Policy,
                         decide_command, decide_write)
from core.proc import euid, force_utf8_io

#: Cómo se llama, en cada runtime, el campo que trae la ruta y el contenido.
#: Herramientas que ESCRIBEN, por runtime. Una de éstas sin ruta legible no es una llamada
#: inocua: es una escritura que no se pudo examinar.
#:
#: Los nombres NO se inventan aquí — se toman de donde el repositorio ya los declaraba, y por
#: eso esto no es una segunda política sino la misma, hecha consultable desde el guardián:
#:
#:     claude     `core.wire.CLAUDE_MATCHER` menos `Bash`, que necesita orden y no ruta
#:     kiro       `adapters.kiro.KIRO_WRITE_TOOLS`, más la variante `fsWrite` del IDE que
#:                `core/policy.py` documenta en su encabezado
#:     gemini     el matcher de `adapters/gemini.py`
#:     opencode   la clave `edit` de `adapters/opencode.py`
#:
#: Cobertura declarada: lo que no está aquí NO se exige. Un runtime cuyo nombre de herramienta
#: de escritura no figure queda fuera de esta comprobación, y decirlo es parte del contrato —
#: es la diferencia entre un PASS de alcance declarado y uno universal que nadie midió.
_ESCRITURA = {
    "claude": ("Write", "Edit", "MultiEdit", "NotebookEdit"),
    "kiro": ("fs_write", "fsWrite"),
    "gemini": ("write_file", "replace", "edit"),
    "opencode": ("edit", "write"),
}

_SHAPES = {
    "claude": {
        "tool": ("tool_name",),
        "path": ("tool_input.file_path", "tool_input.path", "tool_input.notebook_path"),
        "content": ("tool_input.content", "tool_input.new_string", "tool_input.new_source"),
        "command": ("tool_input.command",),
        "cwd": ("cwd",),
        "structured": True,
    },
    "kiro": {
        "tool": ("tool_name", "toolName", "name"),
        "path": ("tool_input.path", "toolInput.path", "input.path", "path", "arguments.path"),
        "content": ("tool_input.content", "toolInput.content", "input.content", "content",
                    "arguments.content", "tool_input.file_text", "arguments.file_text"),
        "command": ("tool_input.command", "toolInput.command", "input.command", "command"),
        "cwd": ("cwd", "workspace"),
        "structured": False,
    },
    "gemini": {
        "tool": ("tool_name", "toolName", "name"),
        "path": ("tool_input.file_path", "tool_input.absolute_path", "args.file_path",
                 "args.absolute_path", "path"),
        "content": ("tool_input.content", "args.content", "args.new_string", "content"),
        "command": ("tool_input.command", "args.command", "command"),
        "cwd": ("cwd",),
        "structured": False,
    },
    "opencode": {
        "tool": ("tool", "tool_name", "name"),
        "path": ("args.filePath", "args.path", "path"),
        "content": ("args.content", "args.newString", "content"),
        "command": ("args.command", "command"),
        "cwd": ("cwd",),
        "structured": False,
    },
}


#: El contenedor existe y no es un objeto: `{"tool_input": "…"}` cuando se buscaba
#: `tool_input.file_path`. No es lo mismo que no estar, y confundirlos era un bypass.
_MAL_CONTENEDOR = object()


def _dig(doc: dict, dotted: str, ausente=None):
    """Baja por una clave con puntos, distinguiendo TRES desenlaces.

        el valor            la clave existe y se llegó hasta ella
        `ausente`           algún tramo no está: la clave no se declaró
        `_MAL_CONTENEDOR`   un tramo ESTÁ y no es un objeto por el que se pueda bajar

    La tercera se añadió el 2026-09-25 al medir R-03. Antes, `{"tool_name": "Write",
    "tool_input": "/ws/gates/base.py"}` salía `allow`: `tool_input` no era un `dict`, la
    condición `not isinstance(node, dict)` lo trataba como «la clave no está», ninguna ruta se
    reconocía, y como el nombre de la herramienta SÍ se había leído, la carga se declaraba
    inocua. Una escritura al juez, aprobada por el contenedor equivocado.
    """
    node = doc
    for part in dotted.split("."):
        if not isinstance(node, dict):
            return _MAL_CONTENEDOR
        if part not in node:
            return ausente
        node = node[part]
    return node


#: Sentinela: la clave no estaba. Distinto de estar con un valor inservible, y `None` no
#: vale para distinguirlo porque `None` es justamente uno de los valores inservibles (JSON
#: `null`). Confundir los dos casos es el defecto R-03.
_SIN_CLAVE = object()


def _campo(doc: dict, keys) -> tuple[str, bool]:
    """El valor canónico de un campo, y si se encontró ILEGIBLE.

    El contrato de admisión, mínimo y explícito
    -------------------------------------------
    Un campo canónico es una **cadena no vacía** bajo alguna de las claves declaradas en
    `_SHAPES`. Tres situaciones, y las tres se responden distinto:

        ADMISIBLE   alguna clave trae una cadena no vacía      → ese valor
        AUSENTE     ninguna clave declarada está presente      → "", legítimo
        ILEGIBLE    alguna clave ESTÁ y su valor no sirve      → "", y se declara

    `ILEGIBLE` cubre `dict`, `list`, `int`, `float`, `bool`, `None`, la cadena vacía y el
    contenedor mal formado (`_MAL_CONTENEDOR`): `{"tool_input": "…"}` cuando se esperaba un
    objeto es una carga que no se pudo examinar, no una carga sin ruta.

    Por qué no se coacciona
    -----------------------
    Sería fácil sacar la ruta de `{"path": "…"}` o de `["…"]`. Está prohibido a propósito: si
    una representación ambigua se normaliza hasta parecerse a la canónica, obtiene los
    privilegios de la canónica, y entonces el contrato no lo fija quien escribió la política
    sino quien eligió la forma de la carga. Una representación que no es la canónica no se
    arregla: se declara inservible.

    El defecto que esto cierra (R-03, medido el 2026-09-25)
    -------------------------------------------------------
    `_first` filtraba por `isinstance(value, str)` y devolvía `""` tanto si la clave no estaba
    como si estaba con un `dict` dentro. `evaluate` veía `path=""`, no encolaba ninguna
    decisión, y como el NOMBRE de la herramienta sí se había reconocido, concluía «la carga no
    trae ruta ni orden que evaluar» → `allow`. Medido, con 13 representaciones de la misma
    escritura al juez: **10 admitidas**, y el diario anotando `Write · allow · target=''`.

    Es la pérdida de información convertida en aprobación: exactamente el ataque
    «entrada ambigua → normalización → se pierde el dato → validación → allow».
    """
    visto_inservible = False
    for key in keys:
        value = _dig(doc, key, _SIN_CLAVE)
        if value is _SIN_CLAVE:
            continue
        if isinstance(value, str) and value:
            # Una clave posterior legible resuelve el campo: `{"file_path": "", "path": "/x"}`
            # es ADMISIBLE, no ilegible. Lo ilegible es no haber podido resolverlo con ninguna.
            return value, False
        visto_inservible = True
    return "", visto_inservible


def normalize(runtime: str, payload: dict) -> dict:
    """Carga del gancho → hecho canónico. Sin esto, cada runtime traería su propia política.

    `carga_vacia` NO es lo mismo que «no reconocí nada»
    ----------------------------------------------------
    El mapeo de campos es por adivinación de nombres: `_first` prueba varias claves hasta que
    una casa. Eso es lo correcto para absorber variantes menores, y tiene un modo de fallo que
    hay que nombrar — si el runtime cambia el esquema de su carga, **ninguna** clave casa, el
    hecho sale con todos los campos vacíos, y un hecho vacío es indistinguible de una llamada
    que legítimamente no toca nada (`Read`, `Grep`).

    Medido el 2026-09-25 contra el guardián real, con la MISMA escritura a una ruta protegida:

        {"tool_name":"Write","tool_input":{"file_path":"gates/base.py"}}  →  deny
        {"toolName":"Write","input":{"filePath":"gates/base.py"}}         →  ALLOW
        {"evento":{"tipo":"write","destino":"gates/base.py"}}             →  ALLOW

    El runtime es un sistema externo que versiona su propio formato por su cuenta. El día que
    uno renombre un campo, el guardián deja de gobernar **en silencio y aprobando**.

    Por eso se distingue, y sólo se puede distinguir aquí: `carga_vacia` dice si el gancho no
    trajo nada —caso legítimo, se permite— frente a trajo algo y no se entendió, que no es una
    aprobación sino una ignorancia. Ver `evaluate`.
    """
    shape = _SHAPES.get(runtime, _SHAPES["kiro"])
    campos = {n: _campo(payload, shape[n])
              for n in ("tool", "path", "content", "command", "cwd")}
    return {
        "runtime": runtime,
        # `payload` sin una sola clave significa que el gancho no entregó carga: modo directo
        # (`--path`), invocación de prueba, o un runtime que no manda cuerpo. No es lo mismo que
        # una carga llena de la que no se reconoció nada.
        "carga_vacia": not payload,
        # Qué campos ESTABAN y no se pudieron leer. Ni un campo ausente ni uno legible entran
        # aquí: sólo los que traían algo inservible. `evaluate` los compone como una decisión
        # más, porque un hecho al que le falta el dato que decide no es un hecho inocuo.
        "campos_ilegibles": tuple(n for n, (_v, ileg) in campos.items() if ileg),
        # ¿Es una herramienta de ESCRITURA declarada para este runtime? Se resuelve aquí, con
        # el nombre ya extraído, para que `evaluate` pueda exigirle ruta. Sin esto, una `Write`
        # cuya ruta viaja en una clave que `_SHAPES` no lista sale `allow` sin que nadie mire:
        # los campos que conocemos están ausentes —no ilegibles— y ausente es legítimo.
        "escribe": campos["tool"][0] in _ESCRITURA.get(runtime, ()),
        "tool": campos["tool"][0],
        "path": campos["path"][0],
        "content": campos["content"][0],
        "command": campos["command"][0],
        "cwd": campos["cwd"][0],
        # El sujeto. Ningún runtime lo trae en la carga del gancho, así que se lee del
        # entorno, que es donde `refuto chat` lo deja. Vacío significa «sesión sin rol
        # declarado», y entonces no hay capacidad que aplicar — no significa «sin límites»:
        # la política general sigue rigiendo igual que antes de que existiera esto.
        "role": os.environ.get("HARNESS_ROLE", ""),
        "structured_reply": shape["structured"],
    }


def _capacidades(rol: str) -> tuple:
    """Las capacidades del rol, o vacío si no se pueden determinar.

    `try` ancho a propósito: el diario no puede caerse porque el registro de roles no se lea. Un
    evento sin la lista es peor que uno con ella y mucho mejor que ninguno.
    """
    try:
        from core.capabilities import capacidades_de
        return capacidades_de(rol)
    except Exception:                                                   # noqa: BLE001
        return ()


def evaluate(policy: Policy, workspace: Path, fact: dict):
    """Aplica la política al hecho normalizado.

    Las dos dimensiones se evalúan, no una U otra
    ----------------------------------------------
    Esto era `if command: … return` / `if path: … return`, dos ramas excluyentes. La
    consecuencia, medida el 2026-09-23 contra el guardián real con la misma política:

        Write  gates/base.py           →  deny   («gates/**»)
        Bash   echo x > gates/base.py  →  allow  ← `protected_paths` no se consultaba

    Una carga puede traer las dos cosas, y aunque no las traiga, una ORDEN tiene efectos
    sobre RUTAS. `decide_command` ya resuelve los efectos (`core.effects`); aquí sólo hay
    que dejar de cortar el flujo antes de tiempo y quedarse con la decisión más restrictiva.
    """
    from core.policy import Decision

    decisiones = []
    if fact["command"]:
        decisiones.append((decide_command(policy, fact["command"], workspace), "command"))
    if fact["path"]:
        decisiones.append((decide_write(policy, workspace, fact["path"], fact["content"]),
                           "write"))
    # ── el SUJETO ────────────────────────────────────────────────────────────────────
    #
    # Se evalúa DESPUÉS de las rutas y las órdenes, y se compone con `max`, que es lo que hace
    # que una capacidad sólo pueda APRETAR por construcción y no por disciplina de quien la
    # escriba: nunca puede convertir un `deny` de la política general en un `allow`.
    #
    # Sin rol declarado no hay capacidad que aplicar, y eso NO significa «sin límites»: la
    # política general rige igual que antes de que esto existiera.
    if fact.get("role"):
        decisiones.append((_decidir_capacidad(policy, workspace, fact), "capability"))

    # ── campos que ESTABAN y no se pudieron leer ─────────────────────────────────────
    #
    # Se encola como una decisión más, y no como un retorno temprano, por el caso mixto: una
    # carga con `command` legible y `path` ilegible SÍ produce decisiones, y devolver la del
    # comando dejaría la ruta sin examinar exactamente igual que antes. Al componerse con
    # `max` la más restrictiva gana, y una ruta ilegible ya no se puede perder por el camino.
    #
    # `ASK` y no `DENY`, por el mismo criterio que `carga-no-reconocida`, del que esto es el
    # caso PARCIAL —allí no se reconoce nada; aquí se reconoce la herramienta y no el dato que
    # decide—: un `deny` ante el primer cambio de esquema de un runtime dejaría el espacio
    # inutilizable, y un espacio inutilizable se arregla desenganchando el gancho. Entonces se
    # deja de mirar el canal entero, que es peor que mirarlo y preguntar.
    # Una herramienta de ESCRITURA declarada, sin ruta que examinar. No entra por
    # `campos_ilegibles` porque los campos que conocemos están AUSENTES, no ilegibles: la ruta
    # viajaba en una clave que `_SHAPES` no lista. La pregunta que el guardián hacía era
    # «¿reconocí algún campo?» y la correcta es «¿reconocí los que ESTA herramienta necesita?».
    if fact.get("escribe") and not fact["path"] and not fact.get("campos_ilegibles"):
        decisiones.append((Decision(
            ASK, rule="escritura-sin-ruta",
            reason=f"«{fact['tool']}» es una herramienta de escritura de «{fact['runtime']}» y "
                   f"esta carga no trae ninguna ruta que `core.guard._SHAPES` sepa leer. Una "
                   f"escritura cuyo destino no se pudo examinar no es una llamada que no toca "
                   f"nada: aprobarla sería afirmar que es inocua sin haberla mirado. Causa "
                   f"habitual: el runtime mueve la ruta a un campo nuevo. Compruebe la forma "
                   f"real con `--runtime {fact['runtime']}` y actualice el mapeo; hasta "
                   f"entonces lo decide una persona."), "shape"))

    if fact.get("campos_ilegibles"):
        cuales = ", ".join(fact["campos_ilegibles"])
        decisiones.append((Decision(
            ASK, rule="campo-ilegible",
            reason=f"la carga de «{fact['runtime']}» trae {cuales} con un valor que no es una "
                   f"ruta ni una orden legible, y la herramienta «{fact['tool'] or '?'}» sí se "
                   f"reconoció. No es una llamada que no toca nada: es una llamada cuyo "
                   f"objetivo no se pudo examinar, y aprobarla registraría un «allow» sobre un "
                   f"destino que nadie leyó. No se coacciona el valor a propósito: sacar la "
                   f"ruta de un `dict` o de una lista le daría a una representación ambigua los "
                   f"privilegios de la canónica. Compruebe la forma real con "
                   f"`--runtime {fact['runtime']}` y actualice `core.guard._SHAPES`; hasta "
                   f"entonces lo decide una persona."), "shape"))

    if not decisiones:
        # Sin ruta ni orden hay DOS situaciones distintas, y responderlas igual era un
        # fail-open estructural. Ver `normalize`, que mide el caso.
        #
        #   la carga se entendió y no toca nada   `Read`, `Grep`: se permite, y es correcto
        #   la carga NO se entendió               no es una aprobación, es una ignorancia
        #
        # Se distinguen por si se reconoció ALGÚN campo. Si el gancho trajo cuerpo y no se
        # reconoció ni el nombre de la herramienta, lo que hay delante no es una llamada
        # inocua: es una llamada que este guardián no sabe leer.
        #
        # `ask` y no `deny`, por el mismo criterio que el fallo de auditoría: el trabajo no se
        # pierde y lo decide quien puede arreglar el mapeo. Un `deny` ante el primer cambio de
        # esquema de un runtime dejaría el espacio inutilizable y se rodearía con `--no-verify`
        # o desenganchando el hook, y entonces no se mira el canal entero.
        if fact.get("carga_vacia", True) or any(
                fact.get(k) for k in ("tool", "path", "content", "command", "cwd")):
            return Decision(ALLOW,
                            reason="la carga del gancho no trae ruta ni orden que evaluar"), "none"
        return Decision(
            ASK, rule="carga-no-reconocida",
            reason=f"el gancho de «{fact['runtime']}» entregó una carga que este guardián no "
                   f"sabe leer: no se reconoció ni el nombre de la herramienta ni ruta, orden o "
                   f"directorio. Eso NO es una llamada que no toca nada — es una llamada que no "
                   f"se pudo examinar, y las dos se respondían igual. Causa habitual: el runtime "
                   f"cambió el esquema de su carga y `core.guard._SHAPES` se quedó atrás. "
                   f"Compruebe la forma real con `--runtime {fact['runtime']}` y actualice el "
                   f"mapeo; hasta entonces lo decide una persona."), "shape"
    # Gana la más restrictiva: la herramienta ejecuta TODO lo que la carga declara.
    peor, kind = max(decisiones, key=lambda d: _ORDEN_DECISION[d[0].outcome])
    return peor, kind


def _decidir_capacidad(policy: Policy, workspace: Path, fact: dict):
    """El veredicto de las capacidades del rol sobre este hecho.

    Reúne lo que el rol necesita saber —qué rutas toca el hecho y qué lecturas de credencial
    lleva— y se lo pasa a `core.capabilities`, que es donde vive la tabla. La separación importa:
    este módulo sabe traducir cargas de gancho y aquél sabe qué significa cada restricción.
    """
    from core.policy import Decision, _lecturas_secretas

    rutas: list = []
    lecturas: tuple = ()
    if fact.get("path"):
        rutas.append(fact["path"])
    if fact.get("command"):
        try:
            from core.effects import efectos
            ef = efectos(fact["command"])
            rutas += sorted(ef.escrituras)
            lecturas = tuple(_lecturas_secretas(policy, workspace, ef.lecturas))
        except Exception:                                               # noqa: BLE001
            pass        # no poder derivar efectos no concede nada: sólo deja de añadir motivos

    from core.capabilities import decidir
    motivo, restriccion = decidir(policy, fact["role"], fact, rutas=rutas,
                                  lecturas_secretas=lecturas)
    if not motivo:
        return Decision(ALLOW, reason=f"ninguna capacidad de «{fact['role']}» lo impide")
    return Decision(DENY, rule=f"rol:{fact['role']}/{restriccion}",
                    reason=f"«{fact['role']}»: {motivo} Esta restricción la declara "
                           f"`roles/registry.json` y hasta el 2026-09-25 sólo se imprimía en el "
                           f"informe de sesión: ahora la aplica el guardián.")


def _digest_de(policy) -> str:
    """El digest efectivo de la política que acaba de decidir, o cadena vacía.

    `getattr` y no acceso directo: `Policy.default()` —la de fábrica, cuando el espacio no
    trae fichero— no pasa por `load` y no lleva identidad. Reventar aquí convertiría un
    espacio sin política en un guardián roto, que es peor que un evento sin digest.
    """
    ident = getattr(policy, "identidad_efectiva", None)
    return ident.efectivo if ident else ""


def digest_entrada(fact: dict) -> str:
    """Identifica la OPERACIÓN, no el evento: los mismos 16 hex en la decisión previa y en el
    resultado posterior, que es lo que permite casarlos.

    Se calcula sobre el hecho ya normalizado —herramienta, ruta, orden, contenido— y no sobre la
    carga cruda del gancho, porque `PreToolUse` y `PostToolUse` no traen la misma envoltura pero
    sí la misma `tool_input`. Sin esto, «cuánto tardó esta orden» sólo se podía estimar por
    proximidad en el tiempo, que con varias herramientas en vuelo es adivinar.
    """
    material = "\u0000".join(str(fact.get(k) or "") for k in
                             ("runtime", "tool", "path", "command", "content"))
    return hashlib.sha256(material.encode("utf-8", "replace")).hexdigest()[:16]


def _emit_event(workspace: Path, fact: dict, decision, kind: str,
                digest: str = "", duration_ms: float | None = None) -> str:
    """Toda decisión del guardián deja rastro. Un control sin rastro no se puede auditar.

    Si no se puede escribir el evento, el guardián NO se cae —bloquear una escritura legítima
    porque el diario está lleno sería peor que perder una línea— pero **tampoco se calla**.

    La primera versión imprimía a stderr y seguía. En una decisión `allow` con respuesta
    estructurada, stderr no llega a ninguna parte: una aprobación sin registrar quedaba idéntica
    a una registrada. Un rastro que se corta en silencio es peor que no tenerlo, porque nadie lo
    echa en falta. Ahora el fallo viaja **dentro de la propia decisión**.

    Devuelve un aviso para adjuntar a la respuesta, o cadena vacía.
    """
    try:
        from core.evidence import append_event
        append_event(workspace, {
            "kind": "policy/decision",
            "runtime": fact["runtime"],
            "tool": fact["tool"],
            "operation": kind,
            "target": fact["path"] or fact["command"],
            "outcome": decision.outcome,
            "rule": decision.rule,
            "reason": decision.reason,
            "euid": euid(),
            "sudo_user": os.environ.get("SUDO_USER", ""),
            # QUIÉN actuó. Sin esto el diario decía qué regla denegó y no a quién, así que
            # una auditoría no podía responder «¿qué hizo el revisor adversarial?». 174
            # decisiones registradas antes de esto y ninguna sabía el rol.
            "role": fact.get("role", ""),
            "role_capabilities": list(_capacidades(fact.get("role", ""))),
            # QUÉ política decidió esto. Sin el digest, un evento dice qué regla denegó pero
            # no de qué política efectiva salió — y con herencia esa pregunta pasa de ociosa a
            # central: la regla pudo venir del cliente, y el cliente pudo cambiar después.
            # Vacío significa «no se pudo determinar», no «no hay»: las dos cosas se
            # distinguen porque la segunda no existe — toda política cargada lleva identidad.
            "policy_digest": digest,
            # Qué se pudo DEMOSTRAR del efecto de la orden, y qué no. Una orden opaca no
            # se deniega —denegar todo `python3` haría inusable la herramienta— pero deja
            # constancia de que hubo una ventana sin demostrar. Es lo que permite que la
            # atestación de `core.trust` distinga «el juez cambió y sé por qué» de «el juez
            # cambió y nadie declaró poder hacerlo». Ver FORMAL-MODEL §6.3.
            "opaco": bool(getattr(decision, "opaco", False)),
            # `opaco` se queda por compatibilidad —está en 2000+ eventos ya escritos— y deja
            # de ser el dato: `resolucion` dice CUÁL de los cinco estados fue, y `opaco` es su
            # proyección. Un diario que sólo guarda el booleano no puede distinguir después
            # «no se pudo derivar» de «se derivó algo que no era una ruta», que es justo la
            # distinción que R-01 costó.
            "resolucion": str(getattr(decision, "resolucion", "") or ""),
            "escrituras_probadas": list(getattr(decision, "escrituras", ()) or ()),
            #: Destinos vistos y no resueltos. Vacío en la inmensa mayoría de eventos.
            "destinos_sin_resolver": list(getattr(decision, "sin_resolver", ()) or ()),
            # SOBRE QUÉ OBJETO se decidió, no sólo sobre qué nombre. Sin esto el diario
            # registraba la ruta y la ruta es un nombre reapuntable: dos eventos sobre
            # «obra/salida.txt» podían ser sobre dos ficheros distintos y nada lo decía.
            # No impide la sustitución —refuto decide antes y ejecuta otro— pero es la
            # precondición para que alguien pueda detectarla después. Ver R-04.
            "objeto": dict(getattr(decision, "objeto", {}) or {}),
            # CUÁNTO COSTÓ decidir, en milisegundos. Hasta el 2026-09-28 ningún evento llevaba
            # duración: se sabía qué se decidió y cuándo, no cuánto costó, así que «el guardián
            # es lento» no era una afirmación comprobable. Mide desde que `main` empieza a
            # trabajar, **no** incluye el arranque del intérprete: esa parte se mide por fuera
            # (82 ms de extremo a extremo el 2026-09-28, 10 invocaciones) y distinguir las dos
            # es lo que separa «optimizar el código» de «hace falta no arrancar un proceso».
            "duration_ms": (round(duration_ms, 2) if duration_ms is not None else None),
            # QUÉ OPERACIÓN es, para poder casar esta decisión con su resultado posterior.
            "entrada_digest": digest_entrada(fact),
        })
    except Exception as exc:                                            # noqa: BLE001
        aviso = (f"AUDITORÍA INTERRUMPIDA: esta decisión no se pudo registrar en "
                 f"{workspace}/.harness/evidence/ledger.jsonl ({type(exc).__name__}: {exc}). "
                 f"Causa habitual: el diario quedó en manos de root tras una sesión con sudo. "
                 f"Arréglelo con: sudo chown -R $USER .harness")
        print(f"harness-guard: {aviso}", file=sys.stderr)
        return aviso
    return ""


#: `kind` del evento que registra CÓMO acabó una operación que el guardián dejó pasar.
KIND_RESULTADO = "tool/result"

#: De dónde se saca el código de salida, por orden. Ningún runtime lo llama igual y ninguno lo
#: promete: por eso el resultado admite «no se pudo determinar» y no lo confunde con «fue bien».
_CLAVES_CODIGO = ("exit_code", "exitCode", "returncode", "returnCode", "code", "status")
_CLAVES_ERROR = ("is_error", "isError", "error", "errorMessage")


def resultado_de(payload: dict) -> dict:
    """Qué se puede AFIRMAR del desenlace de la herramienta, y qué no.

    `ok` es `True`, `False` o **`None`**, y el tercero no es un detalle: la carga de
    `PostToolUse` no promete un código de salida, así que en la mayoría de herramientas lo
    honesto es decir que no se sabe. Poner `True` porque no se vio un error sería exactamente
    la conversión que este programa existe para no hacer.
    """
    resp = payload.get("tool_response")
    out = {"ok": None, "exit_code": None, "error": "", "interrupted": False, "forma": ""}
    if resp is None:
        out["forma"] = "sin tool_response"
        return out
    if isinstance(resp, str):
        out["forma"] = "texto"
        return out
    if isinstance(resp, list):
        # Varias herramientas devuelven una lista de bloques. Se busca el error en cualquiera.
        out["forma"] = "lista"
        resp = next((x for x in resp if isinstance(x, dict)), {})
        if not resp:
            return out
    if not isinstance(resp, dict):
        out["forma"] = type(resp).__name__
        return out
    # Sin el `or`, una respuesta que llegó como lista quedaba registrada como «objeto»: se
    # perdía en el diario la forma que la herramienta usó de verdad, que es lo que hace falta
    # para saber después por qué un desenlace no se pudo determinar.
    out["forma"] = out["forma"] or "objeto"
    for k in _CLAVES_CODIGO:
        v = resp.get(k)
        if isinstance(v, bool):
            continue
        if isinstance(v, int):
            out["exit_code"] = v
            out["ok"] = v == 0
            break
    for k in _CLAVES_ERROR:
        v = resp.get(k)
        if v is True:
            out["ok"] = False
            # El mensaje, por orden de utilidad para quien lea el diario dentro de un mes: el
            # que la herramienta redactó, lo que salió por stderr, y sólo si no hay ninguno, el
            # nombre de la bandera — que dice que falló y no dice nada más.
            out["error"] = out["error"] or str(
                resp.get("errorMessage") or (resp.get("error") if isinstance(resp.get("error"), str) else "")
                or (resp.get("stderr") if isinstance(resp.get("stderr"), str) else "") or k).strip()[:400]
        elif isinstance(v, str) and v.strip():
            out["ok"] = False
            out["error"] = v.strip()[:400]
    if resp.get("interrupted") is True:
        out["interrupted"] = True
        out["ok"] = False
        out["error"] = out["error"] or "la herramienta se interrumpió"
    # QUÉ CLAVES trajo la respuesta, no qué valores. Medido el 2026-09-29 sobre 86 resultados
    # reales: 82 quedaron en `ok=None` porque ninguna de las claves buscadas estaba, y el evento
    # no guardaba con qué averiguar cuáles sí. Los NOMBRES bastan para arreglarlo en la siguiente
    # tanda y no arrastran contenido: un `stdout` en el diario sería filtrar el trabajo entero.
    out["claves"] = sorted(str(k)[:40] for k in list(resp)[:16])
    err = resp.get("stderr")
    if not out["error"] and isinstance(err, str) and err.strip():
        # `stderr` con contenido NO significa fallo —hay programas que informan por ahí— así que
        # se guarda como contexto y **no** se toca `ok`. Confundir ruido con error inventaría
        # fallos que nadie tuvo.
        out["stderr"] = err.strip()[:400]
    return out


def _main_post(opts, raw: str) -> int:
    """`--post`: registra CÓMO acabó una operación. No decide, no bloquea, siempre sale 0.

    El diario sabía qué se permitió y no si funcionó: un `allow` y una orden rota eran
    indistinguibles, y sin dos marcas de tiempo tampoco había forma de saber cuánto tardó nada.
    Este evento aporta las dos cosas — `entrada_digest` lo casa con su decisión, y la diferencia
    entre los dos `ts` ES la duración real de la herramienta.

    Un fallo aquí nunca puede costarle el trabajo a nadie: esto corre DESPUÉS de que la
    herramienta haya actuado, así que bloquear no desharía nada y sí rompería la sesión.
    """
    try:
        payload = json.loads(raw) if raw.strip() else {}
        if not isinstance(payload, dict):
            payload = {}
    except json.JSONDecodeError:
        print("harness-guard: la carga de PostToolUse no es JSON; no se registra el resultado.",
              file=sys.stderr)
        return 0
    fact = normalize(opts.runtime, payload)
    workspace = Path(opts.workspace or fact["cwd"] or os.getcwd()).resolve()
    res = resultado_de(payload)
    try:
        from core.evidence import append_event
        append_event(workspace, {
            "kind": KIND_RESULTADO,
            "runtime": fact["runtime"],
            "tool": fact["tool"],
            "entrada_digest": digest_entrada(fact),
            "ok": res["ok"],
            "exit_code": res["exit_code"],
            "error": res["error"],
            "interrupted": res["interrupted"],
            "respuesta": res["forma"],
            "claves": res.get("claves", []),
            "stderr": res.get("stderr", ""),
        })
    except Exception as exc:                                            # noqa: BLE001
        print(f"harness-guard: no se pudo registrar el resultado ({type(exc).__name__}: {exc}).",
              file=sys.stderr)
    return 0


def main(argv: list | None = None) -> int:
    # El reloj arranca aquí, antes de nada: lo que se mide es lo que el guardián tarda en
    # decidir. El arranque del intérprete queda fuera a propósito y se mide por separado.
    t0 = time.monotonic()
    # Lo PRIMERO, antes de que nada pueda imprimir: la decisión viaja por stdout y los motivos
    # por stderr. En una consola cp1252, un solo carácter del propio mensaje derriba el proceso
    # antes de emitir el JSON, y un gancho que no emite nada no es un gancho que permite: es un
    # gancho que el runtime interpreta como le parece.
    force_utf8_io()

    # `harness-guard` y no `refuto-guard`: es el nombre con el que este programa aparece EN LOS
    # GANCHOS ya instalados (`core.wire.MARK`) y en los mensajes que el runtime muestra cuando
    # bloquea. Es parte del formato de datos compartido con los espacios existentes, igual que
    # `.harness/` y `HARNESS_*`, no del nombre comercial del producto.
    parser = argparse.ArgumentParser(prog="harness-guard", add_help=True)
    parser.add_argument("--runtime", default="kiro", choices=sorted(set(_SHAPES) | {"antigravity"}))
    parser.add_argument("--stdin", action="store_true",
                        help="lee la carga del gancho por la entrada estándar")
    parser.add_argument("--workspace", default="")
    parser.add_argument("--path", default="", help="modo directo, para pruebas")
    parser.add_argument("--content", default="")
    parser.add_argument("--command", default="")
    parser.add_argument("--post", action="store_true",
                        help="registra el RESULTADO de una operación ya ejecutada (PostToolUse). "
                             "No decide y no bloquea: sale 0 siempre.")
    opts = parser.parse_args(argv)

    raw = ""
    if opts.stdin and not sys.stdin.isatty():
        raw = sys.stdin.read()
    if opts.post:
        return _main_post(opts, raw)
    payload: dict = {}
    if opts.runtime == "antigravity":
        return _main_antigravity(opts, raw)
    if raw.strip():
        try:
            payload = json.loads(raw)
        except json.JSONDecodeError:
            # Una carga que no es JSON no se puede evaluar. NO se deja pasar: un guardián que
            # aprueba lo que no entiende no es un guardián.
            print("harness-guard: la carga del gancho no es JSON válido; se bloquea por "
                  "principio de precaución.", file=sys.stderr)
            return 2
        if not isinstance(payload, dict):
            # JSON válido que no es un objeto: una lista, un número, una cadena. `_dig` devuelve
            # `None` para todo y el hecho salía vacío, es decir `allow`. `_main_antigravity` ya
            # rechazaba esta forma —«carga de gancho con forma desconocida»— y los otros cuatro
            # dialectos no: el mismo principio aplicado en un sitio y no en el resto.
            print(f"harness-guard: la carga del gancho es JSON válido pero no es un objeto "
                  f"({type(payload).__name__}); no hay nada que examinar y no se aprueba lo que "
                  f"no se entiende.", file=sys.stderr)
            return 2

    fact = normalize(opts.runtime, payload)
    if opts.path:
        fact["path"] = opts.path
    if opts.content:
        fact["content"] = opts.content
    if opts.command:
        fact["command"] = opts.command

    workspace = Path(opts.workspace or fact["cwd"] or os.getcwd()).resolve()
    policy_file = workspace / ".harness" / "policy.json"
    try:
        policy = Policy.load(policy_file) if policy_file.is_file() else Policy.default()
    except PoliticaIlegible as exc:
        # BLOCKED no aprueba. Un guardián que no entiende su política está en el mismo estado
        # que un guardián que no se encuentra: no puede afirmar nada, luego no deja pasar.
        policy = None
        decision = Decision(DENY, f"política ilegible en {policy_file}: {exc}")

    if policy is None:
        _emit_event(workspace, fact, decision, "policy/illegible",
                    duration_ms=(time.monotonic() - t0) * 1000)
        if fact["structured_reply"]:
            print(json.dumps({"hookSpecificOutput": {
                "hookEventName": "PreToolUse",
                "permissionDecision": "deny",
                "permissionDecisionReason": decision.reason}}, ensure_ascii=False))
            return 0
        print(decision.reason, file=sys.stderr)
        return 2

    decision, kind = evaluate(policy, workspace, fact)
    aviso = _emit_event(workspace, fact, decision, kind, _digest_de(policy),
                        duration_ms=(time.monotonic() - t0) * 1000)

    # Si esto corre como root bajo sudo, se devuelve `.harness/` a quien invocó. Sin ello, una
    # sola sesión con sudo deja a la persona sin poder escribir su propio rastro.
    try:
        from core.launcher import restore_ownership
        restore_ownership(workspace)
    except Exception:                                                   # noqa: BLE001
        pass

    if fact["structured_reply"]:
        mapping = {ALLOW: "allow", DENY: "deny", ASK: "ask"}
        motivo = decision.reason or "política de refuto"
        nombre = mapping[decision.outcome]
        if aviso:
            motivo = f"{motivo}\n\n⚠ {aviso}"
            # Un fallo de auditoría no es «todo bien». Con respuesta estructurada el aviso
            # viajaba en el texto y la decisión seguía siendo `allow`, así que la escritura
            # ocurría igual: el rastro se cortaba y nadie lo echaba en falta — que es lo que
            # `_emit_event` dice existir para impedir.
            #
            # Medido el 2026-09-25 con el diario inescribible y una escritura que aprobaría:
            #
            #     claude                     allow   ← la escritura ocurre
            #     kiro · gemini · opencode   exit 2  ← bloquea
            #     antigravity                ask
            #
            # Tres respuestas al mismo hecho, y la permisiva era la del runtime principal.
            # `_main_antigravity` ya hacía esto; aquí faltaba. Se iguala al más prudente de los
            # dos dialectos estructurados: `ask`, no `deny` — el trabajo no se pierde, lo
            # decide una persona.
            if nombre == "allow":
                nombre = "ask"
        print(json.dumps({
            "hookSpecificOutput": {
                "hookEventName": "PreToolUse",
                "permissionDecision": nombre,
                "permissionDecisionReason": motivo,
            }
        }, ensure_ascii=False))
        return 0

    if decision.outcome == DENY:
        print(f"harness-guard: BLOQUEADO — {decision.reason}", file=sys.stderr)
        return 2
    if decision.outcome == ASK:
        print(f"harness-guard: REQUIERE APROBACIÓN — {decision.reason}", file=sys.stderr)
        return 2
    # Éxito silencioso: un guardián que habla cuando todo va bien se aprende a ignorar.
    # La excepción es el fallo de auditoría, que no es «todo bien».
    return 2 if aviso else 0


_ORDEN_DECISION = {ALLOW: 0, ASK: 1, DENY: 2}


def _main_antigravity(opts, raw: str) -> int:
    """Antigravity: la decisión SIEMPRE viaja en stdout, con salida 0.

    Su documentación no dice qué hace con un gancho que sale con código distinto de cero; un
    guardián no puede apoyar un bloqueo en un comportamiento no documentado. Por eso aquí no
    hay `return 2`: hay un `deny` explícito.
    """
    from core import antigravity as ag

    t0 = time.monotonic()
    try:
        payload = json.loads(raw) if raw.strip() else {}
    except json.JSONDecodeError:
        print(ag.responder("deny", "harness-guard: la carga del gancho no es JSON válido; "
                                   "se bloquea por principio de precaución."))
        return 0
    if not isinstance(payload, dict):
        print(ag.responder("deny", "harness-guard: carga de gancho con forma desconocida."))
        return 0

    workspace = Path(opts.workspace or ag.espacio(payload) or os.getcwd()).resolve()
    if ag.es_pre_invocacion(payload):
        print(ag.pre_invocacion(workspace, payload))
        return 0

    ag.registrar_sesion(workspace, "antigravity", str(payload.get("conversationId") or ""))
    herramienta, facts = ag.hechos(payload)
    if not facts:
        print(ag.responder("allow", f"{herramienta or 'herramienta'}: nada que refuto "
                                    f"deba decidir (lectura o sin ruta ni orden)"))
        return 0

    policy_file = workspace / ".harness" / "policy.json"
    try:
        policy = Policy.load(policy_file) if policy_file.is_file() else Policy.default()
    except PoliticaIlegible as exc:
        decision = Decision(DENY, f"política ilegible en {policy_file}: {exc}")
        _emit_event(workspace, facts[0], decision, "policy/illegible",
                    duration_ms=(time.monotonic() - t0) * 1000)
        print(ag.responder("deny", decision.reason))
        return 0

    peor, motivos, avisos = ALLOW, [], []
    for fact in facts:
        decision, kind = evaluate(policy, workspace, fact)
        aviso = _emit_event(workspace, fact, decision, kind, _digest_de(policy),
                            duration_ms=(time.monotonic() - t0) * 1000)
        if aviso:
            avisos.append(aviso)
        if _ORDEN_DECISION[decision.outcome] > _ORDEN_DECISION[peor]:
            peor = decision.outcome
        if decision.outcome != ALLOW:
            motivos.append(f"{fact['path'] or fact['command']}: {decision.reason}")
    try:
        from core.launcher import restore_ownership
        restore_ownership(workspace)
    except Exception:                                                   # noqa: BLE001
        pass

    nombre = {ALLOW: "allow", DENY: "deny", ASK: "ask"}[peor]
    motivo = "; ".join(motivos) or "política de refuto"
    if avisos:
        # Un fallo de auditoría no es «todo bien»: con decisión allow se convierte en ask.
        motivo += "\n\n⚠ " + " ".join(avisos)
        if nombre == "allow":
            nombre = "ask"
    print(ag.responder(nombre, f"harness-guard: {motivo}"))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
