# -*- coding: utf-8 -*-
"""refuto como servidor MCP stdio. La misma respuesta, por otra boca.

Por qué stdio y no un servidor remoto
-------------------------------------
No es una decisión de coste, aunque también lo sea. refuto necesita el sistema de archivos
local: el espacio, `.harness/`, el guardián, el diario. Un servidor remoto tendría que recibir
el árbol por la red y, peor, **expondría al juez** — el diario y la política son exactamente lo
que el modelo de confianza protege. Un servidor stdio lo arranca el cliente de la propia
persona y no tiene superficie entrante: nadie puede llamarlo desde fuera porque no escucha.

Por qué esto es pequeño
-----------------------
Porque no reimplementa nada. Cada herramienta invoca `refuto.main(argv + ["--json"])` y
devuelve el sobre `harness.envelope/v1` que ya construye la CLI. Una implementación, dos
superficies — que es el mismo motivo por el que hay un solo guardián para seis runtimes: dos
implementaciones de la misma regla son dos reglas, y divergen. Si `verify` cambia su veredicto,
esta boca lo dice al día siguiente sin tocar este archivo.

Y el sobre ya trae lo que un agente necesita: `status` de los seis, `exit` derivado, la
procedencia, y `next` con qué hacer, por qué y **de quién es el turno**. Esa es la razón de
haber construido el sobre antes que esto.

Las tres reglas que este servidor NO negocia
--------------------------------------------
1. **No ejecuta órdenes arbitrarias.** El `argv` sale de una tabla fija de este archivo; el
   modelo sólo aporta una ruta de espacio y booleanos, validados. No hay concatenación de
   cadenas en ninguna parte, luego no hay superficie de inyección que auditar.
2. **No escribe lo que gobierna.** Nada de `--apply`, `--force` ni `unwire`. `upgrade` se
   expone sólo como PLAN. Un agente que pudiera actualizar su propio arnés o recablear su
   propio guardián sería, otra vez, juez de sí mismo — la regla de la que se deriva el resto
   del producto. `verify` sí escribe, y es lo correcto: emite evidencia en un diario de sólo
   añadir y encadenado, y emitir una verificación no es falsificarla.
3. **No gasta dinero.** `--deep` no se expone: el sondeo profundo envía un prompt de verdad
   (`core.probe`) y su coste no está medido. Una herramienta que factura sin decirlo no la
   puede llamar un agente en bucle.

stdout es el protocolo
----------------------
Todo lo que no sea un mensaje JSON-RPC va a stderr. `refuto.main` ya reencamina ahí el texto
humano cuando se le pide `--json`, así que esto encaja sin excepciones: si una orden imprimiera
en stdout, rompería el flujo del cliente — es el mismo defecto que se midió el 2026-09-24
cuando `doctor --json` mezclaba veinte líneas de diagnóstico con el sobre.
"""

from __future__ import annotations

import contextlib
import io
import json
import re
import sys
from pathlib import Path

from core.mcp import LEGACY_PROTOCOL_VERSION, PROTOCOL_VERSION

SERVER_INFO = {"name": "refuto", "version": ""}

#: Códigos de error de JSON-RPC 2.0. Se usan los estándar y no unos propios: un cliente que no
#: conoce el servidor tiene que poder distinguir «no existe ese método» de «los argumentos están
#: mal» sin leer esta documentación.
INVALID_REQUEST = -32600
METHOD_NOT_FOUND = -32601
INVALID_PARAMS = -32602
INTERNAL_ERROR = -32603

_GATE = re.compile(r"^G-[A-Z]+$")


def _tool(nombre, argv, descripcion, *, extra=None):
    return {"name": nombre, "argv": tuple(argv), "description": descripcion,
            "extra": dict(extra or {})}


#: La tabla. Cada entrada es un `argv` FIJO; lo único que el modelo aporta son los valores que
#: `_argv_de` valida uno a uno. Añadir una herramienta es añadir una línea aquí, y por eso no
#: puede aparecer una bandera de escritura sin que alguien la escriba a mano en este archivo.
HERRAMIENTAS = [
    _tool("refuto_doctor", ["doctor"],
          "Qué hay en esta máquina y qué funciona de verdad: agentes con su peldaño de "
          "ejecutabilidad y la firma de su binario, entorno, proveedor al que van las sesiones, "
          "y los artefactos del espacio que faltan. Sólo lectura."),
    _tool("refuto_status", ["status"],
          "Dónde está el trabajo: la última verificación con su veredicto, la orquestación en "
          "curso, las revisiones humanas pendientes y el reparto de la memoria por capas. Sólo "
          "lectura."),
    _tool("refuto_verify", ["verify"],
          "Ejecuta las puertas del espacio y emite evidencia encadenada en "
          "`.harness/evidence/`. Devuelve el veredicto y el estado de cada puerta. Escribe "
          "evidencia —es su función— en un diario de sólo añadir; no modifica el espacio.",
          extra={"gate": {"type": "string",
                          "description": "Ejecutar sólo esta puerta, p. ej. `G-POLICY`."},
                 "offline": {"type": "boolean",
                             "description": "No tocar la red. Las puertas que la necesiten "
                                            "quedarán BLOCKED, que no aprueba."}}),
    _tool("refuto_probe", ["probe"],
          "Escalera de ejecutabilidad de los agentes instalados: NOT_INSTALLED, INSTALLED, "
          "STARTABLE, FUNCTIONAL, VERIFIED, y en cuál se detuvo cada uno y por qué. No incluye "
          "el peldaño VERIFIED, que requiere enviar un prompt de pago. Sólo lectura."),
    _tool("refuto_mcp_check", ["mcp"],
          "Integridad referencial de la cadena MCP del espacio: toda herramienta declarada "
          "resuelve a un servidor configurado que la anuncia. Un resultado vacío devuelve "
          "NOT_APPLICABLE, nunca aprobado. Sólo lectura.",
          extra={"offline": {"type": "boolean",
                             "description": "No interrogar servidores por red."}}),
    _tool("refuto_inventory", ["inventory"],
          "Inventario mecánico del conjunto de repositorios del espacio. Sólo lectura."),
    _tool("refuto_upgrade_plan", ["upgrade"],
          "QUÉ CAMBIARÍA al llevar el espacio a la versión del motor, y en qué se queda corta "
          "su política respecto de la norma del motor. Nunca aplica: `--apply` no se expone a "
          "esta superficie, porque actualizar el arnés y recablear el guardián es un acto de "
          "persona. Sólo lectura."),
]

_POR_NOMBRE = {h["name"]: h for h in HERRAMIENTAS}


def _esquema_de(herr: dict) -> dict:
    props = {"workspace": {"type": "string",
                           "description": "Ruta absoluta del espacio de trabajo. Por omisión, "
                                          "el directorio desde el que se lanzó el servidor."}}
    props.update(herr["extra"])
    return {"type": "object", "properties": props, "required": [], "additionalProperties": False}


def catalogo() -> list:
    """`tools/list`. Se deriva de la tabla: una herramienta nueva no necesita tocar esto."""
    return [{"name": h["name"], "description": h["description"],
             "inputSchema": _esquema_de(h)} for h in HERRAMIENTAS]


def _argv_de(nombre: str, args: dict, *, raiz: Path) -> list:
    """El `argv` exacto de una llamada, validado valor a valor.

    Levanta `ValueError` con un motivo legible. No se normaliza «por si acaso»: un argumento que
    no se entiende se rechaza, porque adivinar la intención de quien llama es como se ejecuta lo
    que nadie pidió.
    """
    herr = _POR_NOMBRE[nombre]
    args = args or {}
    ajenas = sorted(set(args) - {"workspace", *herr["extra"]})
    if ajenas:
        raise ValueError(f"argumentos que «{nombre}» no acepta: {', '.join(ajenas)}")

    ws = args.get("workspace") or str(raiz)
    if not isinstance(ws, str):
        raise ValueError("`workspace` tiene que ser una cadena")
    destino = Path(ws).expanduser()
    if not destino.is_dir():
        raise ValueError(f"`workspace` no es un directorio existente: {destino}")
    # El `workspace` lo aporta el MODELO, y `refuto_verify` ESCRIBE (`.harness/evidence/`). Sin
    # esta comprobación, un agente podía nombrar cualquier directorio de la máquina y sembrarlo.
    #
    # Medido el 2026-09-25 sobre un directorio recién creado, fuera de todo espacio gobernado:
    #
    #     .harness/evidence/ledger.jsonl · sbom.json · ver_edb734a4c5f14c66.json
    #
    # No es destrucción ni exfiltración: es escritura no solicitada, y la doctrina del producto
    # sobre eso ya está escrita en `external_write_allow` —fuera del espacio sólo se escribe en
    # raíces DECLARADAS—. Esta superficie la rodeaba por no preguntarse cuál es el espacio.
    #
    # El criterio es el más estrecho que no cierra ningún uso real: o es el directorio desde el
    # que se lanzó el servidor, o es un espacio que YA está gobernado. Verificar un directorio
    # que nunca fue un espacio no informa de nada —`refuto verify` allí deja casi todas las
    # puertas en `BLOCKED` por falta de manifiesto y de política— así que lo único que se
    # pierde es la siembra. Materializar un espacio nuevo es `refuto init`, que esta superficie
    # no expone a propósito.
    if destino.resolve() != raiz.resolve() and not (destino / ".harness").is_dir():
        raise ValueError(
            f"«{destino}» no es un espacio gobernado: no tiene `.harness/`. Esta superficie no "
            f"materializa espacios —`init` no se expone— y `verify` escribe evidencia, así que "
            f"apuntarla a un directorio cualquiera lo sembraría sin informar de nada. Ejecute "
            f"`refuto init` ahí una vez, o llame sin `workspace` para usar "
            f"«{raiz.resolve()}».")

    argv = ["--workspace", str(destino.resolve()), *herr["argv"]]
    if "gate" in args:
        gate = args["gate"]
        if not isinstance(gate, str) or not _GATE.match(gate):
            raise ValueError(f"`gate` no tiene la forma de una puerta (`G-NOMBRE`): {gate!r}")
        argv += ["--gate", gate]
    if args.get("offline") is True:
        argv.append("--offline")
    # Última red, y es una afirmación sobre TODO el `argv` construido, no sobre los argumentos
    # de entrada: si alguna vez alguien añade una entrada a la tabla con una bandera de
    # escritura, esto lo para aquí en vez de en producción.
    prohibidas = {"--apply", "--force", "--deep", "--execute", "unwire", "wire", "install",
                  "init", "chat", "run"}
    colision = prohibidas.intersection(argv)
    if colision:
        raise ValueError(f"esta superficie no ejecuta operaciones de escritura: "
                         f"{', '.join(sorted(colision))}")
    return [*argv, "--json"]


def invocar(nombre: str, args: dict, *, raiz: Path) -> dict:
    """Ejecuta la herramienta y devuelve el resultado en el vocabulario de MCP.

    `isError` es del PROTOCOLO, no del veredicto
    --------------------------------------------
    Un `verify` que devuelve `FAIL` es una llamada que **funcionó**: informa de que el espacio no
    cumple. Marcarla `isError` haría que el cliente la tratara como un fallo del servidor y, con
    algunos clientes, que la reintentara o la ocultara. El veredicto viaja en
    `structuredContent.status`, que tiene seis valores justamente porque dos no bastan.

    Es el mismo error que se corrigió el 2026-09-24 en los códigos de salida: colapsar «no se
    pudo comprobar» sobre «falló» pierde la distinción que este producto existe para mantener.
    """
    if nombre not in _POR_NOMBRE:
        raise KeyError(nombre)
    argv = _argv_de(nombre, args, raiz=raiz)

    import refuto

    # Se capturan LOS DOS canales. stdout porque ahí viene el sobre y porque en esta superficie
    # stdout pertenece a JSON-RPC. Y stderr porque `refuto.main` reencamina ahí el informe
    # humano —35 líneas por llamada en el caso de `doctor`—, y un cliente MCP lo muestra como
    # log del servidor: en esta boca el sobre YA es el resultado, así que el texto es ruido.
    # No se descarta del todo: si la llamada falla, es lo único que explica por qué, y ahí sí
    # viaja dentro del error.
    buf_out, buf_err = io.StringIO(), io.StringIO()
    try:
        with contextlib.redirect_stdout(buf_out), contextlib.redirect_stderr(buf_err):
            refuto.main(argv)
    except SystemExit as exc:                                   # una orden que aborta
        return _resultado_de_fallo(nombre, f"la orden terminó con SystemExit({exc.code})",
                                   registro=buf_err.getvalue())
    except Exception as exc:                                    # noqa: BLE001
        return _resultado_de_fallo(nombre, f"{type(exc).__name__}: {exc}",
                                   registro=buf_err.getvalue())

    crudo = buf_out.getvalue().strip()
    try:
        sobre = json.loads(crudo)
    except json.JSONDecodeError:
        # Una orden aún sin migrar al sobre, o que imprimió algo en stdout. No se inventa un
        # sobre: se dice que no lo hubo. Fingirlo sería declarar un contrato que no se cumplió.
        return _resultado_de_fallo(
            nombre, "la orden no emitió un sobre `harness.envelope/v1` en stdout; "
                    f"salida recibida: {crudo[:200]!r}",
            registro=buf_err.getvalue())
    return {
        "content": [{"type": "text", "text": _resumen(sobre)}],
        "structuredContent": sobre,
        "isError": False,
    }


def _resumen(sobre: dict) -> str:
    """El texto que un modelo lee primero. Estado, y qué toca — en ese orden."""
    lineas = [f"{sobre.get('command')}: {sobre.get('status')}  (exit {sobre.get('exit')})"]
    for s in sobre.get("next") or ():
        lineas.append(f"  → {s.get('why')}")
        if s.get("do"):
            lineas.append(f"     hacer: {s['do']}   turno: {s.get('who')}")
        else:
            lineas.append(f"     turno: {s.get('who')}")
    if not (sobre.get("next") or ()):
        lineas.append("  nada pendiente")
    return "\n".join(lineas)


def _resultado_de_fallo(nombre: str, motivo: str, *, registro: str = "") -> dict:
    texto = f"{nombre}: {motivo}"
    if registro.strip():
        # Las últimas líneas, que son donde está la causa. Un fallo sin su registro obliga a
        # reproducirlo a mano, y una superficie que un modelo invoca se reproduce mal.
        cola = "\n".join(registro.strip().splitlines()[-12:])
        texto += f"\n\nregistro de la orden:\n{cola}"
    return {"content": [{"type": "text", "text": texto}], "isError": True}


# ── el bucle ─────────────────────────────────────────────────────────────────────────
def _identidad() -> dict:
    from core.model import VERSION

    return {**SERVER_INFO, "version": VERSION}


def _capacidades() -> dict:
    # Sólo `tools`. No se anuncian `resources` ni `prompts`: no los hay, y anunciar una
    # capacidad vacía es la misma clase de aprobado vacuo que este programa persigue.
    return {"tools": {"listChanged": False}}


#: Desde MCP 2026-07-28 **todo resultado lleva `resultType`**, y los clientes que lo omiten se
#: leen como `"complete"` (`docs/research/mcp.md`). Se emite explícito: depender de que el otro
#: lado aplique el valor por omisión es apoyarse en su tolerancia, no en el contrato.
_COMPLETO = {"resultType": "complete"}


def responder(mensaje: dict, *, raiz: Path) -> dict | None:
    """Un mensaje JSON-RPC → su respuesta, o `None` si era una notificación."""
    metodo = mensaje.get("method")
    ident = mensaje.get("id")
    es_notificacion = ident is None

    def ok(resultado):
        return None if es_notificacion else {"jsonrpc": "2.0", "id": ident,
                                             "result": {**_COMPLETO, **resultado}}

    def error(codigo, texto):
        return None if es_notificacion else {"jsonrpc": "2.0", "id": ident,
                                             "error": {"code": codigo, "message": texto}}

    if mensaje.get("jsonrpc") != "2.0" or not isinstance(metodo, str):
        return error(INVALID_REQUEST, "no es un mensaje JSON-RPC 2.0 con `method`")

    # `server/discover` es obligatorio desde MCP 2026-07-28 y `initialize` es el handshake de
    # ≤2025-11-25. Se atienden los dos porque el cliente de refuto (`core.mcp`) prueba los dos,
    # y un servidor que sólo hablara el nuevo no lo podría interrogar su propio proyecto.
    if metodo == "server/discover":
        # `supportedVersions` y la identidad en `_meta`, que es lo que la especificación
        # 2026-07-28 define y lo que el cliente de refuto lee (`core.mcp.interrogate_stdio`).
        # La primera versión de este servidor puso `protocolVersions` y un `serverInfo` suelto:
        # el cliente lo alcanzaba y listaba las 7 herramientas, pero devolvía
        # `protocol_versions: []` y `server_info: {}` — es decir, un servidor que responde y del
        # que no se puede afirmar qué revisión habla. Se corrigió midiendo con el cliente propio,
        # que es la razón de que exista esa simetría.
        #
        # `serverInfo` suelto se emite ADEMÁS, no en su lugar: un superconjunto no rompe a nadie
        # y hay clientes que lo leen ahí. Lo que no se hace es elegir uno y suponer.
        return ok({"supportedVersions": [PROTOCOL_VERSION, LEGACY_PROTOCOL_VERSION],
                   "capabilities": _capacidades(),
                   "serverInfo": _identidad(),
                   "_meta": {"io.modelcontextprotocol/serverInfo": _identidad()}})
    if metodo == "initialize":
        pedida = ((mensaje.get("params") or {}).get("protocolVersion")
                  or LEGACY_PROTOCOL_VERSION)
        # Se responde con la versión que el cliente pidió si se conoce, y con la propia si no.
        # Afirmar que se habla una versión desconocida sería declarar soportado lo que no consta.
        acordada = pedida if pedida in (PROTOCOL_VERSION, LEGACY_PROTOCOL_VERSION) \
            else PROTOCOL_VERSION
        return ok({"protocolVersion": acordada, "capabilities": _capacidades(),
                   "serverInfo": _identidad()})
    if metodo in ("notifications/initialized", "initialized", "notifications/cancelled"):
        return None
    if metodo == "ping":
        return ok({})
    if metodo == "tools/list":
        return ok({"tools": catalogo()})
    if metodo == "tools/call":
        params = mensaje.get("params") or {}
        nombre = params.get("name")
        try:
            return ok(invocar(nombre, params.get("arguments") or {}, raiz=raiz))
        except KeyError:
            return error(METHOD_NOT_FOUND,
                         f"no existe la herramienta «{nombre}». Las que hay: "
                         f"{', '.join(sorted(_POR_NOMBRE))}")
        except ValueError as exc:
            return error(INVALID_PARAMS, str(exc))
        except Exception as exc:                                # noqa: BLE001
            return error(INTERNAL_ERROR, f"{type(exc).__name__}: {exc}")
    return error(METHOD_NOT_FOUND, f"método no soportado: {metodo}")


def serve(raiz: Path, entrada=None, salida=None) -> int:
    """El bucle stdio. Una línea, un mensaje; stdout es SÓLO protocolo.

    No se cae por una línea mala. Un servidor que muere ante el primer mensaje ilegible obliga
    al cliente a distinguir «se cerró» de «no entendió», y no puede: lo que ve es un descriptor
    cerrado. Se responde el error y se sigue escuchando.
    """
    ent = entrada or sys.stdin
    sal = salida or sys.stdout
    for linea in ent:
        linea = linea.strip()
        if not linea:
            continue
        try:
            mensaje = json.loads(linea)
        except json.JSONDecodeError as exc:
            _emitir(sal, {"jsonrpc": "2.0", "id": None,
                          "error": {"code": -32700, "message": f"JSON inválido: {exc}"}})
            continue
        if not isinstance(mensaje, dict):
            _emitir(sal, {"jsonrpc": "2.0", "id": None,
                          "error": {"code": INVALID_REQUEST, "message": "se esperaba un objeto"}})
            continue
        respuesta = responder(mensaje, raiz=raiz)
        if respuesta is not None:
            _emitir(sal, respuesta)
    return 0


def _emitir(salida, doc: dict) -> None:
    salida.write(json.dumps(doc, ensure_ascii=False) + "\n")
    salida.flush()
