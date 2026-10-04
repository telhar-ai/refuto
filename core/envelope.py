# -*- coding: utf-8 -*-
"""Un vocabulario, tres consumidores. La envoltura que toda orden de refuto emite.

El hallazgo que motiva este módulo
----------------------------------
refuto hablaba bien a las personas y a medias a todo lo demás. Medido el 2026-09-24:

    --json presente en             11 de 24 órdenes
    contratos `harness.*/vN` que el código EMITE     20
    contratos publicados en `schemas/`                3
    helper común de emisión                           ninguno — 20 `json.dumps` en línea

Veinte formas distintas no son un protocolo: son veinte protocolos, y ninguno se puede
descubrir ni validar. La causa es estructural y está a la vista en `refuto.py`: cada orden
serializaba lo suyo donde le tocaba, así que no había ni un sitio donde imponer una forma.

Y el código de salida mentía. `refuto context --json` devolvía **2** —el de «no se pudo
comprobar»— con la salida completa y válida en stdout. Para una persona da igual: lee el texto.
Para una máquina en CI, `cmd && siguiente` no encadena nunca; para un agente, el resultado
correcto es indistinguible de un fallo del arnés.

Las tres caras, y por qué la misma estructura sirve a las tres
-------------------------------------------------------------
    HUMANO    lee el texto del TTY. La envoltura no le quita nada: sigue habiendo salida rica.
    MÁQUINA   lee `status` (los seis estados) y encadena por el código de salida derivado.
    AGENTE    lee `next`: qué hacer, por qué, y **de quién es el turno**.

`next` no es cortesía. Es la lección que costó más caro en este repositorio: un control que
deniega sin nombrar la alternativa no protege, DESVÍA — y adonde desvía no lo elige quien
escribió la regla. Medido en un espacio real: un agente al que se le denegó su directorio de
entregables se llevó 9,2 GB a `/tmp`, fuera de git y en una ruta que el sistema borra a los tres
días, sin que nadie se lo pidiera y sin que ninguna regla se lo sugiriera. Por eso aquí un
estado que no aprueba **está obligado a traer al menos un `next`**: no se puede expresar un
«esto está mal» sin decir qué se hace con ello.

Lo que esta envoltura NO hace
-----------------------------
No unifica los veinte contratos de carga útil: cada orden sigue emitiendo el suyo, intacto, bajo
`payload`. Unificarlos sería reescribir veinte formatos a la vez y perder la información que
cada uno tiene de más. Lo que se unifica es el **sobre**: quién responde, con qué estado, sobre
qué espacio, con qué procedencia y qué toca después. Un consumidor que ya leía la carga útil
migra con un acceso: `["payload"]`.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from core.model import (BLOCKED, FAIL, INCONCLUSIVE, NOT_APPLICABLE, NOT_EXECUTABLE, PASS,
                        STATUSES, now)

SCHEMA = "harness.envelope/v1"

# ── códigos de salida ────────────────────────────────────────────────────────────────
#
# Cuatro, y se quedan en cuatro. Viven aquí y no en `refuto.py` porque ahora los DERIVA el
# estado: tenerlos junto a la tabla que los deriva es lo que impide que vuelvan a divergir.
EXIT_OK = 0
EXIT_FAIL = 1
EXIT_BLOCKED = 2
EXIT_USAGE = 64

#: Estado → código de salida. La tabla es deliberadamente GRUESA, y conviene decirlo en vez de
#: fingir que no lo es: seis estados no caben en cuatro códigos sin colapsar alguno.
#:
#: `PASS` y `NOT_APPLICABLE` comparten el 0, y eso NO contradice «un ámbito vacío nunca
#: aprueba». Esa regla gobierna el veredicto de una PUERTA, donde `NOT_APPLICABLE` no cuenta
#: como aprobado y `run_all` lo trata aparte. Aquí se responde otra pregunta —«¿hay algo que
#: arreglar?»— y la respuesta para «esta orden no tiene sujeto en este espacio» es no. Mapearlo
#: a 1 haría fallar el CI de todo espacio que legítimamente no declara MCP.
#:
#: Quien necesite la distinción **lee `status`, que es el campo autoritativo**. El código de
#: salida es para encadenar; el estado, para afirmar. Esta frase es parte del contrato, no una
#: disculpa: lo que no se puede expresar en cuatro códigos se expresa en el sobre.
_EXIT_POR_ESTADO = {
    PASS: EXIT_OK,
    NOT_APPLICABLE: EXIT_OK,
    FAIL: EXIT_FAIL,
    BLOCKED: EXIT_BLOCKED,
    NOT_EXECUTABLE: EXIT_BLOCKED,
    INCONCLUSIVE: EXIT_BLOCKED,
}

#: Comprobado al importar: ningún estado puede quedarse sin código. Si alguien añade un séptimo
#: —y el contrato dice que eso es una decisión, no un detalle— esto revienta aquí, al importar,
#: y no en producción devolviendo un código por omisión que nadie decidió. Misma idea que
#: `core.refinement.REGLAS` con la monotonía.
_SIN_CODIGO = sorted(set(STATUSES) - set(_EXIT_POR_ESTADO))
if _SIN_CODIGO:                                                       # pragma: no cover
    raise RuntimeError(
        f"estados sin código de salida: {', '.join(_SIN_CODIGO)}. Decida su código en "
        f"`_EXIT_POR_ESTADO`: devolver uno por omisión sería una afirmación que nadie hizo.")


def exit_for(status: str) -> int:
    """El código de salida que corresponde a ese estado. Nunca se elige a mano."""
    if status not in _EXIT_POR_ESTADO:
        raise ValueError(f"estado inválido {status!r}; permitidos: {STATUSES}")
    return _EXIT_POR_ESTADO[status]


# ── de quién es el turno ─────────────────────────────────────────────────────────────
#
# Tres, y la distinción es operativa, no descriptiva. `MAQUINA` significa «idempotente y sin
# decisión»: se puede automatizar en CI sin que nadie mire. `PERSONA` significa que hay un
# juicio que el arnés no puede emitir —aceptar un riesgo, anclar un origen, aprobar una
# especificación—. `AGENTE` es trabajo que un agente de código puede hacer pero que alguien
# tendrá que revisar. Marcar de PERSONA lo que es de MÁQUINA cuesta fricción; marcar de MÁQUINA
# lo que es de PERSONA cuesta una aprobación que nadie dio, que es de lo que este programa
# existe para proteger.
PERSONA = "persona"
MAQUINA = "maquina"
AGENTE = "agente"
QUIENES = (PERSONA, MAQUINA, AGENTE)


@dataclass
class Siguiente:
    """Qué toca después: el motivo, la orden exacta y de quién es el turno.

    `do` es una orden ejecutable, no una descripción. La diferencia importa para las dos caras
    no humanas: «actualice la política» no se puede ejecutar y «refuto policy reconcile
    --apply» sí. Si de verdad no hay orden —porque el paso es una decisión— `do` queda vacío y
    `who` lo dice.
    """
    why: str
    do: str = ""
    who: str = PERSONA

    def __post_init__(self) -> None:
        if self.who not in QUIENES:
            raise ValueError(f"«{self.who}» no es un turno válido; permitidos: {QUIENES}")
        if not (self.why or "").strip():
            raise ValueError("un `next` sin `why` es una orden sin motivo: no se acepta")

    def to_dict(self) -> dict:
        return {"why": self.why, "do": self.do, "who": self.who}


#: Estados que OBLIGAN a traer al menos un `next`. Es `NON_PASSING` menos `NOT_APPLICABLE`:
#: «esta orden no tiene sujeto aquí» es una respuesta completa y no deja tarea pendiente.
EXIGEN_SIGUIENTE = frozenset({FAIL, BLOCKED, NOT_EXECUTABLE, INCONCLUSIVE})


def envelope(*, command: str, status: str, workspace: Path | str, payload: dict | list,
             run_id: str = "", generated_at: str = "", provenance: dict | None = None,
             next: list | None = None) -> dict:
    """El sobre de una respuesta de refuto. Una forma, tres lectores.

    Levanta `ValueError` antes de emitir nada si el sobre no cumple el contrato. Es deliberado:
    una envoltura mal formada que se imprime es peor que un fallo, porque el consumidor la
    parsea y sigue.
    """
    if status not in STATUSES:
        raise ValueError(f"estado inválido {status!r}; permitidos: {STATUSES}")
    if not (command or "").strip():
        raise ValueError("el sobre no dice qué orden responde")
    siguientes = list(next or ())
    for s in siguientes:
        if not isinstance(s, Siguiente):
            raise TypeError(f"`next` sólo admite `Siguiente`, no {type(s).__name__}")
    # El invariante que convierte la asistencia en contrato y no en buena intención.
    if status in EXIGEN_SIGUIENTE and not siguientes:
        raise ValueError(
            f"«{command}» responde {status} sin un solo `next`. Un estado que no aprueba y no "
            f"dice qué hacer con ello desvía a quien lo lee: para una persona es un callejón, "
            f"para un agente una invitación a inventarse la salida. Declare el paso siguiente, "
            f"aunque sea «lo decide una persona».")
    return {
        "schema": SCHEMA,
        "command": command,
        "status": status,
        "exit": exit_for(status),
        "workspace": str(workspace),
        "run_id": run_id,
        "generated_at": generated_at or now(),
        "provenance": dict(provenance or {}),
        "payload": payload,
        "next": [s.to_dict() for s in siguientes],
    }


def payload_of(doc):
    """La carga útil, venga en sobre o suelta. El puente de migración, en una función.

    Un consumidor escrito antes del sobre leía la carga útil en la raíz. Con esto sigue
    funcionando con las dos formas y sin ramificar, que es lo que permite migrar el emisor y el
    consumidor en commits distintos. No adivina: reconoce el sobre por su identificador de
    contrato, no por «tiene una clave payload».
    """
    if isinstance(doc, dict) and doc.get("schema") == SCHEMA:
        return doc.get("payload")
    return doc
