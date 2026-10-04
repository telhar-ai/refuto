# -*- coding: utf-8 -*-
"""El sujeto que le faltaba al monitor de referencia.

El defecto que este módulo cierra
---------------------------------
El control de acceso es una relación TERNARIA: `(sujeto, objeto, operación)`. refuto decidía
sobre una binaria:

    decide_write  (policy, workspace, target, content)   → (objeto, operación)
    decide_command(policy, command, workspace)           → (forma de la orden)

`core/guard.py` normalizaba el hecho en siete campos —`runtime`, `tool`, `path`, `content`,
`command`, `cwd`, `structured_reply`— y **ninguno era el sujeto**. El diario tampoco lo
registraba: las claves de `policy/decision` eran 16 y ninguna decía quién actuó. Consecuencia
matemática, no de implementación: **todo agente en todo rol tenía autoridad idéntica**.

Y había un vocabulario de capacidades esperando. Medido el 2026-09-25 sobre
`roles/registry.json`: 22 roles declaran 10 restricciones distintas —`no_write_code` en 12
roles, `no_modify_verifier` en 7, `no_shell` en 6, `no_secret_access` en 3…— y sus únicos
consumidores eran `core/session.py:751` y `refuto.py:1766`, que las imprimen en el informe bajo
«**No puedes:**». Es decir: **10 capacidades × 22 roles, aplicadas por cero líneas de código.**

`no_shell` significaba «se le pide al modelo por favor que no use la shell». El guardián —lo
único que no se puede convencer— no sabía que los roles existían.

Las tres reglas de este módulo
------------------------------
1. **Una capacidad sólo puede APRETAR.** Se expresan en negativo (`no_shell`) y el efectivo es
   la UNIÓN de lo que declara el registro de roles y lo que añada la política del espacio. Unión
   es `ACUMULA`: el espacio puede restringir más un rol, nunca menos. No es estético — una lista
   de concesiones sería `REDUCE` y volvería a la trampa que documenta ADR-0014.
2. **Toda restricción declarada está en esta tabla**, en una de dos categorías: aplicada, o
   **declarada no observable con su motivo**. Una tercera categoría —declarada y en ningún
   sitio— es la que existía, y `G-CAPABILITY` la vuelve imposible.
3. **El rol no es un principal criptográfico.** Llega por `HARNESS_ROLE`, una variable de
   entorno que el propio agente puede reescribir en un subproceso. Esto atenúa por rol
   DECLARADO. Es una barandilla fuerte contra el resbalón y débil contra un adversario
   decidido, igual que las otras dos capas del producto — y decirlo es parte del control. Un
   principal real exigiría ejecutar al agente bajo otro uid, que es otra frontera.
"""

from __future__ import annotations

from core.model import BLOCKED  # noqa: F401  (vocabulario; se usa en el gate)

#: Restricciones que el guardián PUEDE observar, con el predicado que las aplica.
#:
#: Cada entrada recibe el hecho normalizado más lo que el análisis de rutas ya derivó, y
#: devuelve el motivo del rechazo o cadena vacía. No devuelve un veredicto: el veredicto es
#: siempre `DENY`, porque una capacidad que sólo preguntara no restringiría nada que la política
#: general no preguntara ya.
def _no_shell(fact, ctx) -> str:
    if (fact.get("command") or "").strip():
        return ("este rol no puede usar la shell. La restricción existe porque su salida se "
                "evalúa por lo que ESCRIBE, no por lo que ejecuta: una orden de consola es un "
                "efecto que su contrato no declara y que nadie revisa.")
    return ""


def _no_secret_access(fact, ctx) -> str:
    if ctx.get("lecturas_secretas"):
        ruta, patron = ctx["lecturas_secretas"][0]
        return (f"este rol no puede acceder a rutas de credencial, y la orden lee «{ruta}» "
                f"(por «{patron}»). Para el resto de roles esto lo decide una persona; para "
                f"éste está decidido.")
    return ""


def _sin_escribir_en(patrones: tuple, motivo: str):
    def predicado(fact, ctx) -> str:
        for destino in ctx.get("rutas", ()):
            for p in patrones:
                from core.policy import _path_matches, _normalize
                if _path_matches(_normalize(destino), p):
                    return f"{motivo} («{destino}» casa con «{p}»)."
        return ""
    return predicado


def _read_only(fact, ctx) -> str:
    if ctx.get("rutas"):
        return (f"este rol es de sólo lectura sobre la infraestructura y la orden escribe en "
                f"«{sorted(ctx['rutas'])[0]}».")
    return ""


APLICADAS = {
    "no_shell": _no_shell,
    "no_secret_access": _no_secret_access,
    "no_modify_evidence": _sin_escribir_en(
        ("**/evidence/**", "**/evidencia/**"),
        "este rol no puede modificar la evidencia: es lo que prueba lo que hizo"),
    "no_modify_verifier": _sin_escribir_en(
        ("**/verification/**", "**/verificacion/**", "**/gates/**"),
        "este rol no puede modificar el verificador: sería juez de sí mismo"),
    "read_only_infrastructure": _read_only,
}

#: Restricciones declaradas que este guardián **no puede observar**, con el motivo exacto.
#:
#: Estar aquí no es una excusa: es una afirmación comprobable. `G-CAPABILITY` exige que toda
#: restricción del registro esté en `APLICADAS` o aquí, y que aquí traiga motivo escrito — la
#: misma regla que `Result` aplica a `NOT_APPLICABLE`, que no se acepta sin `measure`.
NO_OBSERVABLES = {
    "no_write_code":
        "«código» no tiene definición en la política. Distinguirlo de documentación o de "
        "configuración exigiría un criterio por ruta que el espacio no declara, y adivinarlo "
        "convertiría esta restricción en un rechazo por extensión de fichero.",
    "no_modify_product":
        "mismo motivo que `no_write_code`: «producto» no está delimitado por ninguna ruta "
        "declarada, así que no hay predicado que aplicar sin inventárselo.",
    "no_self_approval":
        "es una propiedad del REGISTRO de revisión humana, no de una llamada de herramienta. La "
        "aplica `G-HUMAN` comparando quién produjo y quién aprobó; el guardián decide sobre un "
        "hecho aislado y no tiene ese par delante.",
    "no_fix_what_it_reviews":
        "exige correlacionar dos fases de una corrida —qué revisó antes y qué toca ahora— y el "
        "guardián decide sobre un hecho sin historia. Su sitio natural es el plano de "
        "evaluación (ADR-0010), no el control previo.",
    "destructive_requires_approval":
        "sería una RELAJACIÓN, no una restricción: lo destructivo ya está en `command_deny` con "
        "veredicto `deny` para todos los roles, y «requiere aprobación» es más débil que "
        "«rechazado». Una capacidad que aflojara rompería la monotonía que este módulo declara. "
        "Se conserva en el registro porque describe la intención del rol, y se aplica como el "
        "`deny` general que ya existe.",
}

#: Comprobado al importar: ninguna restricción puede estar en las dos tablas. Si alguien añade
#: un predicado y olvida quitar el motivo, el espacio quedaría con una restricción que se aplica
#: y que a la vez se declara inaplicable — y el informe diría lo segundo.
_EN_LAS_DOS = sorted(set(APLICADAS) & set(NO_OBSERVABLES))
if _EN_LAS_DOS:                                                       # pragma: no cover
    raise RuntimeError(
        f"restricciones en APLICADAS y en NO_OBSERVABLES a la vez: {', '.join(_EN_LAS_DOS)}. "
        f"Una restricción se aplica o se declara no observable; las dos cosas es una "
        f"contradicción que el informe de sesión propagaría.")

CONOCIDAS = frozenset(APLICADAS) | frozenset(NO_OBSERVABLES)


def capacidades_de(rol: str, policy=None) -> tuple:
    """Las restricciones EFECTIVAS de un rol: registro ∪ lo que añada la política.

    Unión y no sustitución. El registro de roles es la fuente canónica —un rol es lo que su
    contrato dice que es— y la política del espacio puede apretar más, nunca aflojar. Un espacio
    que quisiera que su `backend-engineer` tampoco usara la shell lo declara y se acumula; uno
    que quisiera lo contrario no tiene sintaxis para decirlo, que es el punto.
    """
    if not rol:
        return ()
    del_registro: tuple = ()
    try:
        from core.roles import load
        r = load().get(rol)
        if r is not None:
            del_registro = tuple(r.constraints)
    except Exception:                                                 # noqa: BLE001
        del_registro = ()
    extra = tuple((getattr(policy, "role_capabilities", None) or {}).get(rol) or ())
    return tuple(sorted(set(del_registro) | set(extra)))


def decidir(policy, rol: str, fact: dict, *, rutas=(), lecturas_secretas=()) -> tuple:
    """`(motivo, restriccion)` si alguna capacidad del rol rechaza este hecho; `("", "")` si no.

    No devuelve un `Decision` para no acoplar este módulo al de política: quien llama compone.
    Y compone tomando **lo más restrictivo**, que es lo que hace que una capacidad sólo pueda
    apretar por construcción y no por disciplina de quien la escriba.
    """
    ctx = {"policy": policy, "rutas": tuple(rutas or ()),
           "lecturas_secretas": tuple(lecturas_secretas or ())}
    for restriccion in capacidades_de(rol, policy):
        predicado = APLICADAS.get(restriccion)
        if predicado is None:
            continue            # no observable: declarado en NO_OBSERVABLES, con su motivo
        motivo = predicado(fact, ctx)
        if motivo:
            return motivo, restriccion
    return "", ""
