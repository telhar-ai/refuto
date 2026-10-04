# -*- coding: utf-8 -*-
"""Raíz de confianza: de qué cuelga una política, y cómo se sabe que el juez no cambió.

Los dos huecos que este módulo cierra
-------------------------------------
**1 · La monotonía era relativa, y el hijo elegía el padre.** `core.refinement` demuestra
`hijo ⊒ padre` para cada arista de la cadena. Eso es correcto y no basta: nada obligaba a que
la CIMA de la cadena atenuara nada. Medido el 2026-09-23, tres pasos, todos permitidos por el
propio guardián:

    1. escribir una política laxa en /tmp/claude-*  (raíz declarada en external_write_allow)
    2. reescribir .harness/policy.json por Bash      (B-1, cerrado aparte)
    3. el hijo declara `extends` a esa política

    resultado:  deny → allow  en las tres comprobaciones probadas

La monotonía no se violaba en ningún paso. Lo que faltaba era la raíz:

    Trusted(Π)  ⟺  Reachable(Π, R)  ∧  Monotone(cadena)  ∧  Acyclic(cadena)

**2 · No había `R` en disco.** Los valores de fábrica vivían sólo como constantes de
`core/policy.py`, así que la cima de toda cadena real era el cliente y nadie vigilaba lo que
la cima retiraba (V6, declarada abierta en `test_violaciones_refinamiento.py` con la nota
«lo cerraría un `policies/base.json` versionado, no un parche aquí»).

La solución, y por qué es composición y no validación
------------------------------------------------------
`R` es **la línea base del motor**, que viaja con el código. Toda política —tenga `extends` o
no— se compone con `R` como padre implícito:

    Π_efectiva = Refinar(R, Π_declarada)

No se *valida* contra `R`: se *compone* con `R`. La diferencia es la que hace fuerte al
mecanismo. En los campos `ACUMULA` el efectivo es la UNIÓN, así que vaciar
`protected_paths` o `command_deny` deja de ser una violación detectable para convertirse en
**inexpresable**: el efectivo vuelve a traer las 13 rutas y las 16 órdenes de fábrica. En
`REDUCE` la intersección impide ensanchar agujeros, y en `ENDURECE` apagar una comprobación
de fábrica se rechaza.

Es la misma tesis que `core.refinement` ya defendía para las aristas —«no poder expresar la
violación es más fuerte que detectarla»— aplicada por fin a la raíz.

Lo que esto NO protege: alguien que edite `core/policy.py`. De eso se ocupa la atestación de
abajo, que es la forma operativa de `I6'` (FORMAL-MODEL §6.3).
"""

from __future__ import annotations

import hashlib
from pathlib import Path

#: La raíz del motor: el directorio que contiene `core/`, `gates/`, `adapters/`.
RAIZ_MOTOR = Path(__file__).resolve().parents[1]

#: Los ficheros cuyo contenido DETERMINA un veredicto. No es «todo el repositorio»: un
#: cambio en `README.md` no puede alterar una decisión, y meterlo en la huella haría que la
#: atestación cambiara por motivos que no son de gobierno — una alarma que suena por todo
#: se ignora, y entonces no suena cuando importa.
SUBARBOLES_MOTOR = ("core", "gates", "adapters")
FICHEROS_MOTOR = ("refuto.py",)

#: Y los ficheros de DATOS que deciden. La lista de arriba recorría sólo `*.py`, y eso dejó de
#: describir lo que hace este módulo el día que `core/capabilities.py` entró en el guardián.
#:
#: Medido el 2026-09-25, antes de este cambio:
#:
#:     ficheros en la huella : 73
#:     json en la huella     : []
#:
#: `roles/registry.json` (17 KB) alimenta `capacidades_de()` → `_no_shell`, `_no_secret_access`,
#: `no_modify_verifier`, y esas restricciones **producen `DENY` en el guardián**. Quien lo
#: editara cambiaba las decisiones del juez sin que `deriva_del_motor()` lo notara. La huella se
#: quedó atrás en el mismo commit que volvió relevante al registro, que es como envejece una
#: atestación: nada la obliga a cubrir lo que se añadió después.
#:
#: Se declaran por extensión Y por subárbol para que añadir un fichero de datos nuevo a un
#: directorio ya cubierto entre en la huella solo, sin que nadie se acuerde.
SUBARBOLES_DATOS = ("roles", "schemas", "policies")
EXTENSIONES_DATOS = (".json",)


def _sha_fichero(p: Path) -> str:
    h = hashlib.sha256()
    with p.open("rb") as fh:
        for bloque in iter(lambda: fh.read(65536), b""):
            h.update(bloque)
    return h.hexdigest()


def inventario_motor(raiz: Path | None = None) -> dict:
    """`{ruta relativa: sha256}` de todo lo que participa en una decisión.

    Ordenado y relativo a propósito: la huella tiene que ser la misma en dos máquinas que
    tengan el mismo código en directorios distintos, o la atestación sólo serviría en la
    máquina donde se calculó.
    """
    base = (raiz or RAIZ_MOTOR).resolve()
    out: dict = {}
    for sub in SUBARBOLES_MOTOR:
        d = base / sub
        if not d.is_dir():
            continue
        for p in sorted(d.rglob("*.py")):
            if "__pycache__" in p.parts:
                continue
            out[p.relative_to(base).as_posix()] = _sha_fichero(p)
    for sub in SUBARBOLES_DATOS:
        d = base / sub
        if not d.is_dir():
            continue
        for p in sorted(d.rglob("*")):
            if p.is_file() and p.suffix in EXTENSIONES_DATOS:
                out[p.relative_to(base).as_posix()] = _sha_fichero(p)
    for nombre in FICHEROS_MOTOR:
        p = base / nombre
        if p.is_file():
            out[nombre] = _sha_fichero(p)
    return out


def digest_motor(raiz: Path | None = None) -> str:
    """Una huella del juez entero. Si cambia, el juez cambió.

    No dice QUIÉN lo cambió ni si el cambio es legítimo: dice que el veredicto de antes y el
    de ahora no los emitió el mismo programa. Esa distinción es toda la propiedad `I6'`.
    """
    inv = inventario_motor(raiz)
    cuerpo = "\n".join(f"{ruta} {sha}" for ruta, sha in sorted(inv.items()))
    return hashlib.sha256(cuerpo.encode("utf-8")).hexdigest()


def deriva_del_motor(esperado: dict, raiz: Path | None = None) -> dict:
    """Qué cambió respecto de un inventario anterior. Vacío = nada cambió.

    Devuelve las tres clases por separado porque se arreglan distinto: un fichero
    `modificado` es una edición, uno `ausente` es un borrado, y uno `nuevo` puede ser una
    extensión legítima o una puerta trasera.
    """
    actual = inventario_motor(raiz)
    return {
        "modificados": sorted(k for k in set(esperado) & set(actual)
                              if esperado[k] != actual[k]),
        "ausentes": sorted(set(esperado) - set(actual)),
        "nuevos": sorted(set(actual) - set(esperado)),
    }


# ── raíz de la cadena de políticas ───────────────────────────────────────────────────
def documento_raiz() -> dict:
    """`R`, el documento del que cuelga toda cadena. Se deriva de `Policy.default()`.

    Derivado y no escrito a mano: dos fuentes para la misma norma se separan, y la que se
    separa sin avisar es siempre la que nadie ejecuta.
    """
    from core.policy import documento_base

    return documento_base("refuto-raiz")


def digest_raiz() -> str:
    from core.refinement import digest_de

    return digest_de(documento_raiz())


#: Campos que la RAÍZ DEL MOTOR no acota, y por qué. Uno solo, y tiene que costar añadir otro.
#:
#: `privilege_grants` es la lista de autorizaciones operativas de un espacio: qué rol puede elevar
#: privilegio, para qué forma de orden, en qué host. Su monotonía es `REDUCE_LISTA` —el hijo sólo
#: retira— y eso es correcto entre capas REALES: un proyecto no puede concederse lo que su cliente
#: no le dio. Pero la raíz del motor **no es un cliente**: es la norma base del producto, y no
#: puede enumerar las necesidades operativas de espacios que no conoce.
#:
#: Sin esta excepción el campo sería código muerto, y se midió así el 2026-09-25: con la raíz
#: vacía, un espacio que declaraba UNA concesión obtenía
#:
#:     HerenciaIrresoluble: `privilege_grants`: el hijo declara 1 registro(s) que el padre no
#:                          tiene idénticos
#:
#: es decir, **ningún espacio podía declarar ninguna concesión nunca**. Es exactamente la trampa
#: que ADR-0014 documenta para `writable_paths`, y reconocerla aquí es la razón de que esto exista
#: en vez de haber clasificado el campo como `PROPIO` —que habría dejado a un proyecto aflojar lo
#: que su cliente apretó, que es el defecto de verdad—.
#:
#: Lo que NO se pierde: la autorización sigue siendo un acto de persona, porque
#: `.harness/policy.json` está protegido y un agente no puede escribirlo. Lo que se pierde es que
#: la raíz pueda vetar una concesión, y la raíz nunca supo qué vetar.
RAIZ_NO_ACOTA = {
    "privilege_grants": "es una autorización operativa del espacio, y la raíz del motor no es un "
                        "cliente: no puede enumerar las necesidades de espacios que no conoce. La "
                        "monotonía `REDUCE_LISTA` sigue rigiendo entre capas reales.",
}


def componer_con_raiz(doc: dict):
    """`Refinar(R, doc)`. Devuelve el `Refinamiento`, que el llamador debe comprobar.

    Se llama con el documento de la CIMA de la cadena —el ancestro sin `extends`—, porque
    es el único punto donde antes no había nadie por encima.

    Los campos de `RAIZ_NO_ACOTA` se comparan contra el propio valor del documento, no contra el
    de la raíz: así la raíz no los veta y la monotonía entre capas reales queda intacta.
    """
    from core.refinement import refinar

    raiz = documento_raiz()
    for campo in RAIZ_NO_ACOTA:
        if campo in doc:
            raiz[campo] = doc[campo]
    return refinar(raiz, doc)
