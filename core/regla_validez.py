"""Consumo de la identidad de regla de validez de concordia (`CERTIFICATE-SPEC §11`).

`protocol_version` no identifica la regla: `concordia/pbft/v1` fue provablemente invariante
ante un cambio de semántica que hizo que firmas antes aceptadas pasaran a rechazarse. Este
módulo consume la identidad que SÍ la identifica —derivada del comportamiento sobre un
conjunto fijo de sondas— y la compara con la de refuto.

Lo que este módulo NO hace, a propósito:

- **No confía en el `digest` publicado.** Es una afirmación que se recomputa, no una
  autoridad. Un publicador que mienta no consigue que se acepte una firma falsa: las sondas
  se evalúan con `core.ed25519`, que es una implementación independiente (`ADR-0002`: sin
  dependencias fuera de la biblioteca estándar).
- **No toma las sondas del documento.** `SONDAS` y `PROBE_SET_DIGEST` son constantes del
  motor, cubiertas por `core.trust.digest_motor`. Si el conjunto viniera del documento, el
  paso de comparar instrumentos sería vacío: siempre casaría consigo mismo.
- **No rellena ausencias.** Una identidad ausente da `NO_DECLARADA`/`BLOCKED`, nunca `PASS`.

Divergencia MEDIDA el 2026-09-30, y declarada aquí porque callarla sería el defecto que este
mecanismo existe para eliminar: refuto difiere de la regla estricta de concordia en la sonda
`05-noncanonical-y-encoding-admitted`, y sólo en ésa (10 de 11 coinciden). Una clave cuya `y`
codifica `2^255-1 > p` es NO canónica; `core.ed25519._decode` la rechaza en admisión (`K`) y
dalek la decodifica y la admite, fallando después en la firma (`S`). refuto rechaza MÁS, que
es la dirección segura, pero sigue siendo una regla distinta y se reporta como tal. Resolverla
—alinear a refuto con dalek, o a concordia con refuto— es decisión de una persona, no de este
módulo: hacer que case debilitando `_decode` sería exactamente lo que no se debe hacer.
"""

import hashlib

from core import ed25519
from core.model import BLOCKED, FAIL, INCONCLUSIVE, PASS

# --- La forma canónica (§11.4) ----------------------------------------------------------
# Binaria y con longitud explícita a propósito: un JSON canónico obligaría a acordar orden de
# claves, escapado unicode y representación numérica entre Rust y Python.

DOMINIO = b"concordia/validity-rule/v1"          # 26 B
RULE_ID = "concordia/pbft/v1/attestation-signature"

# Tres valores, no dos: la regla tiene dos etapas, y mover una condición de R1 a R2 cambia la
# regla sin cambiar el conjunto de entradas aceptadas.
BYTE_VEREDICTO = {"S": 0, "A": 1, "K": 2}
ACEPTA = "A"                                      # acepta
RECHAZA_FIRMA = "S"                               # la clave fue admitida; la firma no vale
RECHAZA_CLAVE = "K"                               # rechaza antes de mirar la firma

# --- El instrumento ---------------------------------------------------------------------
# `(id, clave pública, mensaje, firma)` en hex, ORDENADAS POR `id` ascendente. El orden es
# parte de la forma canónica, así que `_comprobar_orden` lo verifica en vez de confiarlo.

SONDAS = (
    # control positivo: firma válida de RFC 8032 TEST 1
    ("01-valid-rfc8032-t1",
     "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
     "",
     "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b"),
    # la firma cubre el mensaje: misma firma, otro mensaje
    ("02-valid-key-wrong-message",
     "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
     "6f74726f206d656e73616a65",
     "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b"),
    # R2: `S` reducida (0 <= S < l). S = 0xFF*32 está muy por encima de l
    ("03-s-not-reduced",
     "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
     "",
     "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e06522490155ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"),
    # R1: la clave mide 32 bytes
    ("04-key-wrong-length",
     "11111111111111111111111111111111111111111111111111111111111111",
     "",
     "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b"),
    # R1: codificación NO canónica de `y` (0xFF*32, y = 2^255-1 > p). Aquí es donde refuto
    # discrepa de concordia: ver la nota de cabecera.
    ("05-noncanonical-y-encoding-admitted",
     "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
     "",
     "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b"),
    # R1 is_weak + R2 sin cofactor: A = identidad con firma fabricada
    ("06-small-order-identity-forged",
     "0100000000000000000000000000000000000000000000000000000000000000",
     "6375616c7175696572206d656e73616a65",
     "01000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"),
    # R1 is_weak + R2 sin cofactor: A = orden-2 con firma fabricada
    ("07-small-order-order2-forged",
     "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
     "6375616c7175696572206d656e73616a65",
     "01000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"),
    # R1 is_weak AISLADA de R2: clave de orden pequeño con una firma que no valida igualmente.
    # Discrimina por la ETAPA del rechazo, no por el resultado.
    ("08-small-order-key-legit-sig",
     "0100000000000000000000000000000000000000000000000000000000000000",
     "",
     "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b"),
    # R2: `R` no de orden pequeño, con A legítima
    ("09-r-small-order",
     "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
     "",
     "01000000000000000000000000000000000000000000000000000000000000005fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b"),
    # R2: la firma mide 64 bytes
    ("10-signature-wrong-length",
     "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
     "",
     "222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222"),
    # R1: la clave es un punto VÁLIDO de la curva. `y = 2` no es decodificable
    ("11-key-not-curve-point",
     "0200000000000000000000000000000000000000000000000000000000000000",
     "",
     "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b"),
)

# Constante del motor, no valor leído: es lo que da contenido a «comparar instrumentos».
# Recalcularlo desde `SONDAS` en vez de fijarlo dejaría pasar una edición del conjunto.
PROBE_SET_DIGEST = "c85f30395910d730a9e46f25e6bdb2960dca69671154f9e3f803a2b6e81e7a6d"

# --- Resoluciones -----------------------------------------------------------------------
# Se declaran por separado porque se arreglan distinto, y ninguna es «firma inválida»:
# reportar una divergencia de regla como firma inválida la hace indistinguible de una réplica
# bizantina, que es el error que todo esto existe para eliminar.

CONCUERDA = "CONCUERDA"                        # misma regla
REGLA_DIVERGENTE = "REGLA_DIVERGENTE"          # otra regla, y se dice en qué sonda
DOCUMENTO_INCOHERENTE = "DOCUMENTO_INCOHERENTE"  # el digest no casa con sus propios veredictos
INSTRUMENTO_DISTINTO = "INSTRUMENTO_DISTINTO"  # otro conjunto de sondas: no comparable
DOCUMENTO_MALFORMADO = "DOCUMENTO_MALFORMADO"  # estructura ilegible
NO_DECLARADA = "NO_DECLARADA"                  # ausente: no se pudo comprobar

ESTADO_DE = {
    CONCUERDA: PASS,
    REGLA_DIVERGENTE: FAIL,
    DOCUMENTO_INCOHERENTE: FAIL,
    DOCUMENTO_MALFORMADO: FAIL,
    INSTRUMENTO_DISTINTO: INCONCLUSIVE,   # no se puede comparar, que no es discrepar
    NO_DECLARADA: BLOCKED,                # no se pudo comprobar, que no es estar bien
}


def _u16be(n: int) -> bytes:
    if not 0 <= n <= 0xFFFF:
        raise ValueError(f"longitud fuera de u16be: {n}")
    return n.to_bytes(2, "big")


def _con_longitud(b: bytes) -> bytes:
    return _u16be(len(b)) + b


def _comprobar_orden(sondas) -> None:
    ids = [s[0].encode("utf-8") for s in sondas]
    if ids != sorted(ids):
        raise ValueError("las sondas no están ordenadas por `id` ascendente: la forma "
                         "canónica quedaría mal definida")
    if len(set(ids)) != len(ids):
        raise ValueError("hay `id` de sonda repetidos")


def forma_canonica(veredictos: str | None = None, sondas=SONDAS) -> bytes:
    """§11.4. `veredictos=None` da la preimagen de `probe_set_digest`, sin los bytes de
    veredicto: identifica el INSTRUMENTO, no la regla."""
    _comprobar_orden(sondas)
    if veredictos is not None and len(veredictos) != len(sondas):
        raise ValueError(f"{len(veredictos)} veredictos para {len(sondas)} sondas")
    out = bytearray(DOMINIO)
    out += _con_longitud(RULE_ID.encode("utf-8"))
    out += _u16be(len(sondas))
    for i, (ident, pk_hex, msg_hex, sig_hex) in enumerate(sondas):
        out += _con_longitud(ident.encode("utf-8"))
        out += _con_longitud(bytes.fromhex(pk_hex))
        out += _con_longitud(bytes.fromhex(msg_hex))
        out += _con_longitud(bytes.fromhex(sig_hex))
        if veredictos is not None:
            v = veredictos[i]
            if v not in BYTE_VEREDICTO:
                raise ValueError(f"veredicto #{i} ilegible: {v!r} (se esperaba A, S o K)")
            out += bytes([BYTE_VEREDICTO[v]])
    return bytes(out)


def veredicto_propio(public_key: bytes, message: bytes, signature: bytes) -> str:
    """El veredicto de refuto sobre una sonda, declarando la ETAPA del rechazo (§11.2)."""
    if not ed25519.admite_clave(public_key):
        return RECHAZA_CLAVE
    return ACEPTA if ed25519.verify(public_key, message, signature) else RECHAZA_FIRMA


def veredictos_propios(sondas=SONDAS) -> str:
    return "".join(veredicto_propio(bytes.fromhex(pk), bytes.fromhex(msg), bytes.fromhex(sig))
                   for _, pk, msg, sig in sondas)


def identidad_propia(sondas=SONDAS) -> dict:
    """La identidad de la regla que ejecuta ESTE verificador. Se deriva, no se declara."""
    if not sondas:
        raise ValueError("conjunto de sondas vacío: un instrumento que no observa nada no "
                         "identifica ninguna regla")
    verdicts = veredictos_propios(sondas)
    return {
        "rule_id": RULE_ID,
        "probe_count": len(sondas),
        "verdicts": verdicts,
        "probe_set_digest": hashlib.sha256(forma_canonica(None, sondas)).hexdigest(),
        "digest": hashlib.sha256(forma_canonica(verdicts, sondas)).hexdigest(),
    }


def _resolucion(resolucion: str, motivo: str, **extra) -> dict:
    return {"resolucion": resolucion, "estado": ESTADO_DE[resolucion],
            "motivo": motivo, **extra}


def consumir(documento) -> dict:
    """Ejecuta los cuatro pasos de `§11.5` sobre la identidad publicada por un tercero.

    `documento` es el `validity_rule` de `GET /v1/status` o la salida de
    `hicon validity-rule`. Devuelve siempre una resolución declarada; nunca lanza por la
    forma de la entrada, y nunca devuelve `PASS` por omisión.
    """
    propia = identidad_propia()

    # Paso 0 · la ausencia se declara, no se rellena.
    if documento is None:
        return _resolucion(NO_DECLARADA,
                           "el publicador no declara `validity_rule`: su regla es "
                           "desconocida, que no es lo mismo que correcta",
                           propio=propia)
    if not isinstance(documento, dict):
        return _resolucion(DOCUMENTO_MALFORMADO,
                           f"se esperaba un objeto con la identidad, llegó {type(documento).__name__}",
                           propio=propia)
    if not documento:
        return _resolucion(DOCUMENTO_MALFORMADO,
                           "objeto de identidad vacío: no declara ningún campo",
                           propio=propia)

    faltan = [k for k in ("rule_id", "probe_count", "verdicts", "probe_set_digest", "digest")
              if k not in documento]
    if faltan:
        return _resolucion(DOCUMENTO_MALFORMADO,
                           f"faltan campos requeridos: {', '.join(faltan)}", propio=propia)

    decl_verdicts = documento["verdicts"]
    if not isinstance(decl_verdicts, str):
        return _resolucion(DOCUMENTO_MALFORMADO,
                           f"`verdicts` debe ser una cadena, llegó {type(decl_verdicts).__name__}",
                           propio=propia)
    if documento["rule_id"] != RULE_ID:
        return _resolucion(INSTRUMENTO_DISTINTO,
                           f"otra regla: {documento['rule_id']!r} != {RULE_ID!r}",
                           propio=propia)

    # Paso 2 · ¿estamos sondeando lo mismo? Si no, los veredictos NO son comparables, y eso
    # no es discrepar: es no poder comparar.
    if documento["probe_set_digest"] != PROBE_SET_DIGEST:
        return _resolucion(INSTRUMENTO_DISTINTO,
                           f"conjunto de sondas distinto (declarado "
                           f"{documento['probe_set_digest'][:16]}, propio "
                           f"{PROBE_SET_DIGEST[:16]}): los veredictos no son comparables",
                           propio=propia)
    if documento["probe_count"] != len(SONDAS):
        return _resolucion(INSTRUMENTO_DISTINTO,
                           f"declara {documento['probe_count']} sondas con el mismo "
                           f"`probe_set_digest` que {len(SONDAS)}: documento contradictorio",
                           propio=propia)
    if len(decl_verdicts) != len(SONDAS):
        return _resolucion(DOCUMENTO_INCOHERENTE,
                           f"declara {len(decl_verdicts)} veredictos para {len(SONDAS)} sondas",
                           propio=propia)

    # Paso 3 · recomputar el digest DESDE LOS VEREDICTOS DECLARADOS. Sin este paso, un
    # documento con los veredictos de una regla y el digest de otra pasaría como válido.
    try:
        recomputado = hashlib.sha256(forma_canonica(decl_verdicts)).hexdigest()
    except ValueError as e:
        return _resolucion(DOCUMENTO_INCOHERENTE, str(e), propio=propia)
    if recomputado != documento["digest"]:
        return _resolucion(DOCUMENTO_INCOHERENTE,
                           f"el digest declarado {str(documento['digest'])[:16]} no casa con "
                           f"sus propios veredictos (recomputado {recomputado[:16]})",
                           propio=propia, recomputado=recomputado)

    # Paso 4 · comparar con la regla propia, y decir EN QUÉ SONDA.
    divergentes = [
        {"indice": i, "sonda": SONDAS[i][0], "declarado": a, "propio": b}
        for i, (a, b) in enumerate(zip(decl_verdicts, propia["verdicts"], strict=True)) if a != b
    ]
    if divergentes:
        detalle = " · ".join(f"{d['sonda']}: declarado {d['declarado']}, propio {d['propio']}"
                             for d in divergentes)
        return _resolucion(REGLA_DIVERGENTE,
                           f"{len(divergentes)} de {len(SONDAS)} sondas discrepan [{detalle}]",
                           propio=propia, divergentes=divergentes)

    return _resolucion(CONCUERDA,
                       f"misma regla sobre las {len(SONDAS)} sondas (digest {recomputado[:16]})",
                       propio=propia, divergentes=[])
