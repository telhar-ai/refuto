# -*- coding: utf-8 -*-
"""Ed25519 (RFC 8032 §5.1) — SÓLO verificación, sólo biblioteca estándar.

Por qué existe
--------------
ADR-0002 (sólo biblioteca estándar) previó exactamente este día: «necesitar criptografía de firma
… sería dependencia opcional y su ausencia `BLOCKED`». Medido el 2026-09-27 en esta máquina: ni
`cryptography` ni `pynacl` están instalados, y `hashlib` no verifica firmas. Las dos salidas eran
delegar en un binario ajeno (`hicon verify-entry`, Rust, cuya procedencia refuto no puede atestar)
o implementar la verificación aquí, sobre `hashlib.sha512` y enteros. Se eligió lo segundo
(ADR-0017): un verificador de ~150 líneas que refuto puede leer, huellar (`core.trust`) y probar
contra vectores publicados es una superficie de confianza MENOR que un ejecutable de 8 MB.

Qué NO hay aquí
---------------
Firma. Este módulo no maneja claves privadas: no puede filtrarlas ni firmar nada en nombre de
nadie, y por eso las consideraciones de canal lateral (tiempo, caché) no aplican — toda la entrada
es pública. La firma de prueba vive en `tests/fixtures/ed25519_firma.py` y sólo en las pruebas.

Rigor del verificador
---------------------
- Ecuación SIN cofactor: `[S]B == R + [k]A` (la misma que `ed25519-dalek::verify`). Es la más
  estricta de las dos variantes de RFC 8032: todo lo que acepta lo acepta también la ecuación con
  cofactor `[8][S]B == [8]R + [8][k]A`, y no al revés.
- `S ≥ L` se rechaza (maleabilidad; RFC 8032 §5.1.7 y dalek).
- Codificaciones NO canónicas de puntos (`y ≥ p`, o `x = 0` con bit de signo a 1) se rechazan.
  dalek las tolera al decodificar; refuto NO. La divergencia va en la dirección segura (refuto
  rechaza más) y ningún firmante honesto produce esas codificaciones: `R = [r]B` se codifica
  canónico por construcción. Queda declarado en el ADR y comprobado en la conformidad.
- Claves públicas de orden pequeño (`[8]A = O`) se rechazan: una membresía con una clave así es
  una membresía maliciosa.

Conformidad medida (ver `tests/unit/test_ed25519.py` y `tests/contract/test_concordia_vectores.py`):
vector RFC 8032 §7.1 TEST 1, los 21 vectores canónicos de concordia (`ai/concordia/contracts/vectors/`),
y regeneración BYTE A BYTE de las firmas del vector 01 desde la semilla sintética de `testkit.rs`,
que confirma a la vez la firma de prueba y esta verificación contra la implementación de referencia.
"""

from __future__ import annotations

import hashlib

# ── el cuerpo y la curva ────────────────────────────────────────────────────────────────
P = 2**255 - 19
L = 2**252 + 27742317777372353535851937790883648493
D = (-121665 * pow(121666, -1, P)) % P          # d = −121665/121666
SQRT_M1 = pow(2, (P - 1) // 4, P)                 # √−1 mod p

# Punto base B: y = 4/5; x el positivo (par) que satisface la curva.
_BY = (4 * pow(5, -1, P)) % P
_BX = 15112221349535400772501151409588531511454012693041857206046113283949847762202
if (-_BX * _BX + _BY * _BY - 1 - D * _BX * _BX * _BY * _BY) % P != 0:
    # Era un `assert`, y un `assert` desaparece con `python -O`: en un módulo que existe para
    # decidir si una firma vale, eso deja la única comprobación del punto base sin ejecutar
    # justo en el modo en que nadie la está mirando. Que una constante del código falle aquí
    # significa que el módulo se editó mal, y entonces no hay verificación que ofrecer.
    raise RuntimeError("core.ed25519: el punto base no está en la curva; el módulo está corrupto")

#: Punto en coordenadas extendidas (X, Y, Z, T) con x = X/Z, y = Y/Z, x·y = T/Z.
IDENTITY = (0, 1, 1, 0)
BASE = (_BX, _BY, 1, (_BX * _BY) % P)


def _add(p1: tuple, p2: tuple) -> tuple:
    """Suma unificada (RFC 8032 §5.1.4, a = −1). Sirve también para doblar."""
    x1, y1, z1, t1 = p1
    x2, y2, z2, t2 = p2
    a = ((y1 - x1) * (y2 - x2)) % P
    b = ((y1 + x1) * (y2 + x2)) % P
    c = (2 * t1 * D * t2) % P
    d = (2 * z1 * z2) % P
    e, f, g, h = b - a, d - c, d + c, b + a
    return ((e * f) % P, (g * h) % P, (f * g) % P, (e * h) % P)


def _mul(k: int, pt: tuple) -> tuple:
    """[k]·pt por doble-y-suma. Sin protección de tiempo constante: todo lo que entra es público."""
    acc = IDENTITY
    while k > 0:
        if k & 1:
            acc = _add(acc, pt)
        pt = _add(pt, pt)
        k >>= 1
    return acc


def _equal(p1: tuple, p2: tuple) -> bool:
    x1, y1, z1, _ = p1
    x2, y2, z2, _ = p2
    return (x1 * z2 - x2 * z1) % P == 0 and (y1 * z2 - y2 * z1) % P == 0


def _decode(b: bytes) -> tuple | None:
    """Descomprime un punto (RFC 8032 §5.1.3). `None` si la codificación no es válida o no es
    canónica. Rechazar más de lo que rechaza la referencia es la dirección segura."""
    if len(b) != 32:
        return None
    y = int.from_bytes(b, "little")
    sign = y >> 255
    y &= (1 << 255) - 1
    if y >= P:                       # no canónico
        return None
    y2 = (y * y) % P
    u = (y2 - 1) % P
    v = (D * y2 + 1) % P
    x2 = (u * pow(v, -1, P)) % P
    x = pow(x2, (P + 3) // 8, P)
    if (x * x - x2) % P != 0:
        x = (x * SQRT_M1) % P
        if (x * x - x2) % P != 0:
            return None              # no hay raíz: fuera de la curva
    if x == 0 and sign == 1:
        return None                  # −0 no es canónico
    if (x & 1) != sign:
        x = P - x
    return (x, y, 1, (x * y) % P)


def encode_point(pt: tuple) -> bytes:
    """Comprime un punto: y en little-endian con el bit de signo de x en el bit 255."""
    x, y, z, _ = pt
    zi = pow(z, -1, P)
    x, y = (x * zi) % P, (y * zi) % P
    return (y | ((x & 1) << 255)).to_bytes(32, "little")


def _small_order(pt: tuple) -> bool:
    return _equal(_mul(8, pt), IDENTITY)


def admite_clave(public_key: bytes) -> bool:
    """`True` si `public_key` supera la ADMISIÓN, antes de mirar firma alguna.

    Es la etapa R1 de `CERTIFICATE-SPEC §11.2`: 32 bytes, punto decodificable y no de orden
    pequeño. Existe separada de `verify` porque hay dos maneras distintas de rechazar —la
    clave o la firma— y colapsarlas en un solo `False` pierde justo la información que
    permite comparar dos verificadores: mover una condición de R1 a R2 no cambia qué
    entradas se aceptan, pero sí cambia la regla.
    """
    if not isinstance(public_key, (bytes, bytearray)) or len(public_key) != 32:
        return False
    pt = _decode(bytes(public_key))
    return pt is not None and not _small_order(pt)


def verify(public_key: bytes, message: bytes, signature: bytes) -> bool:
    """`True` sólo si `signature` es una firma Ed25519 válida de `message` bajo `public_key`.

    Nunca lanza por la forma de la entrada: longitudes incorrectas, puntos inválidos o no
    canónicos, `S ≥ L` y claves de orden pequeño devuelven `False`. Un verificador que revienta
    ante basura es un verificador que alguien acabará envolviendo en `try/except: pass`.
    """
    if not isinstance(public_key, (bytes, bytearray)) or len(public_key) != 32:
        return False
    if not isinstance(signature, (bytes, bytearray)) or len(signature) != 64:
        return False
    if not isinstance(message, (bytes, bytearray)):
        return False
    a_pt = _decode(bytes(public_key))
    if a_pt is None or _small_order(a_pt):
        return False
    r_pt = _decode(bytes(signature[:32]))
    if r_pt is None:
        return False
    s = int.from_bytes(signature[32:], "little")
    if s >= L:
        return False
    k = int.from_bytes(hashlib.sha512(bytes(signature[:32]) + bytes(public_key) + bytes(message)).digest(),
                       "little") % L
    lhs = _mul(s, BASE)
    rhs = _add(r_pt, _mul(k, a_pt))
    return _equal(lhs, rhs)
