# -*- coding: utf-8 -*-
"""Huellas y redacción. Todo lo que se guarda como evidencia pasa por aquí.

La redacción va ANTES de escribir, no al leer. Un secreto que llegó al disco ya se filtró,
aunque después se tape al mostrarlo.
"""

from __future__ import annotations

import hashlib
import re
from pathlib import Path

ALGO = "sha256"


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def digest_tree(root: Path, rel_paths: list[str]) -> str:
    """Huella de un conjunto de archivos, estable e independiente del orden de entrada.

    Se incluye la RUTA además del contenido: si no, mover un archivo de sitio no cambiaría la
    huella, y mover un archivo de sitio sí cambia el sistema.
    """
    h = hashlib.sha256()
    for rel in sorted(rel_paths):
        p = root / rel
        h.update(rel.encode("utf-8"))
        h.update(b"\0")
        h.update(sha256_file(p).encode("ascii") if p.is_file() else b"MISSING")
        h.update(b"\n")
    return h.hexdigest()


# ── redacción ────────────────────────────────────────────────────────────────────────
# Cada patrón corresponde a una forma real de filtrar algo. No se añaden patrones
# preventivos: cada uno cuesta falsos positivos y un redactor ruidoso se desactiva.
_PATTERNS: list[tuple[str, re.Pattern]] = [
    ("AWS_AKID",   re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b")),
    ("GH_TOKEN",   re.compile(r"\bgh[pousr]_[A-Za-z0-9]{16,}\b")),
    ("GL_TOKEN",   re.compile(r"\bglpat-[A-Za-z0-9_-]{20,}\b")),
    ("SK_TOKEN",   re.compile(r"\bsk-[A-Za-z0-9_-]{20,}\b")),
    ("SLACK",      re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b")),
    ("JWT",        re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b")),
    ("PRIVKEY",    re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----")),
    ("BEARER",     re.compile(r"(?i)\b(authorization\s*:\s*bearer\s+)\S+")),
    ("ASSIGNED",   re.compile(r"(?i)\b(api[_-]?key|secret|password|passwd|token)(\s*[=:]\s*)[\"']?[^\s\"',;]{8,}[\"']?")),
]


def redact(text: str) -> tuple[str, list[str]]:
    """Devuelve (texto redactado, etiquetas de lo que se encontró)."""
    hits: list[str] = []
    out = text
    for label, pat in _PATTERNS:
        if pat.search(out):
            hits.append(label)
            if label in ("BEARER", "ASSIGNED"):
                out = pat.sub(lambda m: "".join(m.groups()) + "«REDACTADO»", out)
            else:
                out = pat.sub("«REDACTADO»", out)
    return out, hits


# ── clasificación para DECIDIR (distinta de redactar) ────────────────────────────────
# Redactar y bloquear no son el mismo problema, y tratarlos igual costó caro.
#
# Al redactar evidencia, pasarse es inocuo: se tapa de más y no se pierde nada. Al decidir si
# una escritura ocurre, pasarse **bloquea el trabajo**, y medido en un diario real
# (2026-08-30 → 2026-09-06) `ASSIGNED` produjo 28 rechazos sobre `auth.rs`, módulos de backend
# y ficheros de configuración — es decir, sobre el código que maneja secretos BIEN:
#
#     let secret = std::env::var("JWT_SECRET")?;      ← rechazado
#     secret: process.env.JWT_SECRET,                 ← rechazado
#     password: ${VAULT_PASSWORD}                     ← rechazado
#
# Los tres son la forma correcta de no tener un secreto en el árbol, y la regla los castigaba.
# Ninguno de los secretos reales que el diario sí atrapó lo detectó `ASSIGNED`: los cazaron
# `GL_TOKEN` y `AWS_AKID`, que reconocen la FORMA del secreto y no el nombre de la variable.
#
# De ahí la separación: hay etiquetas que son PRUEBA —la cadena tiene la forma de una
# credencial emitida— y una que es INDICIO —algo llamado «secret» recibe un valor—. La prueba
# rechaza. El indicio lo decide una persona, que es lo que se hace con una ambigüedad.

#: Prueba: la cadena TIENE forma de credencial. Un falso positivo aquí es casi imposible.
CIERTAS = frozenset({"AWS_AKID", "GH_TOKEN", "GL_TOKEN", "SK_TOKEN", "SLACK", "JWT",
                     "PRIVKEY", "BEARER"})

#: Indicio: un nombre sospechoso recibe un valor. El valor se captura aparte para poder mirarlo.
_ASIGNADO = re.compile(
    r"""(?ix)
    \b(api[_-]?key|secret|passwords?|passwd|token)s?
    \s*[=:]\s*
    (?P<v> "[^"\n]{6,}" | '[^'\n]{6,}' | [^\s"',;]{6,} )
    """)

#: Formas que NUNCA son un secreto, lleven comillas o no: remiten a otro sitio, o son un hueco.
_REMISION = re.compile(
    r"""(?ix)
      ^\$                                  # $VAR
    | ^\$\{                                # ${VAR}
    | ^%[A-Z_]+%$                          # %VAR%
    | env                                  # process.env.X · os.environ[…] · std::env::var(…)
    | ^<[^>]*>$ | ^\{\{ | ^\[\[            # <marcador> · {{plantilla}} · [[plantilla]]
    | \(                                   # cualquier llamada a función
    | ^(?:changeme|change_me|redacted|placeholder|example|dummy|sample|none|null|nil|
         true|false|undefined|todo|fixme|xxx+|\*{3,}|\.{3,}|-{3,})
    """)

#: Formas que sólo son inocentes SIN comillas y SIN dígitos. Dos condiciones, dos razones:
#:
#:   comillas   un valor entrecomillado es un literal por definición. `api_key = "a1b2c3d4e5"`
#:              no remite a nada: ES la cadena.
#:   dígitos    un nombre que una persona escribe no suele llevarlos; una cadena generada casi
#:              siempre sí. Sin esta condición, `password=supersecreto123` se leía como «una
#:              variable llamada supersecreto123» y pasaba entera — lo detectó
#:              `test_bloquea_secretos_en_el_contenido`, que existía justo para eso.
_NOMBRE = re.compile(
    r"""(?x)
      ^[A-Za-z_][A-Za-z_]*$                # un identificador a secas: es una variable
    | ^[a-z]+(?:[-_.][a-z]+)+$             # kebab/snake/punteado en minúsculas: un nombre
    | ^(?:[A-Z][a-z]*){2,}$                # PascalCase: un tipo o una clase
    | ^[A-Z][A-Z_]*$                       # CONSTANTE_EN_MAYUSCULAS: una referencia
    """)


def _es_referencia(valor: str) -> bool:
    """¿Ese valor NOMBRA un secreto en vez de SERLO?"""
    bruto = valor.strip()
    entrecomillado = len(bruto) > 1 and bruto[0] in "\"'" and bruto[-1] == bruto[0]
    v = bruto.strip("\"'").strip()
    if not v:
        return True
    if _REMISION.search(v):
        return True
    return not entrecomillado and bool(_NOMBRE.search(v))


def classify(text: str) -> tuple[list[str], list[str]]:
    """Devuelve (pruebas, indicios). Es lo que mira la política para decidir.

    `redact()` sigue tapando de más a propósito: lo suyo es la evidencia, y ahí el coste de
    pasarse es cero. Aquí el coste de pasarse es una escritura legítima bloqueada, así que se
    separa lo que se sabe de lo que se sospecha, y sólo lo que se sabe rechaza.
    """
    pruebas = [label for label, pat in _PATTERNS
               if label in CIERTAS and pat.search(text)]
    indicios: list[str] = []
    for m in _ASIGNADO.finditer(text):
        if not _es_referencia(m.group("v")):
            indicios.append(f"{m.group(1).lower()} con valor literal")
            break
    return pruebas, indicios


def excerpt(text: str, limit: int = 600) -> str:
    """Fragmento redactado y acotado, apto para guardar como evidencia."""
    clean, _ = redact(text)
    clean = clean.strip()
    return clean if len(clean) <= limit else clean[:limit] + f"… (+{len(clean)-limit} car.)"
