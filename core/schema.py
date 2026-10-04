# -*- coding: utf-8 -*-
"""Validador de JSON Schema, subconjunto. Sólo biblioteca estándar.

Por qué no `jsonschema`
-----------------------
Porque refuto tiene que poder diagnosticar una máquina donde todavía no se instaló nada.
Un `doctor` que necesita `pip install` para decir qué falta no sirve para lo único que hace
falta que sirva. Ver ADR-0002.

Qué subconjunto soporta, y por qué basta
----------------------------------------
`type`, `properties`, `required`, `additionalProperties`, `items`, `enum`, `pattern`,
`minimum`, `maximum`, `minLength`, `minItems`, `patternProperties`, `$ref` local (`#/$defs/x`),
`oneOf`, `anyOf`, `const`.

No soporta `allOf`, `not`, `if/then/else`, `$ref` remoto ni `format`. Los esquemas de este
repositorio se escriben dentro del subconjunto **a propósito**, y `tests/unit/test_schema.py`
lo comprueba: un esquema que use algo no soportado falla la prueba en vez de validar de menos
en silencio, que sería un verde falso.
"""

from __future__ import annotations

import functools
import json
import re
from pathlib import Path

SCHEMA_DIR = Path(__file__).resolve().parents[1] / "schemas"

_UNSUPPORTED = ("allOf", "not", "if", "then", "else", "$dynamicRef", "unevaluatedProperties")

_TYPES = {
    "object": dict, "array": list, "string": str, "boolean": bool,
    "number": (int, float), "integer": int, "null": type(None),
}


class UnsupportedSchema(Exception):
    """El esquema usa una palabra clave que este validador no implementa.

    Se lanza en vez de ignorarla: validar de menos sin avisar es peor que no validar.
    """


@functools.lru_cache(maxsize=32)
def load_schema(name: str) -> dict:
    return json.loads((SCHEMA_DIR / name).read_text(encoding="utf-8"))


def assert_supported(schema: dict, where: str = "#") -> None:
    """Recorre el esquema y falla si usa algo fuera del subconjunto."""
    if not isinstance(schema, dict):
        return
    for key in _UNSUPPORTED:
        if key in schema:
            raise UnsupportedSchema(f"{where}: «{key}» no está implementado en core.schema")
    for key in ("properties", "patternProperties", "$defs"):
        for name, sub in (schema.get(key) or {}).items():
            assert_supported(sub, f"{where}.{key}.{name}")
    for key in ("items", "additionalProperties"):
        sub = schema.get(key)
        if isinstance(sub, dict):
            assert_supported(sub, f"{where}.{key}")
    for key in ("oneOf", "anyOf"):
        for i, sub in enumerate(schema.get(key) or []):
            assert_supported(sub, f"{where}.{key}[{i}]")


def validate(instance, schema: dict, *, root: dict | None = None, where: str = "$") -> list:
    """Devuelve la lista de errores. Vacía significa válido.

    Se devuelven TODOS los errores, no el primero: arreglar de uno en uno un manifiesto con
    seis problemas cuesta seis corridas.
    """
    root = root if root is not None else schema
    errors: list = []
    if not isinstance(schema, dict):
        return errors

    if "$ref" in schema:
        target = _resolve_ref(schema["$ref"], root)
        if target is None:
            return [f"{where}: referencia no resoluble {schema['$ref']!r}"]
        return validate(instance, target, root=root, where=where)

    if "const" in schema and instance != schema["const"]:
        errors.append(f"{where}: debe ser exactamente {schema['const']!r}, es {instance!r}")

    if "enum" in schema and instance not in schema["enum"]:
        errors.append(f"{where}: {instance!r} no está entre {schema['enum']}")

    declared = schema.get("type")
    if declared:
        wanted = declared if isinstance(declared, list) else [declared]
        # `bool` es subclase de `int` en Python: sin esta excepción, `true` validaría como
        # `integer` y un manifiesto con `"required": 1` pasaría por booleano.
        ok = any(
            isinstance(instance, _TYPES[t]) and not (t in ("integer", "number") and isinstance(instance, bool))
            for t in wanted if t in _TYPES)
        if not ok:
            errors.append(f"{where}: se esperaba {'|'.join(wanted)}, hay {type(instance).__name__}")
            return errors

    if isinstance(instance, dict):
        errors += _validate_object(instance, schema, root, where)
    elif isinstance(instance, list):
        errors += _validate_array(instance, schema, root, where)
    elif isinstance(instance, str):
        errors += _validate_string(instance, schema, where)
    elif isinstance(instance, (int, float)) and not isinstance(instance, bool):
        errors += _validate_number(instance, schema, where)

    for key in ("oneOf", "anyOf"):
        options = schema.get(key)
        if not options:
            continue
        matches = [i for i, sub in enumerate(options)
                   if not validate(instance, sub, root=root, where=where)]
        if key == "oneOf" and len(matches) != 1:
            errors.append(f"{where}: debe cumplir exactamente una de {len(options)} variantes, "
                          f"cumple {len(matches)}")
        if key == "anyOf" and not matches:
            errors.append(f"{where}: no cumple ninguna de las {len(options)} variantes")
    return errors


def _validate_object(instance: dict, schema: dict, root: dict, where: str) -> list:
    errors = []
    props = schema.get("properties") or {}
    pattern_props = schema.get("patternProperties") or {}
    for name in schema.get("required") or []:
        if name not in instance:
            errors.append(f"{where}: falta la propiedad obligatoria «{name}»")
    for name, value in instance.items():
        if name in props:
            errors += validate(value, props[name], root=root, where=f"{where}.{name}")
            continue
        matched = False
        for pattern, sub in pattern_props.items():
            if re.search(pattern, name):
                errors += validate(value, sub, root=root, where=f"{where}.{name}")
                matched = True
                break
        if matched:
            continue
        extra = schema.get("additionalProperties", True)
        if extra is False and not name.startswith("_"):
            # Las claves que empiezan por `_` son notas para quien lee el archivo. Se permiten
            # siempre: documentar el propio artefacto no debe costar un error de validación.
            errors.append(f"{where}: propiedad no permitida «{name}»")
        elif isinstance(extra, dict):
            errors += validate(value, extra, root=root, where=f"{where}.{name}")
    return errors


def _validate_array(instance: list, schema: dict, root: dict, where: str) -> list:
    errors = []
    if "minItems" in schema and len(instance) < schema["minItems"]:
        errors.append(f"{where}: necesita al menos {schema['minItems']} elementos, hay {len(instance)}")
    item_schema = schema.get("items")
    if isinstance(item_schema, dict):
        for i, item in enumerate(instance):
            errors += validate(item, item_schema, root=root, where=f"{where}[{i}]")
    return errors


def _validate_string(instance: str, schema: dict, where: str) -> list:
    errors = []
    if "minLength" in schema and len(instance) < schema["minLength"]:
        errors.append(f"{where}: cadena más corta de {schema['minLength']}")
    pattern = schema.get("pattern")
    if pattern and not re.search(pattern, instance):
        errors.append(f"{where}: {instance!r} no cumple el patrón /{pattern}/")
    return errors


def _validate_number(instance, schema: dict, where: str) -> list:
    errors = []
    if "minimum" in schema and instance < schema["minimum"]:
        errors.append(f"{where}: {instance} < mínimo {schema['minimum']}")
    if "maximum" in schema and instance > schema["maximum"]:
        errors.append(f"{where}: {instance} > máximo {schema['maximum']}")
    return errors


def _resolve_ref(ref: str, root: dict):
    if not ref.startswith("#/"):
        return None
    node = root
    for part in ref[2:].split("/"):
        if not isinstance(node, dict) or part not in node:
            return None
        node = node[part]
    return node
