# -*- coding: utf-8 -*-
"""Espacios de trabajo falsos, construidos en un directorio temporal.

Todas las pruebas de refuto corren contra un espacio fabricado. Ninguna toca un repositorio
real: una prueba que necesita los repositorios de quien la escribió para pasar no es una
prueba, es una demostración.
"""

from __future__ import annotations

import json
import os
import shutil
import tempfile
from pathlib import Path

from core.digest import sha256_file
from core.lock import LOCK_SCHEMA

# ── credenciales SINTÉTICAS ──────────────────────────────────────────────────────────
#
# Ninguna de estas cadenas es ni ha sido una credencial. Son falsas **por construcción**, y se
# puede comprobar leyéndolas:
#
#     AKIA_SINTETICA   es el ejemplo que AWS publica en su propia documentación, impreso allí
#                      para este uso exacto. Termina en `EXAMPLE`.
#     GHP_SINTETICA    el prefijo de la forma seguido del alfabeto EN ORDEN y de `012345`.
#                      Ningún generador produce eso.
#     SKANT_SINTETICA  el prefijo público de la forma, con relleno declarado.
#     PEM_SINTETICA    una cabecera PEM con tres letras dentro. No es una clave: es su forma.
#
# Existen porque la única manera de probar un detector de secretos es darle algo con FORMA de
# secreto. Se declaran en UN sitio a propósito: así nadie tiene que decidir, leyendo una prueba
# suelta, si acaba de encontrar una fuga o un fixture.
#
# Se arman por concatenación para que ningún escáner —incluido el de este mismo motor,
# `core.digest.classify`— las lea como credenciales emitidas al analizar el repositorio. La
# concatenación es la declaración: lo que se junta en tiempo de ejecución no está en el árbol.
AKIA_SINTETICA = "AKIA" + "IOSFODNN7EXAMPLE"
GHP_SINTETICA = "ghp" + "_abcdefghijklmnopqrstuvwxyz012345"
SKANT_SINTETICA = "sk-ant-" + "api03-" + "x" * 12
PEM_SINTETICA = ("-----BEGIN RSA PRI" + "VATE KEY-----\n"
                 "abc\n"
                 "-----END RSA PRIVATE KEY-----")


class Workspace:
    """Espacio de trabajo desechable. Se usa con `with`.

    Dentro del `with`, `$HOME` apunta a un directorio vacío —hermano de la raíz, nunca dentro
    de ella, para no añadir un árbol que las puertas verían al recorrer el espacio— y al salir
    vuelve a ser el de antes.

    No es una comodidad: es lo que hace cierta la frase de arriba. El código que se prueba lee
    el home real —`core/mcp.py` busca ahí servidores MCP, `core/discovery.py` agentes
    instalados— y sin aislarlo la suite mide el árbol de quien la ejecuta. Falsado el
    2026-09-22 con un `$HOME` en el que `~/.claude/settings.json` es ilegible: **7 de 480
    pruebas** pasan de verde a roja sin tocar una línea del producto. En la máquina donde se
    escribieron pasaban, y por eso nadie lo vio; en la de al lado, no.

    El home es de sólo lectura por convención pero no por permisos: si el código escribe ahí,
    escribe en el temporal y se va con él, que es justo lo que se quiere.
    """

    def __init__(self, name: str = "ws"):
        self.root = Path(tempfile.mkdtemp(prefix=f"harness-{name}-"))
        self.home = Path(tempfile.mkdtemp(prefix=f"harness-{name}-home-"))
        self._home_previo: str | None = None

    def __enter__(self) -> "Workspace":
        self._home_previo = os.environ.get("HOME")
        os.environ["HOME"] = str(self.home)
        return self

    def __exit__(self, *exc) -> None:
        if self._home_previo is None:
            os.environ.pop("HOME", None)
        else:
            os.environ["HOME"] = self._home_previo
        shutil.rmtree(self.home, ignore_errors=True)
        shutil.rmtree(self.root, ignore_errors=True)

    # ── construcción ─────────────────────────────────────────────────────────────────
    def file(self, rel: str, content: str = "") -> Path:
        path = self.root / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        # LF: varias pruebas declaran la huella del texto que escriben aquí. Con CRLF, la
        # huella deja de coincidir y la prueba mide el sistema operativo, no refuto.
        path.write_text(content, encoding="utf-8", newline="\n")
        return path

    def json(self, rel: str, doc) -> Path:
        return self.file(rel, json.dumps(doc, ensure_ascii=False, indent=2) + "\n")

    def manifest(self, **over) -> Path:
        doc = {
            "schema": "harness.manifest/v1",
            "harness": {"version": "0.1.0"},
            "agents": {},
            "gates": ["G-MANIFEST"],
        }
        doc.update(over)
        return self.json(".harness/harness.manifest.json", doc)

    def policy(self, **over) -> Path:
        from core.policy import Policy
        doc = Policy.default().to_dict()
        doc.update(over)
        return self.json(".harness/policy.json", doc)

    def lock_for(self, source: str, commit: str, rels: list, uri: str = "https://example.invalid/x.git",
                 ref: str = "v1.0.0") -> Path:
        files = {rel: sha256_file(self.root / rel) for rel in rels}
        return self.json(".harness/harness.lock.json", {
            "schema": LOCK_SCHEMA,
            "sources": {source: {"uri": uri, "ref": ref, "commit": commit,
                                 "files": files, "resolved_at": "2026-08-27T00:00:00.000+00:00"}},
        })

    def skill(self, directory: str, name: str, description: str = "Una skill de prueba con "
              "descripción suficientemente larga para el contrato.", body: str = "") -> Path:
        text = (f"---\nname: {name}\ndescription: {description}\n---\n\n"
                f"# {name}\n\n{body or 'Cuerpo de la skill con contenido suficiente para que el contrato la acepte como no vacía.'}\n")
        return self.file(f".claude/skills/{directory}/SKILL.md", text)

    def context(self, **kw):
        from core.context import Context
        return Context(workspace=self.root, **kw)
