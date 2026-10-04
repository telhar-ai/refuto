# -*- coding: utf-8 -*-
"""Inventario del espacio. Cada prueba fija una forma concreta de contar de menos.

Un censo que se equivoca por debajo es peor que no tener censo: el informe de sesión afirma
un número, nadie lo duda, y el trabajo que no aparece deja de existir para el agente.
"""

from __future__ import annotations

import unittest

from core.knowledge import inventariar, leer_registro, medir
from tests.fixtures import Workspace


def repo(ws: Workspace, rel: str) -> None:
    """Un repositorio normal: `.git` es un DIRECTORIO."""
    (ws.root / rel / ".git").mkdir(parents=True, exist_ok=True)


def arbol(ws: Workspace, rel: str) -> None:
    """Un árbol de trabajo: `.git` es un FICHERO que apunta al repositorio de origen."""
    ws.file(f"{rel}/.git", "gitdir: /origen/.git/worktrees/x\n")


class TestInventario(unittest.TestCase):

    def test_arboles_bajo_worktrees_se_cuentan(self):
        """`git worktree add` deja los árboles en `.worktrees/`, que empieza por punto.

        Medido en un espacio real: 19 de 89 repositorios vivían ahí y el informe de
        sesión declaraba 71 componentes y 9 árboles. El recorrido descartaba el directorio
        entero por el punto inicial, mientras la docstring de `inventariar` presumía de
        detectar árboles de trabajo. Detectarlos no sirve si nunca se llega a ellos.
        """
        with Workspace("wt") as ws:
            repo(ws, "ai/motor")
            repo(ws, "core/gateway")
            arbol(ws, ".worktrees/rama-a")
            arbol(ws, ".worktrees/rama-b")
            arbol(ws, "labs/suelto")

            repos, truncado = inventariar(ws.root)
            rutas = {r.ruta for r in repos}

            self.assertIn(".worktrees/rama-a", rutas)
            self.assertIn(".worktrees/rama-b", rutas)
            self.assertEqual(5, len(repos))
            self.assertEqual(3, sum(1 for r in repos if r.worktree))
            self.assertEqual(0, truncado)

    def test_ocultos_de_artefacto_siguen_fuera(self):
        """Abrir `.worktrees` no puede abrir la puerta a todo lo oculto.

        `.venv`, `.cache` y `.gradle` contienen repositorios de dependencias que no son
        componentes del espacio. Contarlos infla el censo, que es el defecto simétrico.
        """
        with Workspace("ocultos") as ws:
            repo(ws, "ai/motor")
            repo(ws, ".venv/lib/paquete")
            repo(ws, ".cache/algo")
            repo(ws, ".gradle/dep")
            repo(ws, "node_modules/paquete")

            repos, _ = inventariar(ws.root)
            rutas = {r.ruta for r in repos}

            self.assertEqual({"ai/motor"}, rutas)

    def test_un_repositorio_no_contiene_otro(self):
        """Al encontrar `.git` se deja de bajar: los submódulos no son componentes del espacio."""
        with Workspace("anidado") as ws:
            repo(ws, "ai/motor")
            repo(ws, "ai/motor/vendor/interno")

            repos, _ = inventariar(ws.root)

            self.assertEqual(["ai/motor"], [r.ruta for r in repos])

    def test_la_profundidad_acota(self):
        with Workspace("hondo") as ws:
            repo(ws, "a/b/c/d/muy-hondo")
            repo(ws, "a/b/somero")

            repos, _ = inventariar(ws.root, profundidad=3)

            self.assertEqual(["a/b/somero"], [r.ruta for r in repos])

    def test_el_tope_trunca_y_lo_dice(self):
        """Truncar en silencio es la misma clase de fallo: el censo miente por debajo."""
        with Workspace("tope") as ws:
            for i in range(6):
                repo(ws, f"c/r{i}")

            repos, truncado = inventariar(ws.root, tope=4)

            self.assertEqual(4, len(repos))
            self.assertEqual(2, truncado)

    def test_medir_cuenta_los_arboles_que_inventariar_ve(self):
        """`medir` alimenta el informe: si discrepa de `inventariar`, el informe miente."""
        with Workspace("medir") as ws:
            repo(ws, "ai/motor")
            arbol(ws, ".worktrees/uno")
            arbol(ws, ".worktrees/dos")

            k = medir(ws.root)

            self.assertEqual(3, len(k.repos))
            self.assertEqual(2, k.worktrees)


class TestRegistro(unittest.TestCase):

    def test_se_lee_de_architecture_review(self):
        with Workspace("reg") as ws:
            ws.file("architecture-review/capability-register.yaml",
                    "schema: x\n"
                    "capabilities:\n"
                    "  - capability: routing\n"
                    "    owner: ai/via\n"
                    "    status: active\n"
                    "    contract: acme:v1:execution-plan\n"
                    "  - capability: evidence\n"
                    "    owner: VACANT\n"
                    "    status: vacant\n")

            caps, origen, aviso = leer_registro(ws.root)

            self.assertEqual("architecture-review/capability-register.yaml", origen)
            self.assertEqual(["routing", "evidence"], [c.nombre for c in caps])
            self.assertEqual("ai/via", caps[0].dueno)
            self.assertEqual("", aviso)

    def test_campos_desconocidos_se_denuncian(self):
        """Un lector que ignora en silencio produce un inventario más corto que la realidad."""
        with Workspace("reg2") as ws:
            ws.file("capability-register.yaml",
                    "capabilities:\n"
                    "  - capability: routing\n"
                    "    owner: ai/via\n"
                    "    produces_contracts: [x]\n")

            _, _, aviso = leer_registro(ws.root)

            self.assertIn("produces_contracts", aviso)

    def test_sin_registro_no_inventa(self):
        with Workspace("reg3") as ws:
            caps, origen, aviso = leer_registro(ws.root)
            self.assertEqual(([], "", ""), (caps, origen, aviso))


if __name__ == "__main__":
    unittest.main()
