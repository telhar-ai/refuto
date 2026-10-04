# -*- coding: utf-8 -*-
"""La huella del juez tiene que cubrir lo que decide, no una extensión de fichero.

El defecto que estas pruebas fijan, medido el 2026-09-25
--------------------------------------------------------
`core/trust.py` declara que la huella son «los ficheros cuyo contenido DETERMINA un veredicto»
y recorría sólo `rglob("*.py")` bajo `core/`, `gates/` y `adapters/`:

    ficheros en la huella : 73
    json en la huella     : []

`roles/registry.json` (17 KB) alimenta `core.capabilities.capacidades_de()` → `_no_shell`,
`_no_secret_access`, `no_modify_verifier`, y esas restricciones **producen `DENY` en el
guardián**. Quien lo editara cambiaba las decisiones del juez sin que `deriva_del_motor()` lo
notara.

La forma del defecto es lo que hay que impedir, no el caso: la huella se quedó atrás en el mismo
commit que volvió relevante al registro (`da39715`, `core/capabilities.py`). Una atestación que
enumera extensiones envejece en silencio cada vez que el camino de decisión gana un fichero que
no es código.
"""

from __future__ import annotations

import json
import shutil
import tempfile
import unittest
from pathlib import Path

from core.trust import (RAIZ_MOTOR, deriva_del_motor, digest_motor, inventario_motor)

#: Ficheros de datos que HOY deciden un veredicto. Cada uno con quién los lee, para que añadir
#: uno a la lista obligue a nombrar el consumidor en vez de apuntarlo por si acaso.
DATOS_QUE_DECIDEN = {
    "roles/registry.json": "core.capabilities.capacidades_de → DENY del guardián por rol",
    "schemas/policy.schema.json": "valida la política que el guardián aplica",
    "schemas/manifest.schema.json": "G-MANIFEST valida contra él",
    "schemas/roles.schema.json": "G-ROLES valida contra él",
    "schemas/envelope.schema.json": "el contrato de toda respuesta de refuto",
}


class TestLaHuellaCubreLoQueDecide(unittest.TestCase):
    def test_los_ficheros_de_datos_estan_en_el_inventario(self):
        inv = inventario_motor()
        for ruta, quien in DATOS_QUE_DECIDEN.items():
            with self.subTest(ruta=ruta):
                if not (RAIZ_MOTOR / ruta).is_file():
                    self.skipTest(f"{ruta} no existe en este árbol")
                # `assertTrue` y no `assertIn`: el inventario son ~78 entradas con su sha, y
                # volcarlo entero en el fallo esconde la frase que dice qué pasa.
                self.assertTrue(
                    ruta in inv,
                    f"«{ruta}» decide ({quien}) y no está atestado: editarlo cambia veredictos "
                    f"sin que la atestación lo note. La huella cubre {len(inv)} ficheros y "
                    f"{sum(1 for k in inv if k.endswith('.json'))} de datos")

    def test_editar_el_registro_de_roles_mueve_la_huella(self):
        """La propiedad, medida de verdad: se copia el motor y se toca el registro.

        Sobre una copia y no sobre el árbol: una prueba que modifique `roles/registry.json`
        real deja el repositorio sucio si falla a mitad, y aquí lo que importa es la relación
        entre el contenido y el digest, no dónde vive.
        """
        with tempfile.TemporaryDirectory() as tmp:
            copia = Path(tmp) / "motor"
            shutil.copytree(RAIZ_MOTOR, copia,
                            ignore=shutil.ignore_patterns(
                                ".git", "__pycache__", ".harness", "evidence", ".worktrees"))
            registro = copia / "roles" / "registry.json"
            if not registro.is_file():
                self.skipTest("este árbol no trae roles/registry.json")

            antes = digest_motor(copia)
            doc = json.loads(registro.read_text(encoding="utf-8"))
            doc["_una_marca_que_no_estaba"] = "editado por la prueba"
            registro.write_text(json.dumps(doc, ensure_ascii=False), encoding="utf-8")

            self.assertNotEqual(antes, digest_motor(copia),
                                "editar el registro de roles no movió la huella del motor: "
                                "`I6'` no cubre un fichero que decide DENY")
            deriva = deriva_del_motor(inventario_motor(copia), copia)
            self.assertNotIn("roles/registry.json", deriva["modificados"],
                             "control: comparar un inventario contra sí mismo no puede dar "
                             "deriva; si da, la prueba de arriba no mide lo que dice")


class TestLaHuellaNoSeEnsanchaPorCualquierCosa(unittest.TestCase):
    """El otro lado. Una alarma que suena por todo se ignora, y entonces no suena cuando importa.

    `core/trust.py` lo argumenta: «un cambio en `README.md` no puede alterar una decisión».
    """

    def test_la_documentacion_no_mueve_la_huella(self):
        with tempfile.TemporaryDirectory() as tmp:
            copia = Path(tmp) / "motor"
            shutil.copytree(RAIZ_MOTOR, copia,
                            ignore=shutil.ignore_patterns(
                                ".git", "__pycache__", ".harness", "evidence", ".worktrees"))
            antes = digest_motor(copia)
            (copia / "README.md").write_text("otra cosa\n", encoding="utf-8")
            (copia / "docs").mkdir(exist_ok=True)
            (copia / "docs" / "nuevo.md").write_text("nuevo\n", encoding="utf-8")
            self.assertEqual(antes, digest_motor(copia),
                             "la documentación mueve la atestación: la alarma sonaría por "
                             "motivos que no son de gobierno")

    def test_la_huella_es_independiente_del_directorio(self):
        """Dos máquinas con el mismo código en rutas distintas tienen que coincidir."""
        with tempfile.TemporaryDirectory() as tmp:
            a, b = Path(tmp) / "aqui", Path(tmp) / "alla" / "mas" / "hondo"
            for destino in (a, b):
                destino.parent.mkdir(parents=True, exist_ok=True)
                shutil.copytree(RAIZ_MOTOR, destino,
                                ignore=shutil.ignore_patterns(
                                    ".git", "__pycache__", ".harness", "evidence", ".worktrees"))
            self.assertEqual(digest_motor(a), digest_motor(b))


if __name__ == "__main__":
    unittest.main()
