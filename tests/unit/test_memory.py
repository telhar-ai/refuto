"""El frontmatter de una nota admite escalares de bloque YAML.

Las notas escritas a mano usan `why: >` con el texto sangrado debajo. Un lector que va
línea a línea deja el valor en el indicador —`'>'`— y pierde el texto entero. Medido en
un espacio real: 181 de 192 `why` y 39 de 194 `source` llegaban vacíos al informe de
sesión, que es justo el campo que explica POR QUÉ importa la nota.
"""
import tempfile
import unittest
from pathlib import Path

from core.memory import Memory


class TestEscalaresDeBloque(unittest.TestCase):
    def _nota(self, cuerpo: str):
        tmp = Path(tempfile.mkdtemp())
        p = tmp / ".harness" / "memory" / "project"
        p.mkdir(parents=True)
        (p / "n.md").write_text(cuerpo, encoding="utf-8")
        return Memory(tmp)._read(p / "n.md")

    def test_plegado_se_une_con_espacios(self):
        n = self._nota("---\nlayer: project\nkey: n\nwhy: >\n  primera\n  segunda\n---\n\ncuerpo\n")
        self.assertEqual(n.why, "primera segunda")

    def test_literal_conserva_los_saltos(self):
        n = self._nota("---\nlayer: project\nkey: n\nwhy: |\n  uno\n  dos\n---\n\ncuerpo\n")
        self.assertEqual(n.why, "uno\ndos")

    def test_una_linea_sangrada_con_dos_puntos_no_abre_clave(self):
        """Dentro de un bloque, `Medido: hoy` es texto, no una clave nueva."""
        n = self._nota("---\nlayer: project\nkey: n\nwhy: >\n  algo\n  Medido: hoy\n"
                       "source: directo\n---\n\ncuerpo\n")
        self.assertEqual(n.why, "algo Medido: hoy")
        self.assertEqual(n.source, "directo")

    def test_escalar_normal_sigue_funcionando(self):
        n = self._nota('---\nlayer: project\nkey: n\nwhy: "texto llano"\n---\n\ncuerpo\n')
        self.assertEqual(n.why, "texto llano")

    def test_el_cuerpo_no_se_contamina(self):
        n = self._nota("---\nlayer: project\nkey: n\nwhy: >\n  razón\n---\n\nel cuerpo\n")
        self.assertEqual(n.body, "el cuerpo")


if __name__ == "__main__":
    unittest.main()
