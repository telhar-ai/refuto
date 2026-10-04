# -*- coding: utf-8 -*-
"""Un intérprete no es un lector, y `Ê` no puede decir que lo sea.

El defecto que estas pruebas fijan, medido el 2026-09-25
--------------------------------------------------------
`core/effects.py` consultaba `_ESCRITORES` antes que `_OPACOS`, y `perl` estaba en las dos.
Con clase `en_sitio` y sin su bandera, la rama `else` clasificaba la orden como LECTURA:

    perl -e 'open(F,">","gates/base.py")'      →  escrituras=[]  opaco=False
    awk 'BEGIN{print "x" > "gates/base.py"}'   →  escrituras=[]  opaco=False
    sed 's/a/b/w gates/base.py' README.md      →  escrituras=[]  opaco=False

`Ê` afirmaba «sé que no escribe» de tres lenguajes Turing-completos. El encabezado de
`core/effects.py` promete lo contrario —«lo que `Ê` afirma es sólido»— y toda la garantía del
módulo descansa en esa promesa: una sub-aproximación que afirma de más no es una
sub-aproximación, es un error.

Y la consecuencia no se quedaba en el modelo. `core/grants.py` descarta una concesión
`read-only` cuando la orden es opaca, así que el defecto **invertía su criterio**: la concesión
rechazaba las lecturas de diagnóstico que existe para permitir y admitía la escritura
arbitraria como root.
"""

from __future__ import annotations

import os
import platform
import unittest
from pathlib import Path

from core.effects import _ESCRITORES, _LECTORES, _OPACOS, efectos
from core.policy import ALLOW, DENY, Policy, decide_command

RAIZ = Path(__file__).resolve().parents[2]
ROL = "site-reliability-engineer"

#: Órdenes que ESCRIBEN sin que ningún argumento lo declare. Cada una se midió permitida por
#: una concesión `read-only` antes del arreglo.
ESCRIBEN_SIN_DECLARARLO = (
    ("perl", """perl -e 'open(F,">","gates/base.py"); print F "x"'"""),
    ("awk", """awk 'BEGIN{print "x" > "gates/base.py"}'"""),
    ("sed", """sed 's/a/b/w gates/base.py' README.md"""),
)


class TestUnInterpreteNuncaSaleComoLectura(unittest.TestCase):
    def test_sin_su_bandera_el_efecto_no_se_deriva(self):
        """La propiedad, dicha como propiedad: sin `-i` no se derivó nada, luego `opaco`."""
        for programa, orden in ESCRIBEN_SIN_DECLARARLO:
            with self.subTest(programa=programa):
                ef = efectos(orden)
                self.assertTrue(
                    ef.opaco,
                    f"«{programa}» sale como lectura demostrada: `Ê` afirma «sé que no escribe» "
                    f"de un intérprete Turing-completo, y entonces `Ê ⊆ Effects` es falso")
                self.assertTrue(ef.motivo_opaco, "una opacidad sin motivo no se puede auditar")

    def test_con_su_bandera_la_escritura_se_sigue_derivando(self):
        """El arreglo no puede comprarse perdiendo lo que sí se demostraba."""
        ef = efectos("sed -i '' s/a/b/ gates/base.py")
        self.assertIn("gates/base.py", ef.escrituras)

    def test_las_herramientas_de_formato_siguen_siendo_lectura(self):
        """`ruff` y `gofmt` formatean lo que se les nombra: no ejecutan programa del usuario.

        Si el arreglo hubiera marcado opaco a toda la clase `en_sitio`, `ruff check .` pasaría
        a ser una orden de efecto desconocido — y un detector que marca lo normal enseña a
        ignorarlo, que es como mueren los controles de este repositorio.
        """
        for orden in ("ruff check .", "gofmt -l ."):
            with self.subTest(orden=orden):
                self.assertFalse(efectos(orden).opaco)


class TestNingunProgramaEnDosTablas(unittest.TestCase):
    """La causa raíz, fijada como invariante y no como caso.

    Las tres tablas se consultan POR ORDEN. Un programa duplicado no es redundante: decide en
    silencio cuál clasificación gana, y la que ganaba era la que afirmaba de más.
    """

    def test_las_tres_tablas_son_disjuntas(self):
        for a, b, na, nb in ((_ESCRITORES, _LECTORES, "_ESCRITORES", "_LECTORES"),
                             (_ESCRITORES, _OPACOS, "_ESCRITORES", "_OPACOS"),
                             (_LECTORES, _OPACOS, "_LECTORES", "_OPACOS")):
            with self.subTest(par=f"{na}∩{nb}"):
                self.assertEqual(set(), set(a) & set(b),
                                 f"{na} y {nb} comparten programas: gana el primero que se "
                                 f"consulte, y eso no lo decidió nadie")


class TestLaConcesionReadOnlyNoSeDejaEnganar(unittest.TestCase):
    """El criterio que el defecto invertía, medido de los dos lados."""

    def setUp(self):
        self._previo = os.environ.get("HARNESS_ROLE")
        os.environ["HARNESS_ROLE"] = ROL
        self.policy = Policy.default()
        self.policy.privilege_grants = ({
            "id": "diagnostico-de-lectura", "roles": [ROL], "hosts": [platform.node()],
            "commands": ["sudo *"], "effects": "read-only",
            "human_approval": "once-per-grant", "expires": "2099-01-01",
            "evidence": "SHOME-120"},)

    def tearDown(self):
        if self._previo is None:
            os.environ.pop("HARNESS_ROLE", None)
        else:
            os.environ["HARNESS_ROLE"] = self._previo

    def test_un_interprete_no_se_cuela_por_una_concesion_de_lectura(self):
        for programa, orden in ESCRIBEN_SIN_DECLARARLO:
            with self.subTest(programa=programa):
                d = decide_command(self.policy, f"sudo {orden}", RAIZ)
                self.assertEqual(
                    DENY, d.outcome,
                    f"una concesión `read-only` autorizó «sudo {programa}», que escribe: "
                    f"«no poder demostrar que no escribe no es haber demostrado que no "
                    f"escribe», y aquí ni siquiera se sabía que no se había demostrado")

    def test_y_la_lectura_que_la_concesion_existe_para_permitir_sigue_pasando(self):
        """El otro lado: si todo cae a `deny`, la concesión es adorno y se retira en un mes."""
        d = decide_command(self.policy, "sudo grep -a marca /var/log/api.log", RAIZ)
        self.assertEqual(ALLOW, d.outcome)


if __name__ == "__main__":
    unittest.main()
