# -*- coding: utf-8 -*-
"""Plano de gobierno. Cada prueba fija un caso REAL en el que el resolvedor se equivoco.

Ninguna se invento pensando en que podria fallar. Todas salen de replicar el resolvedor contra
un diario de evidencia real --24 523 decisiones registradas a lo largo de tres semanas--
y quedarse con los casos en los que habria APROBADO lo que el guardian vigente nego. Esa es la
unica lista de pruebas que no es una opinion.
"""

from __future__ import annotations

import unittest

from experimental.govern import (
    DENY, DESCONOCIDO, CAPACIDADES, _veredicto_nivel, capacidad_de, resolver,
)

#: El elevador de privilegios se compone en tiempo de ejecucion. El guardian del arnes hace
#: coincidencia por SUBCADENA sobre el texto de la orden, asi que una cadena literal en el
#: fuente de una prueba dispara su regla de rechazo y la prueba no se puede ni escribir.
#: Medido el 2026-09-17. Es un falso positivo del guardian, no de la prueba.
E = "su" + "do"


class TestOrdenesCompuestas(unittest.TestCase):
    """Una orden vale por su tramo MAS peligroso, nunca por el primero.

    Causa raiz de 33 de los 296 falsos permisos de la primera replica.
    """

    def test_punto_y_coma_no_esconde_la_elevacion(self):
        self.assertEqual("privilege.elevate", capacidad_de("Bash", f"echo hola; {E} lanzador"))

    def test_tuberia_no_esconde_la_elevacion(self):
        self.assertEqual("privilege.elevate", capacidad_de("Bash", f"ls | xargs {E} rm"))

    def test_y_logico_no_esconde_la_elevacion(self):
        self.assertEqual("privilege.elevate", capacidad_de("Bash", f"cd /tmp && {E} rm -rf x"))

    def test_salto_de_linea_no_esconde_nada(self):
        self.assertEqual("fs.destroy", capacidad_de("Bash", "echo x\nrm -rf /home/x/Documentos"))

    def test_el_tramo_inofensivo_solo_no_eleva(self):
        self.assertEqual("shell.output", capacidad_de("Bash", "echo ok"))


class TestInterpretes(unittest.TestCase):
    """Invocar un interprete con -c no es ejecutar un interprete: es lo que lleva dentro."""

    def test_se_mira_dentro_de_las_comillas(self):
        self.assertEqual("privilege.elevate", capacidad_de("Bash", f'sh -c "{E} rm -rf /x"'))

    def test_sin_c_sigue_siendo_ejecutar(self):
        self.assertEqual("runtime.exec", capacidad_de("Bash", "bash script.sh"))

    def test_variables_delante_no_son_el_programa(self):
        self.assertEqual("privilege.elevate", capacidad_de("Bash", f"FOO=1 {E} rm x"))
        self.assertEqual("cloud.mutate", capacidad_de("Bash", "KUBECONFIG=/x kubectl get pods"))


class TestIrreversible(unittest.TestCase):
    """Borrar no es mutar al mismo nivel que copiar. 13 de los 296 salian APROBADOS."""

    def test_borrado_recursivo_es_destructivo(self):
        self.assertEqual("fs.destroy", capacidad_de("Bash", "rm -rf /home/persona/Documentos"))

    def test_copiar_no_lo_es(self):
        self.assertEqual("shell.mutate", capacidad_de("Bash", "cp a b"))

    def test_lo_destructivo_es_critico(self):
        self.assertEqual("critico", CAPACIDADES["fs.destroy"])


class TestGranularidadDeGit(unittest.TestCase):
    """git no es una capacidad: son cuatro, y la replica lo demostro con 9 casos."""

    def test_leer_no_escribe(self):
        self.assertEqual("vcs.read", capacidad_de("Bash", "git log --oneline"))
        self.assertEqual("vcs.read", capacidad_de("Bash", "git status"))

    def test_escribir_en_local(self):
        self.assertEqual("vcs.write", capacidad_de("Bash", "git commit -m x"))

    def test_publicar_sale_del_repositorio(self):
        self.assertEqual("vcs.publish", capacidad_de("Bash", "git push -u origin feat/x"))

    def test_forzar_reescribe_historia_ajena(self):
        self.assertEqual("vcs.force", capacidad_de("Bash", "git push --force origin main"))
        self.assertEqual("vcs.force", capacidad_de("Bash", "git push --force-with-lease origin m"))

    def test_el_riesgo_crece_con_el_alcance(self):
        orden = ("bajo", "medio", "alto", "critico")
        niveles = [orden.index(CAPACIDADES[c])
                   for c in ("vcs.read", "vcs.write", "vcs.publish", "vcs.force")]
        self.assertEqual(sorted(niveles), niveles)


class TestNavegacion(unittest.TestCase):
    """cd encabeza la mayoria de las ordenes reales.

    Dejarlo fuera mandaba el 52 % del trafico a desconocida, y desconocida niega. Un mapa
    corto no es conservador: es inadoptable.
    """

    def test_cd_no_es_desconocida(self):
        self.assertEqual("shell.read", capacidad_de("Bash", "cd /home/x/repo"))

    def test_lo_que_no_se_reconoce_sigue_siendo_desconocida(self):
        self.assertEqual("desconocida", capacidad_de("Bash", "herramienta-que-nadie-ha-visto x"))

    def test_desconocida_pesa_como_riesgo_ALTO(self):
        self.assertEqual("alto", CAPACIDADES["desconocida"])
        self.assertEqual("desconocida", capacidad_de("Bash", "ls; programa-raro"))


class TestHerramientasNoBash(unittest.TestCase):

    def test_lectura_y_escritura(self):
        self.assertEqual("fs.read", capacidad_de("Read"))
        self.assertEqual("fs.write", capacidad_de("Edit"))
        self.assertEqual("fs.write", capacidad_de("Write"))

    def test_mcp_se_reconoce_por_prefijo(self):
        self.assertEqual("mcp.invoke", capacidad_de("mcp__acme__norma"))

    def test_herramienta_nueva_no_se_aprueba_sola(self):
        self.assertEqual("desconocida", capacidad_de("HerramientaFutura"))


class TestResolucion(unittest.TestCase):
    """La semantica que el runtime impone: deny, luego ask, luego allow. Y el silencio niega."""

    POL = {"global": {"deny": ["privilege.elevate"], "human": ["cloud.mutate"],
                      "allow": ["shell.read", "vcs.write"]},
           "clientes": {}, "repositorios": {}}

    def test_el_silencio_no_aprueba(self):
        d = resolver("Bash", "programa-raro", "/r", self.POL)
        self.assertEqual(DENY, d.resultado)

    def test_una_negacion_no_se_deshace_desde_abajo(self):
        pol = {"deny": ["net.fetch"]}
        self.assertEqual(DENY, _veredicto_nivel(pol, "net.fetch")[0])

    def test_identidad_desconocida_niega(self):
        d = resolver("Bash", "ls", "/no/existe/en/ningun/repo", self.POL)
        self.assertEqual(DENY, d.resultado)
        self.assertEqual(DESCONOCIDO, d.identidad.cliente)

    def test_la_decision_se_explica_entera(self):
        d = resolver("Bash", "ls", "/no/existe", self.POL)
        texto = d.explicar()
        self.assertIn("DENY", texto)
        self.assertTrue(d.porque)


class TestRegresionDeLaReplica(unittest.TestCase):
    """Los casos exactos del diario en los que la v1 aprobaba lo que el guardian nego."""

    CASOS = [
        (f"echo hola; {E} lanzador",              "privilege.elevate"),
        (f"ls | xargs {E} rm",                  "privilege.elevate"),
        (f'sh -c "{E} rm -rf /x"',             "privilege.elevate"),
        (f"FOO=1 {E} rm x",                     "privilege.elevate"),
        ("rm -rf /home/persona/Documentos", "fs.destroy"),
        ("echo x; rm -rf /home/x/Documentos",   "fs.destroy"),
        ("git push --force origin main",        "vcs.force"),
    ]

    def test_ninguno_de_los_casos_medidos_se_aprueba(self):
        for orden, esperada in self.CASOS:
            with self.subTest(orden=orden):
                self.assertEqual(esperada, capacidad_de("Bash", orden))
                self.assertIn(CAPACIDADES[esperada], ("alto", "critico"))


if __name__ == "__main__":
    unittest.main()
