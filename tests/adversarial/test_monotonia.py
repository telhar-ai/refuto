# -*- coding: utf-8 -*-
"""Ataques a la monotonicidad de `refuto → cliente → proyecto`.

La invariante bajo ataque
-------------------------
    restricciones(hijo)  ⊇  restricciones(padre)

Un hijo puede endurecer y puede añadir. Si puede aflojar, la capa de cliente deja de ser una
base y se convierte en el sitio donde se relajan los controles — y en silencio, porque un
`merge` de diccionarios no tiene nada que reportar.

Estas pruebas no comprueban que el refinamiento funcione: comprueban que **no se puede usar
para lo que no es**. Cada una intenta un camino distinto hacia un `PASS` indebido, y exige
que el mecanismo lo detecte. Un ataque que sobrevive no es un detalle: es la invariante rota.

Diez ataques, del catálogo de §12. Cada uno nombra qué haría en la práctica si funcionara.
"""

from __future__ import annotations

import copy
import unittest

from core.model import NOT_EXECUTABLE, PASS
from core.refinement import identidad_de, refinar, resolver
from tests.fixtures import Workspace

#: La política del cliente. Deliberadamente pequeña: lo que se prueba es la relación entre
#: las dos, no la riqueza de ninguna.
PADRE = {
    "schema": "harness.policy/v1",
    "name": "cliente-ejemplo",
    "version": "1",
    "protected_paths": ["gates/**", "evidencia/**"],
    "command_deny": ["rm -rf:*", "sudo:*"],
    "command_ask": ["git push:*"],
    "secret_read_deny": [".ssh/id_*"],
    "writable_paths": [".harness/memory/**", "notas/**"],
    "external_write_allow": ["/tmp/agente-*/**"],
    "block_secret_content": True,
}

#: Un hijo legítimo: añade protección y cierra un agujero. No toca nada más.
HIJO_OK = {
    "schema": "harness.policy/v1",
    "name": "proyecto-ejemplo",
    "version": "1",
    "protected_paths": ["gates/**", "evidencia/**", "contratos/**"],
    "writable_paths": [".harness/memory/**"],
}


def _hijo(**cambios) -> dict:
    d = copy.deepcopy(HIJO_OK)
    d.update(cambios)
    return d


class TestElRefinamientoLegitimoFunciona(unittest.TestCase):
    """El control positivo. Sin él, «todo da NOT_EXECUTABLE» pasaría por seguridad."""

    def test_un_hijo_que_endurece_se_acepta(self):
        r = refinar(PADRE, HIJO_OK)
        self.assertEqual(PASS, r.status, r.motivo)
        self.assertIn("contratos/**", r.politica.protected_paths,
                      "lo que el hijo añade no llegó a la política efectiva")
        self.assertIn("gates/**", r.politica.protected_paths,
                      "lo que el padre protegía se perdió")

    def test_lo_que_el_hijo_no_menciona_se_hereda(self):
        r = refinar(PADRE, HIJO_OK)
        self.assertIn("sudo:*", r.politica.command_deny,
                      "una restricción del padre desapareció por no repetirla")
        self.assertTrue(r.politica.block_secret_content)

    def test_el_hijo_puede_cerrar_un_agujero_del_padre(self):
        r = refinar(PADRE, HIJO_OK)
        self.assertEqual([".harness/memory/**"], list(r.politica.writable_paths),
                         "encoger `writable_paths` es endurecer y debe permitirse")


class TestAtaquesALaMonotonia(unittest.TestCase):

    def _rechazado(self, hijo, pista, ataque):
        r = refinar(PADRE, hijo)
        self.assertEqual(NOT_EXECUTABLE, r.status,
                         f"{ataque}: el ataque SOBREVIVIÓ — {r.motivo}")
        self.assertTrue(r.violaciones or r.motivo, f"{ataque}: rechazado sin decir por qué")
        texto = " ".join(r.violaciones) + r.motivo
        self.assertIn(pista, texto, f"{ataque}: el motivo no nombra el campo atacado")
        self.assertIsNone(r.politica,
                          f"{ataque}: devolvió una política pese a rechazar. Una política a "
                          f"medias es indistinguible de una política.")
        return r

    def test_M1_retirar_una_ruta_protegida_heredada_es_INEXPRESABLE(self):
        """En la práctica: el proyecto vuelve a poder editar lo que lo evalúa.

        No se rechaza: **no se puede escribir**. El efectivo de un campo `ACUMULA` es la
        unión, así que un hijo que lista menos no retira nada — simplemente no añade. Es más
        fuerte que detectarlo: no se puede violar lo que no se puede decir.

        La versión anterior de este ataque exigía el rechazo, y ese diseño obligaba al hijo a
        REPETIR cada entrada del padre so pena de «retirarla» — la repetición exacta que la
        herencia existe para eliminar. Un cliente con veinte rutas forzaba veinte copias por
        proyecto, y a la tercera copia alguien recorta.
        """
        r = refinar(PADRE, _hijo(protected_paths=["contratos/**"]))
        self.assertEqual(PASS, r.status, "un hijo que no repite al padre debe poder refinar")
        for heredada in PADRE["protected_paths"]:
            self.assertIn(heredada, r.politica.protected_paths,
                          f"M1 SOBREVIVIÓ: «{heredada}» del padre desapareció del efectivo")
        self.assertIn("contratos/**", r.politica.protected_paths)

    def test_M2_debilitar_una_orden_denegada_pasandola_a_consulta(self):
        """En la práctica: la orden deja de estar prohibida y pasa a preguntarse — y a quien
        se le pregunta en una sesión desatendida es a nadie.

        Tampoco es expresable: `command_deny` acumula, así que la del padre sigue ahí y
        `decide_command` la encuentra antes de llegar a las de consulta.
        """
        from core.policy import decide_command
        r = refinar(PADRE, _hijo(command_deny=[], command_ask=["git push:*", "sudo:*"]))
        self.assertEqual(PASS, r.status)
        self.assertIn("sudo:*", r.politica.command_deny,
                      "M2 SOBREVIVIÓ: la orden denegada por el padre desapareció")
        self.assertEqual("deny", decide_command(r.politica, "sudo algo").outcome,
                         "M2 SOBREVIVIÓ: la orden del padre ya no se deniega")

    def test_M3_ensanchar_writable_paths(self):
        """En la práctica: el agujero que el cliente cerró se reabre en un proyecto."""
        self._rechazado(_hijo(writable_paths=[".harness/memory/**", "gates/**"]),
                        "writable_paths", "M3 ensanchar writable_paths")

    def test_M4_ensanchar_lo_escribible_fuera_del_espacio(self):
        """En la práctica: el agente escribe en un sitio del disco que el cliente no autorizó."""
        self._rechazado(_hijo(external_write_allow=["/tmp/agente-*/**", "/etc/**"]),
                        "external_write_allow", "M4 ensanchar capacidades")

    def test_M5_degradar_la_deteccion_de_secretos(self):
        """En la práctica: deja de comprobarse el contenido antes de escribir."""
        self._rechazado(_hijo(block_secret_content=False),
                        "block_secret_content", "M5 degradar evidencia exigida")

    def test_M6_retirar_una_ruta_de_credencial_es_INEXPRESABLE(self):
        """En la práctica: la clave privada vuelve a ser legible.

        `secret_read_deny` acumula, así que vaciarlo en el hijo no retira nada del padre.
        Como M1 y M2: la violación no se detecta porque no se puede escribir.
        """
        r = refinar(PADRE, _hijo(secret_read_deny=[]))
        self.assertEqual(PASS, r.status)
        for ruta in PADRE["secret_read_deny"]:
            self.assertIn(ruta, r.politica.secret_read_deny,
                          f"M6 SOBREVIVIÓ: «{ruta}» del padre desapareció del efectivo")

    def test_M7_padre_ausente_no_cae_a_valores_por_omision(self):
        """El más peligroso: el silencio produce un espacio que PARECE gobernado."""
        with Workspace("mono-sinpadre") as ws:
            r = resolver(ws.root, _hijo(extends="cliente-que-no-existe"),
                         buscar=lambda ref: None)
            self.assertEqual(NOT_EXECUTABLE, r.status, "un padre ausente produjo política")
            self.assertIsNone(r.politica)
            self.assertIn("parece gobernado", r.motivo,
                          "no se declara la consecuencia de heredar sin padre")

    def test_M8_el_padre_cambio_bajo_los_pies_del_hijo(self):
        """En la práctica: el cliente afloja y todos sus proyectos heredan el aflojamiento sin
        que ninguno cambie. El ancla `extends_digest` lo convierte en detectable."""
        with Workspace("mono-digest") as ws:
            hijo = _hijo(extends="cliente-ejemplo",
                         extends_digest=identidad_de(PADRE).digest)
            otro = copy.deepcopy(PADRE)
            otro["command_deny"] = ["rm -rf:*"]          # el cliente retira `sudo`
            r = resolver(ws.root, hijo, buscar=lambda ref: otro)
            self.assertEqual(NOT_EXECUTABLE, r.status,
                             "el padre cambió y el hijo no se enteró")
            self.assertIn("cambió", r.motivo)

    def test_M9_el_hijo_declara_un_campo_sin_regla_de_monotonia(self):
        """Un campo de política sin regla sería un agujero por omisión: se hereda como el
        autor suponga, que es como no decidirlo."""
        import core.refinement as R
        # Todo campo de `Policy` tiene regla hoy —lo garantiza una comprobación al importar
        # el módulo—, así que el ataque se monta quitando una y comprobando que el hijo que
        # la declara deja de aceptarse. Es el escenario de «alguien añade un campo y olvida
        # decidir cómo se hereda».
        guardadas = dict(R.REGLAS)
        try:
            del R.REGLAS["command_deny"]
            r = refinar(PADRE, _hijo(command_deny=["rm -rf:*", "sudo:*"]))
        finally:
            R.REGLAS.clear()
            R.REGLAS.update(guardadas)
        self.assertEqual(NOT_EXECUTABLE, r.status,
                         "se aceptó un campo de política sin regla de monotonía declarada")
        self.assertIn("sin regla de monotonía", r.motivo)
        # Y la red que lo impide de raíz: el módulo no se puede importar con un campo suelto.
        self.assertEqual([], sorted(set(R.Policy.__dataclass_fields__) - set(R.REGLAS)),
                         "hay campos de Policy sin regla y el módulo se importó igual")

    def test_M10_un_documento_ajeno_no_pasa_por_politica(self):
        """Ya ocurrió: otro programa reclamaba `.harness/policy.json` y `Policy.from_dict`
        producía los valores de fábrica. Aquí se comprueba por el lado del padre."""
        ajeno = {"schema": "otro:contrato/v9", "client_identifiers": [], "pii_patterns": []}
        r = refinar(ajeno, HIJO_OK)
        self.assertEqual(NOT_EXECUTABLE, r.status,
                         "un documento de otro programa se interpretó como política padre")
        self.assertIn("no se pudo interpretar", r.motivo)


class TestLaIdentidadEfectivaDetectaElCambio(unittest.TestCase):

    def test_mismo_padre_y_mismo_hijo_dan_la_misma_identidad(self):
        a = refinar(PADRE, HIJO_OK).identidad
        b = refinar(copy.deepcopy(PADRE), copy.deepcopy(HIJO_OK)).identidad
        self.assertEqual(a.efectivo, b.efectivo, "la identidad no es determinista")

    def test_un_padre_distinto_cambia_la_identidad_del_hijo(self):
        """El punto entero de encadenar: el proyecto no se tocó y su significado sí cambió."""
        # Se cambia un campo que el hijo NO declara: así el refinamiento sigue siendo
        # legítimo y lo único que cambia es el padre. Endurecer `protected_paths` del padre
        # sería otra cosa —el hijo, que los repite, pasaría a retirar uno— y eso ya lo
        # cubre M1.
        otro = copy.deepcopy(PADRE)
        otro["command_deny"] = otro["command_deny"] + ["dd:*"]
        a = refinar(PADRE, HIJO_OK).identidad
        b = refinar(otro, HIJO_OK).identidad
        self.assertIsNotNone(b, "el refinamiento con el padre endurecido debería aceptarse")
        self.assertEqual(a.digest, b.digest, "el hijo no cambió: su digest propio tampoco")
        self.assertNotEqual(a.efectivo, b.efectivo,
                            "el padre cambió y la identidad efectiva no se enteró")

    def test_un_comentario_no_cambia_la_identidad(self):
        """Si una nota contara, editar un comentario invalidaría la identidad de todos los
        proyectos que heredan — y nadie volvería a escribir notas."""
        con_nota = copy.deepcopy(PADRE)
        con_nota["_que_es"] = "una nota que no es política"
        self.assertEqual(identidad_de(PADRE).digest, identidad_de(con_nota).digest)


if __name__ == "__main__":
    unittest.main()
