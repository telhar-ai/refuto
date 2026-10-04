# -*- coding: utf-8 -*-
"""La credencial que vive en una variable de entorno, no en un fichero.

La asimetría que esto cierra, medida el 2026-09-25
--------------------------------------------------
En el entorno de una sesión gobernada real: **70 variables y 7 con forma de credencial**, todas
legibles con un `printenv`. No se enumeran cuáles, y eso es parte del arreglo: una lista de
servicios en un repositorio público dice de qué servicios hay credenciales, y para alguien
hostil ese mapa es casi tan útil como los valores. Mientras tanto `.env` estaba protegido contra escritura y su
lectura pasó a `ask` en la Capa 1.

Es decir: el fichero vigilado y el mismo secreto en `$MI_SERVICIO_API_KEY`, libre. `printenv` era un
`cat` de todos los secretos de la máquina.

Las dos vías, y por qué hay que cerrar las dos
----------------------------------------------
1. **Nombrada**: `printenv MI_SERVICIO_API_KEY`, `echo $MI_SERVICIO_TOKEN`. Se atrapa comparando el NOMBRE
   contra `secret_env_deny`. Nunca el valor: mirar el valor de cada variable para decidir si es
   un secreto obligaría a leer todos los secretos para protegerlos.
2. **A granel**: `env`, `printenv`, `set`. No declaran ninguna lectura —medido,
   `efectos("env").lecturas == set()`— porque no hay argumento que derivar. Es la vía MÁS FÁCIL,
   así que cerrar sólo la primera habría sido cerrar la puerta y dejar la ventana.

Lo que estas pruebas vigilan por el otro lado
---------------------------------------------
Que no marque lo que no es. El sondeo inicial con `SESSION|AUTH|KEY` marcaba `SSH_AUTH_SOCK`
—la ruta de un socket, y quitarla rompe el agente de ssh—, `TERM_SESSION_ID` y `HARNESS_SESSION`,
que es de refuto. Un detector que marca lo normal enseña a ignorarlo, y entonces deja de proteger
de lo que sí.
"""

from __future__ import annotations

import os
import unittest
from pathlib import Path

from core.effects import efectos
from core.policy import ALLOW, ASK, DENY, Policy, decide_command

RAIZ = Path(__file__).resolve().parents[2]


class TestLaViaNombrada(unittest.TestCase):
    def setUp(self):
        self.p = Policy.default()

    def test_leer_una_variable_con_forma_de_credencial_lo_decide_una_persona(self):
        for orden in ("printenv MI_SERVICIO_API_KEY", "echo $MI_SERVICIO_TOKEN",
                      "printenv OTRO_SERVICIO_SECRET", "echo $MI_SERVICIO_PASSWORD",
                      "printenv MI_SERVICIO_AUTH_TOKEN", "printenv UNA_APP_CREDENTIALS"):
            with self.subTest(orden=orden):
                self.assertEqual(ASK, decide_command(self.p, orden, RAIZ).outcome)

    def test_NO_marca_lo_que_no_es_una_credencial(self):
        """La mitad que evita que el control se desactive por ruidoso."""
        for orden in ("printenv PATH", "printenv HOME", "printenv SSH_AUTH_SOCK",
                      "printenv HARNESS_SESSION", "printenv TERM_SESSION_ID",
                      "echo $PWD", "echo $USER"):
            with self.subTest(orden=orden):
                self.assertEqual(ALLOW, decide_command(self.p, orden, RAIZ).outcome)

    def test_la_comparacion_es_por_nombre_y_no_por_valor(self):
        """Mirar el valor obligaría a leer todos los secretos para protegerlos."""
        self.assertTrue(self.p.is_secret_env("cualquier_cosa_TOKEN"))
        self.assertTrue(self.p.is_secret_env("mi_servicio_token"),
                        "debe ser insensible a mayúsculas")
        self.assertFalse(self.p.is_secret_env("PATH"))
        self.assertFalse(self.p.is_secret_env(""))


class TestLaViaAGranel(unittest.TestCase):
    """El entorno se CONTROLA en cada prueba: si no, se mide la máquina y no el mecanismo.

    La primera versión no lo hacía y pasó en local y cayó en CI, en las dos versiones de Python:
    el runner no tiene ninguna variable con forma de credencial, así que `env` salía `allow` y
    nueve aserciones fallaron. Es la misma lección que ya costó siete pruebas en este repositorio
    —una suite que medía el `$HOME` de quien la ejecutaba— y la volví a cometer.

    Que la prueba dependa del entorno es especialmente malo AQUÍ, porque lo que se está probando
    es precisamente un control que mira el entorno: la prueba y el sujeto compartían la variable
    oculta.
    """

    #: Una variable con forma de credencial, inventada para la prueba. El valor no se mira nunca
    #: —el control compara el NOMBRE— así que no hay secreto que inventar.
    CENTINELA = "REFUTO_PRUEBA_API_KEY"

    def setUp(self):
        self.p = Policy.default()
        self._previo = dict(os.environ)
        # Se retira lo que la máquina traiga y se pone UNA conocida: así el estado de partida es
        # el mismo en cualquier sitio, y lo que falle es el mecanismo.
        for k in [k for k in os.environ if self.p.is_secret_env(k)]:
            os.environ.pop(k, None)
        os.environ[self.CENTINELA] = "no-es-un-secreto-de-verdad"

    def tearDown(self):
        os.environ.clear()
        os.environ.update(self._previo)

    def test_el_centinela_es_lo_unico_con_forma_de_credencial(self):
        """Sin esto, las de abajo podrían estar pasando por una variable de la máquina."""
        marcadas = sorted(k for k in os.environ if self.p.is_secret_env(k))
        self.assertEqual([self.CENTINELA], marcadas)

    def test_un_volcado_del_entorno_se_pregunta(self):
        for orden in ("env", "printenv", "set", "declare -p", "env | grep KEY"):
            with self.subTest(orden=orden):
                self.assertEqual(ASK, decide_command(self.p, orden, RAIZ).outcome)

    def test_el_modelo_de_efectos_NO_deriva_nada_de_un_volcado(self):
        """Por eso hace falta enumerarlos: no hay argumento del que derivar la lectura."""
        self.assertEqual(set(), efectos("env").lecturas)

    def test_env_como_ENVOLTORIO_no_es_un_volcado(self):
        """`env FOO=1 orden` ajusta el entorno, no lo imprime. Marcarlo sería marcar la mitad
        de los lanzamientos con entorno ajustado."""
        self.assertEqual(ALLOW, decide_command(self.p, "env FOO=1 ls", RAIZ).outcome)

    def test_volcar_el_entorno_Y_escribir_fuera_es_exfiltracion(self):
        """La vía más fácil de todas, y la última en cerrarse: la redirección rompía la
        comprobación de «sólo banderas», así que `env > …` salía `allow`."""
        for orden in ("env > /tmp/claude-x/todo", "env >> /tmp/claude-x/t",
                      "printenv > ~/.claude/projects/p/memory/n.md",
                      "env | tee /tmp/claude-x/t"):
            with self.subTest(orden=orden):
                self.assertEqual(DENY, decide_command(self.p, orden, RAIZ).outcome)

    def test_escribir_algo_que_NO_es_el_entorno_sigue_pasando(self):
        self.assertEqual(ALLOW, decide_command(self.p, "echo hola > /tmp/claude-x/n",
                                               RAIZ).outcome)

    def test_sin_credenciales_en_el_entorno_un_volcado_no_molesta(self):
        """En una máquina limpia `env` es inofensivo, y preguntarlo sería ruido.

        Ésta es la contraparte, y no es decorativa: sin ella, todo lo de arriba se satisface
        preguntando por cualquier `env`. Un runner de CI es exactamente esa máquina limpia — de
        hecho es donde se descubrió que las otras dependían del entorno.
        """
        os.environ.pop(self.CENTINELA, None)
        self.assertEqual(ALLOW, decide_command(self.p, "env", RAIZ).outcome)


class TestLaMonotoniaYElContrato(unittest.TestCase):
    def test_secret_env_deny_acumula(self):
        from core.refinement import ACUMULA, REGLAS
        self.assertEqual(ACUMULA, REGLAS["secret_env_deny"],
                         "marcar de más cuesta una consulta; marcar de menos cuesta el secreto")

    def test_un_espacio_puede_anadir_patrones_y_no_retirarlos(self):
        from core.refinement import refinar
        r = refinar({"schema": "harness.policy/v1", "version": "1"},
                    {"schema": "harness.policy/v1", "version": "1",
                     "secret_env_deny": ["MI_COSA_RARA"]})
        self.assertEqual("PASS", r.status, r.violaciones)
        efectivo = Policy.from_dict(r.politica.to_dict())
        self.assertIn("MI_COSA_RARA", set(efectivo.secret_env_deny))
        # La PROPIEDAD, no la cadena: lo que traía la raíz sigue atrapándose. Fijar un patrón
        # concreto ató esta prueba a la lista de entonces, y al sustituir los nombres de
        # producto por formas estructurales cayó teniendo el control intacto.
        self.assertTrue(efectivo.is_secret_env("UN_SERVICIO_API_KEY"),
                        "la unión perdió la cobertura que traía la raíz")

    def test_la_raiz_no_esta_vacia_asi_que_ACUMULA_no_cae_en_la_trampa(self):
        """`REDUCE` con raíz vacía convierte un campo en código muerto — pasó dos veces en dos
        días (`writable_paths` en ADR-0014, `privilege_grants` en ADR-0016). `ACUMULA` no tiene
        ese problema, y que la raíz traiga cobertura es lo que hace útil el campo sin
        declararlo. Se comprueba la COBERTURA y no el tamaño de la lista: contar entradas ató
        la prueba a una lista concreta y cayó al sustituir once nombres de producto por formas
        estructurales que cubren lo mismo y más."""
        p = Policy.default()
        for n in ("UN_SERVICIO_API_KEY", "OTRO_TOKEN", "APP_PASSWORD", "X_CREDENTIALS",
                  "UN_SERVICIO_QUE_NO_EXISTIA_AL_ESCRIBIR_ESTO_SECRET"):
            with self.subTest(nombre=n):
                self.assertTrue(p.is_secret_env(n))


if __name__ == "__main__":
    unittest.main()
