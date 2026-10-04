# -*- coding: utf-8 -*-
"""El cuerpo de un documento aquí citado es TEXTO, y el guardián lo leía como órdenes.

La propiedad que estas pruebas fijan
------------------------------------
Un control debe saltar con la ACCIÓN, no con el TEXTO. La lista `command_deny` describe
órdenes que no se ejecutan; MENCIONAR una de ellas en prosa no es ejecutarla.

El defecto, medido el 2026-09-24 contra el guardián real con la política de un espacio real.
Un agente documentaba en markdown la frontera de lo que NO había ejecutado:

    cat > 00_AUTHORIZATION.md <<'EOF'
    ## NO ejecutado (fuera de la frontera)
    `adb root`, fastboot, flashing, `dd`, escritura de particiones…
    EOF
                                →  deny  («dd:*»)

`_segmentos` extraía órdenes de los acentos invertidos —correcto para shell— sobre un cuerpo
que el shell no expande. El guardián rechazaba la declaración de abstinencia del agente.

Por qué esta prueba y no un caso más en `test_attacks.py`
--------------------------------------------------------
Porque el eje es el contrario al de una prueba de ataque: aquí lo que hay que demostrar es que
el control **no** salta, y a la vez que las cinco vías por las que un documento aquí SÍ puede
ejecutar algo siguen cerradas. Las dos mitades tienen que vivir juntas: sin la segunda, la
primera se satisface desactivando el control, que es exactamente el error que se estaba
arreglando cuando se midió que `_partir` ya había tenido este mismo problema con las comillas.
"""

from __future__ import annotations

import unittest

from core.effects import efectos
from core.policy import ALLOW, DENY, Policy, decide_command
from tests.fixtures import Workspace

#: Órdenes denegadas de fábrica, mencionadas en prosa markdown dentro de un cuerpo literal.
#: Se construyen con `chr(96)` y no con el carácter literal porque el propio defecto impedía
#: EDITAR el fichero que lo arreglaba: la orden de escritura disparaba la regla. Ya le pasó a
#: `_partir` con las comillas y lo cuenta su docstring; que vuelva a pasar con otro mecanismo
#: es la señal de que esto necesita una prueba y no un parche.
B = chr(96)

MENCIONES = [
    "dd", "sudo", "rm -rf /", "mkfs", "git push --force", "chmod -R 777",
    "git reset --hard", "dd if=/dev/zero of=/dev/disk0",
]


class TestLaProsaNoEsUnaOrden(unittest.TestCase):
    """`Menciona(cuerpo, orden) ∧ ¬Expande(cuerpo) ⟹ ALLOW`."""

    def setUp(self):
        self.p = Policy.default()

    def test_mencionar_una_orden_denegada_en_un_cuerpo_literal_no_la_ejecuta(self):
        with Workspace("heredoc-prosa") as ws:
            fallos = []
            for mencion in MENCIONES:
                for delim in ("'EOF'", '"EOF"'):
                    orden = (f"cat > informe.md <<{delim}\n"
                             f"## NO ejecutado\n"
                             f"{B}{mencion}{B}, y nada de esto se hizo.\n"
                             f"EOF")
                    d = decide_command(self.p, orden, ws.root)
                    if d.outcome != ALLOW:
                        fallos.append(f"<<{delim} · {mencion!r} → {d.outcome} ({d.rule})")
            self.assertEqual([], fallos,
                             f"{len(fallos)} menciones en prosa se trataron como ejecución:\n  "
                             + "\n  ".join(fallos))

    def test_una_linea_del_cuerpo_no_es_una_sentencia(self):
        """`_partir` corta por saltos de línea, y un cuerpo son líneas."""
        with Workspace("heredoc-lineas") as ws:
            orden = ("cat > guia.md <<'EOF'\n"
                     "sudo apt install foo\n"
                     "rm -rf /tmp/algo\n"
                     "EOF")
            self.assertEqual(ALLOW, decide_command(self.p, orden, ws.root).outcome)

    def test_el_cuerpo_literal_no_produce_escrituras_derivadas(self):
        """Prosa que MENCIONA una redirección no redirige."""
        ef = efectos("cat > nota.md <<'EOF'\nredirige con > /etc/passwd\nEOF")
        self.assertNotIn("/etc/passwd", " ".join(ef.escrituras),
                         f"el modelo de efectos derivó una escritura del texto: {ef.escrituras}")

    def test_con_sangria_el_terminador_lleva_tabuladores(self):
        with Workspace("heredoc-sangria") as ws:
            orden = "\tcat > n.md <<-'EOF'\n\tnada de " + B + "sudo" + B + "\n\tEOF"
            self.assertEqual(ALLOW, decide_command(self.p, orden, ws.root).outcome)


class TestElArregloNoAbreUnaVia(unittest.TestCase):
    """Las cinco formas en que un documento aquí SÍ puede ejecutar o escribir algo."""

    def setUp(self):
        self.p = Policy.default()

    def test_el_destino_protegido_se_sigue_denegando(self):
        """Lo que impide que esto sea una vía de escape: la línea del operador se conserva."""
        with Workspace("heredoc-destino") as ws:
            fallos = []
            for destino in (".harness/policy.json", "gates/g.py", "evidence/x.json",
                            "harness.manifest.json", "policies/base.json"):
                for delim in ("'EOF'", "EOF"):
                    orden = f"cat > {destino} <<{delim}\nsoy inofensivo\nEOF"
                    d = decide_command(self.p, orden, ws.root)
                    if d.outcome != DENY:
                        fallos.append(f"{destino} <<{delim} → {d.outcome}")
            self.assertEqual([], fallos,
                             "un documento aquí escribió en el juez:\n  " + "\n  ".join(fallos))

    def test_sin_citar_el_delimitador_el_cuerpo_si_se_expande(self):
        """`<<EOF` expande sustituciones: el cuerpo sigue siendo código y se sigue mirando."""
        with Workspace("heredoc-expande") as ws:
            for cuerpo in ("$(sudo rm -rf /)", B + "sudo rm -rf /" + B):
                orden = f"cat > n.md <<EOF\ntexto {cuerpo} mas texto\nEOF"
                self.assertEqual(DENY, decide_command(self.p, orden, ws.root).outcome,
                                 f"un cuerpo expandible dejó pasar {cuerpo!r}")

    def test_lo_que_va_despues_del_terminador_se_sigue_evaluando(self):
        with Workspace("heredoc-despues") as ws:
            orden = ("cat > n.md <<'EOF'\n"
                     "inofensivo\n"
                     "EOF\n"
                     "sudo rm -rf /")
            d = decide_command(self.p, orden, ws.root)
            self.assertEqual(DENY, d.outcome, "la orden tras el terminador no se evaluó")

    def test_sin_terminador_no_se_traga_nada(self):
        """Sin línea de cierre el shell fallaría: no hay cuerpo que descartar."""
        with Workspace("heredoc-sin-cierre") as ws:
            orden = "cat > n.md <<'EOF'\nsudo rm -rf /"
            self.assertEqual(DENY, decide_command(self.p, orden, ws.root).outcome,
                             "un operador sin terminador se tragó las órdenes siguientes")

    def test_el_operador_citado_es_texto_y_no_abre_cuerpo(self):
        with Workspace("heredoc-operador-citado") as ws:
            orden = "echo \"<<EOF\"\nsudo rm -rf /\nEOF"
            self.assertEqual(DENY, decide_command(self.p, orden, ws.root).outcome,
                             "un `<<EOF` entre comillas abrió un cuerpo y ocultó la orden")

    def test_dos_documentos_en_la_misma_linea(self):
        """Los cuerpos se consumen en orden; el segundo no puede quedar huérfano."""
        with Workspace("heredoc-dos") as ws:
            orden = ("cat <<'A' > uno.md; cat <<B > dos.md\n"
                     "nada de " + B + "sudo" + B + "\n"
                     "A\n"
                     "$(sudo rm -rf /)\n"
                     "B")
            self.assertEqual(DENY, decide_command(self.p, orden, ws.root).outcome,
                             "el segundo cuerpo, que SÍ expande, no se analizó")


if __name__ == "__main__":
    unittest.main()
