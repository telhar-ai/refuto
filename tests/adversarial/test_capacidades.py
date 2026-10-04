# -*- coding: utf-8 -*-
"""El sujeto del monitor de referencia, y el canal de lectura que estaba sin mirar.

Los dos defectos que estas pruebas fijan, medidos el 2026-09-25
--------------------------------------------------------------
**F1 · Un monitor sin principal.** El control de acceso es una relación ternaria
`(sujeto, objeto, operación)`. `core/guard.py` normalizaba el hecho en siete campos y ninguno
era el sujeto, así que —consecuencia matemática, no de implementación— **todo agente en todo rol
tenía autoridad idéntica**. Y había un vocabulario esperando: 22 roles declaran 10 restricciones
en `roles/registry.json`, cuyos únicos consumidores eran `core/session.py:751` y
`refuto.py:1766`, que las imprimen en el informe bajo «**No puedes:**». Diez capacidades por
veintidós roles, aplicadas por cero líneas de código.

Peor: `G-ROLES` declaraba en su umbral «restricciones **aplicables**» y `validate_registry`
las contrastaba contra `KNOWN_CONSTRAINTS`, que es el **diccionario de prosa** del informe. O
sea, «refuto no sabe aplicar» significaba «no tengo una frase en español para describirla». La
puerta decía lo correcto y medía lo de al lado.

**F2 · El canal de lectura.** `secret_read_deny` se aplicaba en `decide_write` (escrituras) y en
`adapters/claude.py` (la capa de permisos del agente, sobre `Read`). El guardián engancha `Bash`
y no preguntaba por lecturas, así que:

    Write  .env      →  deny
    Bash   cat .env  →  ALLOW

Y `Efectos.lecturas` ya se poblaba: `decide_command` tenía tres referencias a `escrituras` y
cero a `lecturas`. El dato se calculaba y se descartaba.

Lo que aquí NO se prueba, porque no se afirma
---------------------------------------------
`HARNESS_ROLE` es una variable de entorno y el agente puede reescribirla en un subproceso: esto
atenúa por rol DECLARADO, no por principal criptográfico. Un `tar czf` sigue opaco. Una
credencial anidada bajo un directorio leído recursivamente no se detecta. Las tres son
incompletitudes declaradas, no olvidos.
"""

from __future__ import annotations

import unittest
from pathlib import Path

from core.capabilities import (APLICADAS, CONOCIDAS, NO_OBSERVABLES, capacidades_de,
                               decidir)
from core.guard import evaluate, normalize
from core.policy import ALLOW, ASK, DENY, Policy, decide_command
from core.roles import KNOWN_CONSTRAINTS, load, validate_registry
from tests.fixtures import Workspace


class TestNingunaRestriccionSeQuedaEnProsa(unittest.TestCase):
    """La invariante que vuelve inexpresable el defecto original."""

    def test_toda_restriccion_del_registro_esta_clasificada(self):
        usadas = {c for r in load().values() for c in r.constraints}
        self.assertEqual(set(), usadas - CONOCIDAS,
                         f"restricciones declaradas que ni se aplican ni se declaran no "
                         f"observables: {sorted(usadas - CONOCIDAS)}")

    def test_ninguna_esta_en_las_dos_tablas(self):
        self.assertEqual(set(), set(APLICADAS) & set(NO_OBSERVABLES))

    def test_cada_no_observable_trae_motivo_escrito(self):
        """Misma regla que `Result` con `NOT_APPLICABLE`: sin motivo es un aprobado cómodo."""
        for c, motivo in NO_OBSERVABLES.items():
            with self.subTest(restriccion=c):
                self.assertGreater(len(motivo.strip()), 60,
                                   f"«{c}» se declara no observable sin explicar por qué")

    def test_toda_aplicada_tiene_texto_para_el_informe(self):
        """Si el guardián la aplica y el informe no la explica, el agente la incumple a ciegas."""
        for c in APLICADAS:
            with self.subTest(restriccion=c):
                self.assertIn(c, KNOWN_CONSTRAINTS)

    def test_el_registro_valida_contra_las_capacidades_y_no_contra_la_prosa(self):
        """La corrección de `core/roles.py`: una restricción inventada tiene que doler."""
        self.assertEqual([], validate_registry())
        import json
        import tempfile
        with tempfile.TemporaryDirectory() as d:
            doc = json.loads(Path("roles/registry.json").read_text(encoding="utf-8"))
            doc["roles"][0]["constraints"] = ["no_hacer_el_mal"]
            ruta = Path(d) / "registry.json"
            ruta.write_text(json.dumps(doc), encoding="utf-8")
            problemas = validate_registry(str(ruta))
            self.assertTrue(any("no_hacer_el_mal" in p for p in problemas),
                            f"una restricción que nadie aplica pasó la validación: {problemas}")


class TestLasCapacidadesSoloAPRIETAN(unittest.TestCase):
    def test_el_efectivo_es_la_union_de_registro_y_politica(self):
        rol = next(r.id for r in load().values() if "no_shell" not in r.constraints)
        base = set(capacidades_de(rol))
        p = Policy.default()
        p.role_capabilities = {rol: ["no_shell"]}
        self.assertEqual(base | {"no_shell"}, set(capacidades_de(rol, p)),
                         "la política del espacio no acumuló sobre el registro")

    def test_la_politica_no_puede_retirar_lo_que_el_registro_declara(self):
        """No hay sintaxis para quitar. No poder expresar la relajación es más fuerte que
        detectarla — la misma razón por la que `protected_paths` es `ACUMULA`."""
        rol = next(r.id for r in load().values() if r.constraints)
        declaradas = set(load()[rol].constraints)
        p = Policy.default()
        p.role_capabilities = {rol: []}
        self.assertTrue(declaradas <= set(capacidades_de(rol, p)))

    def test_role_capabilities_declara_su_monotonia(self):
        from core.refinement import ACUMULA_MAPA, REGLAS
        self.assertEqual(ACUMULA_MAPA, REGLAS["role_capabilities"])


class TestElGuardianAplicaLasCapacidades(unittest.TestCase):
    def _hecho(self, **kw):
        base = {"runtime": "claude", "tool": "Bash", "path": "", "content": "", "command": "",
                "cwd": "", "role": "", "structured_reply": True}
        base.update(kw)
        return base

    def test_no_shell_deniega_una_orden(self):
        rol = next(r.id for r in load().values() if "no_shell" in r.constraints)
        with Workspace("cap-shell") as ws:
            d, kind = evaluate(Policy.default(), ws.root,
                               self._hecho(command="ls -la", role=rol))
            self.assertEqual(DENY, d.outcome, "un rol `no_shell` ejecutó una orden")
            self.assertIn("no_shell", d.rule)

    def test_y_sin_rol_la_misma_orden_pasa(self):
        """La contraparte: sin ella lo de arriba se satisface denegando toda orden."""
        with Workspace("cap-sin-rol") as ws:
            d, _ = evaluate(Policy.default(), ws.root, self._hecho(command="ls -la"))
            self.assertEqual(ALLOW, d.outcome)

    def test_un_rol_sin_esa_restriccion_tambien_pasa(self):
        rol = next(r.id for r in load().values() if "no_shell" not in r.constraints)
        with Workspace("cap-otro-rol") as ws:
            d, _ = evaluate(Policy.default(), ws.root,
                            self._hecho(command="ls -la", role=rol))
            self.assertEqual(ALLOW, d.outcome)

    def test_una_capacidad_nunca_convierte_un_deny_en_allow(self):
        """Se compone con `max`, así que apretar es lo único que puede hacer."""
        rol = next(r.id for r in load().values() if "no_shell" not in r.constraints)
        with Workspace("cap-no-afloja") as ws:
            d, _ = evaluate(Policy.default(), ws.root,
                            self._hecho(command="sudo algo", role=rol))
            self.assertEqual(DENY, d.outcome)

    def test_no_secret_access_deniega_lo_que_para_otros_es_ask(self):
        rol = next((r.id for r in load().values() if "no_secret_access" in r.constraints), "")
        self.assertTrue(rol, "ningún rol declara `no_secret_access`")
        with Workspace("cap-secreto") as ws:
            (ws.root / ".env").write_text("TOKEN=x\n", encoding="utf-8")
            sin_rol, _ = evaluate(Policy.default(), ws.root, self._hecho(command="cat .env"))
            con_rol, _ = evaluate(Policy.default(), ws.root,
                                  self._hecho(command="cat .env", role=rol))
            self.assertEqual(ASK, sin_rol.outcome, "para el resto lo decide una persona")
            self.assertEqual(DENY, con_rol.outcome, "para este rol está decidido")

    def test_el_rol_llega_por_el_entorno_y_se_normaliza(self):
        import os
        previo = os.environ.get("HARNESS_ROLE")
        os.environ["HARNESS_ROLE"] = "backend-engineer"
        try:
            self.assertEqual("backend-engineer", normalize("claude", {})["role"])
        finally:
            if previo is None:
                os.environ.pop("HARNESS_ROLE", None)
            else:
                os.environ["HARNESS_ROLE"] = previo

    def test_una_restriccion_no_observable_no_deniega_nada(self):
        """Está declarada y no se finge aplicada: eso es el contrato, no un hueco."""
        p = Policy.default()
        p.role_capabilities = {"rol-x": ["no_write_code"]}
        motivo, _ = decidir(p, "rol-x", self._hecho(path="app/main.py"),
                            rutas=("app/main.py",))
        self.assertEqual("", motivo)


class TestElCanalDeLecturaYaSeMira(unittest.TestCase):
    def test_leer_una_credencial_lo_decide_una_persona(self):
        with Workspace("lee-cred") as ws:
            for orden in ("cat .env", "head -1 secrets/clave.pem", "cat ~/.aws/credentials"):
                with self.subTest(orden=orden):
                    self.assertEqual(ASK, decide_command(Policy.default(), orden,
                                                         ws.root).outcome)

    def test_leer_una_credencial_Y_escribir_fuera_es_exfiltracion(self):
        """La combinación no tiene lectura legítima, y da igual que el destino esté declarado
        escribible: `external_write_allow` abre el cuaderno del agente, no una salida para
        credenciales. La cuarta de estas rutas SOBREVIVE a la sesión."""
        with Workspace("exfil") as ws:
            for orden in ("cp .env /tmp/claude-x/robado",
                          "cat .env > /tmp/claude-x/robado",
                          "cp ~/.aws/credentials /tmp/claude-x/c",
                          "cp .env ~/.claude/projects/p/memory/nota.md"):
                with self.subTest(orden=orden):
                    self.assertEqual(DENY, decide_command(Policy.default(), orden,
                                                          ws.root).outcome)

    def test_el_trabajo_normal_sigue_pasando(self):
        """Sin esto, lo de arriba se satisface denegando todo — y un control ruidoso se desactiva."""
        with Workspace("normal") as ws:
            for orden in ("cat README.md", "ls -la", "grep -rn TODO src/",
                          "echo nota > /tmp/claude-x/apunte.md"):
                with self.subTest(orden=orden):
                    self.assertEqual(ALLOW, decide_command(Policy.default(), orden,
                                                           ws.root).outcome)

    def test_un_directorio_que_contiene_una_credencial_se_pregunta(self):
        """`grep -rn AKIA .` lee `.`, y ningún patrón de ruta casa con `.`."""
        with Workspace("dir-cred") as ws:
            (ws.root / ".env").write_text("TOKEN=x\n", encoding="utf-8")
            self.assertEqual(ASK, decide_command(Policy.default(), "grep -rn AKIA .",
                                                 ws.root).outcome)

    def test_y_sin_credencial_en_el_directorio_no_se_pregunta(self):
        with Workspace("dir-limpio") as ws:
            (ws.root / "README.md").write_text("hola\n", encoding="utf-8")
            self.assertEqual(ALLOW, decide_command(Policy.default(), "grep -rn AKIA .",
                                                   ws.root).outcome)

    def test_lo_opaco_se_declara_opaco_y_no_se_finge_cubierto(self):
        with Workspace("opaco") as ws:
            d = decide_command(Policy.default(), "tar czf /tmp/claude-x/t.tgz .", ws.root)
            self.assertTrue(d.opaco, "`tar` no declara lecturas y eso tiene que constar")


if __name__ == "__main__":
    unittest.main()
