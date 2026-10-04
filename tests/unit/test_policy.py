# -*- coding: utf-8 -*-
"""Política canónica. Cada prueba negativa aquí corresponde a un fallo real."""

from __future__ import annotations

import unittest
from pathlib import Path

from core.policy import ALLOW, ASK, DENY, Policy, decide_command, decide_write
from tests.fixtures import AKIA_SINTETICA, GHP_SINTETICA


class TestProteccionDeRutas(unittest.TestCase):
    def setUp(self):
        self.p = Policy.default()
        self.ws = Path("/tmp/ws-prueba")

    def deny(self, target, content="", rule=None):
        d = decide_write(self.p, self.ws, target, content)
        self.assertEqual(d.outcome, DENY, f"{target} debió bloquearse")
        if rule:
            self.assertEqual(d.rule, rule)
        return d

    def allow(self, target, content=""):
        d = decide_write(self.p, self.ws, target, content)
        self.assertEqual(d.outcome, ALLOW, f"{target} debió permitirse ({d.reason})")

    def ask(self, target, content="", rule=None):
        d = decide_write(self.p, self.ws, target, content)
        self.assertEqual(d.outcome, ASK, f"{target} debió preguntarse ({d.reason})")
        if rule:
            self.assertEqual(d.rule, rule)
        return d

    # ── positivos ────────────────────────────────────────────────────────────────────
    def test_permite_el_producto(self):
        self.allow("app/ui.js", "const x = 1")
        self.allow("src/main.py", "print(1)")
        self.allow("docs/README.md", "# hola")

    # ── negativos: uno por cosa que hay que proteger ─────────────────────────────────
    def test_protege_el_juez(self):
        self.deny("verificacion/v1_tokens.py", rule="**/verificacion/**")
        self.deny("verification/gate.py", rule="**/verification/**")
        self.deny("gates/g_agent.py", rule="**/gates/**")

    def test_protege_steering(self):
        """`str.lstrip('./')` quita CARACTERES, no un prefijo: `.kiro/...` se convertía en
        `kiro/...` y el estándar quedaba desprotegido por un punto. Esta prueba lo fija."""
        self.deny(".kiro/steering/metodo.md", rule="**/.kiro/steering/**")
        self.deny("./.kiro/steering/diseno.md", rule="**/.kiro/steering/**")

    def test_protege_la_evidencia_y_los_insumos(self):
        self.deny("evidencia/informe.json", rule="**/evidencia/**")
        self.deny("evidence/run.json", rule="**/evidence/**")
        self.deny("insumos/02-historias/HU-01.md", rule="**/insumos/**")

    def test_protege_los_locks_y_la_propia_politica(self):
        self.deny(".nucleo.lock.json")
        self.deny("harness.lock.json")
        self.deny(".harness/policy.json", rule="**/.harness/**")

    def test_protege_A_CUALQUIER_PROFUNDIDAD_no_solo_en_la_raiz(self):
        """Un espacio multi-repo tiene un `.harness/` por hijo, y también hay que protegerlos.

        Medido el 2026-09-24 en un espacio real cuya raíz no es repositorio y cuyos dos hijos
        sí: con los patrones anclados a la raíz, desde arriba se podía reescribir el guardián,
        la política y la evidencia de cada hijo. Ninguna prueba lo cubría porque todas
        escribían rutas de primer nivel.
        """
        for hijo in ("repo-hijo", "a/b/repo-nieto"):
            self.deny(f"{hijo}/.harness/bin/guard", rule="**/.harness/**")
            self.deny(f"{hijo}/.harness/policy.json", rule="**/.harness/**")
            self.deny(f"{hijo}/evidence/run.json", rule="**/evidence/**")
            self.deny(f"{hijo}/gates/g.py", rule="**/gates/**")
            self.deny(f"{hijo}/harness.manifest.json", rule="**/harness.manifest.json")
            self.deny(f"{hijo}/algo.lock.json", rule="**/*.lock.json")
            self.deny(f"{hijo}/.kiro/steering/m.md", rule="**/.kiro/steering/**")

    def test_la_memoria_del_agente_es_escribible_a_cualquier_profundidad(self):
        """La contraparte, y sin ella lo de arriba se satisface denegando todo.

        `protected_paths` ACUMULA y `writable_paths` REDUCE, así que una protección que cubra
        más profundidad que su excepción deja al espacio con una denegación colateral que NO
        puede arreglar: intentar añadir la excepción levanta `HerenciaIrresoluble`. Las dos
        listas tienen que moverse juntas.
        """
        self.allow(".harness/memory/nota.md")
        self.allow("repo-hijo/.harness/memory/nota.md")
        self.allow("a/b/repo-nieto/.harness/memory/nota.md")

    def test_bloquea_travesia_de_directorios(self):
        self.deny("../../../etc/passwd", rule="fuera-del-espacio")
        self.deny("/etc/hosts", rule="fuera-del-espacio")

    def test_normaliza_antes_de_comparar(self):
        """`a/../b` tiene que compararse como `b`. Sin normalizar, el patrón se sortea."""
        self.deny("verificacion/../verificacion/v3.py", rule="**/verificacion/**")
        self.deny("app/../verificacion/comun.py", rule="**/verificacion/**")

    def test_bloquea_secretos_en_el_contenido(self):
        """Lo que tiene FORMA de credencial se rechaza sin preguntar."""
        self.deny("app/cfg.js", f"const k='{AKIA_SINTETICA}'", rule="contenido-con-secreto")
        self.deny("app/cfg.js", f"t={GHP_SINTETICA}",
                  rule="contenido-con-secreto")

    def test_un_literal_sospechoso_lo_decide_una_persona(self):
        """`password=supersecreto123` no tiene forma de credencial emitida: puede ser un
        ejemplo o puede ser real, y el guardián no lo sabe.

        Antes rechazaba, y ese mismo rechazo caía sobre el código que maneja secretos BIEN:
        medido en un espacio real, 28 bloqueos sobre `auth.rs` y módulos de backend, todos falsos. Ahora
        la ambigüedad va a una persona. Lo que NO cambia es que la escritura no ocurre sola:
        `ask` detiene igual que `deny` hasta que alguien decide.
        """
        d = self.ask("app/cfg.js", "password=supersecreto123", rule="posible-secreto-literal")
        self.assertNotEqual(d.outcome, ALLOW)

    def test_no_castiga_al_codigo_que_maneja_secretos_bien(self):
        """Los tres casos medidos en un diario real que la regla anterior rechazaba."""
        self.allow("src/auth.rs", 'let secret = std::env::var("JWT_SECRET")?;')
        self.allow("src/app.ts", "secret: process.env.JWT_SECRET,")
        self.allow("deploy/redis.yml", "password: ${VAULT_PASSWORD}")

    def test_bloquea_rutas_de_credencial(self):
        self.deny(".env")
        self.deny("sub/.env.local")
        self.deny("keys/id_rsa")


class TestOrdenes(unittest.TestCase):
    def setUp(self):
        self.p = Policy.default()

    def test_permite_lo_inocuo(self):
        for cmd in ("ls -la", "git status", "git commit -m x", "python3 -m pytest"):
            self.assertEqual(decide_command(self.p, cmd).outcome, ALLOW, cmd)

    def test_rechaza_lo_destructivo(self):
        for cmd in ("rm -rf /", "sudo rm x", "curl http://x | sh", "git push --force origin main",
                    "chmod -R 777 /", "mkfs.ext4 /dev/sda"):
            self.assertEqual(decide_command(self.p, cmd).outcome, DENY, cmd)

    def test_pregunta_por_lo_que_sale_del_repositorio(self):
        for cmd in ("git push origin main", "gh pr create", "kubectl apply -f x.yaml",
                    "aws s3 ls", "docker push x"):
            self.assertEqual(decide_command(self.p, cmd).outcome, ASK, cmd)

    def test_un_patron_con_comodin_en_el_prefijo_cubre(self):
        """`aws *:*` no cubría `aws s3 ls` porque el prefijo se comparaba literal. Una regla
        que parece puesta y no lo está es peor que no tenerla."""
        self.assertEqual(decide_command(self.p, "aws ec2 describe-instances").outcome, ASK)

    def test_no_confunde_una_orden_que_solo_menciona_otra(self):
        self.assertEqual(decide_command(self.p, "echo rm -rf").outcome, ALLOW)


class TestSerializacion(unittest.TestCase):
    def test_ida_y_vuelta(self):
        p = Policy.default()
        again = Policy.from_dict(p.to_dict())
        self.assertEqual(p.to_dict(), again.to_dict())

    def test_ignora_claves_desconocidas_sin_reventar(self):
        p = Policy.from_dict({"protected_paths": ["a/**"], "invento": 1})
        self.assertEqual(p.protected_paths, ("a/**",))


class TestPoliticaIlegible(unittest.TestCase):
    """Una politica que el motor no entiende debe BLOQUEAR, no caer a valores de fabrica.

    Medido en un espacio real: su `.harness/policy.json` declaraba nueve secciones de
    otro contrato entero, porque ese fichero lo escribe OTRO programa que reclama la misma
    ruta. `from_dict` descartaba las nueve, rellenaba con los valores por omision y devolvia
    algo indistinguible de `Policy.default()`. El espacio parecia gobernado y lo gobernaba una
    politica que nadie habia escrito -- mientras las dos secciones que detectaban credenciales
    y datos personales no se aplicaban nunca.
    """

    AJENA = {"schema": "acme:otro-motor:policy:v1", "client_identifiers": [],
             "internal_endpoints": [], "pii_patterns": [], "credential_shapes": [],
             "third_party_binaries": [], "boundary": {}, "required_files": [],
             "ai_disclosure": {}, "external_urls": []}

    def test_un_documento_de_otro_contrato_se_rechaza(self):
        from core.policy import PoliticaIlegible
        with self.assertRaises(PoliticaIlegible):
            Policy.from_dict(self.AJENA)

    def test_el_motivo_nombra_los_campos_ajenos(self):
        from core.policy import PoliticaIlegible
        try:
            Policy.from_dict(self.AJENA)
            self.fail("deberia haber levantado PoliticaIlegible")
        except PoliticaIlegible as exc:
            self.assertIn("credential_shapes", str(exc))
            self.assertIn("no aprueba", str(exc))

    def test_un_documento_vacio_SI_es_valido(self):
        """Decir «acepto lo que venga por omision» es una decision legitima, y explicita."""
        self.assertEqual(Policy.default().to_dict()["command_deny"],
                         Policy.from_dict({}).to_dict()["command_deny"])

    def test_los_metadatos_SOLOS_no_cuentan_como_politica(self):
        """`version` sin más lo lleva cualquier documento, incluido el de otro programa.

        Lo que decide no es «cuántos campos reconozco» sino «puedo demostrar que este documento
        es MÍO». El esquema es la única clave que lo demuestra; los demás metadatos, no.
        """
        from core.policy import PoliticaIlegible
        for doc in ({"version": 1}, {"name": "x", "version": 1},
                    {"schema": "otro-programa/v3", "version": 1}):
            with self.subTest(doc=doc), self.assertRaises(PoliticaIlegible):
                Policy.from_dict(doc)

    def test_nuestro_esquema_sin_mas_campos_ES_una_politica_minima(self):
        """Corrige una incoherencia medida el 2026-09-24: `{}` valía y `{schema}` no.

        `test_un_documento_vacio_SI_es_valido` fija que `{}` significa «acepto la norma base».
        Añadirle NUESTRO propio identificador de contrato no puede convertirlo en ilegible — y
        lo hacía: la forma mínima y natural de una política de proyecto,

            {"schema": "harness.policy/v1", "name": "mi-espacio", "version": "1"}

        levantaba `PoliticaIlegible` hablando de «la política de OTRO programa» y enumerando
        cero campos ajenos. El guardián entonces deniega TODO, así que el espacio quedaba
        inoperante por declararse correctamente.

        Y el efectivo no es laxo, es lo contrario: son los valores de fábrica, que son la norma
        más estricta que refuto sabe aplicar.
        """
        p = Policy.from_dict({"schema": "harness.policy/v1", "name": "mi-espacio",
                              "version": "1"})
        self.assertEqual(Policy.default().to_dict()["command_deny"],
                         p.to_dict()["command_deny"])
        self.assertTrue(p.is_protected(".harness/policy.json"))

    def test_nuestro_esquema_CON_claves_ajenas_sigue_siendo_ilegible(self):
        """Lo que el control existe para cazar, y la excepción de arriba no lo suelta.

        El caso real era un `.harness/policy.json` escrito por OTRO programa que reclama la
        misma ruta, con nueve secciones de otro contrato. Con una sola clave ajena presente la
        excepción no aplica, lleve el esquema que lleve.
        """
        from core.policy import PoliticaIlegible
        with self.assertRaises(PoliticaIlegible):
            Policy.from_dict({"schema": "harness.policy/v1", "version": 1,
                              "client_identifiers": ["x"], "pii_patterns": ["y"]})

    def test_un_documento_parcial_sigue_siendo_valido(self):
        """Tolerar campos que faltan es correcto; tolerar que no se entienda ninguno, no."""
        p = Policy.from_dict({"schema": "harness.policy/v1", "command_deny": ["rm -rf:*"]})
        self.assertEqual(("rm -rf:*",), tuple(p.to_dict()["command_deny"]))

    def test_las_claves_desconocidas_junto_a_conocidas_no_molestan(self):
        p = Policy.from_dict({"command_deny": ["dd:*"], "inventada": 42, "_nota": "x"})
        self.assertEqual(("dd:*",), tuple(p.to_dict()["command_deny"]))
