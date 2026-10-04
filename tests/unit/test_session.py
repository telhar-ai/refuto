# -*- coding: utf-8 -*-
"""Sesión interactiva gobernada.

La regla que estas pruebas fijan: **el modo interactivo no relaja nada**. Un modo «para
trabajar cómodo» que apaga el guardián no es un modo: es una puerta trasera con nombre amable.
"""

from __future__ import annotations

import json
import unittest
from pathlib import Path

from core.proc import TEXT_IO
from core.session import build_brief, plan
from core.wire import audit_claude, wire_claude
from tests.fixtures import Workspace

HARNESS = Path(__file__).resolve().parents[2]


class TestPrecondiciones(unittest.TestCase):
    def test_sin_guardian_enganchado_NO_se_abre(self):
        with Workspace("ses-noguard") as ws:
            ws.policy()
            sp = plan(ws.root, runtime="claude")
            self.assertTrue(sp.blockers)
            self.assertTrue(any("guardián no está enganchado" in b for b in sp.blockers))

    def test_con_guardian_enganchado_si_se_abre(self):
        with Workspace("ses-guard") as ws:
            ws.policy()
            wire_claude(ws.root, harness_root=HARNESS)
            sp = plan(ws.root, runtime="claude")
            self.assertEqual(sp.blockers, [], sp.blockers)
            self.assertTrue(sp.argv)

    def test_kiro_exige_los_agentes_enganchados(self):
        with Workspace("ses-kiro") as ws:
            ws.policy()
            ws.json(".kiro/agents/a.json", {"name": "a", "tools": ["read"]})
            sp = plan(ws.root, runtime="kiro")
            self.assertTrue(any("guardián sólo está enganchado" in b for b in sp.blockers))

    def test_un_runtime_desconocido_se_rechaza(self):
        with Workspace("ses-x") as ws:
            ws.policy()
            self.assertTrue(plan(ws.root, runtime="inventado").blockers)

    def test_un_rol_inexistente_se_rechaza(self):
        with Workspace("ses-rol") as ws:
            ws.policy()
            wire_claude(ws.root, harness_root=HARNESS)
            sp = plan(ws.root, runtime="claude", role_id="rol-que-no-existe")
            self.assertTrue(any("no existe" in b for b in sp.blockers))


class TestInforme(unittest.TestCase):
    def brief(self, ws, **kw) -> str:
        return build_brief(ws.root, runtime=kw.pop("runtime", "claude"), **kw)[0]

    def test_declara_lo_protegido(self):
        with Workspace("brief-prot") as ws:
            ws.policy()
            text = self.brief(ws)
            self.assertIn("verificacion/**", text)
            self.assertIn("fuera de tu control", text)

    def test_declara_los_cuatro_estados(self):
        with Workspace("brief-est") as ws:
            ws.policy()
            text = self.brief(ws)
            for st in ("PASS", "FAIL", "BLOCKED", "NOT_EXECUTABLE"):
                self.assertIn(st, text)
            self.assertIn("`BLOCKED` no aprueba", text)

    def test_resume_la_especificacion_activa(self):
        with Workspace("brief-spec") as ws:
            ws.policy()
            ws.file(".kiro/specs/mod/requirements.md",
                    "# Requisitos\n\n### REQ-001\nx\n\n### REQ-002\ny\n")
            ws.file(".kiro/specs/mod/tasks.md", "- [x] uno\n- [ ] dos\n- [ ] tres\n")
            text = self.brief(ws)
            self.assertIn("`mod`", text)
            self.assertIn("2 requisitos", text)
            self.assertIn("1/3 tareas", text)

    def test_con_varias_specs_avisa_en_vez_de_elegir(self):
        with Workspace("brief-multi") as ws:
            ws.policy()
            for n in ("a", "b"):
                ws.file(f".kiro/specs/{n}/requirements.md", "# x\n### REQ-001\ny\n")
            _, warnings, _ = build_brief(ws.root, runtime="claude")
            self.assertTrue(any("Elija con --spec" in w for w in warnings))

    def test_sin_specs_lo_dice(self):
        with Workspace("brief-nospec") as ws:
            ws.policy()
            self.assertIn("No hay ninguna en este espacio", self.brief(ws))

    def test_el_rol_aporta_su_contrato_completo(self):
        with Workspace("brief-rol") as ws:
            ws.policy()
            text = self.brief(ws, role_id="visual-validator")
            self.assertIn("visual-validator", text)
            self.assertIn("observa; no repara", text)
            self.assertIn("HUMAN_VISUAL_REVIEW", text)


class TestOrden(unittest.TestCase):
    def test_claude_recibe_el_informe_como_prompt_de_sistema(self):
        with Workspace("argv-claude") as ws:
            ws.policy()
            wire_claude(ws.root, harness_root=HARNESS)
            sp = plan(ws.root, runtime="claude")
            self.assertIn("--append-system-prompt-file", sp.argv)
            self.assertIn(str(sp.brief_path), sp.argv)

    def test_el_informe_se_escribe_al_disco(self):
        with Workspace("argv-file") as ws:
            ws.policy()
            wire_claude(ws.root, harness_root=HARNESS)
            sp = plan(ws.root, runtime="claude")
            self.assertTrue(sp.brief_path.is_file())
            self.assertEqual(sp.brief_path.read_text(encoding="utf-8"), sp.brief)


class TestEngancheDeClaude(unittest.TestCase):
    def test_engancha_y_audita(self):
        with Workspace("wc") as ws:
            self.assertFalse(audit_claude(ws.root)["wired"])
            wire_claude(ws.root, harness_root=HARNESS)
            self.assertTrue(audit_claude(ws.root)["wired"])

    def test_es_idempotente(self):
        with Workspace("wc2") as ws:
            wire_claude(ws.root, harness_root=HARNESS)
            self.assertEqual([r.action for r in wire_claude(ws.root, harness_root=HARNESS)],
                             ["already"])

    def test_preserva_la_configuracion_existente(self):
        """Pisar la configuración de alguien para instalar un control es empezar el control
        rompiendo algo."""
        with Workspace("wc3") as ws:
            ws.json(".claude/settings.local.json",
                    {"permissions": {"allow": ["Read(./**)"]},
                     "hooks": {"PreToolUse": [{"matcher": "Bash",
                                               "hooks": [{"type": "command",
                                                          "command": "mi-script.sh"}]}]}})
            wire_claude(ws.root, harness_root=HARNESS)
            doc = json.loads((ws.root / ".claude/settings.local.json").read_text(encoding="utf-8"))
            self.assertEqual(doc["permissions"]["allow"], ["Read(./**)"])
            cmds = [h["command"] for e in doc["hooks"]["PreToolUse"] for h in e["hooks"]]
            self.assertIn("mi-script.sh", cmds)
            self.assertEqual(len(cmds), 2)

    def test_un_settings_ilegible_no_se_pisa(self):
        with Workspace("wc4") as ws:
            ws.file(".claude/settings.local.json", "{{{ roto")
            r = wire_claude(ws.root, harness_root=HARNESS)
            self.assertEqual(r[0].action, "skipped")
            self.assertIn("ilegible", r[0].detail)


class TestEleccionDeEspecificacion(unittest.TestCase):
    """Elegir la primera de varias homónimas es peor que no elegir ninguna.

    El agente recibe UNA especificación y la trata como la autoridad del espacio. Si había
    trece con ese nombre, nadie se entera de que se eligió una al azar.
    """

    @staticmethod
    def _con_specs(ws: Workspace, *rutas: str) -> None:
        for r in rutas:
            ws.file(f"{r}/especificacion/requirements.md", "# requisitos\n")

    def test_nombre_repetido_NO_elige_al_azar(self):
        from core.session import _elegir_spec, _specs
        with Workspace("spec-amb") as ws:
            self._con_specs(ws,
                            ".worktrees/rama-a/sdd/espacios/emision-de-factura",
                            ".worktrees/rama-b/sdd/espacios/emision-de-factura",
                            "servicios/facturacion/sdd/espacios/emision-de-factura")
            specs = _specs(ws.root, incluir_ocultos=True)  # camino de --spec
            self.assertEqual(3, len(specs))

            elegida, porque = _elegir_spec(specs, "emision-de-factura", ws.root)

            self.assertIsNone(elegida)
            self.assertIn("no identifica una sola", porque)
            self.assertIn("coincide con 3", porque)
            self.assertIn("servicios/facturacion", porque)

    def test_la_ruta_desambigua(self):
        from core.session import _elegir_spec, _specs
        with Workspace("spec-ruta") as ws:
            self._con_specs(ws,
                            ".worktrees/rama-a/sdd/espacios/emision-de-factura",
                            "servicios/facturacion/sdd/espacios/emision-de-factura")
            specs = _specs(ws.root, incluir_ocultos=True)  # camino de --spec

            elegida, porque = _elegir_spec(
                specs, "servicios/facturacion/sdd/espacios/emision-de-factura", ws.root)

            self.assertEqual("", porque)
            self.assertIsNotNone(elegida)
            self.assertTrue(str(elegida).endswith("servicios/facturacion/sdd/espacios/emision-de-factura"))

    def test_nombre_unico_sigue_funcionando(self):
        from core.session import _elegir_spec, _specs
        with Workspace("spec-uno") as ws:
            self._con_specs(ws, "servicios/alta/sdd/espacios/alta-de-cliente")
            specs = _specs(ws.root)

            elegida, porque = _elegir_spec(specs, "alta-de-cliente", ws.root)

            self.assertEqual("", porque)
            self.assertEqual("alta-de-cliente", elegida.name)

    def test_nombre_inexistente_lista_los_que_hay_sin_repetir(self):
        from core.session import _elegir_spec, _specs
        with Workspace("spec-no") as ws:
            self._con_specs(ws,
                            "a/sdd/espacios/memoria",
                            "b/sdd/espacios/memoria",
                            "c/sdd/espacios/inteligencia-web")
            specs = _specs(ws.root)

            elegida, porque = _elegir_spec(specs, "no-existe", ws.root)

            self.assertIsNone(elegida)
            self.assertIn("inteligencia-web, memoria", porque)
            self.assertEqual(1, porque.count("memoria"))

    def test_el_aviso_agrupa_por_nombre(self):
        with Workspace("spec-aviso") as ws:
            ws.policy()
            wire_claude(ws.root, harness_root=HARNESS)
            self._con_specs(ws,
                            "a/sdd/espacios/emision-de-factura",
                            "b/sdd/espacios/emision-de-factura",
                            "c/sdd/espacios/inteligencia-web")
            sp = plan(ws.root, runtime="claude")
            aviso = next((w for w in sp.warnings if "especificaciones" in w), "")

            self.assertIn("3 especificaciones bajo 2 nombres", aviso)
            self.assertIn("emision-de-factura (×2)", aviso)
            self.assertIn("hace falta la ruta", aviso)


class TestElGitignoreDelEspacio(unittest.TestCase):
    """Defectos medidos en arranques reales de sesiones gobernadas."""

    def test_gitignore_converge_sin_pisar_lo_que_habia(self):
        from core.session import GITIGNORE_ENTRIES, ensure_gitignore
        with Workspace("ses-gi") as ws:
            ws.file(".harness/.gitignore", "evidence/\nmio/")
            self.assertTrue(ensure_gitignore(ws.root / ".harness"))
            lineas = (ws.root / ".harness/.gitignore").read_text().splitlines()
            self.assertEqual(["evidence/", "mio/"], lineas[:2],
                             "lo que había escrito una persona no se toca ni se reordena")
            self.assertEqual(set(GITIGNORE_ENTRIES) | {"mio/"}, set(lineas))
            self.assertFalse(ensure_gitignore(ws.root / ".harness"), "no es idempotente")

    def test_gitignore_con_crlf_no_se_reescribe_entero(self):
        # `read_text` traduce CRLF a LF y la escritura devolvía el fichero entero
        # normalizado. Se añade lo que falta; lo que había no se toca.
        from core.session import ensure_gitignore
        with Workspace("ses-gi-crlf") as ws:
            gi = ws.root / ".harness/.gitignore"
            gi.parent.mkdir(parents=True)
            gi.write_bytes(b"evidence/\r\nmio/\r\n")
            self.assertTrue(ensure_gitignore(ws.root / ".harness"))
            crudo = gi.read_bytes()
            self.assertTrue(crudo.startswith(b"evidence/\r\nmio/\r\n"))
            self.assertNotIn(b"\n\n", crudo.replace(b"\r\n", b"\n"))
            self.assertIn(b"state/\r\n", crudo)
            self.assertNotIn(b"state/\n", crudo.replace(b"\r\n", b"\r\r"))

    def test_lo_que_lleva_datos_de_la_maquina_o_del_proyecto_no_se_versiona(self):
        """El defecto de producto con la peor consecuencia medida.

        `.harness/.gitignore` sólo excluía `evidence/` y `state/`, así que TODO espacio que
        adoptara este motor versionaba por omisión la instantánea de la máquina de quien lo
        instaló (`context/`), las notas de memoria del proyecto (`memory/`) —que pueden ser de
        un cliente—, las copias de los ficheros ajenos que `policy wire` tocó (`backup/`), el
        lanzador con rutas absolutas (`bin/`) y `binding.json` con sus remotos.

        Antes de este arreglo esta prueba falla en las cinco últimas rutas.
        """
        from core.session import ensure_gitignore
        with Workspace("ses-gi-fuga") as ws:
            (ws.root / ".harness").mkdir(parents=True, exist_ok=True)
            ensure_gitignore(ws.root / ".harness")
            lineas = {ln.strip()
                      for ln in (ws.root / ".harness/.gitignore").read_text().splitlines()}
            for ruta in ("evidence/", "state/", "context/", "memory/", "backup/", "bin/",
                         "binding.json"):
                self.assertIn(ruta, lineas, f"«{ruta}» se versionaría por omisión")

    def test_lo_declarado_SI_se_versiona(self):
        """La otra mitad: si se ignorara el manifiesto o la política, el espacio dejaría de
        ser reproducible por otra persona, que es lo único que justifica versionar algo."""
        from core.session import GITIGNORE_ENTRIES
        for declarado in ("harness.manifest.json", "harness.lock.json", "policy.json"):
            self.assertNotIn(declarado, GITIGNORE_ENTRIES)

    def test_abrir_sesion_deja_state_fuera_de_git(self):
        with Workspace("ses-gi2") as ws:
            ws.policy()
            wire_claude(ws.root, harness_root=HARNESS)
            plan(ws.root, runtime="claude")
            self.assertIn("state/", (ws.root / ".harness/.gitignore").read_text().split())

    def test_los_arboles_de_trabajo_no_son_especificaciones(self):
        from core.session import _specs
        with Workspace("ses-wt") as ws:
            ws.file("servicios/memoria/sdd/espacios/memoria/especificacion/requirements.md", "# r")
            ws.file(".worktrees/rama/sdd/espacios/memoria/especificacion/requirements.md", "# r")
            ws.file("ai/.worktrees/sdd/espacios/memoria/especificacion/requirements.md", "# r")
            specs = _specs(ws.root)
            self.assertEqual([s.relative_to(ws.root).as_posix() for s in specs],
                             ["servicios/memoria/sdd/espacios/memoria"])

    def test_nombre_de_sesion_lleva_el_espacio(self):
        with Workspace("ses-nombre") as ws:
            ws.policy()
            wire_claude(ws.root, harness_root=HARNESS)
            sp = plan(ws.root, runtime="claude")
            nombre = sp.argv[sp.argv.index("--name") + 1]
            self.assertEqual(nombre, f"{ws.root.name} · sesión")
            self.assertNotIn("harness ·", nombre)

    def test_clean_no_dice_que_perdera_la_suscripcion(self):
        import os
        with Workspace("ses-prov") as ws:
            ws.policy()
            wire_claude(ws.root, harness_root=HARNESS)
            os.environ["ANTHROPIC_API_KEY"] = "sk-ant-prueba-no-real"
            try:
                limpia = plan(ws.root, runtime="claude", provider="clean")
                self.assertTrue(limpia.clean_provider)
                self.assertFalse(any("NO usará su suscripción" in w for w in limpia.warnings),
                                 limpia.warnings)
                hereda = plan(ws.root, runtime="claude", provider="inherit")
                self.assertTrue(any("NO usará su suscripción" in w for w in hereda.warnings),
                                "sin limpieza el aviso SÍ es cierto y debe salir")
            finally:
                os.environ.pop("ANTHROPIC_API_KEY", None)

    def test_detecta_otra_sesion_viva_sobre_el_mismo_espacio(self):
        import subprocess, sys
        from core.session import sesiones_vivas
        with Workspace("ses-viva") as ws:
            (ws.root / ".harness/state").mkdir(parents=True, exist_ok=True)
            marca = str(ws.root / ".harness/state/session-brief.md")
            v_init = sesiones_vivas(ws.root)
            if v_init.ciego:
                self.skipTest(f"el entorno de ejecución no permite ejecutar 'ps': {v_init.ciego}")
            self.assertEqual(v_init, [])
            p = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(30)",
                                  "--append-system-prompt-file", marca])
            try:
                import time
                time.sleep(0.3)
                self.assertEqual([pid for pid, _ in sesiones_vivas(ws.root)], [p.pid])
                with Workspace("ses-otra") as otro:
                    self.assertEqual(sesiones_vivas(otro.root), [], "confunde espacios")
            finally:
                p.kill(); p.wait()

    def test_no_poder_mirar_la_tabla_de_procesos_no_es_estar_sola(self):
        """Falsado el 2026-09-22 leyendo el `except`, no ejecutando: `sesiones_vivas` devolvía
        `[]` tanto cuando no había otra sesión como cuando `ps` no se podía ejecutar —y
        `PermissionError` es un `OSError`, así que un entorno con la inspección de procesos
        restringida caía en la misma rama—. Quien llamaba sólo avisaba si la lista traía algo:
        la sesión abría declarando en silencio que estaba sola. Eso es una afirmación sin
        medición, dicha por el programa que existe para no dejar hacer eso.

        Las dos mitades importan: vacío-y-ciego tiene que avisar, y vacío-y-mirado NO tiene
        que avisar, o el aviso se vuelve ruido y se deja de leer.
        """
        import unittest.mock as mock
        from core.session import plan, sesiones_vivas
        with Workspace("ses-ciega") as ws:
            ws.manifest()
            with mock.patch("core.session.subprocess.run",
                            return_value=mock.Mock(stdout="123 1 python --help\n")):
                vistas = sesiones_vivas(ws.root)
                self.assertEqual([], vistas)
                self.assertEqual("", vistas.ciego, "se miró de verdad: no puede declararse ciego")
                self.assertFalse(any("no se pudo comprobar si hay otras sesiones" in w
                                     for w in plan(ws.root, runtime="claude").warnings),
                                 "avisa de ceguera cuando sí pudo mirar: el aviso sería ruido")

            with mock.patch("core.session.subprocess.run",
                            side_effect=PermissionError(1, "Operation not permitted")):
                ciegas = sesiones_vivas(ws.root)
                self.assertEqual([], ciegas)
                self.assertIn("tabla de procesos", ciegas.ciego,
                              "no poder mirar se devolvió como «no hay nadie»")
                avisos = plan(ws.root, runtime="claude").warnings
                self.assertTrue(any("no se pudo comprobar si hay otras sesiones" in w
                                    for w in avisos),
                                f"la sesión abrió sin decir que no lo sabía: {avisos}")

    def test_un_espacio_que_contiene_la_ruta_de_otro_no_es_el_mismo(self):
        # Falsado el 2026-09-21: la marca se buscaba como subcadena, y `/b/x/pub/.harness/…`
        # contiene `/x/pub/.harness/…`. Una copia de respaldo que replica la ruta daba «otra
        # sesión viva» sobre el espacio original.
        import subprocess, sys, time
        from core.session import sesiones_vivas
        with Workspace("ses-sufijo") as ws:
            espejo = Path(str(ws.root) + "-espejo" + str(ws.root))
            marca = str(espejo / ".harness/state/session-brief.md")
            p = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(30)",
                                  "--append-system-prompt-file", marca])
            try:
                time.sleep(0.3)
                self.assertEqual(sesiones_vivas(ws.root), [])
            finally:
                p.kill(); p.wait()

    def test_la_sesion_desde_la_que_se_lanza_no_cuenta_como_otra(self):
        # Falsado en vivo: `refuto chat --dry-run` ejecutado DESDE una sesión abierta
        # sobre el mismo espacio la denunciaba como concurrente. La sesión es el abuelo
        # (claude → shell → python), no el padre, y sólo se excluía al padre.
        import subprocess, sys
        with Workspace("ses-abuelo") as ws:
            marca = str(ws.root / ".harness/state/session-brief.md")
            hijo = (f"import sys; sys.path.insert(0, {str(HARNESS)!r}); "
                    f"from pathlib import Path; from core.session import sesiones_vivas; "
                    f"print(len(sesiones_vivas(Path({str(ws.root)!r}))))")
            # `; true` impide que el shell haga exec del último proceso: así hay abuelo.
            abuelo = (f"import subprocess, sys; subprocess.run(['sh', '-c', "
                      f"{sys.executable!r} + ' -c \"' + {hijo!r} + '\"; true'])")
            out = subprocess.run([sys.executable, "-c", abuelo, "--append-system-prompt-file",
                                  marca], capture_output=True, timeout=30, **TEXT_IO)
            self.assertEqual(out.stdout.strip(), "0", out.stderr)

    def test_una_redireccion_rota_que_se_limpia_no_anuncia_que_la_sesion_morira(self):
        # La otra mitad del arreglo del proveedor: `r.problems` se añadía sin mirar si se iba a
        # limpiar, y el arranque decía «muere en el primer mensaje» junto a la línea verde.
        import os
        with Workspace("ses-rota") as ws:
            ws.policy()
            wire_claude(ws.root, harness_root=HARNESS)
            os.environ["ANTHROPIC_BASE_URL"] = "/ruta/rota"
            try:
                for modo in ("auto", "clean"):
                    sp = plan(ws.root, runtime="claude", provider=modo)
                    self.assertTrue(sp.clean_provider, modo)
                    self.assertFalse(any("muere en el primer mensaje" in w
                                         for w in sp.warnings), (modo, sp.warnings))
                    self.assertTrue(any("ANTHROPIC_BASE_URL" in w and "ignora" in w
                                        for w in sp.warnings), (modo, sp.warnings))
                hereda = plan(ws.root, runtime="claude", provider="inherit")
                self.assertTrue(any("muere en el primer mensaje" in w for w in hereda.warnings),
                                "sin limpieza el aviso SÍ es cierto y debe salir")
            finally:
                os.environ.pop("ANTHROPIC_BASE_URL", None)


class TestLaDistribucionDeLasSpecsSeDeclara(unittest.TestCase):
    """Los patrones de búsqueda de especificaciones estaban CABLEADOS a la distribución de un
    solo espacio (`*/*/sdd/espacios/*/especificacion/requirements.md`, tres niveles exactos).

    En un espacio con otra organización el informe de sesión decía «No hay ninguna» teniendo
    especificaciones completas delante, y el agente arrancaba sin la única autoridad que tenía
    — que es justo lo que el informe existe para evitar.

    Antes del arreglo, `test_una_distribucion_propia_se_declara_en_el_manifiesto` falla: no
    había forma de declararla.
    """

    def test_por_omision_siguen_valiendo_las_tres_convenciones(self):
        from core.session import _specs
        with Workspace("spec-def") as ws:
            ws.file(".kiro/specs/uno/requirements.md", "# x\n")
            ws.file("specs/dos/requirements.md", "# x\n")
            ws.file("a/b/sdd/espacios/tres/especificacion/requirements.md", "# x\n")
            nombres = {p.name for p in _specs(ws.root)}
            self.assertEqual({"uno", "dos", "tres"}, nombres)

    def test_una_distribucion_propia_se_declara_en_el_manifiesto(self):
        from core.session import _specs
        with Workspace("spec-decl") as ws:
            ws.manifest(specs={"globs": ["proyectos/*/requirements.md",
                                         "proyectos/*/especificacion/requirements.md"]})
            ws.file("proyectos/pagos/requirements.md", "# x\n")
            ws.file("proyectos/altas/especificacion/requirements.md", "# x\n")
            ws.file(".kiro/specs/ignorada/requirements.md", "# x\n")
            nombres = {p.name for p in _specs(ws.root)}
            self.assertEqual({"pagos", "altas"}, nombres,
                             "`globs` declarado manda: si no, no sirve de nada declararlo. Y el "
                             "directorio de la spec se deriva del patrón, sin declarar niveles")

    def test_se_puede_declarar_solo_un_perfil_conocido(self):
        from core.session import _specs
        with Workspace("spec-perfil") as ws:
            ws.manifest(specs={"profiles": ["kiro"]})
            ws.file(".kiro/specs/uno/requirements.md", "# x\n")
            ws.file("specs/dos/requirements.md", "# x\n")
            self.assertEqual({"uno"}, {p.name for p in _specs(ws.root)})

    def test_una_convencion_con_directorio_oculto_ESCRITO_sigue_valiendo(self):
        """`.kiro/` empieza por punto y está en el patrón. Descartar «todo lo oculto» a secas
        —que es lo que hacía la comprobación anterior— habría borrado la convención de Kiro
        entera. Lo que se descarta es lo oculto alcanzado por un COMODÍN."""
        from core.session import _specs
        with Workspace("spec-oculto-ok") as ws:
            ws.file(".kiro/specs/uno/requirements.md", "# x\n")
            self.assertEqual({"uno"}, {p.name for p in _specs(ws.root)})

    def test_las_copias_en_un_contenedor_no_cuentan_como_specs_distintas(self):
        from core.session import _specs
        with Workspace("spec-wt") as ws:
            ws.file("repo/sdd/espacios/una/especificacion/requirements.md", "# x\n")
            ws.file(".worktrees/rama/sdd/espacios/una/especificacion/requirements.md", "# x\n")
            self.assertEqual(1, len(_specs(ws.root)), "un árbol de trabajo no es otra spec")
            self.assertEqual(2, len(_specs(ws.root, incluir_ocultos=True)),
                             "pedirla por nombre SÍ tiene que verlas: pueden divergir")


class TestNingunRuntimeAbreSinGuardian(unittest.TestCase):
    """La documentación dice que `refuto chat` se niega a abrir sin guardián enganchado.

    El código sólo lo comprobaba para `claude`. Antes del arreglo, las tres primeras pruebas
    fallan: `gemini` y `opencode` abrían sin comprobar nada, y `kiro` con CERO agentes pasaba
    por bueno porque la condición miraba la proporción (`rep["agents"] and …`) en vez de la
    existencia de un sitio donde enganchar.
    """

    def test_gemini_no_abre_sin_guardian(self):
        with Workspace("g-gem") as ws:
            ws.policy()
            sp = plan(ws.root, runtime="gemini")
            self.assertTrue(any("no tiene guardián enganchable" in b for b in sp.blockers),
                            sp.blockers)

    def test_opencode_no_abre_sin_guardian(self):
        with Workspace("g-oc") as ws:
            ws.policy()
            sp = plan(ws.root, runtime="opencode")
            self.assertTrue(any("no tiene guardián enganchable" in b for b in sp.blockers),
                            sp.blockers)

    def test_kiro_con_cero_agentes_NO_cuenta_como_enganchado(self):
        with Workspace("g-kiro0") as ws:
            ws.policy()
            sp = plan(ws.root, runtime="kiro")
            self.assertTrue(any("no hay ningún agente" in b for b in sp.blockers), sp.blockers)

    def test_la_excepcion_se_declara_en_el_manifiesto_y_se_avisa(self):
        """Declararlo no lo arregla: lo hace visible. Y el informe se lo dice al agente."""
        from core.session import build_brief
        with Workspace("g-decl") as ws:
            ws.policy()
            ws.manifest(agents={"gemini": {"required": False, "unguarded": True}})
            sp = plan(ws.root, runtime="gemini")
            self.assertFalse(any("guardián enganchable" in b for b in sp.blockers), sp.blockers)
            self.assertTrue(any("SIN guardián preventivo" in w for w in sp.warnings), sp.warnings)
            texto, _, _ = build_brief(ws.root, runtime="gemini")
            self.assertIn("NO corre el guardián preventivo", texto)

    def test_con_guardian_el_informe_SI_promete_el_control(self):
        from core.session import build_brief
        with Workspace("g-ok") as ws:
            ws.policy()
            wire_claude(ws.root, harness_root=HARNESS)
            texto, _, _ = build_brief(ws.root, runtime="claude")
            self.assertIn("es un programa fuera de", texto)
            self.assertNotIn("NO corre el guardián preventivo", texto)
