# -*- coding: utf-8 -*-
"""Las seis brechas de assurance medidas el 2026-09-25, fijadas como deuda DECLARADA.

Qué es este fichero y qué NO es
--------------------------------
No arregla nada. Cada prueba de aquí **falla hoy** y está marcada `@unittest.expectedFailure`,
así que la suite sigue en verde y el defecto queda escrito con su reproducción ejecutable. El
día que alguien lo cierre, `unittest` lo reporta como `unexpectedSuccess` y
`tests/runner.py::_resumen` invalida la corrida — es decir, **el arreglo no puede pasar
inadvertido**, y la prueba obliga a reescribir esta documentación en vez de dejarla mintiendo.

Ése es el único mecanismo honesto que conozco para «deuda declarada»: ni un `skip` que se olvida,
ni un rojo permanente que se aprende a ignorar.

Verification ≠ Assurance
------------------------
El resto de la suite responde a la pregunta de VERIFICACIÓN: «¿la implementación satisface la
propiedad bajo las condiciones evaluadas?». Las 813 pruebas la responden bien.

Este fichero responde a la de ASSURANCE: «¿hay evidencia suficiente e independiente para confiar
en que la propiedad se mantiene frente a las clases de fallo relevantes?». Son preguntas
distintas y hoy tienen respuestas distintas, y el vocabulario de seis estados no puede expresar
la diferencia: un `PASS` producido, registrado y verificado por el mismo uid no es el mismo
hecho que uno anclado fuera. Mientras el tipo no distinga

    PASS / LOCAL        producido y verificado dentro del mismo dominio de confianza
    PASS / INDEPENDENT  verificado por otro principal
    PASS / ANCHORED     anclado fuera de quien lo produjo

todo `PASS` de refuto es `PASS / LOCAL`, y este fichero existe para que eso conste.

La pregunta que gobierna las seis
----------------------------------
No «¿decide bien refuto?», sino:

    Si refuto decide MAL, ¿qué impide que el efecto ocurra, cómo sabemos si ocurrió,
    y quién puede demostrarlo sin confiar en el mismo componente que decidió?

`G5` es esa pregunta en su forma más desnuda, y es la que peor sale.

Cada brecha se documenta con la cadena completa: PROPERTY · CONTRACT · IMPLEMENTATION · UNIT ·
ADVERSARIAL · RUNTIME · OBSERVATION · EVIDENCE · INDEPENDENT · VERDICT.
"""

from __future__ import annotations

import json
import os
import subprocess  # nosec B404 — lanzar el guardián real ES la medición
import sys
import tempfile
import unittest
from pathlib import Path

from core.effects import efectos
from core.evidence import append_event, cabeza, ledger_path, verificar_cadena
from core.guard import normalize
from core.policy import (ALLOW, DENY, IDENTIDAD_DISTINGUE_REUSO_DE_INODO, Policy,
                         decide_command, decide_write)
from core.proc import TEXT_IO

RAIZ = Path(__file__).resolve().parents[2]
#: Ruta que la política de fábrica protege. Aprobar una escritura aquí es inequívocamente un
#: fallo: es el juez.
PROTEGIDA = "gates/base.py"


def _guard(ws: Path, carga: dict, runtime: str = "claude"):
    p = subprocess.run(  # nosec B603
        [sys.executable, "-m", "core.guard", "--runtime", runtime, "--stdin",
         "--workspace", str(ws)],
        input=json.dumps(carga), capture_output=True, cwd=str(RAIZ), timeout=120, **TEXT_IO)
    decision = ""
    if p.stdout.strip():
        try:
            doc = json.loads(p.stdout)
            decision = (doc.get("hookSpecificOutput", {}).get("permissionDecision")
                        or doc.get("decision", ""))
        except json.JSONDecodeError:
            pass
    return p.returncode, decision


# ── G1 · el modelo de efectos afirma certezas que no tiene ───────────────────────────
class G1_ElModeloDeEfectosAfirmaCertezaFalsa(unittest.TestCase):
    """
    PROPERTY:     `Ê ⊆ Effects` — «si Ê dice que se escribe en p, se escribe en p»
    CONTRACT:     core/effects.py, encabezado: «lo que Ê afirma es sólido»
    IMPLEMENTATION: core/effects.py::_de_un_segmento · _EXPANSION · _LECTORES
    UNIT:         ninguna prueba cubre expansión de variables ni `find -exec`
    ADVERSARIAL:  9 formas de expansión probadas → 6 con opaco=False y ruta falsa
    RUNTIME:      medido contra decide_command real
    OBSERVATION:  ninguna — nadie comprueba después si la escritura ocurrió
    EVIDENCE:     el evento registra `opaco: false` y `escrituras_probadas: []`
    INDEPENDENT:  no
    VERDICT:      FAIL

    El daño no es que estas órdenes pasen: `python3 -c` también pasa y está bien, porque se
    declara `opaco` y el diario lo dice. El daño es que **se registra una certeza falsa**.
    `opaco: bool` colapsa dos situaciones opuestas en el mismo `False`:

        cp a b            opaco=False  ← se derivó todo: la certeza es real
        find . -exec …    opaco=False  ← no se derivó nada, y no se notó

    Un booleano no puede distinguir «resolví» de «no resolví y no me di cuenta». El arreglo no
    es un parche de la expresión regular: es cambiar el tipo por una resolución declarada
    (RESOLVED · AMBIGUOUS · UNRESOLVED · DYNAMIC · UNSAFE).
    """

    #: `(nombre, orden)` — órdenes que escriben en el juez y salen `opaco=False`.
    CIEGAS = (
        ("variable de shell", f"D={PROTEGIDA}; echo x > $D"),
        ("variable con llaves", f"D={PROTEGIDA}; echo x > ${{D}}"),
        ("valor por omisión", f"echo x > ${{V:-{PROTEGIDA}}}"),
        ("find -exec", "find . -name base.py -exec truncate -s0 {} ;"),
    )

    def test_control_lo_que_si_se_resuelve_se_deniega(self):
        """Control positivo. Sin él, «todo da allow» aprobaría la prueba de abajo."""
        d = decide_command(Policy.default(), f"echo x > {PROTEGIDA}", RAIZ)
        self.assertEqual(DENY, d.outcome)
        self.assertFalse(d.opaco, "la orden se resolvió del todo: la certeza es real")

    def test_control_lo_opaco_se_declara(self):
        """Control positivo. `python3 -c` pasa, y eso es correcto: lo declara."""
        e = efectos(f"python3 -c \"open('{PROTEGIDA}','w')\"")
        self.assertTrue(e.opaco)
        self.assertTrue(e.motivo_opaco)

    def test_DEUDA_una_orden_que_no_se_pudo_resolver_no_puede_declararse_cierta(self):
        """**CERRADA en R-01, 2026-09-25.** Era `@expectedFailure`; ahora es regresión.

        Las cuatro órdenes ciegas se conservan íntegras. Lo que cambió no es que ahora se
        rechacen —`find -exec` sigue saliendo `allow`, igual que `python3 -c`— sino que ya no
        se declaran CIERTAS: `opaco` es hoy una proyección de `resolucion`, y ninguna de las
        cuatro queda en `RESUELTO`.
        """
        for nombre, orden in self.CIEGAS:
            with self.subTest(caso=nombre):
                e = efectos(orden)
                self.assertTrue(
                    e.opaco,
                    f"«{nombre}»: Ê afirma saber qué toca ({sorted(e.escrituras)}) y no lo sabe. "
                    f"Registrar esto como certeza es peor que registrarlo como ignorancia")

    def test_DEUDA_ninguna_ruta_derivada_contiene_metacaracteres_sin_expandir(self):
        """Corolario comprobable: una ruta con `$`, `~` o `*` no se resolvió.

        Es la forma más barata de detectar la clase entera sin enumerar casos.

        **CERRADA en R-01, 2026-09-25.** Era `@expectedFailure`; ahora es regresión. Los
        destinos sin resolver no se descartan: salen de `escrituras` y entran en
        `sin_resolver`, que es lo que permite que `decide_command` los trate como una
        escritura a destino desconocido en vez de como una ruta llamada `$D`.
        """
        for nombre, orden in self.CIEGAS:
            for ruta in efectos(orden).escrituras:
                with self.subTest(caso=nombre, ruta=ruta):
                    self.assertFalse(
                        any(c in ruta for c in "$~*?`"),
                        f"Ê derivó «{ruta}» como destino real; es una plantilla sin expandir")


# ── G2 · el diario borrado aprueba, incluso contra un ancla ──────────────────────────
class G2_UnDiarioAusenteApruebaContraSuAncla(unittest.TestCase):
    """
    PROPERTY:     La evidencia no puede ser eliminada por quien la produce sin ser detectada
    CONTRACT:     SECURITY.md · «tamper-EVIDENCIA»; AGENTS.md · «un ámbito vacío nunca aprueba»
    IMPLEMENTATION: core/evidence.py::verificar_cadena, rama `if not path.is_file()`
    UNIT:         test_ledger_concurrente cubre truncación de cola, no borrado total
    ADVERSARIAL:  5 ataques → editar y borrar-intermedio detectados; borrar TODO no
    RUNTIME:      sí
    OBSERVATION:  —
    EVIDENCE:     la propia función de integridad es la que aprueba el vacío
    INDEPENDENT:  no
    VERDICT:      FAIL

    Es la Prueba del Vacío aplicada al componente que existe para aplicarla. Con un ancla
    publicada, «hay ancla y no hay diario» es la detección más barata posible: el ancla prueba
    que hubo eventos.
    """

    def _con_diario(self):
        tmp = tempfile.TemporaryDirectory()
        ws = Path(tmp.name)
        (ws / ".harness").mkdir()
        for i in range(5):
            append_event(ws, {"kind": "policy/decision", "outcome": "deny", "n": i})
        return tmp, ws, cabeza(ws)

    def test_control_editar_un_evento_se_detecta(self):
        tmp, ws, _ = self._con_diario()
        with tmp:
            p = ledger_path(ws)
            lineas = p.read_text(encoding="utf-8").splitlines()
            ev = json.loads(lineas[2])
            ev["outcome"] = "allow"
            p.write_text("\n".join(lineas[:2] + [json.dumps(ev, ensure_ascii=False)]
                                   + lineas[3:]) + "\n", encoding="utf-8")
            self.assertFalse(verificar_cadena(ws)["ok"])

    def test_control_truncar_la_cola_se_detecta_con_ancla(self):
        tmp, ws, ancla = self._con_diario()
        with tmp:
            p = ledger_path(ws)
            p.write_text("\n".join(p.read_text(encoding="utf-8").splitlines()[:2]) + "\n",
                         encoding="utf-8")
            self.assertTrue(verificar_cadena(ws)["ok"], "sin ancla es indetectable, y consta")
            self.assertFalse(verificar_cadena(ws, esperado=ancla)["ok"])

    def test_R02_borrar_el_diario_entero_se_detecta_con_ancla(self):
        """**CERRADA en C-02, 2026-09-25.** Era `@expectedFailure`; ahora es regresión.

        Se conserva la reproducción íntegra —no se reescribió para que pasara— y el estado
        explícito se comprueba además del booleano, porque `ok=False` por el motivo equivocado
        sería un aprobado accidental.
        """
        tmp, ws, ancla = self._con_diario()
        with tmp:
            ledger_path(ws).unlink()
            r = verificar_cadena(ws, esperado=ancla)
            self.assertFalse(
                r["ok"],
                f"el diario se borró y la verificación aprueba ({r}). El ancla demuestra que "
                f"hubo eventos: «no hay fichero» es la manipulación más burda y la única que "
                f"pasaba")
            self.assertEqual("AUSENTE", r["estado"],
                             "retiene, pero por el motivo equivocado")


# ── G3 · admisión: una Write cuya ruta no se pudo leer se aprueba ────────────────────
class G3_LaAdmisionNoExigeLosCamposDeLaHerramienta(unittest.TestCase):
    """
    PROPERTY:     Toda solicitud se valida estructuralmente antes de decidir
    CONTRACT:     core/guard.py::main · «un guardián que aprueba lo que no entiende no es un guardián»
    IMPLEMENTATION: _SHAPES — lista campos CANDIDATOS; no exige ninguno; sin apiVersion
    UNIT:         test_carga_no_reconocida cubre el piso («¿reconocí algo?»)
    ADVERSARIAL:  16 formas → 5 aprueban una escritura al juez
    RUNTIME:      guardián real, dialecto claude
    OBSERVATION:  —
    EVIDENCE:     el evento no guarda la carga cruda: la admisión no es auditable después
    INDEPENDENT:  no
    VERDICT:      FAIL

    La pregunta que el guardián hace es «¿reconocí ALGÚN campo?». La correcta es «¿reconocí los
    que ESTA herramienta necesita?». Una `Write` sin `path` extraíble no es una llamada inocua:
    es una `Write` que no se pudo examinar, y las dos se responden igual.
    """

    #: Cargas que declaran `tool_name: Write` y cuya ruta NO se puede extraer.
    OPACAS = (
        ("ruta en un campo no listado", {"tool_name": "Write",
                                         "arguments": {"path": PROTEGIDA}}),
        ("ruta con tipo dict", {"tool_name": "Write",
                                "tool_input": {"file_path": {"a": PROTEGIDA}}}),
        ("ruta con tipo lista", {"tool_name": "Write",
                                 "tool_input": {"file_path": [PROTEGIDA]}}),
        ("ruta numérica", {"tool_name": "Write", "tool_input": {"file_path": 123}}),
        ("tool_input nulo", {"tool_name": "Write", "tool_input": None}),
    )

    def test_control_la_forma_canonica_se_deniega(self):
        with tempfile.TemporaryDirectory() as t:
            ws = Path(t)
            (ws / ".harness").mkdir()
            _, d = _guard(ws, {"tool_name": "Write",
                               "tool_input": {"file_path": PROTEGIDA, "content": "x"}})
            self.assertEqual("deny", d)

    def test_control_una_lectura_sin_ruta_sigue_pasando(self):
        """Sin esto, «denegar toda carga sin ruta» aprobaría la prueba de abajo y rompería
        cualquier gancho que dispare en herramientas de lectura."""
        with tempfile.TemporaryDirectory() as t:
            ws = Path(t)
            (ws / ".harness").mkdir()
            _, d = _guard(ws, {"tool_name": "Grep", "tool_input": {"pattern": "x"}})
            self.assertEqual("allow", d)

    def test_DEUDA_una_herramienta_de_escritura_sin_ruta_legible_no_se_aprueba(self):
        """**CERRADA en R-03, 2026-09-25.** Era `@expectedFailure`; ahora es regresión.

        Se conserva **íntegra**, con las mismas cinco cargas: es la reproducción histórica del
        defecto y sigue siendo el instrumento con el que se intenta falsificar la propiedad.
        El nombre mantiene el prefijo `DEUDA` a propósito — renombrarla rompería la traza con
        el registro de remediación, que la cita así.

        Las cinco se cierran por **dos** mecanismos distintos, y conviene no confundirlos:

            ruta con tipo dict/lista/numérica   → `campo-ilegible`     (el campo ESTÁ, no sirve)
            tool_input nulo                     → `campo-ilegible`     (contenedor mal formado)
            ruta en un campo no listado         → `escritura-sin-ruta` (el campo está AUSENTE)

        El segundo no lo cubría el primero: los campos conocidos estaban ausentes —que es
        legítimo— y sólo saber que «Write» ESCRIBE convierte esa ausencia en una contradicción.
        """
        for nombre, carga in self.OPACAS:
            with self.subTest(caso=nombre):
                with tempfile.TemporaryDirectory() as t:
                    ws = Path(t)
                    (ws / ".harness").mkdir()
                    codigo, decision = _guard(ws, carga)
                    paso = decision == "allow" or (not decision and codigo == 0)
                    self.assertFalse(
                        paso,
                        f"«{nombre}»: se declara `Write` y su ruta no se pudo leer. "
                        f"Aprobarla es afirmar que no toca nada, sin haberlo mirado")

    @unittest.expectedFailure
    def test_DEUDA_existe_un_contrato_de_admision_versionado(self):
        """Sin versión, una deriva de esquema del runtime es indetectable por construcción."""
        import core.guard as g
        for runtime, forma in g._SHAPES.items():                       # noqa: SLF001
            with self.subTest(runtime=runtime):
                self.assertIn("schema_version", forma,
                              f"«{runtime}» no declara con qué versión de carga habla")


# ── G4 · se autoriza una ruta, no un objeto ──────────────────────────────────────────
class G4_LaDecisionSeVinculaALaRutaYNoAlObjeto(unittest.TestCase):
    """
    PROPERTY:     Lo autorizado en T1 es lo afectado en T5
    CONTRACT:     implícita en decide_write, que resuelve con realpath
    IMPLEMENTATION: core/policy.py::decide_write — resuelve la ruta y descarta la identidad
    UNIT:         test_attacks cubre symlink EN EL MOMENTO de decidir
    ADVERSARIAL:  T1 allow → T2 el sujeto pone un enlace al juez → T3 la misma ruta daría deny
    RUNTIME:      medido: inode distinto entre T1 y T2
    OBSERVATION:  ninguna — nadie comprueba en T5 qué objeto se tocó
    EVIDENCE:     la Decision no lleva dev/inode/tipo/propietario
    INDEPENDENT:  no
    VERDICT:      FAIL estructural

    La defensa contra enlaces simbólicos es CORRECTA en el instante de decidir: `realpath` los
    sigue y `test_attacks` lo prueba. Lo que no existe es la vinculación de la decisión a una
    IDENTIDAD de objeto, y sin ella la ventana entre decisión y ejecución queda abierta por
    construcción — el hook es `PreToolUse` y quien ejecuta es el runtime.

    Cerrarlo del todo exige enforcement (descriptor, `O_NOFOLLOW`, o el kernel). Lo que SÍ se
    puede hacer sin eso es que la decisión REGISTRE sobre qué objeto se emitió, y entonces un
    observador posterior puede detectar la sustitución aunque no haya podido impedirla.
    """

    def test_control_un_enlace_existente_se_detecta_al_decidir(self):
        with tempfile.TemporaryDirectory() as t:
            ws = Path(t).resolve()
            (ws / "gates").mkdir()
            (ws / "gates" / "base.py").write_text("juez", encoding="utf-8")
            (ws / "obra").mkdir()
            os.symlink(ws / "gates" / "base.py", ws / "obra" / "atajo")
            self.assertEqual(DENY, decide_write(Policy.default(), ws, "obra/atajo").outcome)

    def test_DEUDA_la_decision_declara_sobre_que_objeto_se_emitio(self):
        """**CERRADA en R-04, 2026-09-25.** Era `@expectedFailure`; ahora es regresión.

        **Reescrita, y conviene decir por qué.** La versión anterior asertaba
        `hasattr(d, c) for c in ("dev", "inode", "identidad", "objetivo")` — una lista de
        nombres ADIVINADOS antes de que el campo existiera. STEP 1 la clasificó como
        ESPECIFICACIÓN por eso mismo: comprobaba un nombre, no una propiedad, y habría seguido
        roja con la propiedad cerrada sólo porque el campo se llamó `objeto`. También habría
        pasado en verde con un campo vacío que no distinguiera nada.

        Ahora comprueba la PROPIEDAD: que la decisión identifique el objeto, y que esa
        identidad **sirva para distinguir una sustitución**. La versión vieja queda descrita
        aquí en vez de borrada.
        """
        with tempfile.TemporaryDirectory() as t:
            ws = Path(t).resolve()
            (ws / "obra").mkdir()
            (ws / "obra" / "salida.txt").write_text("inocuo", encoding="utf-8")
            d = decide_write(Policy.default(), ws, "obra/salida.txt")
            self.assertEqual(ALLOW, d.outcome)
            self.assertTrue(
                d.objeto,
                "la Decision no registra la identidad del objeto autorizado: si el sujeto lo "
                "sustituye entre la decisión y la ejecución, nada puede detectarlo después")

            # Y que la identidad DISTINGA: mismo nombre, otro objeto. Donde el sistema de
            # ficheros reutiliza el inodo y no da hora de creación —ext4— esto NO se distingue, y
            # es un límite declarado del mecanismo: ver `IDENTIDAD_DISTINGUE_REUSO_DE_INODO`. La
            # mitad de arriba (que la `Decision` LLEVE la identidad) se exige en todas partes.
            if not IDENTIDAD_DISTINGUE_REUSO_DE_INODO:
                self.skipTest("la identidad llega a la Decision, pero este sistema de ficheros "
                              "reutiliza el inodo y no expone hora de creación: distinguir la "
                              "sustitución no aplica aquí (NOT_APPLICABLE, no PASS)")
            (ws / "obra" / "salida.txt").unlink()
            (ws / "obra" / "salida.txt").write_text("sustituido", encoding="utf-8")
            d2 = decide_write(Policy.default(), ws, "obra/salida.txt")
            self.assertNotEqual(
                d.objeto, d2.objeto,
                "la identidad no cambió al sustituir el objeto: no sirve para detectar nada")


# ── G5 · fault containment: ¿qué pasa si refuto se equivoca? ─────────────────────────
class G5_UnaDecisionErroneaNoEstaContenida(unittest.TestCase):
    """
    PROPERTY:     Un error en la decisión no se convierte en un efecto no autorizado
    CONTRACT:     ADR-0011 · TB-3 «el agente no puede escribir en esta zona ni directa ni
                  indirectamente»
    IMPLEMENTATION: ninguna. uid(sujeto) = uid(guardián) = uid(evidencia) = el mismo
    UNIT:         —
    ADVERSARIAL:  el guardián deniega y la escritura ocurre igual
    RUNTIME:      medido
    OBSERVATION:  ninguna
    EVIDENCE:     el diario registra `deny` de una acción que SÍ ocurrió
    INDEPENDENT:  no
    VERDICT:      FAIL — y `FORMAL-MODEL §6.2` ya demuestra que no es cerrable con un uid

    Ésta es la brecha que gobierna a las demás. `deny` es una recomendación que el runtime
    honra; no es una barrera. Por eso el diario puede contener un `deny` junto a la prueba
    física de que el efecto ocurrió, y nada en el sistema detecta esa contradicción.

    La prueba no exige un sandbox: exige lo mínimo que hace la contradicción DETECTABLE —
    que alguien compruebe después si lo denegado ocurrió. Hoy nadie lo hace, porque no hay
    `PostToolUse` ni observador.
    """

    @unittest.expectedFailure
    def test_DEUDA_lo_denegado_no_ocurre_o_al_menos_se_detecta(self):
        with tempfile.TemporaryDirectory() as t:
            ws = Path(t).resolve()
            (ws / ".harness").mkdir()
            (ws / "gates").mkdir()
            juez = ws / "gates" / "base.py"
            juez.write_text("original", encoding="utf-8")

            codigo, decision = _guard(ws, {"tool_name": "Write",
                                           "tool_input": {"file_path": str(juez),
                                                          "content": "alterado"}})
            self.assertEqual("deny", decision, "control: el guardián sí deniega")

            # El sujeto ignora la recomendación. Es lo que puede hacer cualquier proceso con
            # su mismo uid, y es el escenario que ADR-0011 declara imposible.
            juez.write_text("alterado", encoding="utf-8")

            eventos = [json.loads(x) for x in
                       ledger_path(ws).read_text(encoding="utf-8").splitlines() if x.strip()]
            denegados = [e for e in eventos if e.get("outcome") == "deny"]
            self.assertTrue(denegados, "control: la denegación quedó registrada")

            contradicciones = [e for e in eventos if e.get("kind") == "efecto/contradiccion"]
            self.assertTrue(
                contradicciones,
                f"el guardián denegó la escritura, la escritura ocurrió, y el sistema no "
                f"produce ninguna observación de la contradicción. El diario afirma «deny» "
                f"sobre un efecto que SÍ sucedió: {juez.read_text(encoding='utf-8')!r}")


# ── G6 · identidad por transición de confianza ───────────────────────────────────────
class G6_LasTransicionesDeConfianzaNoDeclaranSuPrincipal(unittest.TestCase):
    """
    PROPERTY:     Cada transición de confianza declara quién la ejecutó
    CONTRACT:     ADR-0011 (cuatro fronteras) · page-7 (Run Supervisor)
    IMPLEMENTATION: `role` (auto-declarado por HARNESS_ROLE) · `policy_digest` · `euid`
    UNIT:         test_identidad, test_identidad_politica
    ADVERSARIAL:  core/capabilities.py ya declara «el rol no es un principal criptográfico»
    RUNTIME:      2 de 6 principales presentes en el evento real
    OBSERVATION:  —
    EVIDENCE:     enforcer · observer · verifier · witness: ausentes incluso como CAMPO
    INDEPENDENT:  no
    VERDICT:      FAIL

    La identidad NO se modela aquí como un subsistema: se modela como una propiedad de cada
    transición, que es lo barato y lo correcto. Hoy cuatro de las seis transiciones no tienen
    dónde declarar su principal — ni siquiera para decir «es el mismo uid 501», que ya sería
    una afirmación comprobable y hoy no consta en ninguna parte.
    """

    #: `transicion → clave que la declararía`
    TRANSICIONES = {
        "subject": "role",
        "decisioner": "policy_digest",
        "enforcer": "enforcer",
        "observer": "observer",
        "verifier": "verifier",
        "witness": "witness",
    }

    def _un_evento(self) -> dict:
        with tempfile.TemporaryDirectory() as t:
            ws = Path(t)
            (ws / ".harness").mkdir()
            _guard(ws, {"tool_name": "Write",
                        "tool_input": {"file_path": "nota.txt", "content": "x"}})
            lineas = [x for x in ledger_path(ws).read_text(encoding="utf-8").splitlines()
                      if x.strip()]
            return json.loads(lineas[-1])

    def test_control_el_sujeto_y_el_decisor_si_constan(self):
        ev = self._un_evento()
        self.assertIn("role", ev)
        self.assertIn("policy_digest", ev)

    @unittest.expectedFailure
    def test_DEUDA_toda_transicion_declara_su_principal(self):
        ev = self._un_evento()
        faltan = [t for t, clave in self.TRANSICIONES.items() if clave not in ev]
        self.assertEqual(
            [], faltan,
            f"{len(faltan)} de {len(self.TRANSICIONES)} transiciones de confianza no declaran "
            f"principal: {faltan}. Sin el campo, «lo hizo el mismo uid» no es una afirmación "
            f"que nadie pueda comprobar — es una ausencia")

    @unittest.expectedFailure
    def test_DEUDA_el_sujeto_no_puede_declarar_su_propia_identidad(self):
        """`HARNESS_ROLE` es una variable de entorno que el propio sujeto reescribe.

        No exige criptografía: exige que el evento diga de dónde salió el valor, para que
        «rol declarado por el entorno» y «rol verificado» dejen de ser indistinguibles.
        """
        ev = self._un_evento()
        self.assertIn(
            "role_origen", ev,
            "el evento no dice si el rol lo declaró el sujeto o lo verificó alguien; las dos "
            "cosas se registran igual")


if __name__ == "__main__":
    unittest.main()
