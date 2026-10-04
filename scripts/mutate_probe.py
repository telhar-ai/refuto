#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Sonda de mutación: ¿las pruebas de refuto sujetan lo que refuto afirma?

    python3 scripts/mutate_probe.py            # todas las mutaciones
    python3 scripts/mutate_probe.py --id M4    # una sola
    python3 scripts/mutate_probe.py --json

Qué mide, y por qué no es cobertura
-----------------------------------
La cobertura dice qué líneas se ejecutaron. No dice si alguien se habría enterado de que esas
líneas hacían lo contrario. Una suite puede recorrer el 100 % de un invariante y no sujetarlo:
basta con que ninguna prueba afirme el caso que el invariante impide.

Esta sonda **debilita el juez a propósito** y comprueba si la suite lo nota. Cinco resultados,
y sólo el primero es evidencia:

    MUERTA               la mató el TESTIGO declarado → la propiedad está sujeta
    MUERTA_INCIDENTAL    la mató otra prueba, que no afirma nada sobre la propiedad
    MUERTA_ESTRUCTURAL   rompió el import; las pruebas murieron en el vestíbulo
    MUERTA_SIN_TESTIGO   murió, pero no se declaró quién debía matarla
    VIVA                 todas pasaron → hueco de cobertura semántica

Una mutación VIVA no es un fallo del producto: es un fallo de la evidencia. Significa que esa
propiedad se sostiene hoy porque nadie la ha tocado, no porque algo lo impida.

Por qué hace falta el testigo, y no basta con «algo falló»
----------------------------------------------------------
Medido el 2026-09-22. La primera versión contaba **6/6 MUERTAS** y parecía cobertura perfecta.
Con el árbol en HEAD, las mutaciones de `BLOCKED` y `NOT_EXECUTABLE` las mataba
`test_portabilidad::test_ninguna_escritura_generada_hereda_el_salto_del_sistema` — una prueba
de SALTOS DE LÍNEA. Ninguna prueba aseveraba esas propiedades; morían de rebote.

Declarar por adelantado QUÉ prueba debe matar cada mutación convierte el recuento en evidencia.
Sin esa declaración, el número sube en la dirección cómoda y nadie se entera.

Las mutaciones no son aleatorias
--------------------------------
Cada una es un **camino de falso aseguramiento** concreto, del catálogo de §42: convertir
BLOCKED en integrable, aprobar con hallazgos dentro, dejar pasar un estado inventado, abrir el
guardián. Son las que un desarrollador con prisa introduce sin mala fe y las que un atacante
introduciría con ella. Mutar una `+` en `-` no enseña nada de este sistema.

Seguridad de la sonda
---------------------
El fichero se respalda en memoria, se muta, se ejecuta y se restaura en `finally`. Al terminar
se verifica el sha256 contra el original: si no coincide, la sonda **grita** en vez de salir en
silencio, porque dejar el árbol mutado es peor que no haber medido.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import subprocess
import sys
import tempfile
from dataclasses import dataclass, field
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from core.proc import TEXT_IO

MUERTA = "MUERTA"
#: Murió, pero sin mérito: el fichero dejó de importarse y falló todo. NO es evidencia de que
#: la propiedad esté sujeta — es evidencia de que se rompió el módulo. Contarlo como MUERTA es
#: el falso positivo que hace parecer excelente a una suite que no comprueba nada.
MUERTA_ESTRUCTURAL = "MUERTA_ESTRUCTURAL"
#: Murió, pero la mató otra cosa. Medido el 2026-09-22: con el árbol en HEAD, las mutaciones
#: M4 y M5 —«BLOCKED integra», «NOT_EXECUTABLE integra»— las mataba
#: `test_portabilidad::test_ninguna_escritura_generada_hereda_el_salto_del_sistema`, una prueba
#: de SALTOS DE LÍNEA que no afirma nada sobre veredictos. La propiedad no estaba sujeta: nadie
#: la aseveraba. El recuento «6/6 MUERTAS» lo ocultaba por completo.
#:
#: Importa por dos razones. El mensaje de fallo manda a quien lo lea al sitio equivocado, y si
#: esa prueba ajena cambiara, la propiedad quedaría sin sujetar sin que nada avisara.
MUERTA_INCIDENTAL = "MUERTA_INCIDENTAL"
#: Murió y no se había declarado quién debía matarla. No se puede distinguir de la anterior.
MUERTA_SIN_TESTIGO = "MUERTA_SIN_TESTIGO"
VIVA = "VIVA"
NO_APLICADA = "NO_APLICADA"

#: Señales de que la muerte fue estructural y no semántica. `_FailedTest` es cómo unittest
#: reporta un módulo que no se pudo importar: la prueba nunca llegó a ejecutarse.
RUINA = ("_FailedTest", "SyntaxError", "ImportError", "ModuleNotFoundError",
         "IndentationError")


@dataclass
class Mutacion:
    id: str
    fichero: str
    viejo: str
    nuevo: str
    propiedad: str
    camino: str
    suites: list = field(default_factory=lambda: ["contract", "selftest"])
    #: Qué DEBE pasar. Sin esto la sonda sólo sabe informar, no juzgarse: una sonda que
    #: devolviera MUERTA siempre —por un fallo suyo— daría 6/6 y parecería excelente.
    espera: str = "MUERTA"
    #: QUIÉN debe matarla. Se declara por adelantado, y es la diferencia entre «algo falló» y
    #: «la propiedad está sujeta». Sin testigo, una mutación puede morir a manos de una prueba
    #: que no afirma nada sobre ella — y entonces el recuento miente en la dirección cómoda.
    testigos: tuple = ()


#: Cada entrada nombra la PROPIEDAD que debería morir con ella. Si la mutación sobrevive, esa
#: propiedad no está demostrada — está supuesta.
MUTACIONES = [
    Mutacion(
        id="M1",
        fichero="core/model.py",
        viejo="        if self.status == PASS and self.findings:",
        nuevo="        if False and self.status == PASS and self.findings:",
        propiedad="un resultado con hallazgos no puede aprobar",
        camino="PASS falso: la puerta emite hallazgos y aprueba igual",
        testigos=("test_pass_con_hallazgos_se_rechaza_al_construir",),
    ),
    Mutacion(
        id="M2",
        fichero="core/model.py",
        viejo='        if self.status == NOT_APPLICABLE and not (self.measure or "").strip():',
        nuevo='        if False and self.status == NOT_APPLICABLE and not (self.measure or "").strip():',
        propiedad="NOT_APPLICABLE exige motivo escrito",
        camino="NOT_APPLICABLE abusado: «no aplica» sin demostrar el ámbito vacío",
        testigos=("test_no_aplica_exige_motivo_declarado",),
    ),
    Mutacion(
        id="M3",
        fichero="core/model.py",
        viejo="        if self.status not in STATUSES:",
        nuevo="        if False and self.status not in STATUSES:",
        propiedad="sólo existen los estados del vocabulario",
        camino="estado inventado: «OK», «DONE», «GREEN» se cuelan sin ser ninguno de los seis",
        testigos=("test_un_estado_invalido_se_rechaza_al_construir",),
    ),
    Mutacion(
        id="M4",
        fichero="core/evidence.py",
        viejo="    if BLOCKED in statuses:",
        nuevo="    if False and BLOCKED in statuses:",
        propiedad="BLOCKED no permite integrar",
        camino="BLOCKED convertido en PASS: lo que no se pudo comprobar pasa por comprobado",
        suites=["contract", "selftest", "unit"],
        testigos=("test_una_corrida_con_bloqueo_no_es_integrable",),
    ),
    Mutacion(
        id="M5",
        fichero="core/evidence.py",
        viejo="    if NOT_EXECUTABLE in statuses:",
        nuevo="    if False and NOT_EXECUTABLE in statuses:",
        propiedad="NOT_EXECUTABLE no permite integrar",
        camino="NOT_EXECUTABLE convertido en PASS: ni se sabe cuántos fallos hay, y se integra",
        suites=["contract", "selftest", "unit"],
        testigos=("test_una_corrida_con_error_de_ejecucion_no_es_integrable",),
    ),
    Mutacion(
        id="M6",
        fichero="core/policy.py",
        viejo="def decide_write(policy: Policy, workspace: Path, target: str, content: str = \"\") -> Decision:",
        nuevo=("def decide_write(policy: Policy, workspace: Path, target: str, content: str = \"\") -> Decision:\n"
               "    return Decision(outcome=\"allow\", reason=\"\", rule=\"\")  # MUTACIÓN"),
        propiedad="el guardián deniega la escritura protegida",
        camino="política puenteada: toda escritura se permite, incluida la del propio juez",
        testigos=("test_escribir_la_politica_se_deniega",),
        suites=["unit", "adversarial", "selftest"],
    ),

    Mutacion(
        id="M7",
        fichero="core/policy.py",
        viejo="        if not doc.get(\"extends\"):",
        nuevo="        if True or not doc.get(\"extends\"):",
        propiedad="la política efectiva que aplica el guardián resuelve `extends`",
        camino="herencia analizable pero no vigente: el cliente declara restricciones y "
               "ningún proyecto las aplica, mientras la herramienta informa de que la "
               "herencia está bien",
        suites=["adversarial"],
        testigos=("test_una_regla_que_SOLO_esta_en_el_padre_se_aplica",),
    ),

    Mutacion(
        id="M8",
        fichero="core/guard.py",
        viejo="    return ident.efectivo if ident else \"\"",
        nuevo="    return \"\"",
        propiedad="cada decisión del guardián cita la política efectiva que la produjo",
        camino="evidencia sin procedencia de política: se sabe QUÉ regla denegó y no de qué "
               "política salió — y con herencia la regla pudo venir del cliente",
        suites=["unit"],
        testigos=("test_una_denegacion_lleva_el_digest_efectivo",),
    ),

    Mutacion(
        id="M9",
        fichero="refuto.py",
        viejo="    write_json(ctx.policy_path, doc)",
        nuevo="    write_json(ctx.policy_path, {**Policy.default().to_dict(), **doc})",
        propiedad="un espacio que se da de alta heredando declara lo SUYO y nada más",
        camino="la copia vuelve por la puerta de atrás: el hijo hereda Y arrastra la norma "
               "entera del padre. Todo sigue funcionando —la cadena resuelve, el guardián "
               "deniega igual— y por eso no lo ve ninguna prueba de comportamiento. Lo que se "
               "pierde es que lo copiado diverge en silencio en cuanto alguien lo toca, que "
               "es el defecto que la herencia existía para cerrar",
        suites=["adversarial"],
        testigos=("test_el_hijo_declara_lo_suyo_y_NADA_mas",),
    ),

    # ── C-02 · integridad del propio artefacto de evidencia ─────────────────────────
    #
    # La sonda cubría el vocabulario de estados, el veredicto y la herencia. No cubría el
    # DIARIO, que es donde vive todo lo demás — y ahí estaba R-02: borrar el fichero pasaba
    # la verificación incluso contra un ancla publicada. Una sonda que no ataca el soporte de
    # la evidencia mide la disciplina del juez y no su memoria.
    Mutacion(
        id="M-LEDGER-01",
        fichero="core/evidence.py",
        viejo='            "ok": not expectativa, "estado": AUSENTE, "eventos": 0, "legado": 0,',
        nuevo='            "ok": True, "estado": AUSENTE, "eventos": 0, "legado": 0,',
        propiedad="un diario AUSENTE no aprueba cuando se esperaba evidencia",
        camino="la manipulación más simple que existe: borrar el fichero. Con esta mutación "
               "vuelve R-02 — el artefacto de evidencia no existe y la verificación aprueba, "
               "aunque haya un ancla publicada que demuestra que hubo eventos",
        suites=["adversarial"],
        testigos=("test_11_borrar_el_diario_entero",
                  "test_R02_borrar_el_diario_entero_se_detecta_con_ancla"),
    ),
    Mutacion(
        id="M-LEDGER-02",
        fichero="core/evidence.py",
        viejo="    if hay_ancla and esperado not in vistas:",
        nuevo="    if False and hay_ancla and esperado not in vistas:",
        propiedad="una cadena coherente que no contiene el ancla publicada no aprueba",
        camino="sustitución de la historia: reescribir el diario entero, cambiarlo por el de "
               "otro espacio o hacer rollback produce cadenas internamente válidas. El ancla "
               "es lo único que las distingue, y esta mutación la ignora",
        suites=["adversarial"],
        testigos=("test_05_reescribir_todo_coherente",
                  "test_06_sustituir_por_otro_ledger_valido",
                  "test_09_rollback_a_version_anterior"),
    ),
    Mutacion(
        id="M-EVIDENCE-03",
        fichero="core/evidence.py",
        viejo="    if eventos_minimos and n < eventos_minimos:",
        nuevo="    if False and eventos_minimos and n < eventos_minimos:",
        propiedad="una cadena íntegra sobre evidencia incompleta no aprueba",
        camino="cobertura fingida: la cadena cierra y trae menos eventos de los exigidos. Es "
               "la regla de suficiencia en su forma mínima — integridad no es suficiencia, y "
               "colapsarlas deja que «miré poco» pase por «no encontré nada»",
        suites=["adversarial"],
        testigos=("test_menos_eventos_de_los_exigidos_no_aprueba",),
    ),

    # ── controles de la propia sonda ────────────────────────────────────────────────
    #
    # Sin éstos, «6/6 MUERTAS» no es un resultado: es una cifra sin instrumento calibrado.
    # Una sonda que informara MUERTA pase lo que pase daría exactamente ese 6/6.

    Mutacion(
        id="NC1",
        fichero="core/model.py",
        viejo="    @property\n    def passing(self) -> bool:",
        nuevo="    @property  # control negativo: cambio semánticamente nulo\n    def passing(self) -> bool:",
        propiedad="(control negativo) un comentario no cambia el comportamiento",
        camino="ninguno: esta mutación NO debe matar nada",
        espera=VIVA,
        suites=["contract"],
    ),
    Mutacion(
        id="NC2",
        fichero="core/model.py",
        viejo="    @property\n    def passing(self) -> bool:",
        nuevo="    @property\n    def passing(self) -> bool:\n        ( sintaxis rota",
        propiedad="(control de ruina) un fichero que no importa hace fallar TODO",
        camino="ninguno: demuestra que MUERTA se puede producir sin mérito de las pruebas",
        espera=MUERTA_ESTRUCTURAL,
        suites=["contract"],
    ),
]


def _sha(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


# ── diario de la sonda: sobrevivir a que nos maten ───────────────────────────────────
#
# `finally` no corre con SIGKILL. La primera versión de esta sonda se quedó sin proceso a mitad
# de una mutación y **dejó `core/evidence.py` mutado en el árbol** — medido el 2026-09-22. Una
# herramienta de assurance que puede corromper en silencio el árbol que audita es peor que no
# tenerla: el siguiente que ejecute las pruebas medirá un juez debilitado y no lo sabrá.
#
# Por eso el respaldo se escribe AL DISCO antes de tocar nada, y la sonda se repara sola al
# arrancar. El diario vive fuera del espacio a propósito: dentro tendría que ser un artefacto
# versionado o una ruta ignorada, y las dos cosas son peores que un temporal con nombre estable.
_DIARIO = Path(tempfile.gettempdir()) / f"refuto-mutacion-{_sha(str(ROOT).encode())[:12]}"


def _abrir_diario(ruta: Path, original: bytes) -> None:
    _DIARIO.mkdir(parents=True, exist_ok=True)
    (_DIARIO / "backup").write_bytes(original)
    (_DIARIO / "meta.json").write_text(json.dumps(
        {"fichero": str(ruta), "sha": _sha(original), "pid": os.getpid()}),
        encoding="utf-8", newline="\n")


def _cerrar_diario() -> None:
    for n in ("backup", "meta.json"):
        (_DIARIO / n).unlink(missing_ok=True)


def reparar_si_hace_falta() -> str:
    """Si una ejecución anterior murió mutando, deshacerlo ANTES de medir nada.

    Devuelve un aviso si hubo que reparar. Medir sobre un árbol que quedó mutado por una sonda
    difunta daría cifras perfectamente formateadas y completamente falsas.
    """
    meta = _DIARIO / "meta.json"
    if not meta.is_file():
        return ""
    try:
        doc = json.loads(meta.read_text(encoding="utf-8"))
        ruta = Path(doc["fichero"])
        original = (_DIARIO / "backup").read_bytes()
    except (OSError, ValueError, KeyError) as exc:
        return (f"hay un diario de mutación ilegible en {_DIARIO} ({type(exc).__name__}). "
                f"NO se puede afirmar que el árbol esté intacto: revíselo a mano.")
    actual = ruta.read_bytes() if ruta.is_file() else b""
    if _sha(actual) == doc["sha"]:
        _cerrar_diario()
        return ""
    ruta.write_bytes(original)
    _cerrar_diario()
    return (f"REPARADO: {ruta} había quedado mutado por una sonda anterior (pid {doc['pid']}) "
            f"y se restauró. Cualquier medición hecha entre medias es INVÁLIDA.")


def _correr(suites: list, etiqueta: str = "") -> tuple[bool, str]:
    """Devuelve (todas_pasaron, salida_completa).

    Caché de bytecode aislada por ejecución, y no es una precaución de manual
    ------------------------------------------------------------------------
    Python invalida un `.pyc` comparando **(mtime, tamaño)** del fuente. Las mutaciones M2 y M3
    insertan la MISMA cadena (`"False and "`) en el MISMO fichero, así que los dos ficheros
    mutados pesan exactamente lo mismo — medido: 16 509 bytes los dos. En un ejecutor rápido
    ambas escrituras caen dentro del mismo segundo, y entonces el intérprete sirve el `.pyc`
    de la mutación ANTERIOR como si fuera el de la actual.

    Ocurrió de verdad. CI (ubuntu-latest, Python 3.13, corrida 35805060715) informó
    `M3 … MUERTA_INCIDENTAL`, muerta por `test_no_aplica_exige_motivo_declarado` —que es el
    testigo de **M2**, no de M3— mientras el testigo de M3 pasaba tranquilamente. La sonda
    estaba midiendo una mutación y ejecutando otra. En local nunca se reprodujo porque entre
    mutación y mutación pasan segundos.

    Una sonda que puede atribuir el resultado de una mutación a otra no mide cobertura
    semántica: fabrica un número. `PYTHONPYCACHEPREFIX` apunta cada ejecución a un directorio
    nuevo, así que siempre se compila el fuente que hay en disco.
    """
    argv = [sys.executable, str(ROOT / "refuto.py"), "selftest"]
    for s in suites:
        argv += ["--suite", s]
    with tempfile.TemporaryDirectory(prefix=f"refuto-pyc-{etiqueta or 'x'}-") as pyc:
        env = dict(os.environ, PYTHONPYCACHEPREFIX=pyc)
        p = subprocess.run(argv, capture_output=True, cwd=str(ROOT), timeout=900,
                           env=env, **TEXT_IO)
    return p.returncode == 0, (p.stdout or "") + (p.stderr or "")


def _clasificar_muerte(salida: str, testigos: tuple) -> tuple[str, list]:
    """¿Murió porque la prueba que debía afirmarlo lo afirmó — o por otra cosa?

    Tres formas de morir sin mérito, y las tres se contaban como éxito:

        ESTRUCTURAL   el módulo dejó de importarse; las pruebas murieron en el vestíbulo
        INCIDENTAL    la mató una prueba que no afirma nada sobre la propiedad
        SIN_TESTIGO   no se declaró quién debía matarla, así que no se puede distinguir

    Sólo `MUERTA` es evidencia de que la propiedad está sujeta.
    """
    culpables = [ln.strip() for ln in salida.splitlines()
                 if ln.startswith(("FAIL:", "ERROR:"))]
    if any(s in salida for s in RUINA):
        return MUERTA_ESTRUCTURAL, culpables[:20]
    if not testigos:
        return MUERTA_SIN_TESTIGO, culpables[:20]
    if any(t in c for c in culpables for t in testigos):
        return MUERTA, culpables[:20]
    return MUERTA_INCIDENTAL, culpables[:20]


def probar(m: Mutacion) -> dict:
    ruta = ROOT / m.fichero
    original = ruta.read_bytes()
    sha_original = _sha(original)
    texto = original.decode("utf-8")

    apariciones = texto.count(m.viejo)
    if apariciones != 1:
        # `conforme=False` siempre: NO_APLICADA nunca cumple lo esperado, porque no se midió
        # nada. Un ámbito vacío no aprueba, tampoco aquí. Y el estado del fichero se registra:
        # si el ancla falta porque alguien lo dejó mutado, el diagnóstico tiene que decirlo en
        # vez de quedarse en «no se aplicó».
        return {"id": m.id, "estado": NO_APLICADA, "espera": m.espera, "conforme": False,
                "propiedad": m.propiedad, "camino": m.camino, "fichero": m.fichero,
                "culpables": [], "testigos": list(m.testigos),
                "detalle": f"el ancla aparece {apariciones} veces, se exige exactamente 1. "
                           f"NO se concluye nada. sha del fichero: {sha_original[:16]} — "
                           f"si esperaba 1, compruebe si el fichero quedó mutado por una "
                           f"ejecución anterior (`git status {m.fichero}`)"}
    _abrir_diario(ruta, original)
    try:
        ruta.write_bytes(texto.replace(m.viejo, m.nuevo, 1).encode("utf-8"))
        paso, salida = _correr(m.suites, etiqueta=m.id)
    finally:
        ruta.write_bytes(original)
        if _sha(ruta.read_bytes()) != sha_original:
            raise SystemExit(f"FATAL: {m.fichero} no se restauró. Restaure con `git restore`.")
        _cerrar_diario()

    if paso:
        estado, culpables = VIVA, []
    else:
        estado, culpables = _clasificar_muerte(salida, m.testigos)

    return {"id": m.id, "estado": estado, "espera": m.espera,
            "conforme": estado == m.espera,
            "propiedad": m.propiedad, "camino": m.camino, "fichero": m.fichero,
            "suites": m.suites, "culpables": culpables, "testigos": list(m.testigos),
            "detalle": "\n".join(salida.strip().splitlines()[-3:])}


def main() -> int:
    ap = argparse.ArgumentParser(description="sonda de mutación del juez")
    ap.add_argument("--id", action="append", help="sólo estas mutaciones")
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--porque", action="store_true",
                    help="qué prueba mató a cada mutación (la atribución, no sólo el recuento)")
    o = ap.parse_args()

    aviso = reparar_si_hace_falta()
    if aviso:
        print(f"  ⚠ {aviso}\n", file=sys.stderr)

    objetivo = [m for m in MUTACIONES if not o.id or m.id in o.id]
    if not objetivo:
        print("ninguna mutación seleccionada. Ámbito vacío no aprueba: esto es un error.",
              file=sys.stderr)
        return 1

    filas = []
    for m in objetivo:
        if not o.json:
            print(f"  {m.id} … ", end="", flush=True)
        r = probar(m)
        filas.append(r)
        if not o.json:
            print(f"{r['estado']:<20} {'✓' if r['conforme'] else '✗ ESPERABA ' + r['espera']}")

    controles = [r for r in filas if r["id"].startswith("NC")]
    reales = [r for r in filas if not r["id"].startswith("NC")]
    calibrada = all(r["conforme"] for r in controles) and bool(controles)

    if o.json:
        print(json.dumps({"schema": "harness.mutation/v1", "calibrada": calibrada,
                          "mutaciones": filas}, ensure_ascii=False, indent=2))
    else:
        if not controles:
            print("\n  ⊘ sin controles de calibración: el resultado es INCONCLUSIVE, no un dato.")
        elif not calibrada:
            print("\n  ✗ SONDA NO CALIBRADA — los controles no dieron lo esperado.")
            print("    Mientras no lo den, NINGUNA cifra de esta sonda es evidencia.")
        else:
            print(f"\n  ✓ sonda calibrada ({len(controles)} controles conformes)")
        vivas = [r for r in reales if r["estado"] == VIVA]
        estruct = [r for r in reales if r["estado"] == MUERTA_ESTRUCTURAL]
        incid = [r for r in reales if r["estado"] == MUERTA_INCIDENTAL]
        sintest = [r for r in reales if r["estado"] == MUERTA_SIN_TESTIGO]
        noap = [r for r in reales if r["estado"] == NO_APLICADA]
        buenas = [r for r in reales if r["estado"] == MUERTA]
        print(f"  {len(buenas)}/{len(reales)} mutaciones muertas POR SU TESTIGO"
              f"{' (el resto, abajo)' if len(buenas) != len(reales) else ''}")
        for r in vivas:
            print(f"\n  ✗ VIVA · {r['id']} — {r['fichero']}")
            print(f"      propiedad no sujeta: {r['propiedad']}")
            print(f"      camino de falso aseguramiento: {r['camino']}")
        for r in estruct:
            print(f"\n  ✗ MUERTA_ESTRUCTURAL · {r['id']} — rompió el módulo, no lo detectó "
                  f"una prueba. No es evidencia de que «{r['propiedad']}» esté sujeta.")
        # En los casos NO conformes se imprime la lista COMPLETA, no `culpables[0]`.
        # Medido el 2026-09-23: en CI, M3 salió `MUERTA_INCIDENTAL` y el informe mostraba un
        # solo culpable, así que era imposible saber desde el log si el testigo había fallado
        # también o no. Un diagnóstico que no deja reconstruir la decisión obliga a adivinar,
        # y adivinar sobre el instrumento es lo que esta sonda existe para no tener que hacer.
        for r in incid:
            print(f"\n  ✗ MUERTA_INCIDENTAL · {r['id']} — la mató una prueba que NO afirma "
                  f"«{r['propiedad']}».")
            print(f"      esperaba a: {', '.join(r['testigos'])}")
            print(f"      fallaron {len(r['culpables'])}:")
            for c in r["culpables"]:
                print(f"        {c}")
            print("      El testigo NO está entre ellas: la propiedad no está sujeta.")
        for r in sintest:
            print(f"\n  ⊘ MUERTA_SIN_TESTIGO · {r['id']} — murió, pero no se declaró quién "
                  f"debía matarla, así que no se distingue de una muerte incidental.")
            print(f"      fallaron {len(r['culpables'])}:")
            for c in r["culpables"]:
                print(f"        {c}")
        for r in noap:
            print(f"\n  ⊘ NO_APLICADA · {r['id']}: {r['detalle']}")
        if buenas and o.porque:
            print("\n  quién las mató:")
            for r in buenas:
                # El testigo, no el primer fallo de la lista. Mostrar `culpables[0]` señalaba a
                # una prueba cualquiera y hacía parecer incidental una muerte que no lo era.
                testigo = next((c for c in r["culpables"]
                                if any(t in c for t in r["testigos"])), "")
                otros = len(r["culpables"]) - (1 if testigo else 0)
                print(f"    {r['id']}: {testigo or '(sin detalle)'}")
                if otros > 0:
                    print(f"          (+{otros} fallo(s) colateral(es), no son el testigo)")

    # Sin calibración no hay aprobado, por muchas que hayan muerto.
    return 0 if calibrada and all(r["conforme"] for r in filas) else 1


if __name__ == "__main__":
    raise SystemExit(main())
