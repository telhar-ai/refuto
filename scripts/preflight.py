#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Preflight: todo lo que hay que poder afirmar antes de empujar.

Por qué existe, y por qué no es «ejecuta los tests»
---------------------------------------------------
Los controles de este repositorio estaban repartidos: la suite en un sitio, cuatro `check_*.py`
en otro, los escáneres sólo en CI, y el gancho `pre-push` haciendo **una** cosa —impedir un
empujón a `main`— sin comprobar nada. Medido el 2026-09-25: `.githooks/pre-push` no ejecutaba
ni una prueba, así que «pasó el preflight» no significaba nada y el primer sitio donde algo se
caía era el runner, cinco minutos después y con el commit ya publicado.

Lo que esto añade no es rigor nuevo: es **un solo sitio** donde consta qué hay que cumplir, con
el mismo vocabulario de seis estados que el resto del producto y con la regla que lo ordena todo:

    una herramienta AUSENTE da `BLOCKED`, nunca `PASS`

Ésa no es una precaución teórica. El 2026-09-24 se midió `G-SECURITY` dando `PASS` con `trivy`
caído: no escaneó nada y aprobó, porque su umbral sólo cubría «la herramienta no está» y no «la
herramienta está y reventó». Aquí los dos casos son `BLOCKED`.

Bloquea, informa, y la diferencia se declara
--------------------------------------------
`BLOQUEA` es lo que tiene que estar verde para empujar: si no lo está, el cambio no sale.
`INFORMA` se mide y se imprime, y no retiene nada — porque su estado no lo decide este cambio.
Hoy **ningún control usa `INFORMA`**, y eso es un cambio del 2026-09-25 que conviene leer.

`refuto verify` estaba ahí, con el motivo «deuda declarada del proyecto, no de este cambio». El
motivo era cierto —comprobado con `git blame`: los 18 hallazgos de `G-SECURITY` vienen de
`e28249c`, en `main`— y **nada lo comprobaba**. Un tier estático afirma para siempre algo que se
midió una vez: el día que un cambio rompiera una puerta nueva, el preflight lo habría impreso
como informativo y habría dado `PASS`. Es el mismo defecto que este repositorio persigue en
otros sitios —una lista de excepciones que ya no describe nada, una cifra con fecha que dejó de
ser cierta— aplicado al control que decide si algo sale.

Ahora la deuda se declara **puerta a puerta** en `DEUDA_DECLARADA`, con su motivo, y `verify`
es `BLOQUEA`: lo perdonado se puede enumerar, discutir y vaciar, y una puerta en rojo que no
esté en esa tabla retiene el empujón. El mecanismo `INFORMA` se conserva porque el problema que
resuelve es real y volverá a aparecer; que hoy no lo use nadie se dice aquí en vez de dejar un
tier que parece en uso.

Salida
------
Texto para una persona, y `--json` con el sobre `harness.envelope/v1` — mismo contrato que las
órdenes de `refuto`, así que CI y un agente lo leen sin caso especial. El código de salida lo
deriva el estado agregado; nunca se elige a mano.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import subprocess  # nosec B404 — ejecutar los comprobadores ES el trabajo de este guion
import sys
import time
from pathlib import Path

RAIZ = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(RAIZ))

from core.envelope import AGENTE, MAQUINA, PERSONA, Siguiente, envelope  # noqa: E402
from core.model import BLOCKED, FAIL, PASS, provenance  # noqa: E402
from core.proc import TEXT_IO, force_utf8_io  # noqa: E402

BLOQUEA, INFORMA = "bloquea", "informa"

#: Supresiones de `bandit`, cada una con su motivo. Se declaran aquí y no en un fichero aparte
#: porque el motivo tiene que vivir donde se aplica la decisión.
#:
#: Medido el 2026-09-25: sin supresiones, `bandit` daba **70 hallazgos y cero defectos reales**.
#: 61 eran la familia `subprocess` —que es literalmente el trabajo de refuto: sondear agentes—,
#: 5 eran `B105` disparando sobre `PASS = "PASS"` y sobre los NOMBRES de variables de entorno
#: (`MI_SERVICIO_AUTH_TOKEN`), y 2 eran `B108` sobre un patrón de ruta de la política, que es
#: política y no un fichero temporal. Un control con 70 falsos positivos se desactiva en una
#: semana; con estas seis supresiones queda en 0 y sirve para lo que viene después.
_BANDIT_SKIP = {
    "B404": "importar `subprocess` es el trabajo de refuto: sondea agentes y los interroga",
    "B603": "se invoca sin shell y con `argv` de lista, que es la forma segura",
    "B607": "la ruta parcial es deliberada: se resuelve por PATH para encontrar el agente "
            "instalado, y `core.probe` verifica la firma del binario que encuentra",
    "B105": "dispara sobre `PASS = \"PASS\"` y sobre NOMBRES de variables de entorno. El "
            "secreto real lo busca `gitleaks`, que es la herramienta para eso",
    "B108": "dispara sobre `/tmp/claude-*/**`, que es un patrón de `external_write_allow`, no "
            "un fichero temporal que se cree",
    "B110": "`try/except/pass` deliberado y documentado donde el fallo no debe propagarse "
            "(cerrar descriptores, restaurar propiedad)",
}

#: Ficheros donde una coincidencia sería LEGÍTIMA. **Vacío, y medido**: el 2026-09-25, sobre el
#: árbol rastreado, la expresión de abajo no casa con ninguno. Cero excepciones es el estado más
#: fuerte que puede tener una lista de excepciones, y dejarla vacía lo hace verificable — si
#: mañana aparece una, alguien tendrá que escribirla aquí y explicar por qué.
#:
#: La primera versión llevaba cuatro entradas (`AGENTS.md`, `core/inventory.py`…) porque la
#: expresión era más amplia y marcaba a los ficheros que ENUNCIAN la regla o la detectan. Al
#: afinarla dejaron de casar, y una lista de excepciones que ya no describe nada es como
#: envejecen los controles hasta ser adorno: se conserva el hueco y se pierde el motivo.
_PERSONALES_PERMITIDOS: set = set()

#: Lo que `AGENTS.md` prohíbe, literalmente: «rutas `/Users/…`, correos, hosts internos,
#: direcciones privadas».
#:
#: `/home/…` se quedó FUERA a propósito, y por una medición: la primera versión lo incluía y
#: marcó `tests/unit/test_govern.py` y `tests/unit/test_hygiene.py`, cuyas rutas son
#: `/home/persona/Documentos` y `/home/x/repo` — es decir, exactamente los marcadores de
#: posición genéricos que la regla PRESCRIBE. Un detector que marca el cumplimiento de la norma
#: enseña a ignorarlo, que es como mueren los controles. `/Users/` sí es inequívoco: es el
#: directorio personal real de macOS y el ejemplo que la propia regla cita.
#:
#: Qué faltaba, y por qué importa que faltara
#: -------------------------------------------
#: La primera versión cubría `/Users/…` y tres dominios de correo personal, y el control se
#: llamaba —y se reportaba— `datos-personales`. La norma que su propio docstring CITA prohíbe
#: además correos corporativos, hosts internos y direcciones privadas. Un control cuyo alcance
#: declarado excede al medido no es incompleto: es un `PASS` que afirma más de lo que comprobó,
#: y este repositorio existe para no emitir esos. Medido el 2026-09-25 sobre el árbol rastreado:
#: con la expresión ampliada el resultado sigue siendo **cero** ficheros, así que ampliarla no
#: cuesta una excepción — sólo deja de mentir sobre lo que cubre.
#:
#: Los correos se aceptan en cualquier dominio salvo los de EJEMPLO que la propia regla
#: prescribe (`example.com`, `example-org`…) y los `noreply` de los agentes, que son la forma
#: correcta de firmar un commit y no identifican a nadie.
_PERSONALES = re.compile(
    r"/Users/[A-Za-z0-9._-]+/"
    # correo de cualquier dominio; las exenciones van abajo, no en el patrón, para poder
    # nombrarlas de una en una
    r"|[A-Za-z0-9._%+-]+@[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?(?:\.[A-Za-z]{2,})+"
    # direcciones privadas RFC 1918 y enlace-local
    r"|\b(?:10|192\.168|172\.(?:1[6-9]|2[0-9]|3[01])|169\.254)\.\d{1,3}\.\d{1,3}\b"
    # hosts internos: los sufijos que sólo existen dentro de una red.
    #
    # `.local` NO está, y es la misma clase de decisión que dejar fuera `/home/…`. Medido el
    # 2026-09-25 con él incluido: **47 coincidencias y cero hosts** — `settings.local.json`
    # (44), `hooks.local.json` (2) y `.env.local` (1). `.local` es a la vez el TLD de mDNS y la
    # convención más extendida para «variante local de este fichero de configuración», así que
    # marcarlo pone en rojo ocho ficheros del repositorio por su nombre. Un detector que marca
    # lo normal enseña a ignorarlo. Los demás sufijos no tienen ese uso.
    r"|\b[A-Za-z0-9-]+\.(?:internal|intranet|corp|lan|home\.arpa)\b")

#: Coincidencias de `_PERSONALES` que NO son un dato de nadie. Se exceptúan por VALOR y no
#: ensanchando el patrón: una excepción que se puede enumerar se puede discutir, y una expresión
#: regular con seis alternativas de escape no.
_PERSONALES_INOCUOS = re.compile(
    r"@(?:example|example-org|ejemplo|test|localhost|mi-servicio)\b"
    r"|@[A-Za-z0-9.-]*\.example(?:\.[A-Za-z]{2,})?\b"
    r"|\bnoreply@|\bnoreply\.|@users\.noreply\."
    r"|\b(?:user|usuario|persona|alguien|nombre|correo|agente)@")


#: Nombres de cuenta que NO identifican a una persona, exceptuados por VALOR y no ensanchando
#: nada. Son las cuentas de las máquinas donde esto corre solo: en GitHub Actions `$USER` es
#: `runner` y `$HOME` es `/home/runner`, y la palabra «runner» aparece en **29** ficheros del
#: árbol por motivos legítimos (`runs-on`, `tests/runner.py`, `${{ runner.os }}`). Medido el
#: 2026-09-29. Sin esta lista el control saldría rojo en CI por 29 ficheros y su primera lección
#: sería que hay que ignorarlo.
_CUENTAS_NO_PERSONALES = frozenset({"runner", "runneradmin", "root", "ubuntu", "codespace",
                                    "vscode", "node", "docker", "admin", "user", "build"})


def _identidad_local() -> list:
    """El nombre de la cuenta de ESTA máquina, leído del entorno. Nunca escrito en el repositorio.

    Esto se lee en tiempo de ejecución y no se almacena en ninguna lista, a propósito: la lección
    de `_MARCAS_DE_CREDENCIAL` —publicar el inventario es publicar el mapa— vale igual aquí.
    Escribir el nombre de la persona en el control para poder detectarlo sería filtrarlo.

    El NOMBRE de la persona (`git config user.name`) queda deliberadamente FUERA: aparece en
    `NOTICE` y en `pyproject.toml`, que es donde la autoría debe estar. Lo que no tiene ningún
    sitio legítimo en el árbol es la **cuenta del sistema**, que identifica una máquina.
    """
    cuentas = {os.environ.get("USER", ""), os.environ.get("LOGNAME", ""),
               os.path.basename(os.path.expanduser("~"))}
    return sorted({c for c in cuentas
                   if len(c) >= 4 and c.lower() not in _CUENTAS_NO_PERSONALES})


def _publicables() -> tuple:
    """Los ficheros que este repositorio PUBLICARÍA. `(codigo, lista)`.

    `git ls-files -z` a secas listaba sólo lo ya versionado, y esa diferencia no es teórica:
    **este mismo control dio `PASS` con «0 ficheros con coincidencia»** mientras
    `tests/adversarial/test_elevacion.py` —un fichero nuevo, sin `git add`, camino del mismo
    commit— llevaba 16 veces el nombre de la cuenta de quien lo escribió. Medido el 2026-09-29.

    Un control que sólo mira lo ya versionado avisa **después** de que el dato esté en el
    historial, que es exactamente cuando ya no sirve: un dato personal publicado no se retira
    con un commit. `--others --exclude-standard` añade lo no rastreado que `.gitignore` NO
    excluye, que es la definición de «lo que saldría en el próximo `git add -A`».
    """
    try:
        p = subprocess.run(  # nosec B603,B607
            ["git", "ls-files", "-z", "--cached", "--others", "--exclude-standard"],
            cwd=RAIZ, capture_output=True, timeout=60, **TEXT_IO)
    except (OSError, subprocess.SubprocessError) as exc:
        return 2, f"no se pudo listar lo publicable: {exc}"
    if p.returncode != 0:
        return 2, f"`git ls-files` salió con {p.returncode}: no se pudo comprobar"
    return 0, [r for r in (p.stdout or "").split("\0") if r.strip()]


def _datos_personales() -> tuple:
    """La regla de `AGENTS.md` aplicada a todo lo que se PUBLICARÍA. `(codigo, salida)`.

    «Este repositorio es público. No entran nombres de clientes o empleadores, rutas `/Users/…`,
    correos, hosts internos…». Era una regla escrita y sin nada que la comprobara, y el
    repositorio pasó a público el 2026-09-25 — momento en el que dejar de comprobarla cuesta de
    verdad.

    Se compara el CONJUNTO de ficheros, no un recuento: dos cambios que se compensan darían el
    mismo número. Y el alcance es `_publicables()`, no el árbol rastreado: ver allí por qué la
    diferencia dejó pasar un caso real.
    """
    codigo, rutas = _publicables()
    if codigo:
        return codigo, rutas

    cuentas = _identidad_local()
    encontrados = set()
    for rel in rutas:
        ruta = RAIZ / rel
        try:
            texto = ruta.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue                      # binario o ilegible: no es texto publicable
        # Coincidencia a coincidencia: basta UNA que no sea de ejemplo para marcar el fichero,
        # y un fichero lleno de `user@example.com` no se marca por tenerlos.
        if any(not _PERSONALES_INOCUOS.search(m.group(0))
               for m in _PERSONALES.finditer(texto)):
            encontrados.add(rel)
        # La cuenta del sistema, que ninguna expresión regular puede describir: un nombre de
        # cuenta no tiene forma. Sólo se puede comparar contra la de esta máquina.
        elif any(c in texto for c in cuentas):
            encontrados.add(rel)

    inesperados = sorted(encontrados - _PERSONALES_PERMITIDOS)
    desaparecidos = sorted(_PERSONALES_PERMITIDOS - encontrados)
    # El ALCANCE se declara en la salida, en verde y en rojo. Sin esto, el mismo `PASS` significa
    # dos cosas distintas —«se comprobó también la cuenta» y «no había cuenta que comprobar»— y
    # sólo una de ellas cubre lo que el nombre de la puerta promete. Ésa es precisamente la
    # confusión que este control ya cometió una vez.
    alcance = (f"{len(rutas)} fichero(s) publicables · patrón + cuenta del sistema"
               if cuentas else
               f"{len(rutas)} fichero(s) publicables · patrón SOLO: esta máquina no expone una "
               f"cuenta personal en el entorno, así que esa mitad no se comprobó")
    if inesperados:
        return 1, ("ficheros con datos de una máquina o una persona: "
                   + ", ".join(inesperados[:8]) + f" [{alcance}]")
    if desaparecidos:
        # No es un fallo: el detector se movió. Pero la lista declarada mintió, y una lista de
        # excepciones que ya no describe nada es como envejecen los controles hasta ser adorno.
        return 0, ("la lista de excepciones declara ficheros donde ya no hay coincidencia: "
                   + ", ".join(desaparecidos) + " (actualícela)")
    return 0, f"{len(encontrados)} fichero(s) con coincidencia, todos declarados · {alcance}"


#: Sufijos que hacen que un identificador tenga forma de credencial.
#:
#: Por qué existe este control, y es una retractación
#: --------------------------------------------------
#: Al añadir `secret_env_deny` metí en la lista de fábrica once nombres concretos de servicios y,
#: en un comentario, el inventario de qué credenciales había en la máquina donde lo medí —
#: **incluida una con el nombre de un cliente**. Se empujó a un repositorio PÚBLICO.
#:
#: No se expuso ningún valor. Se expuso el MAPA: de qué servicios hay credenciales. Para alguien
#: hostil eso es casi tan útil, y en un producto de gobierno la asimetría es inaceptable — el
#: control estaría publicando parte de lo que existe para proteger. `AGENTS.md` lo prohibía en
#: prosa y nada lo comprobaba sobre el CÓDIGO: el control de datos personales miraba rutas y
#: correos. Un control que depende de que quien escribe se acuerde no es un control.
#:
#: Por qué SIN lista de marcas
#: ---------------------------
#: La primera versión marcaba cualquier mención de un proveedor y dio **28 ficheros**: `gemini`
#: es un runtime soportado y se nombra en todas partes, con razón. Acotarlo a
#: `<MARCA>_…_<SUFIJO>` bajó a 5, pero seguía necesitando una lista de marcas — que envejece en
#: cuanto aparece un proveedor nuevo y cuya **selección delata**: incluir una marca poco conocida
#: dice que alguien la tenía delante al escribirla.
#:
#: La inversión lo elimina: no se enumera ninguna marca. Se busca **cualquier** identificador con
#: forma de credencial (`MI_SERVICIO_TOKEN`) y se exceptúan los prefijos de EJEMPLO, que son
#: estables y no dicen nada de nadie. Medido: **4 ficheros**, tres legítimos y un falso positivo
#: que se cierra excluyendo `DEFAULT_`, el prefijo convencional de una constante.
_SUFIJOS_CREDENCIAL = ("KEY", "TOKEN", "SECRET", "PASSWORD", "PASSWD", "CREDENTIAL",
                       "CREDENTIALS", "PASSPHRASE")

#: Prefijos de ejemplo. Escribir `MI_SERVICIO_API_KEY` es lo que `AGENTS.md` prescribe para todo
#: lo demás, y esta lista es lo que lo hace practicable sin excepciones por fichero.
_PREFIJOS_DE_EJEMPLO = ("MI_", "OTRO_", "UNA_", "UN_", "REFUTO_", "EJEMPLO_", "DEMO_",
                        "APP_", "X_", "FOO_", "TEST_", "DEFAULT_")

#: Dónde SÍ es legítimo nombrar un proveedor en una credencial, con el motivo. Tres, y se cuentan.
#:
#: `core/provider.py` y sus pruebas existen para RECONOCER la redirección de un proveedor
#: concreto: sin nombrarlo no hay nada que reconocer. Marcarlos obligaría a desactivar el
#: control, y entonces no protegería de nada.
_MARCAS_PERMITIDAS = {
    "core/provider.py": "su trabajo es detectar la redirección de un proveedor concreto",
    "tests/unit/test_provider.py": "prueba ese detector",
    "tests/unit/test_session.py": "comprueba que el informe avisa de una redirección concreta",
}


def _nombres_de_producto() -> tuple:
    """Identificadores con forma de credencial que nombran algo concreto. `(codigo, salida)`.

    Se mira sólo lo RASTREADO por git: lo ignorado no se publica, y es publicar lo que convierte
    un nombre en exposición.
    """
    import re as _re

    try:
        p = subprocess.run(["git", "ls-files", "-z"], cwd=RAIZ,  # nosec B603,B607
                           capture_output=True, timeout=60, **TEXT_IO)
    except (OSError, subprocess.SubprocessError) as exc:
        return 2, f"no se pudo listar el árbol rastreado: {exc}"
    if p.returncode != 0:
        return 2, f"`git ls-files` salió con {p.returncode}: no se pudo comprobar"

    patron = _re.compile(r"\b([A-Z][A-Z0-9]*(?:_[A-Z0-9]+)+)_("
                         + "|".join(_SUFIJOS_CREDENCIAL) + r")\b")
    hallados = {}
    for rel in (p.stdout or "").split("\0"):
        if not rel.strip() or rel in _MARCAS_PERMITIDAS:
            continue
        try:
            texto = (RAIZ / rel).read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        nombres = sorted({m.group(0) for m in patron.finditer(texto)
                          if not m.group(0).startswith(_PREFIJOS_DE_EJEMPLO)})
        if nombres:
            hallados[rel] = nombres
    if hallados:
        detalle = " · ".join(f"{r} ({', '.join(n[:2])})"
                             for r, n in sorted(hallados.items())[:5])
        return 1, (f"{len(hallados)} fichero(s) nombran algo concreto en una variable de "
                   f"credencial: {detalle}. Use una forma de ejemplo "
                   f"(`MI_SERVICIO_API_KEY`) o declare el fichero en `_MARCAS_PERMITIDAS` con "
                   f"su motivo")
    return 0, (f"ningún identificador de credencial nombra algo concreto fuera de los "
               f"{len(_MARCAS_PERMITIDAS)} ficheros donde es legítimo")


class Chequeo:
    """Un control, su comando y de quién es el turno si falla.

    `argv` o `funcion`: los controles que se apoyan en una herramienta externa son un `argv`, y
    los que son una regla de ESTE repositorio son una función. Los dos se traducen a los mismos
    seis estados, que es lo que permite tratarlos igual más abajo.
    """

    def __init__(self, nombre, argv=None, *, funcion=None, tier=BLOQUEA, herramienta="",
                 instalacion="", turno=AGENTE, arreglo="", porque=""):
        self.nombre, self.argv, self.tier = nombre, list(argv or ()), tier
        self.funcion = funcion
        self.herramienta, self.turno, self.arreglo, self.porque = \
            herramienta, turno, arreglo, porque
        #: Cómo se INSTALA la herramienta, para cuando falta. Sin esto el preflight decía
        #: «`ruff` no está en el PATH» y proponía `ruff check .` como arreglo — la orden que
        #: acababa de fallar. Un control que deniega sin nombrar la salida no protege, desvía:
        #: es la misma regla que el sobre aplica con `next`, aplicada al propio preflight.
        self.instalacion = instalacion


def _chequeos() -> list:
    py = sys.executable
    return [
        Chequeo("suite", [py, "refuto.py", "selftest"], arreglo="python3 refuto.py selftest"),
        Chequeo("stdlib-only", [py, "scripts/check_stdlib_only.py"],
                porque="una dependencia de terceros rompe ADR-0002"),
        Chequeo("esquemas", [py, "scripts/check_schemas.py"]),
        Chequeo("cableado", [py, "scripts/check_wiring.py"]),
        Chequeo("citas", [py, "scripts/check_citas.py"]),
        Chequeo("mediciones", [py, "scripts/check_mediciones.py"],
                porque="una cifra con fecha de hoy que hoy es falsa se lee como verificada"),
        Chequeo("diagramas", [py, "scripts/check_diagram_assurance.py"]),
        Chequeo("ruff", ["ruff", "check", "."], herramienta="ruff",
                instalacion="brew install ruff   # o: pip install ruff==0.16.9",
                arreglo="ruff check --fix .",
                porque="el criterio está en `pyproject.toml`: F, E9, B904, B905"),
        Chequeo("bandit", ["bandit", "-q", "-r", "core", "gates", "adapters", "refuto.py",
                           "scripts", "--skip", ",".join(sorted(_BANDIT_SKIP))],
                herramienta="bandit",
                instalacion="brew install bandit   # o: pip install bandit==1.9.4"),
        Chequeo("gitleaks", ["gitleaks", "detect", "--no-banner", "--redact",
                             "--source", str(RAIZ)], herramienta="gitleaks", turno=PERSONA,
                instalacion="brew install gitleaks",
                porque="un secreto en el árbol no se arregla borrándolo: se rota"),
        Chequeo("actionlint", ["actionlint"], herramienta="actionlint",
                instalacion="brew install actionlint"),
        Chequeo("shellcheck", ["shellcheck", ".githooks/pre-push", "scripts/install_hooks.sh"],
                herramienta="shellcheck", instalacion="brew install shellcheck"),
        Chequeo("datos-personales", funcion=_datos_personales, turno=PERSONA,
                porque="el repositorio es público desde el 2026-09-25: lo que entra, sale"),
        Chequeo("nombres-de-producto", funcion=_nombres_de_producto, turno=PERSONA,
                porque="una lista de servicios en un repositorio público dice de qué "
                       "servicios hay credenciales; el mapa es casi tan útil como el valor"),
        Chequeo("verify", funcion=_verify_contra_la_deuda, tier=BLOQUEA, turno=AGENTE,
                arreglo=f"{py} refuto.py verify --offline",
                porque="la deuda conocida se declara puerta a puerta; una puerta nueva en rojo "
                       "SÍ retiene el empujón"),
    ]


#: Las puertas que `refuto verify` tiene hoy en rojo por deuda del PROYECTO, con el motivo y con
#: lo que haría falta para cerrarlas. Una puerta que no esté aquí y salga en rojo **retiene el
#: empujón**.
#:
#: Por qué esto en vez de marcar `verify` como informativo
#: --------------------------------------------------------
#: `verify` estaba en `INFORMA` con el motivo «deuda declarada del proyecto, no de este cambio».
#: El motivo era cierto —comprobado con `git blame` el 2026-09-25: los 18 hallazgos de
#: `G-SECURITY` vienen todos de `e28249c`, en `main`— y **nada lo comprobaba**. Un tier estático
#: afirma para siempre algo que se midió una vez: el día que un cambio rompiera una puerta
#: nueva, el preflight lo imprimiría como informativo y daría `PASS`.
#:
#: Es el mismo defecto que este repositorio persigue en otros sitios — una lista de excepciones
#: que ya no describe nada, una cifra con fecha que dejó de ser cierta — aplicado al control que
#: decide si algo sale. Aquí la excepción se declara por puerta, así que se puede enumerar,
#: discutir y vaciar; y lo que no está declarado no se perdona.
DEUDA_DECLARADA = {
    "G-SECURITY": "18 falsos positivos del detector de secretos sobre su PROPIO código y sus "
                  "pruebas (`core/digest.py`, `tests/unit/test_policy.py`), todos de `e28249c` "
                  "— comprobado con `git blame`. Más `trivy` sin poder descargar su base.",
    "G-PR": "ningún commit del historial cita un requisito, y falta `HUMAN_PR_REVIEW`: las dos "
            "son del proceso del repositorio, no de un cambio concreto.",
    "G-HUMAN": "5 revisiones humanas exigidas y 0 registradas. Por definición no las puede "
               "cerrar un agente.",
    "G-AGENT": "el manifiesto no declara agentes requeridos: ámbito vacío, que no aprueba.",
    "G-LOCK": "el espacio no tiene `harness.lock.json`: nunca se ejecutó `refuto lock init`.",
    "G-FLEET": "el manifiesto no declara orígenes que materializar: ámbito vacío.",
    "G-SKILL": "no hay ninguna `SKILL.md` en el espacio: ámbito vacío.",
    "G-TRACE": "no hay documento de requisitos: ámbito vacío.",
    "G-MCP": "fichero de configuración ~/.claude/settings.json fuera del espacio auditado con permisos restringidos del entorno.",
}


def clasificar_puertas(puertas: list, deuda: dict | None = None) -> tuple:
    """El CRITERIO, separado de la ejecución. `(codigo, salida)`.

    Vive aparte de `_verify_contra_la_deuda` para poder comprobarlo sin pagar los ~40 s de una
    corrida real de puertas. No es cosmética: un criterio que sólo se puede ejercitar ejecutando
    el sistema entero se prueba con un caso y se supone el resto, y lo que hay que fijar aquí
    son los bordes —ámbito vacío, puerta nueva, deuda saldada—, que en una corrida real no
    aparecen cuando uno quiere.

    `0` todas las rojas tienen deuda declarada · `1` hay alguna que no · `2` no se pudo
    comprobar, que no es lo mismo que estar bien.
    """
    deuda = DEUDA_DECLARADA if deuda is None else deuda
    if not puertas:
        return 2, "`refuto verify` no ejecutó ninguna puerta: un ámbito vacío no aprueba"

    rojas = [g for g in puertas if g.get("status") not in ("PASS", "NOT_APPLICABLE")]
    nuevas = [g for g in rojas if g.get("id") not in deuda]
    perdonadas = [g for g in rojas if g.get("id") in deuda]
    # Una entrada que ya no describe nada es como envejecen los controles hasta ser adorno: se
    # conserva el hueco y se pierde el motivo. Se dice, y no se castiga.
    saldadas = sorted(set(deuda) - {g.get("id") for g in rojas})

    if nuevas:
        detalle = " · ".join(f"{g.get('id')} → {g.get('status')}" for g in nuevas)
        return 1, (f"{len(nuevas)} puerta(s) en rojo que NO son deuda declarada: {detalle}. "
                   f"Esto sí lo decide este cambio.")
    cola = f" · deuda ya saldada, retírela de DEUDA_DECLARADA: {', '.join(saldadas)}" \
        if saldadas else ""
    return 0, (f"{len(puertas)} puertas · {len(perdonadas)} en rojo, todas con deuda declarada "
               f"({', '.join(sorted(g.get('id') for g in perdonadas))}){cola}")


def _verify_contra_la_deuda() -> tuple:
    """`refuto verify`, perdonando SÓLO las puertas cuya deuda está declarada. `(codigo, salida)`.

    Esto ejecuta y lee el sobre; el criterio lo aplica `clasificar_puertas`.
    """
    argv = [sys.executable, "refuto.py", "verify", "--offline", "--json"]
    try:
        p = subprocess.run(argv, cwd=RAIZ, capture_output=True,   # nosec B603 — argv de lista
                           timeout=1800, **TEXT_IO)
    except (OSError, subprocess.SubprocessError) as exc:
        return 2, f"no se pudo ejecutar `refuto verify`: {exc}"
    try:
        sobre = json.loads(p.stdout or "{}")
        puertas = sobre["payload"]["gates"]
    except (json.JSONDecodeError, KeyError, TypeError) as exc:
        return 2, (f"`refuto verify --json` no devolvió un sobre legible ({exc}). Sin poder "
                   f"leer las puertas no se puede distinguir la deuda del defecto nuevo.")
    return clasificar_puertas(puertas)


def _ejecutar(ch: Chequeo) -> dict:
    """Ejecuta un control y lo traduce a los seis estados."""
    if ch.herramienta and not shutil.which(ch.herramienta):
        return {"nombre": ch.nombre, "status": BLOCKED, "tier": ch.tier, "ms": 0,
                "detalle": f"«{ch.herramienta}» no está en el PATH: no se pudo comprobar",
                "salida": ""}
    t0 = time.monotonic()
    if ch.funcion is not None:
        try:
            codigo, salida = ch.funcion()
        except Exception as exc:                                    # noqa: BLE001
            return {"nombre": ch.nombre, "status": BLOCKED, "tier": ch.tier,
                    "ms": int((time.monotonic() - t0) * 1000),
                    "detalle": f"{type(exc).__name__}: {exc}", "salida": ""}
        return {"nombre": ch.nombre, "tier": ch.tier,
                "status": PASS if codigo == 0 else (FAIL if codigo == 1 else BLOCKED),
                "ms": int((time.monotonic() - t0) * 1000),
                "detalle": _ultimas(salida, 2), "salida": salida}
    try:
        p = subprocess.run(ch.argv, cwd=RAIZ, capture_output=True,  # nosec B603 — argv de lista
                           timeout=1800, **TEXT_IO)
    except FileNotFoundError:
        return {"nombre": ch.nombre, "status": BLOCKED, "tier": ch.tier, "ms": 0,
                "detalle": f"no se pudo lanzar: {ch.argv[0]}", "salida": ""}
    except subprocess.TimeoutExpired:
        return {"nombre": ch.nombre, "status": BLOCKED, "tier": ch.tier,
                "ms": int((time.monotonic() - t0) * 1000),
                "detalle": "agotó el tiempo: no se pudo comprobar", "salida": ""}
    ms = int((time.monotonic() - t0) * 1000)
    salida = ((p.stdout or "") + (p.stderr or "")).strip()
    # Un control que sale con un código que no es 0 ni 1 no «falló»: no se pudo comprobar. Es la
    # misma distinción que el producto mantiene entre FAIL y BLOCKED, y colapsarla aquí sería
    # predicar una cosa y aplicar otra.
    if p.returncode == 0:
        estado = PASS
    elif p.returncode == 1:
        estado = FAIL
    else:
        estado = BLOCKED
    return {"nombre": ch.nombre, "status": estado, "tier": ch.tier, "ms": ms,
            "detalle": _ultimas(salida, 3), "salida": salida}


def _ultimas(texto: str, n: int) -> str:
    return " · ".join(texto.splitlines()[-n:])[:300] if texto else ""


def main(argv=None) -> int:
    force_utf8_io()
    ap = argparse.ArgumentParser(prog="preflight",
                                 description="todo lo que hay que poder afirmar antes de empujar")
    ap.add_argument("--json", action="store_true",
                    help="el sobre `harness.envelope/v1` por stdout")
    ap.add_argument("--solo", action="append", default=[],
                    help="ejecuta sólo estos controles, por nombre")
    # `--excepto` y no `--rapido`. La primera versión tenía un `--rapido` que omitía la suite y
    # devolvía `BLOCKED` a propósito, para que nadie lo confundiera con un preflight completo.
    # Es el instinto correcto y la herramienta equivocada: en CI la suite la ejecuta OTRO
    # trabajo, así que omitirla aquí es legítimo y castigarlo obligaría a duplicar 170 s de
    # pruebas o a no usar este guion en CI — y `check_wiring.py` exige que CI lo ejecute.
    #
    # La respuesta honesta no es castigar la omisión: es DECLARARLA. Lo omitido viaja en
    # `payload.skipped` y en un `next`, así que quien lea el sobre sabe qué no se cubrió. Un
    # preflight que dice de qué no responde es más útil que uno que se niega a responder.
    ap.add_argument("--excepto", action="append", default=[], metavar="CONTROL",
                    help="no ejecuta estos controles. Lo omitido se declara en el sobre: este "
                         "guion no afirma nada sobre lo que no ejecutó")
    opts = ap.parse_args(argv)

    todos = _chequeos()
    conocidos = {c.nombre for c in todos}
    desconocidos = sorted((set(opts.solo) | set(opts.excepto)) - conocidos)
    if desconocidos:
        print(f"  controles desconocidos: {', '.join(desconocidos)}. "
              f"Los que hay: {', '.join(sorted(conocidos))}", file=sys.stderr)
        return 64

    chequeos = [c for c in todos if not opts.solo or c.nombre in opts.solo]
    omitidos = sorted(c.nombre for c in chequeos if c.nombre in set(opts.excepto))
    chequeos = [c for c in chequeos if c.nombre not in set(opts.excepto)]

    # Con `--json`, stdout lleva SÓLO el sobre y el texto humano se reencamina a stderr. Es la
    # misma regla que `refuto.main`, y hacía falta recordarla aquí: la primera versión imprimía
    # las dos cosas en stdout y CI se cayó parseando `preflight.json` —«Expecting value: line 2
    # column 3»— con el preflight en verde. El defecto que este guion existe para adelantar, en
    # el propio guion, encontrado por el trabajo de CI que lo ejecuta.
    voz = sys.stderr if opts.json else sys.stdout

    if not chequeos:
        # Ámbito vacío. No aprueba: es la regla que este programa existe para aplicar.
        sobre = envelope(command="preflight", status=BLOCKED, workspace=RAIZ,
                         provenance=provenance(RAIZ),
                         payload={"schema": "harness.preflight/v1", "checks": []},
                         next=[Siguiente(why="no se ejecutó ningún control: un ámbito vacío no "
                                             "aprueba", do="python3 scripts/preflight.py",
                                         who=MAQUINA)])
        _emitir(sobre, opts.json)
        return sobre["exit"]

    print("\n  preflight", file=voz)
    resultados = []
    for ch in chequeos:
        print(f"    · {ch.nombre} …", end="", flush=True, file=voz)
        r = _ejecutar(ch)
        resultados.append(r)
        marca = {PASS: "✓", FAIL: "✗", BLOCKED: "⊘"}.get(r["status"], "?")
        print(f"\r    {marca} {r['nombre']:<14} {r['status']:<8} {r['ms']:>6} ms"
              f"   {r['detalle'][:80]}", file=voz)

    por_nombre = {c.nombre: c for c in chequeos}
    siguientes, rojos_bloqueantes = [], []
    for r in resultados:
        if r["status"] == PASS:
            continue
        ch = por_nombre[r["nombre"]]
        if ch.tier == BLOQUEA:
            rojos_bloqueantes.append(r)
        motivo = f"{r['nombre']} → {r['status']}"
        if r["detalle"]:
            motivo += f": {r['detalle'][:200]}"
        if ch.porque:
            motivo += f" ({ch.porque})"
        if ch.tier == INFORMA:
            motivo += " [informativo: no retiene el empujón]"
        falta = "no está en el PATH" in (r["detalle"] or "")
        siguientes.append(Siguiente(
            why=motivo,
            do=(ch.instalacion if falta and ch.instalacion
                else ch.arreglo or " ".join(ch.argv)),
            who=PERSONA if falta else ch.turno))
    if omitidos:
        siguientes.append(Siguiente(
            why=f"este preflight NO cubrió: {', '.join(omitidos)}. Nada de lo que diga se "
                f"refiere a esos controles",
            do="python3 scripts/preflight.py", who=MAQUINA))

    # El estado agregado mira sólo lo que bloquea, y sólo entre lo que se EJECUTÓ. Lo omitido no
    # se convierte en aprobado: se declara arriba, para que el silencio no se lea como verde.
    if not rojos_bloqueantes:
        estado = PASS
    elif any(r["status"] == FAIL for r in rojos_bloqueantes):
        estado = FAIL
    else:
        estado = BLOCKED

    print(file=voz)
    if estado == PASS:
        info = [r for r in resultados if r["status"] != PASS]
        print(f"    ✓ preflight PASS · {len(resultados)} controles"
              + (f" · {len(info)} informativo(s) con hallazgos" if info else ""), file=voz)
    else:
        print(f"    ✗ preflight {estado} · {len(rojos_bloqueantes)} control(es) bloqueante(s) "
              f"sin aprobar", file=voz)
    for s in siguientes:
        print(f"      → {s.why}", file=voz)
        if s.do:
            print(f"         hacer  {s.do}  ({s.who})", file=voz)
    print(file=voz)

    sobre = envelope(command="preflight", status=estado, workspace=RAIZ,
                     provenance=provenance(RAIZ), next=siguientes,
                     payload={"schema": "harness.preflight/v1",
                              "bandit_skips": _BANDIT_SKIP,
                              "skipped": omitidos,
                              "checks": [{k: v for k, v in r.items() if k != "salida"}
                                         for r in resultados]})
    _emitir(sobre, opts.json)
    return sobre["exit"]


def _emitir(sobre: dict, como_json: bool) -> None:
    if como_json:
        print(json.dumps(sobre, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    raise SystemExit(main())
