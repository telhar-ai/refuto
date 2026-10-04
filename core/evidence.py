# -*- coding: utf-8 -*-
"""Diario de evidencia. JSON Lines, append-only, con procedencia.

Regla de dirección, y es la que separa evidencia de informe:

    evidencia estructurada  →  informe humano
    NUNCA al revés

Un informe HTML del que después se extraen datos es una captura con pretensiones. Lo que se
audita dentro de un año es el JSONL.
"""

from __future__ import annotations

import contextlib
import hashlib
import json
import os
from pathlib import Path

from core.model import now, provenance

LEDGER = "ledger.jsonl"

#: Con qué mecanismo se serializa `append_event`. Se expone para poder AFIRMARLO: una prueba
#: que dijera «la cadena aguanta la concurrencia» sin saber si hubo bloqueo estaría midiendo la
#: suerte del planificador.
try:                                                                  # pragma: no cover
    import fcntl as _fcntl
    MECANISMO_DE_BLOQUEO = "fcntl.flock"
except ImportError:                                                   # pragma: no cover
    _fcntl = None
    try:
        import msvcrt as _msvcrt
        MECANISMO_DE_BLOQUEO = "msvcrt.locking"
    except ImportError:
        _msvcrt = None
        MECANISMO_DE_BLOQUEO = ""
else:                                                                 # pragma: no cover
    _msvcrt = None


@contextlib.contextmanager
def _exclusivo(fh):
    """Bloqueo exclusivo sobre el diario mientras se lee la cabeza y se escribe el eslabón.

    Por qué hace falta, medido el 2026-09-25
    -----------------------------------------
    `append_event` leía la cabeza y escribía sin serializar, y el argumento de que eso bastaba
    —una escritura de menos de PIPE_BUF en modo `a` no se entrelaza— es correcto **sobre los
    bytes** y no dice nada **sobre la cadena**. Dos guardianes concurrentes leen la misma cabeza
    y emiten dos eventos con el mismo `prev`. Con 12 invocaciones simultáneas:

        eventos escritos : 12
        cadena ok        : False  (rota en la línea 3)
        motivo           : «falta, sobra o se movió algún evento entre medias»

    Es decir, el diario acusaba de MANIPULACIÓN lo que era concurrencia normal — y un agente de
    código invoca herramientas en paralelo de forma rutinaria. Una alarma de integridad que
    salta con el uso normal se aprende a ignorar, que es el mismo modo de muerte que este
    repositorio ya documentó en `core.policy._partir` (comillas) y en `dd:*` (`ddev`).

    Si no hay mecanismo de bloqueo se SIGUE escribiendo, sin bloquear. Perder el evento sería
    peor que perder la serialización, y el estado queda declarado en `MECANISMO_DE_BLOQUEO`
    para que nadie afirme una garantía que este proceso no tiene.
    """
    if _fcntl is not None:
        _fcntl.flock(fh.fileno(), _fcntl.LOCK_EX)
        try:
            yield True
        finally:
            _fcntl.flock(fh.fileno(), _fcntl.LOCK_UN)
        return
    if _msvcrt is not None:                                           # pragma: no cover
        fh.seek(0)
        try:
            _msvcrt.locking(fh.fileno(), _msvcrt.LK_LOCK, 1)
        except OSError:
            yield False       # no se pudo bloquear: se escribe igual y se declara
            return
        try:
            yield True
        finally:
            with contextlib.suppress(OSError):
                fh.seek(0)
                _msvcrt.locking(fh.fileno(), _msvcrt.LK_UNLCK, 1)
        return
    yield False                                                       # pragma: no cover


def ledger_path(workspace: Path) -> Path:
    return workspace / ".harness" / "evidence" / LEDGER


#: Semilla de la cadena de huellas. Un diario vacío tiene una cabeza definida, así que
#: «no hay eventos» y «me borraron los eventos» dejan de ser el mismo estado.
GENESIS = hashlib.sha256(b"harness.ledger/v1").hexdigest()


def _canonico(evento: dict) -> str:
    """El texto del que se saca la huella. Claves ordenadas y sin espacios: dos procesos
    distintos tienen que producir el mismo byte para el mismo evento."""
    return json.dumps({k: v for k, v in sorted(evento.items()) if k != "h"},
                      ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def _eslabon(previo: str, evento: dict) -> str:
    return hashlib.sha256((previo + "\n" + _canonico(evento)).encode("utf-8")).hexdigest()


def _ultima_linea(fh) -> str:
    """La última línea no vacía, leyendo desde el FINAL. `fh` abierto en binario.

    La versión anterior hacía `read_text().splitlines()` del diario entero, y `append_event` la
    llama en cada evento: el guardián leía el fichero completo antes de cada decisión. Con 1.779
    eventos el coste es invisible; el diario es de sólo añadir, así que crece sin techo y el
    coste con él — en el camino caliente, que es donde un control lento se acaba desactivando.

    Se leen bloques desde el final hasta encontrar un salto de línea. El caso normal —la última
    línea mide unos cientos de bytes— se resuelve con UNA lectura de 4 KiB.
    """
    fh.seek(0, os.SEEK_END)
    fin = fh.tell()
    if fin == 0:
        return ""
    bloque, datos, pos = 4096, b"", fin
    while pos > 0:
        paso = min(bloque, pos)
        pos -= paso
        fh.seek(pos)
        datos = fh.read(paso) + datos
        lineas = [ln for ln in datos.split(b"\n") if ln.strip()]
        # Con más de una línea completa, la última ya está entera: sólo si `pos == 0` puede
        # la primera estar cortada, y entonces no hay más fichero que leer.
        if len(lineas) > 1 or pos == 0:
            return lineas[-1].decode("utf-8", "replace") if lineas else ""
    return ""


def cabeza(workspace: Path) -> str:
    """La huella del último evento del diario, o `GENESIS` si no hay ninguno.

    Leer la cabeza es barato y no exige recorrer la cadena: es el campo `h` de la última
    línea legible. Verificarla SÍ exige recorrerla, y para eso está `verificar_cadena`.
    """
    path = ledger_path(workspace)
    if not path.is_file():
        return GENESIS
    try:
        with path.open("rb") as fh:
            ultima = _ultima_linea(fh)
    except OSError:
        return GENESIS
    if not ultima:
        return GENESIS
    try:
        return str(json.loads(ultima).get("h") or GENESIS)
    except json.JSONDecodeError:
        return GENESIS


def append_event(workspace: Path, event: dict) -> None:
    """Añade un evento al diario, encadenado por huella. Append atómico: una línea, una
    escritura.

    En POSIX, una escritura de menos de PIPE_BUF a un descriptor abierto en modo `a` no se
    entrelaza con la de otro proceso. Por eso los eventos del guardián —que corre en procesos
    distintos y concurrentes— no se corrompen entre sí.

    La cadena, y qué compra
    -----------------------
        h₀ = H("harness.ledger/v1")
        hᵢ = H( hᵢ₋₁ ‖ canonical(eventoᵢ) )

    El diario era JSON Lines plano: sin huella, sin firma, sin encadenar. «Sólo añadir» era
    una propiedad de QUIEN ESCRIBE, no una propiedad frente a quien lee o edita. Medido el
    2026-09-23: purgar selectivamente las denegaciones dejaba un diario coherente, más corto
    y sin rastro de la purga.

    Con la cadena, borrar, reordenar o editar un evento rompe todos los eslabones
    posteriores. **Esto es tamper-EVIDENCIA, no tamper-proofing**: un adversario que reescriba
    la cadena ENTERA y todas sus copias publicadas produce un diario coherente. Lo que ya no
    puede es editar una línea y marcharse. Ver FORMAL-MODEL §3.5.

    Leer la cabeza y escribir el eslabón es UNA operación
    -----------------------------------------------------
    Las dos van dentro del mismo bloqueo exclusivo (`_exclusivo`). Separarlas es lo que hacía
    que dos guardianes concurrentes encadenaran los dos al mismo `prev` y produjeran un diario
    que `verificar_cadena` declaraba manipulado. La atomicidad de los BYTES no da atomicidad de
    la CADENA: son dos propiedades y sólo una se seguía de `O_APPEND`.
    """
    path = ledger_path(workspace)
    path.parent.mkdir(parents=True, exist_ok=True)
    # `a+` y no `a`: hace falta LEER la cabeza con el bloqueo ya tomado. Leerla antes de
    # abrir —como se hacía— deja la ventana entre la lectura y la escritura, que es justo la
    # carrera. Se abre en binario porque `_ultima_linea` busca desde el final.
    with path.open("a+b") as fh:
        with _exclusivo(fh):
            ultima = _ultima_linea(fh)
            previo = GENESIS
            if ultima:
                try:
                    previo = str(json.loads(ultima).get("h") or GENESIS)
                except json.JSONDecodeError:
                    previo = GENESIS
            record = {"ts": now(), **event, "prev": previo}
            record["h"] = _eslabon(previo, record)
            line = json.dumps(record, ensure_ascii=False) + "\n"
            fh.seek(0, os.SEEK_END)
            fh.write(line.encode("utf-8"))
            fh.flush()
            os.fsync(fh.fileno())


#: Estado del diario, explícito. `ok` es un booleano y colapsaba seis situaciones distintas;
#: éstas se distinguen porque **se arreglan distinto**, y porque una de ellas aprobaba.
#:
#:   AUSENTE       el fichero no existe
#:   VACIO         existe y no tiene ni un evento
#:   INTEGRA       la cadena cierra de principio a fin
#:   ROTA          un eslabón no cuadra: se editó, se borró o se movió algo
#:   CICATRIZADA   cierra salvo discontinuidades DECLARADAS, y son exactamente las declaradas
#:   DESALINEADA   la cadena cierra y el ancla publicada no está en ella
#:   INSUFICIENTE  la cadena cierra y trae menos eventos de los exigidos
AUSENTE, VACIO, INTEGRA, ROTA, DESALINEADA, INSUFICIENTE, CICATRIZADA = (
    "AUSENTE", "VACIO", "INTEGRA", "ROTA", "DESALINEADA", "INSUFICIENTE", "CICATRIZADA")

#: Dónde se declaran las discontinuidades. En un SUBDIRECTORIO de `evidence/` a propósito: el
#: `glob("*.json")` de `latest_verification` no es recursivo, así que un fichero suelto ahí se
#: leería como si fuera un artefacto de verificación. Mismo motivo que `evidence/anchors/`.
DIR_DISCONTINUIDADES = ("evidence", "discontinuities")
NOMBRE_DISCONTINUIDADES = "declared.json"
SCHEMA_DISCONTINUIDADES = "refuto.discontinuities/v1"

#: Los campos que una declaración tiene que traer, todos. No hay valores por omisión: una
#: discontinuidad declarada a medias no se puede contrastar con la rotura que dice explicar.
CAMPOS_DISCONTINUIDAD = ("line", "found_prev", "expected_head", "cause", "declared_by", "declared_at")


def ruta_discontinuidades(workspace: Path) -> Path:
    return Path(workspace) / ".harness" / DIR_DISCONTINUIDADES[0] / DIR_DISCONTINUIDADES[1] / NOMBRE_DISCONTINUIDADES


def discontinuidades(workspace: Path) -> dict:
    """Las discontinuidades que una PERSONA declaró, y los problemas de la declaración.

    Por qué esto existe
    -------------------
    Hasta el 2026-09-28 una cadena con una sola rotura quedaba `ROTA` **para siempre**, y con
    ella el espacio entero en `NO INTEGRABLE` aunque el defecto que la causó estuviera cerrado.
    Medido en un espacio real: dos roturas del 2026-09-24, las dos por la carrera de
    concurrencia del guardián que se cerró el 2026-09-25 (`7eb0945`); 13.063 eventos y ninguna
    huella alterada. El espacio no podía volver a operar nunca.

    Es el mismo argumento que ya justificaba el trato del `legado`: convertir toda instalación
    previa en sospechosa el día de la actualización es como se enseña a ignorar una alarma. Y
    hay una salida peor esperando: borrar el diario, que es la manipulación más simple que
    existe.

    Por qué esto NO abre una puerta
    -------------------------------
    Una declaración sólo surte efecto si **coincide exactamente** con la rotura: misma línea,
    mismo `prev` encontrado y misma cabeza que se esperaba. Editar un evento cambia su huella
    —y eso lo caza otra comprobación, no ésta—; borrar o insertar eventos desplaza las líneas y
    cambia los digests, con lo que la declaración deja de casar y la cadena vuelve a `ROTA`. Es
    decir: declarar una discontinuidad no permite ocultar ninguna manipulación posterior, sólo
    reconocer una concreta que ya ocurrió.

    Y el fichero vive bajo `evidence/`, que la política protege: lo escribe una persona.
    """
    p = ruta_discontinuidades(workspace)
    fuera = {"declaradas": [], "problema": ""}
    if not p.is_file():
        return fuera
    try:
        doc = json.loads(p.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        return {"declaradas": [], "problema": f"{p}: ilegible ({type(exc).__name__}: {exc})"}
    if not isinstance(doc, dict) or doc.get("schema") != SCHEMA_DISCONTINUIDADES:
        return {"declaradas": [], "problema": f"{p}: no es {SCHEMA_DISCONTINUIDADES}"}
    entradas = doc.get("entries")
    if not isinstance(entradas, list):
        return {"declaradas": [], "problema": f"{p}: `entries` no es una lista"}
    buenas, malas = [], []
    for i, e in enumerate(entradas):
        if not isinstance(e, dict) or any(k not in e for k in CAMPOS_DISCONTINUIDAD):
            malas.append(f"entrada {i}: faltan campos de {list(CAMPOS_DISCONTINUIDAD)}")
            continue
        if not isinstance(e["line"], int) or isinstance(e["line"], bool) or e["line"] < 1:
            malas.append(f"entrada {i}: `line` no es un número de línea")
            continue
        buenas.append(e)
    return {"declaradas": buenas,
            "problema": "; ".join(malas) if malas else ""}


def _declarada(decls: list, linea: int, encontrado: str, esperado: str):
    """La declaración que explica ESA rotura, o `None`. La coincidencia es exacta a propósito."""
    for d in decls:
        if (d["line"] == linea and str(d["found_prev"]) == encontrado
                and str(d["expected_head"]) == esperado):
            return d
    return None


def verificar_cadena(workspace: Path, esperado: str = "", *,
                     eventos_minimos: int = 0) -> dict:
    """Recorre el diario y comprueba que cada eslabón cierra.

    `esperado` es un ANCLA PUBLICADA: una cabeza que alguien guardó fuera de este árbol
    (en el registro de CI, en un mensaje de commit, en otra máquina). Sirve para lo único
    que la cadena por sí sola NO puede detectar.

    Ausencia no es integridad
    -------------------------
    Hasta el 2026-09-25 esta función devolvía `ok=True, eventos=0` cuando el fichero **no
    existía**, y lo hacía antes de mirar `esperado`. Medido:

        5 eventos escritos · ancla publicada · se borra ledger.jsonl
        → {'ok': True, 'eventos': 0, …}

    Es decir: la forma más burda de manipular el diario —borrarlo— era la única que pasaba,
    y pasaba incluso contra un ancla que demuestra que hubo eventos. Es la Prueba del Vacío
    incumplida por el componente que existe para aplicarla, y no es un caso de borde: el
    diario lo puede borrar cualquier proceso con el uid del sujeto (`FORMAL-MODEL §6.2`).

    La asimetría que lo delataba: **vaciar** el fichero sí se detectaba con ancla, porque la
    función seguía adelante y el ancla no aparecía en una cadena vacía. **Borrarlo** no,
    porque se retornaba antes.

    Ahora se distingue AUSENTE de VACIO y de INTEGRA, y la ausencia sólo aprueba cuando no
    hay ninguna expectativa de evidencia — que es el caso legítimo de un espacio recién
    creado que todavía no ha decidido nada.

    Qué es una expectativa
    ----------------------
    Un ancla publicada (`esperado`) o un mínimo de eventos exigido (`eventos_minimos`). Las
    dos son afirmaciones de que ALGO tuvo que quedar escrito. Sin ninguna de las dos, «no hay
    diario» y «no ha pasado nada» son indistinguibles y aprobar es correcto; con cualquiera de
    ellas, «no hay diario» es una contradicción.

    `eventos_minimos` es la forma mínima de la regla de suficiencia: pedir una propiedad sin
    declarar cuánta evidencia exige es pedirla sin poder comprobar que se cumplió.

    El límite que esto NO cierra
    ----------------------------
    Cortar la COLA del diario deja una cadena que cierra: los eslabones que quedan siguen
    siendo consistentes entre sí. Dentro de un único fichero mutable eso no es detectable por
    construcción — no hay nada que diga cuántos eventos «debería» haber. Con `esperado` sí: si
    la huella publicada ya no está en la cadena, el diario se cortó por detrás de ella.

    **Sin ancla publicada, la truncación de cola sigue siendo `NOT_PROVEN`.** Hasta el 2026-09-27
    refuto no ofrecía ninguna orden para obtener esa ancla (el CLI de `evidence` sólo tenía
    `--last`, `--kind` y `--json`), y los seis ataques que dependen de ella quedaban detectables
    en teoría y no en la práctica (registro de C-02). Desde ADR-0017 el ancla la produce
    `refuto evidence --anchor` (y cada `refuto verify` en un espacio que declare `anchoring`):
    un checkpoint `{root, size, …}` ordenado y certificado por `≥ q` réplicas de concordia, que
    `refuto status` relee OFFLINE y pasa aquí como `esperado`/`eventos_minimos`
    (`core/concordia.py::verificar_ancla`).

    Devuelve `{"ok", "estado", "eventos", "legado", "rota_en", "motivo", "cabeza"}`. `ok=False`
    NO dice quién lo hizo ni por qué: dice que el diario de ahora no es el que se escribió.
    `estado` dice CUÁL de las seis situaciones es, porque se arreglan distinto.

    Un evento sin `prev`/`h` se cuenta como `legado`: los diarios escritos antes de que
    existiera la cadena siguen siendo legibles, y tratarlos como rotos convertiría toda
    instalación previa en sospechosa el día de la actualización — que es como se enseña a
    ignorar una alarma.
    """
    path = ledger_path(workspace)
    hay_ancla = bool(esperado) and esperado != GENESIS
    expectativa = hay_ancla or eventos_minimos > 0
    if not path.is_file():
        return {
            "ok": not expectativa, "estado": AUSENTE, "eventos": 0, "legado": 0,
            "rota_en": -1, "cabeza": GENESIS, "cicatrices": [],
            "motivo": "" if not expectativa else (
                f"no hay diario en {path} y se esperaba evidencia"
                + (f" (ancla publicada {esperado[:12]}…)" if hay_ancla else "")
                + (f" (al menos {eventos_minimos} evento(s))" if eventos_minimos else "")
                + ". Un artefacto de evidencia ausente no es un artefacto íntegro: "
                  "borrarlo es la manipulación más simple que existe."),
        }
    disc = discontinuidades(workspace)
    decls = disc["declaradas"]
    cicatrices: list = []
    previo, n, legado = GENESIS, 0, 0
    vistas: set = set()
    for i, line in enumerate(path.read_text(encoding="utf-8").splitlines()):
        if not line.strip():
            continue
        try:
            ev = json.loads(line)
        except json.JSONDecodeError as exc:
            return {"ok": False, "estado": ROTA, "eventos": n, "legado": legado, "rota_en": i,
                    "motivo": f"la línea {i + 1} no es JSON legible: {exc}", "cabeza": previo,
                    "cicatrices": []}
        n += 1
        if "h" not in ev or "prev" not in ev:
            legado += 1
            continue
        if ev["prev"] != previo:
            d = _declarada(decls, i + 1, str(ev["prev"]), previo)
            if d is None:
                return {"ok": False, "estado": ROTA, "eventos": n, "legado": legado, "rota_en": i,
                        "motivo": f"la línea {i + 1} encadena a {str(ev['prev'])[:12]}… y el "
                                  f"evento anterior es {previo[:12]}…: falta, sobra o se movió "
                                  f"algún evento entre medias.", "cabeza": previo,
                        "cicatrices": cicatrices}
            # Rotura RECONOCIDA: se acepta el salto y se sigue verificando desde aquí. No se
            # aprueba en silencio — viaja en `cicatrices` y el estado deja de ser INTEGRA.
            cicatrices.append({"line": i + 1, "cause": str(d["cause"])[:300],
                               "declared_by": str(d["declared_by"]), "declared_at": str(d["declared_at"]),
                               "expected_head": previo, "found_prev": str(ev["prev"])})
            # Y se adopta el `prev` que el evento DECLARA, porque su huella se calculó con ése.
            # Sin esto la comprobación de abajo acusaba de «editado después» a un evento
            # auténtico: lo que la cicatriz autoriza es el SALTO, no una huella incoherente,
            # y ésa se sigue exigiendo igual de fuerte. Medido con un diario real el 2026-09-28.
            previo = str(ev["prev"])
        huella = _eslabon(previo, ev)
        if ev["h"] != huella:
            return {"ok": False, "estado": ROTA, "eventos": n, "legado": legado, "rota_en": i,
                    "motivo": f"la línea {i + 1} lleva huella {str(ev['h'])[:12]}… y su "
                              f"contenido produce {huella[:12]}…: el evento se editó "
                              f"después de escribirse.", "cabeza": previo,
                    "cicatrices": cicatrices}
        vistas.add(ev["h"])
        previo = ev["h"]
    # Fichero presente y sin un solo evento. Se distingue de AUSENTE porque se llega aquí
    # habiendo podido LEER el diario: son dos fallos distintos y se arreglan distinto.
    if n == 0:
        return {"ok": not expectativa, "estado": VACIO, "eventos": 0, "legado": 0,
                "rota_en": -1, "cabeza": GENESIS, "cicatrices": [],
                "motivo": "" if not expectativa else
                          "el diario existe y no tiene ni un evento, y se esperaba evidencia"
                          + (f" (ancla {esperado[:12]}…)" if hay_ancla else "")
                          + (f" (al menos {eventos_minimos})" if eventos_minimos else "")}
    if hay_ancla and esperado not in vistas:
        return {"ok": False, "estado": DESALINEADA, "eventos": n, "legado": legado,
                "rota_en": -1,
                "motivo": f"el ancla publicada {esperado[:12]}… no está en la cadena: el "
                          f"diario se cortó por detrás de ella o se reescribió entero.",
                "cabeza": previo, "cicatrices": cicatrices}
    if eventos_minimos and n < eventos_minimos:
        return {"ok": False, "estado": INSUFICIENTE, "eventos": n, "legado": legado,
                "rota_en": -1,
                "motivo": f"la cadena cierra pero trae {n} evento(s) y se exigían "
                          f"{eventos_minimos}. Una cadena íntegra sobre evidencia incompleta "
                          f"sigue siendo evidencia incompleta.", "cabeza": previo,
                "cicatrices": cicatrices}
    if cicatrices:
        # Cierra, pero NO de principio a fin: hay saltos reconocidos. Se distingue de INTEGRA
        # porque no se puede afirmar lo mismo — el tramo anterior a una cicatriz no está atado
        # al posterior — y porque quien exige integridad total (el ancla) tiene que poder
        # distinguirlos sin leer una lista.
        return {"ok": True, "estado": CICATRIZADA, "eventos": n, "legado": legado, "rota_en": -1,
                "motivo": f"{len(cicatrices)} discontinuidad(es) declarada(s): la cadena cierra "
                          f"por tramos, no de principio a fin"
                          + (f". {disc['problema']}" if disc["problema"] else ""),
                "cabeza": previo, "cicatrices": cicatrices}
    return {"ok": True, "estado": INTEGRA, "eventos": n, "legado": legado, "rota_en": -1,
            "motivo": disc["problema"], "cabeza": previo, "cicatrices": []}


def read_events(workspace: Path, kinds: list | None = None) -> list:
    path = ledger_path(workspace)
    if not path.is_file():
        return []
    out = []
    for line in path.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        try:
            ev = json.loads(line)
        except json.JSONDecodeError:
            continue
        if kinds and ev.get("kind") not in kinds:
            continue
        out.append(ev)
    return out


def write_run(workspace: Path, run_id: str, results: list, extra: dict | None = None) -> Path:
    """Escribe el informe estructurado de una corrida y devuelve su ruta.

    El artefacto se COMPROMETE con tres cosas que no están dentro de él
    -------------------------------------------------------------------
    `engine_digest`  qué programa emitió este veredicto (`core.trust`). Si el juez cambia,
                     el veredicto de antes y el de ahora no los emitió el mismo programa, y
                     eso se puede afirmar sin tener que impedir la edición. Es `I6'`.
    `ledger_head`    la cabeza de la cadena del diario en el instante de escribir.
    `gates`          el estado de cada puerta, que también viaja al diario.

    El compromiso es lo que convierte la redundancia en detección. Medido el 2026-09-23:
    editando SÓLO el artefacto —conservando su `mtime`— `refuto status` pasaba de
    «NO INTEGRABLE · 2 en rojo» a «INTEGRABLE · 0 en rojo», y el diario conservaba intacto
    el veredicto verdadero sin que nadie los comparara. Los datos ya estaban; faltaba el
    cruce. Ahora lo hace `latest_verification`.
    """
    from core.model import write_json
    from core.trust import digest_motor

    estados = {r.id: r.status for r in results}
    # El evento va PRIMERO: si se escribiera después, un fallo entre las dos escrituras
    # dejaría un artefacto sin contraparte en el diario, y «no hay con qué comparar» es
    # indistinguible de «alguien borró la contraparte».
    append_event(workspace, {"kind": "run/complete", "run_id": run_id,
                             "verdict": verdict_of(results), "gates": estados})
    payload = {
        "schema": "harness.run/v1",
        "run_id": run_id,
        "provenance": provenance(workspace, extra),
        "verdict": verdict_of(results),
        "engine_digest": digest_motor(),
        "ledger_head": cabeza(workspace),
        "gates": [r.to_dict() for r in results],
    }

    # ── Vinculación criptográfica: Cápsula de Decisión y Grafo de Evidencia DAG ──
    try:
        import sys
        from core.protocol import DecisionCapsule, CAPSULE_SCHEMA
        from core.evidence_graph import (EvidenceGraph, NODE_CLAIM, NODE_SUBJECT,
                                         NODE_POLICY, NODE_TOOL, NODE_GATE, NODE_CAPSULE,
                                         REL_DERIVED_FROM, REL_VERIFIED_BY)
        from core.assurance import compute_assurance_level

        total_examined = sum(
            getattr(r.scope, "examined", 0) for r in results if getattr(r, "scope", None)
        )
        sin_scope = [
            r.id for r in results
            if r.status == "PASS" and (getattr(r, "scope", None) is None or getattr(r.scope, "examined", 0) <= 0)
        ]

        pol_file = workspace / ".harness" / "policy.json"
        pol_dig = hashlib.sha256(pol_file.read_bytes()).hexdigest() if pol_file.is_file() else None

        env_fp = hashlib.sha256(f"{sys.platform}:{sys.version.split()[0]}".encode("utf-8")).hexdigest()
        tool_dig = digest_motor()

        evidence_dict = {
            "test_status": verdict_of(results),
            "suite_passed": (verdict_of(results) == "PASS" and len(sin_scope) == 0),
            "tests_run": total_examined,
            "scope": {"examined": total_examined if not sin_scope else 0},
            "document_path": run_id,
        }
        epistemic = compute_assurance_level(evidence_dict)

        capsule = DecisionCapsule(
            schema=CAPSULE_SCHEMA,
            decision_id=f"cap_{run_id}",
            claim_id=f"clm_{run_id}",
            status=verdict_of(results),
            epistemic_level=epistemic,
            scope={
                "items_examined": total_examined,
                "unscoped_gates": sin_scope,
                "declared": len(sin_scope) == 0,
            },
            verdict_rationale=f"Veredicto {verdict_of(results)} sobre {len(results)} compuerta(s)",
            ledger_head=cabeza(workspace),
            subject_digest=run_id,
            timestamp=now(),
            gates=[r.to_dict() for r in results],
            policy_digest=pol_dig,
            env_fingerprint=env_fp,
            tool_digest=tool_dig,
        )
        capsule.capsule_digest = capsule.compute_digest()
        payload["capsule"] = capsule.to_dict()

        # Grafo de Evidencia DAG (ADR-0010)
        ev_graph = EvidenceGraph()
        claim_id = f"clm_{run_id}"
        ev_graph.add_node(claim_id, NODE_CLAIM, digest=hashlib.sha256(claim_id.encode("utf-8")).hexdigest())
        subj_id = f"subj_{run_id[:8]}"
        ev_graph.add_node(subj_id, NODE_SUBJECT, digest=run_id)
        ev_graph.add_dependency(child_id=subj_id, parent_id=claim_id, relation=REL_DERIVED_FROM)

        ev_graph.add_node("tool_refuto", NODE_TOOL, digest=tool_dig)
        ev_graph.add_dependency(child_id=subj_id, parent_id="tool_refuto", relation=REL_DERIVED_FROM)

        if pol_dig:
            pol_node_id = f"pol_{pol_dig[:8]}"
            ev_graph.add_node(pol_node_id, NODE_POLICY, digest=pol_dig)
            ev_graph.add_dependency(child_id=pol_node_id, parent_id=claim_id, relation=REL_DERIVED_FROM)

        for r in results:
            g_node_id = f"gate_{r.id}"
            g_dig = hashlib.sha256(f"{r.id}:{r.status}:{r.measure}".encode("utf-8")).hexdigest()
            ev_graph.add_node(g_node_id, NODE_GATE, digest=g_dig, status=r.status)
            ev_graph.add_dependency(child_id=g_node_id, parent_id=subj_id, relation=REL_VERIFIED_BY)

        cap_node_id = capsule.decision_id
        ev_graph.add_node(cap_node_id, NODE_CAPSULE, digest=capsule.capsule_digest or "", status=capsule.status)
        for r in results:
            ev_graph.add_dependency(child_id=cap_node_id, parent_id=f"gate_{r.id}", relation=REL_DERIVED_FROM)

        payload["evidence_graph"] = ev_graph.to_dict()

        cap_path = workspace / ".harness" / "evidence" / f"{run_id}.capsule.json"
        write_json(cap_path, capsule.to_dict())
        graph_path = workspace / ".harness" / "evidence" / f"{run_id}.graph.json"
        write_json(graph_path, ev_graph.to_dict())
    except Exception:
        pass

    path = workspace / ".harness" / "evidence" / f"{run_id}.json"
    write_json(path, payload)
    return path


def reconciliar(workspace: Path, doc: dict) -> dict:
    """¿Dice el diario lo mismo que este artefacto? Es la comprobación de `I4`.

    Tres veredictos, y los tres son distintos a propósito:

        `ok`            las dos fuentes coinciden y la cadena cierra
        `contradice`    las dos fuentes son legibles y NO coinciden  →  FAIL
        `indeterminado` no se pudo establecer la integridad          →  INCONCLUSIVE

    La tercera existe porque «no pude comprobarlo» no es «está mal» ni «está bien». Un
    artefacto de antes de que existiera la cadena cae aquí, y cae en un estado que no
    aprueba pero tampoco acusa.
    """
    run_id = doc.get("run_id", "")
    declarado = {g.get("id", ""): g.get("status", "") for g in doc.get("gates", [])}
    cadena = verificar_cadena(workspace)
    if not cadena["ok"]:
        return {"estado": "contradice", "motivo": f"la cadena del diario está rota: "
                                                  f"{cadena['motivo']}"}
    # Truncar el diario entero lo dejaba «coherente»: una cadena vacía cierra trivialmente,
    # que es la misma verdad vacua que este trabajo existe para cerrar — y la cometí aquí al
    # escribirlo. El artefacto se comprometió con la cabeza que había al emitirse, así que
    # esa huella TIENE que seguir estando: si desapareció, el diario se cortó por detrás.
    ancla = str(doc.get("ledger_head") or "")
    if ancla:
        huellas = {str(e.get("h") or "") for e in read_events(workspace)}
        if ancla != GENESIS and ancla not in huellas:
            return {"estado": "contradice",
                    "motivo": f"el artefacto se ancló a la cabeza {ancla[:12]}… del diario y "
                              f"esa huella ya no está en la cadena: el diario se truncó o se "
                              f"reescribió después de emitir el veredicto."}

    eventos = [e for e in read_events(workspace, ["run/complete"])
               if e.get("run_id") == run_id]
    if not eventos:
        return {"estado": "indeterminado",
                "motivo": f"el diario no registra ninguna corrida «{run_id}»: no hay con qué "
                          f"contrastar el artefacto. Puede ser un artefacto de otro espacio, "
                          f"o un diario truncado."}
    ev = eventos[-1]
    if ev.get("gates") != declarado:
        difs = [f"{k}: artefacto dice {declarado.get(k, '—')} y diario dice {v}"
                for k, v in (ev.get("gates") or {}).items() if declarado.get(k) != v]
        return {"estado": "contradice",
                "motivo": f"el artefacto y el diario discrepan en {len(difs)} puerta(s): "
                          f"{'; '.join(difs[:3])}. Dos registros de la misma corrida que no "
                          f"coinciden: uno de los dos se editó después."}
    if ev.get("verdict") != doc.get("verdict"):
        return {"estado": "contradice",
                "motivo": f"el artefacto declara «{doc.get('verdict')}» y el diario registró "
                          f"«{ev.get('verdict')}» para la misma corrida."}
    return {"estado": "ok", "motivo": f"artefacto y diario coinciden · {cadena['eventos']} "
                                      f"eventos encadenados"}


def latest_verification(workspace: Path) -> dict | None:
    """La última verificación registrada: `{run_id, verdict, gates, path, generated_at}`.

    Por qué existe
    --------------
    `refuto verify` escribía aquí e imprimía la ruta; `refuto status` leía
    `.harness/state/` (las ejecuciones orquestadas, `core/run.py`) y respondía **«no hay
    ninguna ejecución registrada»** justo después. Ninguno de los dos mentía: leían dos
    familias distintas que, hasta la identidad tipada, además se llamaban igual.

    La corrección NO es fusionarlas —una sesión contiene N verificaciones y una verificación
    puede ocurrir sin orquestación, en CI—, sino que quien informa del estado lea **las dos
    fuentes** y las nombre por separado. Ver ADR-0012.

    Devuelve `None` sólo cuando no hay ninguna. Un fichero ilegible NO se salta en silencio:
    se declara en `unreadable`, porque «no pude leerlo» y «no existe» son cosas distintas y
    confundirlas es el defecto que este módulo entero existe para impedir.
    """
    d = workspace / ".harness" / "evidence"
    if not d.is_dir():
        return None
    candidatos = [p for p in d.glob("*.json") if p.name != "sbom.json"]
    if not candidatos:
        return None
    unreadable = []
    mejor = None
    for p in sorted(candidatos, key=lambda x: x.stat().st_mtime, reverse=True):
        try:
            doc = json.loads(p.read_text(encoding="utf-8"))
        except (OSError, ValueError) as exc:
            unreadable.append({"path": str(p), "problem": f"{type(exc).__name__}: {exc}"})
            continue
        if doc.get("schema") != "harness.run/v1":
            continue
        integridad = reconciliar(workspace, doc)
        veredicto = doc.get("verdict", "")
        if integridad["estado"] != "ok":
            # El veredicto del artefacto deja de ser la autoridad en cuanto su integridad
            # no se sostiene. No se «corrige» el veredicto —no se sabe cuál era— : se
            # declara que no se puede afirmar. Un informe que sigue imprimiendo INTEGRABLE
            # mientras su respaldo no cuadra es exactamente la captura con pretensiones que
            # el encabezado de este módulo rechaza.
            veredicto = (f"NO INTEGRABLE — la evidencia no se sostiene: "
                         f"{integridad['motivo']}")
        mejor = {
            "run_id": doc.get("run_id", ""),
            "verdict": veredicto,
            "gates": {g.get("id", ""): g.get("status", "") for g in doc.get("gates", [])},
            "generated_at": (doc.get("provenance") or {}).get("generated_at", ""),
            "path": str(p),
            "unreadable": unreadable,
            "integrity": integridad,
        }
        break
    if mejor is None and unreadable:
        return {"run_id": "", "verdict": "", "gates": {}, "generated_at": "", "path": "",
                "unreadable": unreadable}
    return mejor


def verdict_of(results: list) -> str:
    """Un veredicto por corrida, con las mismas palabras que las puertas.

    El orden importa: un NOT_EXECUTABLE manda sobre un FAIL porque significa que ni siquiera
    se sabe cuántos fallos hay.

    `NOT_APPLICABLE` no impide integrar, pero **tampoco cuenta como aprobado**: una corrida en
    la que ninguna puerta encontró sujeto no es INTEGRABLE, es una corrida sin ámbito. Ésa es
    la diferencia que un `PASS` de cortesía borraba.
    """
    from core.model import (BLOCKED, FAIL, INCONCLUSIVE, NOT_APPLICABLE, NOT_EXECUTABLE,
                            PASS)

    # `PASS ⟹ Proof(PASS)`, aplicado por quien tiene autoridad de veredicto.
    #
    # Una puerta que aprueba sin declarar CUÁNTO miró no ha demostrado nada: «no encontré
    # nada» y «no miré nada» producen el mismo resultado y no son el mismo hecho. El
    # invariante no se puede exigir al construir `Result` —el registro de puertas vive en
    # `gates/`, que la política protege del propio sujeto— así que se exige aquí, que es
    # donde se decide si la corrida es integrable. Una puerta sin cobertura declarada NO
    # retiene el cambio por sí sola, pero tampoco suma a los verdes: cuenta como
    # `INCONCLUSIVE`. Ver FORMAL-MODEL §3.3 e `I1`.
    sin_prueba = [r.id for r in results
                  if r.status == PASS and (getattr(r, "scope", None) is None or getattr(r.scope, "examined", 0) <= 0)]
    statuses = {r.status for r in results}
    if sin_prueba:
        statuses.discard(PASS)
        statuses.add(INCONCLUSIVE)
        if any(r.status == PASS and getattr(r, "scope", None) is not None and getattr(r.scope, "examined", 0) > 0
               for r in results):
            statuses.add(PASS)
    if NOT_EXECUTABLE in statuses:
        return "NO INTEGRABLE — hay verificaciones que no se pudieron ejecutar"
    if FAIL in statuses:
        return "NO INTEGRABLE — hay puertas en rojo"
    if BLOCKED in statuses:
        return "NO INTEGRABLE TODAVÍA — hay puertas que no se pudieron comprobar"
    # Después de los tres bloqueantes «duros»: un fallo real manda sobre un aprobado sin
    # justificar, porque el primero dice qué está mal y el segundo sólo dice que no se sabe.
    if INCONCLUSIVE in statuses:
        return (f"NO INTEGRABLE — {len(sin_prueba)} puerta(s) aprueban sin declarar qué "
                f"observaron: {', '.join(sin_prueba[:4])}. Un PASS sin cobertura no es una "
                f"demostración")
    if not statuses:
        return "SIN PUERTAS EJECUTADAS"
    if PASS not in statuses:
        n = sum(1 for r in results if r.status == NOT_APPLICABLE)
        return (f"SIN ÁMBITO — ninguna puerta encontró nada que comprobar "
                f"({n} no aplican). Eso no es un aprobado")
    if statuses <= {PASS, NOT_APPLICABLE}:
        n = sum(1 for r in results if r.status == NOT_APPLICABLE)
        return "INTEGRABLE" + (f" — {n} puertas sin sujeto en este espacio" if n else "")
    return "SIN PUERTAS EJECUTADAS"
