# -*- coding: utf-8 -*-
"""Primitivas de proceso y de consola que se comportan igual en los tres sistemas.

Por qué existe este módulo
--------------------------
Refuto nació en macOS y daba por hecho POSIX en cuatro sitios que no se ven hasta que
alguien lo ejecuta en Windows. Los cuatro se encontraron ejecutándolo de verdad sobre un
repositorio real de ~9 200 archivos, no leyendo el código:

1. **`os.geteuid()` no existe en Windows.** Estaba en el registro de CADA decisión del
   guardián. La excepción caía en el `except` que avisa de «auditoría interrumpida», así que
   el guardián devolvía `2` incluso para las escrituras que debía **permitir**: falla cerrado,
   que es lo correcto, pero deja el espacio inoperante y el diario vacío.
2. **`os.killpg` y `signal.SIGKILL` tampoco existen.** La sonda mataba el grupo de procesos al
   terminar, así que todo agente se reportaba `NOT_INSTALLED` con
   `AttributeError: module 'os' has no attribute 'killpg'` — un Claude Code perfectamente
   instalado declarado ausente.
3. **`subprocess(text=True)` decodifica con la codificación del sistema**, que en Windows es
   `cp1252`. La primera tilde de un mensaje del propio harness reventaba a quien lo leía:
   `UnicodeDecodeError: 'charmap' codec can't decode byte 0x8d`.
4. **`print()` de un carácter fuera de `cp1252`** —el `⚠` del aviso de auditoría— reventaba la
   respuesta estructurada del gancho: el guardián salía con `1`, sin JSON, y no comunicaba
   nada.

Los cuatro comparten la misma forma: **una llamada que en POSIX no puede fallar**, y por eso
nadie la envolvió.

La regla de este módulo
-----------------------
Aquí no se emula POSIX. Donde el concepto no existe —no hay `euid` en Windows— se devuelve
algo que dice «no aplica», y quien pregunta lo declara. Fingir un `0` sería declarar como
comprobado lo que no se ha comprobado, que es justo lo que este proyecto no hace en ninguna
otra parte.
"""

from __future__ import annotations

import os
import shutil
import signal
import subprocess
import sys

#: ¿Estamos sobre POSIX? Se pregunta una vez y se responde igual en todo el árbol.
POSIX = os.name == "posix"

#: Argumentos de decodificación para `subprocess`. **Siempre** estos, nunca `text=True` a secas.
#:
#: Refuto escribe sus propios mensajes en UTF-8 y luego los lee de vuelta desde el proceso
#: hijo. Sin fijar la codificación, esa lectura usa la del sistema y una tilde propia derriba
#: al lector. `errors="replace"` porque un mojibake en un extracto de diagnóstico es un
#: inconveniente; una excepción a mitad de una puerta es un veredicto perdido.
TEXT_IO = {"text": True, "encoding": "utf-8", "errors": "replace"}


def spawn_kwargs() -> dict:
    """Cómo aislar al hijo para poder matarlo entero después.

    Un lanzador de Node (Gemini, OpenCode, el `npx` de un servidor MCP) crea hijos que heredan
    los descriptores y los mantienen abiertos aunque el padre ya esté muerto. Hay que poder
    terminar el **grupo**, y para eso hay que crearlo al lanzar.

    En POSIX se hace con `setsid`; en Windows con `CREATE_NEW_PROCESS_GROUP`. `start_new_session`
    se acepta en Windows y **se ignora en silencio**, que es peor que no ponerlo: parece que
    aísla y no aísla.
    """
    if POSIX:
        return {"start_new_session": True}
    flags = getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0)
    return {"creationflags": flags} if flags else {}


def terminate(proc: subprocess.Popen, *, grace: float = 3.0,
              close_streams: bool = True) -> None:
    """Termina el proceso y su descendencia. Cortés primero, contundente después.

    Matar sólo al proceso no basta: el hijo que queda vivo mantiene el descriptor abierto y
    cuelga a quien esté leyéndolo. En POSIX se termina el grupo; en Windows se pide a
    `taskkill /T` que se lleve el árbol, y si no está —no siempre lo está en una imagen
    mínima— se cae a `Popen.kill()`, que al menos mata la raíz.

    `close_streams=False` para quien todavía tenga un hilo drenando `stderr`: cerrarle el
    descriptor por debajo cambia un fin de fichero limpio por una excepción dentro del hilo.
    """
    if proc.poll() is None:
        for hard in (False, True):
            try:
                _signal_tree(proc, hard=hard)
            except (ProcessLookupError, PermissionError, OSError):
                break
            try:
                proc.wait(timeout=grace)
                break
            except subprocess.TimeoutExpired:
                continue
    if close_streams:
        for stream in (proc.stdin, proc.stdout, proc.stderr):
            try:
                if stream and not stream.closed:
                    stream.close()
            except (OSError, ValueError):
                pass
    try:
        proc.wait(timeout=2)
    except subprocess.TimeoutExpired:
        pass


def _signal_tree(proc: subprocess.Popen, *, hard: bool) -> None:
    """Manda la señal al árbol entero. `hard` significa «ya no se pregunta»."""
    if POSIX:
        # `SIGKILL` existe en todo POSIX; el `getattr` es por si algún día no.
        sig = getattr(signal, "SIGKILL", signal.SIGTERM) if hard else signal.SIGTERM
        os.killpg(os.getpgid(proc.pid), sig)
        return
    if hard:
        # `/T` es lo que hace la diferencia: sin él se repite el problema del hijo de Node.
        killed = subprocess.run(["taskkill", "/F", "/T", "/PID", str(proc.pid)],
                                capture_output=True, timeout=10, **TEXT_IO)
        if killed.returncode == 0:
            return
        proc.kill()                       # `taskkill` ausente o sin permiso: al menos la raíz.
        return
    proc.terminate()


def euid() -> int | None:
    """El id efectivo de usuario, o `None` donde el concepto no existe.

    `None` **no** es un fallo: es la respuesta correcta en Windows, donde no hay `euid`. Quien
    lo registre debe escribir `null`, no `0`. Un `0` significaría «corriendo como root», que es
    exactamente lo contrario de la verdad.
    """
    getter = getattr(os, "geteuid", None)
    return getter() if getter else None


def owns_by_uid() -> bool:
    """¿Tiene sentido en este sistema hablar de dueño por `uid` y de `chown`?

    En Windows `st_uid` vale 0 para todo y `os.chown` no existe: comparar dueños ahí no
    detectaría nada y **devolvería un informe en verde sin haber comprobado nada**. Quien
    pregunte esto y reciba `False` debe declarar `checked: False`, no `PASS`.
    """
    return POSIX and hasattr(os, "chown")


def force_utf8_io() -> None:
    """Fija UTF-8 en la salida de ESTE proceso. Idempotente y sin efecto en POSIX moderno.

    Un gancho devuelve su decisión por `stdout` y sus motivos por `stderr`. Si la consola es
    `cp1252`, un solo carácter del propio mensaje —`⚠`, `—`, una tilde— tira el proceso con
    `UnicodeEncodeError` **antes** de imprimir el JSON. El resultado no es una decisión mala:
    es la ausencia de decisión, que el runtime interpreta como le parece.

    `backslashreplace` en vez de `replace` a propósito: en un canal que otro programa va a
    parsear, es mejor un escape reversible que un `?` que borra la información.
    """
    for stream in (sys.stdout, sys.stderr):
        reconfigure = getattr(stream, "reconfigure", None)
        if reconfigure is None:                       # stream sustituido en una prueba
            continue
        try:
            reconfigure(encoding="utf-8", errors="backslashreplace")
        except (ValueError, OSError):
            # Un `stdout` ya cerrado o no reconfigurable no es motivo para no arrancar.
            continue


def interpreter() -> str:
    """Con qué nombre se invoca Python **en esta máquina**, comprobándolo.

    El informe de sesión promete comandos al agente, y su propio módulo lo dice: «un informe que
    promete comandos inexistentes es peor que uno que no promete nada, porque el agente los
    intenta». `python3` estaba escrito a mano ahí. En POSIX siempre existe; en Windows es un
    alias que puede estar o no, y cuando no está el agente gasta una vuelta averiguando qué
    ejecutar — que es exactamente lo que ese informe existe para ahorrarle.

    Se devuelve el primer nombre corto que **resuelve de verdad**, y si ninguno resuelve, la
    ruta del intérprete que está corriendo esto: no es bonita, pero es la única que consta.
    """
    for nombre in ("python3", "python"):
        if shutil.which(nombre):
            return nombre
    return f'"{sys.executable}"' if " " in sys.executable else sys.executable
