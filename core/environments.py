# -*- coding: utf-8 -*-
"""Contra qué está trabajando el agente. Declarado, no adivinado.

El fallo que este módulo corrige
---------------------------------
Una sesión concluyó que «nada de la plataforma está sirviendo». Era falso. Había sondeado
`app.example.com`, `sso.example.com` y `api.example.com` —**producción**— dando por hecho que
eran el entorno de trabajo. El de desarrollo usaba otra familia entera: `app-dev`,
`dev-gateway`, `dev-sso`, `dev-auth`.

Dos errores encadenados, y ninguno era de red:

1. **Se infirió el entorno del nombre del dominio.** `app.example.com` *parece* el sitio
   principal, así que se trató como el sitio a medir. El nombre de un dominio es una convención,
   no una declaración.
2. **La lista correcta estaba publicada y a mano** — en la cabecera `content-security-policy`
   que sirve la propia aplicación de desarrollo — y no se leyó. Un `connect-src` enumera
   exactamente los orígenes con los que ese frontend habla: es la declaración que el nombre no
   da.

El daño no fue perder una sonda: fue afirmar un diagnóstico de plataforma entero sobre el
entorno equivocado, y darlo por medido.

Por qué se declara y no se descubre
-----------------------------------
Un descubridor que busque «los dominios de este proyecto» acabaría eligiendo por heurística —y
elegir mal aquí significa apuntar a producción creyendo que es desarrollo, que es la categoría
de error que este módulo existe para impedir—. Así que el entorno se **declara** en
`.harness/environments.json`, que está protegido: lo escribe una persona. Refuto sólo lo
lee, lo enseña al arrancar, y puede comprobarlo.

Lo declarado dice cuál es el entorno de trabajo. Lo comprobado dice si responde. No es lo mismo
y no se presentan como si lo fueran.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path

ARCHIVO = ".harness/environments.json"
SCHEMA = "harness.environments/v1"

#: Qué significa cada código al sondear un servicio. La sesión que falló leyó `401` como
#: «caído», y `401` es exactamente lo contrario: hay algo vivo que exige credenciales.
LECTURA_HTTP = {
    "2xx": "vivo y sirviendo",
    "3xx": "vivo; redirige (típico de un flujo de autenticación)",
    "401": "VIVO y exigiendo autenticación — no es una caída",
    "403": "VIVO y denegando — no es una caída",
    "404": "vivo; esa ruta no existe",
    "5xx": "el origen falla",
    "503": "sin origen detrás",
    "521": "Cloudflare llegó y el origen no contestó",
    "sin DNS": "el nombre no existe",
}


@dataclass
class Entorno:
    nombre: str
    estado: str = ""
    es_el_de_trabajo: bool = False
    proposito: str = ""
    dominios: dict = field(default_factory=dict)
    hosts: list = field(default_factory=list)
    servicios: list = field(default_factory=list)
    datos: list = field(default_factory=list)
    acceso: dict = field(default_factory=dict)
    credenciales: str = ""
    avisos: list = field(default_factory=list)


@dataclass
class Inventario:
    ruta: str = ""
    autoridad: dict = field(default_factory=dict)
    entornos: list = field(default_factory=list)
    medido_el: str = ""
    error: str = ""

    @property
    def de_trabajo(self):
        return next((e for e in self.entornos if e.es_el_de_trabajo), None)


def leer(workspace: Path) -> Inventario:
    """El inventario declarado, o uno vacío. Nunca inventa un entorno."""
    p = workspace / ARCHIVO
    if not p.is_file():
        return Inventario()
    try:
        doc = json.loads(p.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        return Inventario(ruta=ARCHIVO, error=f"{type(exc).__name__}: {exc}")

    inv = Inventario(ruta=ARCHIVO, autoridad=doc.get("autoridad") or {},
                     medido_el=doc.get("medido_el", ""))
    conocidos = {f for f in Entorno.__dataclass_fields__}            # noqa: SLF001
    for nombre, bloque in (doc.get("entornos") or {}).items():
        if not isinstance(bloque, dict):
            continue
        campos = {k: v for k, v in bloque.items() if k in conocidos and k != "nombre"}
        inv.entornos.append(Entorno(nombre=nombre, **campos))
    # El de trabajo primero: es el que hay que leer, y lo demás es contexto para no confundirlo.
    inv.entornos.sort(key=lambda e: (not e.es_el_de_trabajo, e.nombre))
    return inv


#: Un `User-Agent` que no delate a la biblioteca. NO es cosmético ni una evasión: sin él,
#: Cloudflare responde **403 a todo** —al frontend vivo y a la producción caída por igual—, y el
#: sondeo mide la protección de bots en vez del servicio. Se detectó en el acto porque
#: el mismo host daba 200 con `curl` y 403 con `urllib` en la misma máquina y el mismo segundo.
_AGENTE = "harness-environments/1.0 (+sondeo de disponibilidad)"


def _codigo(url: str, *, timeout: float) -> str:
    """El código de respuesta de un dominio, o por qué no lo hay. Sólo cabeceras: no se
    descarga el cuerpo, y no se sigue la redirección — a dónde redirige es parte del hecho."""
    import urllib.error
    import urllib.request

    class _SinRedirigir(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, *_a, **_k):
            return None

    peticion = urllib.request.Request(url, method="HEAD",
                                      headers={"User-Agent": _AGENTE})
    abridor = urllib.request.build_opener(_SinRedirigir)
    try:
        with abridor.open(peticion, timeout=timeout) as r:
            return str(r.status)
    except urllib.error.HTTPError as exc:
        return str(exc.code)
    except urllib.error.URLError as exc:
        motivo = str(getattr(exc, "reason", exc))
        if "Name or service not known" in motivo or "nodename nor servname" in motivo:
            return "sin DNS"
        return f"sin respuesta ({motivo[:40]})"
    except OSError as exc:                                              # noqa: BLE001
        return f"sin respuesta ({type(exc).__name__})"


def verificar(workspace: Path, *, escribir: bool = False, timeout: float = 12.0) -> dict:
    """Vuelve a sondear lo declarado y dice en qué ha cambiado.

    Existe porque una declaración con una fecha dentro se pudre en silencio: dentro de tres
    meses el informe seguirá diciendo «200 el 2026-09-06» y nadie sabrá si sigue siendo verdad.
    Con `escribir`, actualiza el sondeo y la fecha en el propio archivo — que es la única forma
    de que el dato del informe sea de hoy y no de cuando alguien se acordó.

    Lo ejecuta una persona o su herramienta, no el agente: el archivo está protegido por
    política justo para eso.
    """
    from core.model import now

    p = workspace / ARCHIVO
    if not p.is_file():
        return {"ok": False, "razon": f"no hay {ARCHIVO} que verificar"}
    doc = json.loads(p.read_text(encoding="utf-8"))

    resultados, cambios = [], []
    for nombre, bloque in (doc.get("entornos") or {}).items():
        for dominio, d in (bloque.get("dominios") or {}).items():
            if not isinstance(d, dict):
                d = {"papel": str(d)}
                bloque["dominios"][dominio] = d
            antes = d.get("sondeo", "")
            codigo = _codigo(f"https://{dominio}", timeout=timeout)
            marca = f"{codigo} el {now()[:10]}"
            previo = antes.split(" el ")[0]
            if previo and previo != codigo:
                cambios.append(f"{dominio}: era «{previo}», ahora «{codigo}»")
            resultados.append({"entorno": nombre, "dominio": dominio,
                               "antes": previo or "—", "ahora": codigo})
            d["sondeo"] = marca

    # Si TODOS los dominios devuelven lo mismo, lo más probable no es que a todos les pase lo
    # mismo: es que el sondeo esté midiendo otra cosa. Pasó de verdad — 403 en los siete, que
    # era la protección de bots de Cloudflare rechazando a `urllib`. Un instrumento que puede
    # fallar así entero debe decirlo antes de que alguien firme el resultado.
    sospecha = ""
    distintos = {r["ahora"] for r in resultados}
    if len(resultados) > 2 and len(distintos) == 1:
        unico = distintos.pop()
        sospecha = (f"los {len(resultados)} dominios devuelven «{unico}», incluidos los que "
                    f"deberían diferir. Antes de creerlo, contrástalo con "
                    f"`curl -sS -o /dev/null -w '%{{http_code}}' https://<dominio>`: si curl "
                    f"discrepa, lo que estás midiendo es el sondeo, no el servicio.")

    if escribir and not sospecha:
        doc["medido_el"] = now()[:10]
        p.write_text(json.dumps(doc, ensure_ascii=False, indent=2) + "\n", encoding="utf-8", newline="\n")
    return {"ok": True, "resultados": resultados, "cambios": cambios,
            "escrito": escribir and not sospecha, "sospecha": sospecha}


def seccion(workspace: Path) -> list:
    """Las líneas del informe de sesión. Vacío si el espacio no declara entornos."""
    inv = leer(workspace)
    if inv.error:
        return ["## Entornos", "",
                f"⚠ `{inv.ruta}` existe y no se pudo leer ({inv.error}). El agente no sabe "
                f"contra qué trabaja: **no sondees nada hasta arreglarlo**, porque el fallo "
                f"conocido de esta casa es medir producción creyendo que es desarrollo.", ""]
    if not inv.entornos:
        return []

    L = ["## Contra qué estás trabajando", ""]
    trabajo = inv.de_trabajo
    if trabajo is not None:
        L += [f"**Entorno de trabajo: `{trabajo.nombre}`.** {trabajo.proposito}".rstrip() , "",
              "Todo lo que midas, sondees o toques es aquí, salvo que alguien te diga otra cosa "
              "**por su nombre**. No deduzcas el entorno del nombre de un dominio: es una "
              "convención, no una declaración.", ""]

    for e in inv.entornos:
        marca = "◀ ES EL DE TRABAJO" if e.es_el_de_trabajo else ""
        L += [f"### `{e.nombre}` — {e.estado or 'estado no declarado'} {marca}".rstrip(), ""]
        if e.proposito and not e.es_el_de_trabajo:
            L += [e.proposito, ""]
        if e.dominios:
            L.append("| dominio | papel | último sondeo |")
            L.append("|---|---|---|")
            for dominio, d in e.dominios.items():
                if isinstance(d, dict):
                    L.append(f"| `{dominio}` | {d.get('papel', '—')} | "
                             f"{d.get('sondeo', '—')} |")
                else:
                    L.append(f"| `{dominio}` | {d} | — |")
            L.append("")
        if e.hosts:
            L += ["**Máquinas**", ""]
            for h in e.hosts:
                L.append(f"- `{h.get('alias', '?')}` ({h.get('hostname', '?')}) — "
                         f"{h.get('papel', '')}")
            L.append("")
        if e.servicios:
            L += ["**Servicios** _(puerto → qué corre ahí)_", ""]
            for s in e.servicios:
                nota = f" · {s['nota']}" if s.get("nota") else ""
                L.append(f"- `{s.get('puerto')}` — **{s.get('servicio')}** en "
                         f"`{s.get('host', '?')}`{nota}")
            L.append("")
        if e.datos:
            L += ["**Plano de datos**", ""]
            for d in e.datos:
                nota = f" · {d['nota']}" if d.get("nota") else ""
                L.append(f"- `{d.get('puerto')}` — **{d.get('motor')}** en "
                         f"`{d.get('host', '?')}`{nota}")
            L.append("")
        if e.acceso:
            L += ["**Cómo se llega**", ""]
            if e.acceso.get("mecanismo"):
                L.append(f"- {e.acceso['mecanismo']}")
            for orden in e.acceso.get("ordenes", []):
                L.append(f"- `{orden}`")
            L.append("")
        if e.credenciales:
            L += [f"**Credenciales**: {e.credenciales}", ""]
        if e.avisos:
            L += ["**Trampas medidas** — cada una costó una sesión:", ""]
            L += [f"- {a}" for a in e.avisos]
            L.append("")

    if inv.autoridad:
        L += ["### Cuando dudes de qué dominio es cuál", "",
              inv.autoridad.get("descripcion", ""), ""]
        if inv.autoridad.get("comando"):
            L += ["```bash", inv.autoridad["comando"], "```", ""]

    L += ["### Cómo se lee un sondeo", "",
          "Un código de respuesta dice si hay algo detrás, no si funciona:", ""]
    L += [f"- `{k}` — {v}" for k, v in LECTURA_HTTP.items()]
    L += ["", "**`401` y `403` significan VIVO.** Contarlos como caída es el error que produjo "
              "el diagnóstico falso del 2026-09-06.", ""]

    proc = f"declarado en `{inv.ruta}`"
    if inv.medido_el:
        proc += f", medido por última vez el {inv.medido_el}"
    L += [f"_Procedencia: {proc}. Está protegido por política: si algo aquí ya no es cierto, "
          f"se corrige con una persona, no se edita al vuelo. Un agente que puede reapuntarse "
          f"solo a otro entorno puede reapuntarse a producción._", ""]
    return L
