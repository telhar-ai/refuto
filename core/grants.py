# -*- coding: utf-8 -*-
"""Concesiones de privilegio: la excepción NOMBRADA en el canal de órdenes.

El callejón que esto resuelve
-----------------------------
`command_deny` colapsa cuatro dimensiones en una lista plana con dos verdictos: elevación de
privilegio (`sudo`), destrucción (`rm -rf`, `dd`), alcance externo (`git push --force`) e
integridad de suministro (`curl | bash`). Dos verdictos sobre una dimensión —la forma de la
cadena— no bastan para cuatro preguntas distintas, y la consecuencia operativa es concreta:
`sudo cat /etc/shadow` y `sudo systemctl status` son la misma regla.

Observado el 2026-09-25 en un espacio real: un agente necesitaba cinco lecturas de diagnóstico
con `sudo` sobre un host concreto para cerrar un ticket. Con el modelo plano las únicas salidas
eran que una persona tecleara cada orden a mano, o mover `sudo` de «rechazo» a «consulta» para
todo el espacio y para siempre. Ninguna de las dos es proporcionada.

La forma que ya existía en el modelo
------------------------------------
`writable_paths` es una **excepción nombrada** a `protected_paths`: se evalúa ANTES —«evaluada
después nunca podría ganarle a lo protegido», dice `decide_write`— y su monotonía es `REDUCE`,
porque abre un agujero y por tanto el hijo sólo puede cerrarlo. Una concesión de privilegio es
exactamente su análogo en el canal de órdenes, y se construye igual a propósito: un mecanismo
nuevo con una forma nueva es un mecanismo que nadie sabe auditar.

Qué hace que una concesión no sea un agujero
--------------------------------------------
1. **La concesión ES el registro de aprobación.** Vive en `.harness/policy.json`, que la política
   protege, así que **un agente no puede concederse privilegio a sí mismo**: no puede escribir el
   fichero. `human_approval` no es un campo que alguien tenga que comprobar — es una propiedad
   del sitio donde la concesión está escrita.
2. **`effects: read-only` se VERIFICA contra `Ê`.** Si la orden concreta deriva alguna escritura,
   la concesión no aplica. Y si la orden es **opaca** tampoco: no poder demostrar que no escribe
   no es haber demostrado que no escribe. Eso convierte «confía en que es de lectura» en
   «demuéstralo», que es la diferencia entre este mecanismo y una lista de excepciones.
3. **Caduca.** `expires` es obligatorio. Una autorización sin fecha se convierte en permanente por
   omisión, y las permanentes son las que nadie revisa.
4. **Nada se abre por omisión.** `roles` y `hosts` son obligatorios, y `["*"]` significa
   «cualquiera» — hay que escribir el comodín. Un campo ausente no concede: una lista vacía
   tampoco. El defecto clásico de este tipo de tabla es que «sin especificar» signifique «todo».
5. **Una concesión mal formada no concede nada**, y se puede enumerar para decirlo en vez de
   ignorarla en silencio.

Lo que esto NO es
-----------------
No es un modelo de privilegio del sistema operativo. El agente sigue corriendo con el uid del
operador, así que una concesión no le da nada que no pudiera tomar rodeando el guardián con un
intérprete opaco. Lo que da es que el camino **declarado** exista, esté acotado y deje rastro —
`I6'`, no `I6`. Un control que no ofrece camino legítimo se rodea, y entonces no se mira.
"""

from __future__ import annotations

import fnmatch
import platform
from dataclasses import dataclass, field
from datetime import date

SCHEMA = "harness.grant/v1"

#: Valores admitidos de `human_approval`, y qué significan al decidir.
#:
#: `once-per-grant`  la persona aprobó la CLASE al escribir la concesión → `allow`.
#: `each-time`       la persona aprueba cada instancia → `ask`.
#:
#: El valor por omisión es el ESTRICTO. Un campo ausente en una tabla de autorización que
#: significara «adelante» es el modo clásico de conceder por descuido.
APROBACIONES = ("each-time", "once-per-grant")
APROBACION_POR_OMISION = "each-time"

#: Valores admitidos de `effects`. `read-only` es el único que se puede VERIFICAR hoy, contra
#: `Ê`; `unrestricted` no se verifica y por eso se nombra así y no «any»: quien lo escriba debe
#: leer que está renunciando a la comprobación.
EFECTOS = ("read-only", "unrestricted")
EFECTOS_POR_OMISION = "read-only"


@dataclass(frozen=True)
class Concesion:
    id: str
    roles: tuple = ()
    hosts: tuple = ()
    commands: tuple = ()
    effects: str = EFECTOS_POR_OMISION
    human_approval: str = APROBACION_POR_OMISION
    expires: str = ""
    evidence: str = ""

    @classmethod
    def from_dict(cls, d: dict) -> "Concesion":
        return cls(id=str(d.get("id", "")),
                   roles=tuple(d.get("roles") or ()),
                   hosts=tuple(d.get("hosts") or ()),
                   commands=tuple(d.get("commands") or ()),
                   effects=str(d.get("effects") or EFECTOS_POR_OMISION),
                   human_approval=str(d.get("human_approval") or APROBACION_POR_OMISION),
                   expires=str(d.get("expires", "")),
                   evidence=str(d.get("evidence", "")))

    def problemas(self) -> list:
        """Por qué esta concesión no se puede aplicar. Vacío significa bien formada.

        Se enumeran TODOS los problemas y no el primero: quien arregla una concesión quiere la
        lista, y descubrirlos de uno en uno invita a dejar de mirar.
        """
        malos = []
        if not self.id.strip():
            malos.append("sin `id`: una concesión que no se puede nombrar no se puede auditar ni "
                         "retirar")
        for campo, valor in (("roles", self.roles), ("hosts", self.hosts),
                             ("commands", self.commands)):
            if not valor:
                malos.append(f"`{campo}` vacío. Una lista vacía NO significa «cualquiera»: para "
                             f"eso se escribe `[\"*\"]`, y escribir el comodín es el punto — un "
                             f"campo que concede todo por omisión concede por descuido")
        if self.effects not in EFECTOS:
            malos.append(f"`effects: {self.effects}` no es uno de {EFECTOS}")
        if self.human_approval not in APROBACIONES:
            malos.append(f"`human_approval: {self.human_approval}` no es uno de {APROBACIONES}")
        if not self.expires.strip():
            malos.append("sin `expires`. Una autorización sin fecha se vuelve permanente por "
                         "omisión, y las permanentes son las que nadie revisa")
        else:
            try:
                date.fromisoformat(self.expires)
            except ValueError:
                malos.append(f"`expires: {self.expires}` no es una fecha ISO (AAAA-MM-DD)")
        return malos

    def caducada(self, hoy: date | None = None) -> bool:
        try:
            return date.fromisoformat(self.expires) < (hoy or date.today())
        except ValueError:
            return True         # ilegible se trata como caducada: no concede

    def to_dict(self) -> dict:
        return {"id": self.id, "roles": list(self.roles), "hosts": list(self.hosts),
                "commands": list(self.commands), "effects": self.effects,
                "human_approval": self.human_approval, "expires": self.expires,
                "evidence": self.evidence}


@dataclass
class Veredicto:
    """El resultado de buscar una concesión. `concesion` vacía significa «ninguna aplica»."""
    concesion: Concesion | None = None
    motivo: str = ""
    #: Por qué NO aplicó cada candidata que compartía la forma de la orden. Es lo que convierte
    #: «no hay concesión» en un diagnóstico: casi siempre la concesión existe y está caducada, o
    #: es de otro host, o la orden escribe.
    descartes: list = field(default_factory=list)


def _coincide(valor: str, patrones) -> bool:
    return any(p == "*" or fnmatch.fnmatch(valor, p) for p in patrones)


def cargar(policy) -> tuple:
    """Las concesiones de la política, como objetos. No filtra las mal formadas: las trae."""
    return tuple(Concesion.from_dict(d) if isinstance(d, dict) else Concesion(id="")
                 for d in (getattr(policy, "privilege_grants", None) or ()))


def buscar(policy, orden: str, *, rol: str = "", host: str = "", efectos=None,
           hoy: date | None = None) -> Veredicto:
    """¿Alguna concesión autoriza esta orden, para este rol, en este host, hoy?

    `efectos` es el `Efectos` de la orden si quien llama ya lo calculó; se pide en vez de
    recalcularlo porque `decide_command` lo tiene delante y derivarlo dos veces sería pagar dos
    veces el único coste medible de esta ruta.
    """
    anfitrion = host or platform.node()
    v = Veredicto()
    for c in cargar(policy):
        malos = c.problemas()
        if malos:
            v.descartes.append(f"«{c.id or '(sin id)'}» mal formada: {malos[0]}")
            continue
        if not _coincide(orden, c.commands):
            continue            # no es candidata: ni se menciona
        # Desde aquí la concesión SÍ describe esta orden, así que todo descarte se explica — es
        # la diferencia entre «no hay concesión» y «la hay y no aplica porque caducó ayer».
        if c.caducada(hoy):
            v.descartes.append(f"«{c.id}» describe esta orden y CADUCÓ el {c.expires}")
            continue
        if not _coincide(rol or "(sin rol)", c.roles):
            v.descartes.append(f"«{c.id}» describe esta orden y es para {list(c.roles)}; "
                               f"esta sesión declara «{rol or '(sin rol)'}»")
            continue
        if not _coincide(anfitrion, c.hosts):
            v.descartes.append(f"«{c.id}» describe esta orden y es para {list(c.hosts)}; "
                               f"esta máquina es «{anfitrion}»")
            continue
        if c.effects == "read-only":
            # Sin `Ê` no hay nada que verificar, y entonces la concesión NO aplica. Es la misma
            # asimetría que el caso opaco de abajo, y omitirla convertía el argumento de este
            # módulo en falso desde la propia API: con `efectos=None` la comprobación se saltaba
            # entera y `read-only` volvía a ser una promesa de quien la escribe. Hoy quien llama
            # (`decide_command`) siempre los pasa; una firma que concede por omisión sólo espera
            # a que alguien la llame de otra forma.
            if efectos is None:
                v.descartes.append(
                    f"«{c.id}» se declara `read-only` y esta consulta no trae los efectos de la "
                    f"orden: no hay nada contra lo que verificarlo, así que no concede")
                continue
            if efectos.escrituras:
                v.descartes.append(
                    f"«{c.id}» se declara `read-only` y la orden escribe en "
                    f"{sorted(efectos.escrituras)[:3]}: la concesión no la cubre")
                continue
            if efectos.opaco:
                v.descartes.append(
                    f"«{c.id}» se declara `read-only` y el efecto de esta orden no se puede "
                    f"derivar ({efectos.motivo_opaco}). No poder demostrar que no escribe no es "
                    f"haber demostrado que no escribe")
                continue
        v.concesion = c
        v.motivo = (f"autorizada por la concesión «{c.id}»"
                    + (f" ({c.evidence})" if c.evidence else "")
                    + f", para {list(c.roles)} en {list(c.hosts)}, "
                    + (f"efectos `{c.effects}` verificados contra Ê, "
                       if c.effects == "read-only" else f"efectos `{c.effects}`, ")
                    + f"vigente hasta {c.expires}")
        return v
    return v


def problemas_declarados(policy) -> list:
    """Todas las concesiones mal formadas de una política, para que una puerta lo diga.

    Una concesión mal formada no concede nada —eso lo garantiza `buscar`— y aun así es un
    problema: alguien creyó estar autorizando algo. Ignorarla en silencio deja a una persona
    esperando un permiso que no existe.
    """
    fuera = []
    for c in cargar(policy):
        for m in c.problemas():
            fuera.append(f"{c.id or '(sin id)'}: {m}")
    return fuera
