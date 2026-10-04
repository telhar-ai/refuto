# -*- coding: utf-8 -*-
"""Higiene del permiso. Reglas de aprobación que dejaron de decir lo que parecen decir.

El problema que este módulo ataca
---------------------------------
Una lista de permitidos crece sola. Cada sesión añade la orden concreta que se aprobó ese día,
nadie la retira nunca, y a los meses el fichero tiene miles de reglas que ya no describen una
política: describen un historial. Un historial no es una política, y el riesgo no es que sea
largo — es que **algunas de esas reglas aprueban hoy más de lo que aprobaron el día que se
escribieron**.

Medido en un espacio real: `.claude/settings.local.json` tenía 3465 reglas `allow` y
0 reglas `deny`.

Tres clases de podredumbre, y son distintas
-------------------------------------------
    HUECO     El comodín no está al final. `Bash(cmd:*)` acota un PREFIJO y es correcto;
              `Bash(sudo -u X -H ssh host ' *)` acota un HUECO, y todo lo que se inserte ahí
              queda aprobado sin preguntar. Esa regla concreta existía, y aprobaba cualquier
              orden ejecutada con privilegios por SSH contra un host de producción. No es un
              permiso amplio: es un permiso que no se puede leer.
              583 de las 3465.

    MUERTA    La regla nombra el scratchpad de una sesión que ya no existe. No aprueba nada
              —la ruta no está— pero tampoco es inofensiva: engorda el fichero, esconde las
              reglas vivas, y si alguna vez se reutilizara un identificador de sesión pasaría
              a aprobar algo que nadie decidió. 317 de las 3465, y las 317 muertas.

    INERTE    `Write(ruta)` no lo mira ninguna comprobación de permisos de fichero: las reglas
              de edición son `Edit(ruta)`, que cubre todas las herramientas de escritura. Una
              regla inerte es peor que ninguna, porque quien la escribió cree estar cubierto.

Qué NO se toca
--------------
El comodín dentro de una regla `Read(...)` o `Edit(...)` es un glob de rutas legítimo:
`Read(docs/**)` significa lo que parece. La detección de HUECO se limita a `Bash(...)`, donde
el contenido es una orden y el comodín tiene otra semántica. Confundir las dos cosas y podar
globs de lectura sería introducir un fallo mientras se arregla otro.

Y nada de esto decide por la persona: `analizar` mide, `podar` sólo actúa cuando se le pide,
siempre con copia de seguridad, y devuelve exactamente qué quitó.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path

from core.model import now

#: Raíz de los espacios efímeros por sesión. Una regla que nombra uno de éstos y cuya sesión
#: ya no existe es, por construcción, inaplicable.
SCRATCHPAD = re.compile(r"(/private/tmp/claude-\d+/[^/\s\"']+/[0-9a-f]{8}-[0-9a-f]{4}-"
                        r"[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})")

HUECO = "hueco"
MUERTA = "muerta"
INERTE = "inerte"

MOTIVOS = {
    HUECO:  "el comodín no está al final: aprueba lo que se inserte en esa posición",
    MUERTA: "nombra el scratchpad de una sesión que ya no existe",
    INERTE: "`Write(ruta)` no lo mira ninguna comprobación de permisos; la regla útil es `Edit(ruta)`",
}


def _carga(regla: str) -> tuple:
    """Parte `Herramienta(contenido)`. Devuelve `("", regla)` si no tiene esa forma."""
    if not regla.endswith(")") or "(" not in regla:
        return "", regla
    i = regla.index("(")
    return regla[:i], regla[i + 1:-1]


def tiene_hueco(regla: str) -> bool:
    """Un comodín que no acota un prefijo, en una regla cuyo contenido es una ORDEN.

    Sólo `Bash(...)`. En `Read(...)`/`Edit(...)` el contenido es una ruta y el comodín es un
    glob legítimo; tratarlos igual convertiría el arreglo en un defecto nuevo.
    """
    herramienta, cuerpo = _carga(regla)
    if herramienta != "Bash" or "*" not in cuerpo:
        return False
    return "*" in (cuerpo[:-2] if cuerpo.endswith(":*") else cuerpo)


def esta_muerta(regla: str, *, existe=Path.is_dir) -> bool:
    """Nombra un scratchpad de sesión, y esa sesión ya no está.

    Se exige que la ruta sea identificable: si la regla menciona un scratchpad con una forma
    que no se reconoce, se deja en paz. Podar por sospecha es podar de más.
    """
    m = SCRATCHPAD.search(regla)
    return bool(m) and not existe(Path(m.group(1)))


def es_inerte(regla: str) -> bool:
    return _carga(regla)[0] == "Write"


@dataclass
class Informe:
    total: int = 0
    conserva: list = field(default_factory=list)
    retira: dict = field(default_factory=dict)      # regla -> motivo

    @property
    def retiradas(self) -> int:
        return len(self.retira)

    def por_motivo_crudo(self) -> dict:
        """Cuenta por CLASE (`hueco`, `muerta`, `inerte`). Es lo que se asevera y se compara."""
        out: dict = {}
        for motivo in self.retira.values():
            out[motivo] = out.get(motivo, 0) + 1
        return out

    def por_motivo(self) -> dict:
        """Lo mismo, con la explicación en vez de la etiqueta. Es lo que se imprime."""
        return {MOTIVOS[k]: v for k, v in self.por_motivo_crudo().items()}

    def to_dict(self) -> dict:
        return {"total": self.total, "conservadas": len(self.conserva),
                "retiradas": self.retiradas, "por_motivo": self.por_motivo()}


def analizar(reglas: list, *, existe=Path.is_dir) -> Informe:
    """Clasifica sin tocar nada. Una regla se retira por UN motivo: el primero que aplica."""
    inf = Informe(total=len(reglas))
    for r in reglas:
        if tiene_hueco(r):
            inf.retira[r] = HUECO
        elif esta_muerta(r, existe=existe):
            inf.retira[r] = MUERTA
        elif es_inerte(r):
            inf.retira[r] = INERTE
        else:
            inf.conserva.append(r)
    return inf


def podar(settings: Path, *, dry_run: bool = True, existe=Path.is_dir) -> dict:
    """Retira las reglas podridas de un `settings*.json`, con copia previa.

    No reescribe reglas: las quita. Reescribir una regla con hueco exige saber qué quiso decir
    su autor, y esa suposición es justo la que produjo el hueco. Quitarla devuelve la decisión
    a la persona la próxima vez que haga falta, que es donde estaba antes de que el historial
    se disfrazara de política.
    """
    doc = json.loads(settings.read_text(encoding="utf-8"))
    permisos = doc.get("permissions") or {}
    reglas = permisos.get("allow") or []
    inf = analizar(reglas, existe=existe)

    resultado = {"fichero": str(settings), "dry_run": dry_run, "copia": "", **inf.to_dict(),
                 "ejemplos": {}}
    for regla, motivo in inf.retira.items():
        resultado["ejemplos"].setdefault(motivo, []).append(regla)
    for motivo in resultado["ejemplos"]:
        resultado["ejemplos"][motivo] = resultado["ejemplos"][motivo][:3]

    if dry_run or not inf.retiradas:
        return resultado

    copia = settings.with_name(f"{settings.name}.antes-de-podar-{now()[:19].replace(':', '')}")
    copia.write_bytes(settings.read_bytes())   # copia exacta: ni CRLF ni LF impuestos
    permisos["allow"] = inf.conserva
    doc["permissions"] = permisos
    settings.write_text(json.dumps(doc, ensure_ascii=False, indent=2) + "\n", encoding="utf-8", newline="\n")
    resultado["copia"] = str(copia)
    return resultado
