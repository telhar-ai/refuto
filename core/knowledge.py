# -*- coding: utf-8 -*-
"""Qué es este espacio. Lo que el informe de sesión decía de todo menos del proyecto.

El hueco que este módulo cubre
------------------------------
`core.session` compone un informe excelente sobre el GOBIERNO —dónde estás, qué no puedes
tocar, qué puertas correrán— y ni una línea sobre el PROYECTO. Un agente que abre sesión sabe
que hay reglas y no sabe qué se construye, con qué tecnología, ni quién responde de cada parte.

Eso no es un detalle estético: es la mitad cara del arranque. Medido en un espacio real, el
propio motor declaraba «Repositorio: —» y «Stack: no detectado» después de una semana de uso,
porque `core.discovery` modela un espacio como UN repositorio y aquel espacio eran **82**
bajo una raíz que no es git. La pregunta se dejó en `ASK`, nadie la respondió, y el agente
empezaba cada sesión sin saber en qué constelación estaba.

Qué se mide y qué se lee
------------------------
Dos grados de evidencia, y se distinguen porque no valen lo mismo:

    MEDIDO      del sistema de archivos, ahora: repositorios, árboles de trabajo, marcadores
                de construcción. No se puede discutir; puede estar incompleto.
    DECLARADO   de un registro que el espacio mantiene: capacidades, dueños, contratos.
                Dice lo que el proyecto CREE de sí mismo, que es distinto de lo que hay.

Nunca se presentan juntos sin decir cuál es cuál. Un inventario que mezcla lo que encontró con
lo que le contaron produce un agente seguro de cosas falsas, que es peor que uno ignorante.

Por qué no se usa un analizador de YAML
---------------------------------------
Refuto no tiene dependencias fuera de la biblioteca estándar, y añadir `PyYAML` para leer
un registro de capacidades sería cambiar esa propiedad por comodidad. Se lee el subconjunto que
el registro usa de verdad —listas de mapas planos— y se **declara** que es un subconjunto: si
un día el registro usa algo más rico, esto lo dirá en vez de inventárselo.
"""

from __future__ import annotations

import os
import re
from dataclasses import dataclass, field
from pathlib import Path

#: Directorios que no se recorren. Cuestan minutos y no contienen componentes del proyecto.
SKIP = {".git", "node_modules", "target", "dist", "build", ".next", ".nuxt", ".venv", "venv",
        "__pycache__", ".mypy_cache", ".pytest_cache", ".cache", "vendor", ".gradle",
        ".terraform", "coverage", ".turbo"}

#: Directorios OCULTOS que sí contienen componentes, y por qué hacen falta nombrados.
#:
#: La regla general descarta todo lo que empieza por punto, y es buena: lo oculto suele ser
#: artefacto. Pero `git worktree add` deja los árboles bajo `.worktrees/` por convención, y ahí
#: hay trabajo que no está en ningún otro sitio.
#:
#: Medido en un espacio real de 89 repositorios: 19 vivían bajo `.worktrees/` y el informe de
#: sesión declaraba «71 componentes, 9 árboles de trabajo». El filtro los descartaba DOS veces
#: —por `SKIP` y por el punto inicial— mientras la docstring de `inventariar` presumía de
#: detectar árboles de trabajo. Detectarlos no sirve de nada si el recorrido nunca llega a
#: ellos. Quitarlo de `SKIP` por sí solo tampoco arreglaba nada.
#:
#: `.worktrees` es una CONVENCIÓN, no una ley: el espacio puede declarar las suyas en
#: `workspace.containers` del manifiesto (ver `core.context.container_dirs`).
CONTENEDORES = {".worktrees"}

#: Marcador de construcción → tecnología. Es una MEDIDA: el fichero está o no está.
#: No se infiere del nombre del repositorio ni de su descripción, que mienten al envejecer.
MARCADORES = (
    ("Cargo.toml",       "rust"),
    ("go.mod",           "go"),
    ("pyproject.toml",   "python"),
    ("requirements.txt", "python"),
    ("setup.py",         "python"),
    ("package.json",     "node/ts"),
    ("deno.json",        "deno"),
    ("pom.xml",          "java"),
    ("build.gradle",     "java"),
    ("build.gradle.kts", "kotlin"),
    ("Gemfile",          "ruby"),
    ("composer.json",    "php"),
    ("mix.exs",          "elixir"),
    ("Package.swift",    "swift"),
    ("Dockerfile",       "contenedor"),
    ("Chart.yaml",       "helm"),
    ("main.tf",          "terraform"),
    ("kustomization.yaml", "kustomize"),
)

#: Dónde puede estar el registro de capacidades. El primero que exista manda.
#:
#: El orden estaba puesto al revés: primero la ruta de UN espacio concreto
#: (`architecture-review/…`) y en último lugar la del propio motor. Ahora manda la ruta que
#: refuto define —`.harness/capabilities.yaml`—, y detrás van las convenciones frecuentes. Un
#: espacio con otra distribución la declara en el manifiesto (`knowledge.capability_register`)
#: en vez de esperar a que su nombre entre en esta lista.
REGISTROS = (
    ".harness/capabilities.yaml",
    "architecture/capability-register.yaml",
    "architecture-review/capability-register.yaml",
    "capability-register.yaml",
)

#: Esquema del registro: `harness.capabilities/v1`. Se publica para que se pueda escribir uno
#: desde cero, en vez de copiarlo de un espacio que no se puede mirar.
#:
#:     capabilities:
#:       - capability: facturacion          # obligatorio: el nombre
#:         owner: equipo-pagos              # quién responde
#:         status: active                   # en qué estado está
#:         contract: acme:v1:emitir-factura # qué contrato publica
#:
#: `CAMPOS_LEIDOS` es lo que este lector extrae; `CAMPOS_CONOCIDOS` es lo que además admite
#: sin quejarse. Cualquier otra clave se reporta como «no leída»: un lector que ignora en
#: silencio lo que no entiende produce un inventario más corto que la realidad.
CAPABILITIES_SCHEMA = "harness.capabilities/v1"
CAMPOS_LEIDOS = {"owner": "dueno", "status": "estado", "contract": "contrato"}
#: Extensiones habituales de un registro de arquitectura. No se leen, pero tampoco son un
#: error: estaban aquí porque son las de un registro real, y se conservan documentadas como lo
#: que son —campos frecuentes—, no como el esquema.
CAMPOS_CONOCIDOS = ("bounded_context", "sub_contracts", "consumes_contracts",
                    "active_implementation", "consumers", "invariants", "notes",
                    "description", "tags")

#: Dónde suelen vivir los contratos publicados.
RAICES_CONTRATO = ("contracts/schemas", "contracts/openapi", "contracts", "schemas")


@dataclass
class Repo:
    ruta: str
    tecnologias: list = field(default_factory=list)
    worktree: bool = False


@dataclass
class Capacidad:
    nombre: str
    dueno: str = ""
    estado: str = ""
    contrato: str = ""


@dataclass
class Conocimiento:
    workspace: Path
    raiz_es_repo: bool = False
    repos: list = field(default_factory=list)
    truncado: int = 0
    capacidades: list = field(default_factory=list)
    registro: str = ""
    registro_parcial: str = ""
    contratos: dict = field(default_factory=dict)
    procedencia: list = field(default_factory=list)

    @property
    def worktrees(self) -> int:
        return sum(1 for r in self.repos if r.worktree)


def _tecnologias(directorio: Path) -> list:
    """Las tecnologías de un componente, por los marcadores que TIENE."""
    vistas = []
    for marcador, etiqueta in MARCADORES:
        if etiqueta not in vistas and (directorio / marcador).exists():
            vistas.append(etiqueta)
    return sorted(vistas)


def inventariar(workspace: Path, *, profundidad: int = 3, tope: int = 200) -> tuple:
    """Los componentes del espacio, medidos del sistema de archivos.

    Se detecta el repositorio por la EXISTENCIA de `.git`, no por que sea un directorio. Un
    árbol de trabajo (`git worktree`) tiene `.git` como FICHERO, y la comprobación habitual
    —`find -type d -name .git`— no lo ve. En un espacio real eso escondía 28 árboles de
    trabajo, algunos con trabajo que no estaba en ningún otro sitio. El defecto no es raro: es el que tiene toda
    herramienta que da por hecho que `.git` es un directorio.

    Detectar no basta: hay que LLEGAR. El recorrido descarta lo oculto, y `git worktree add`
    deja los árboles precisamente en un directorio oculto (`.worktrees/`). Por eso existe
    `CONTENEDORES`: la lista de directorios ocultos que sí se abren, nombrados uno a uno.
    """
    from core.context import container_dirs

    base = workspace.resolve()
    contenedores = set(container_dirs(base)) | CONTENEDORES
    repos: list = []
    truncado = 0
    for dirpath, dirnames, _ in os.walk(base, followlinks=False):
        aqui = Path(dirpath)
        relativo = aqui.relative_to(base)
        if len(relativo.parts) > profundidad:
            dirnames[:] = []
            continue
        dirnames[:] = [d for d in dirnames if d not in SKIP
                       and (d in contenedores or not d.startswith("."))]
        if not (aqui / ".git").exists():
            continue
        if len(repos) >= tope:
            truncado += 1
        else:
            repos.append(Repo(ruta=str(relativo) or ".",
                              tecnologias=_tecnologias(aqui),
                              worktree=(aqui / ".git").is_file()))
        # Un repositorio no contiene otro repositorio de trabajo: se deja de bajar.
        dirnames[:] = []
    return sorted(repos, key=lambda r: r.ruta), truncado


def registros(workspace: Path) -> tuple:
    """Dónde buscar el registro de capacidades en ESTE espacio.

    `knowledge.capability_register` del manifiesto manda; si no está, las convenciones.
    """
    from core.context import read_manifest

    cfg = read_manifest(workspace).get("knowledge")
    if isinstance(cfg, dict):
        declarado = cfg.get("capability_register")
        if isinstance(declarado, str) and declarado:
            return (declarado,) + REGISTROS
        if isinstance(declarado, list) and declarado:
            return tuple(str(x) for x in declarado) + REGISTROS
    return REGISTROS


def leer_registro(workspace: Path) -> tuple:
    """El registro de capacidades, si el espacio mantiene uno.

    Lee el subconjunto de YAML que estos registros usan —una lista de mapas planos bajo
    `capabilities:`, esquema `harness.capabilities/v1`— y nada más. Si encuentra algo que no
    sabe leer, lo DICE: un lector que ignora en silencio lo que no entiende produce un
    inventario más corto que la realidad, y nadie se entera.
    """
    for candidato in registros(workspace):
        p = workspace / candidato
        if not p.is_file():
            continue
        try:
            texto = p.read_text(encoding="utf-8")
        except OSError as exc:
            return [], candidato, f"no se pudo leer: {exc}"

        # `(?:^|\n)` y no `"\ncapabilities:"`: un registro cuya PRIMERA línea es
        # `capabilities:` no lleva salto delante, y partir por el salto lo declaraba vacío —
        # un fichero correcto reportado como ilegible, que es la misma clase de mentira que
        # este módulo existe para evitar. Descubierto por `tests/unit/test_knowledge.py`.
        corte = re.search(r"(?:^|\n)capabilities:", texto)
        if corte is None:
            return [], candidato, "no tiene una sección `capabilities:` que leer"
        cuerpo = ["", texto[corte.end():]]

        capacidades: list = []
        actual: Capacidad | None = None
        campos = dict(CAMPOS_LEIDOS)
        raras = set()
        for linea in cuerpo[1].splitlines():
            if linea and not linea[0].isspace():
                break                                     # se acabó la sección
            m = re.match(r"\s*-\s+capability:\s*(\S+)", linea)
            if m:
                actual = Capacidad(nombre=m.group(1))
                capacidades.append(actual)
                continue
            if actual is None:
                continue
            m = re.match(r"\s+([a-z_]+):\s*(.*)$", linea)
            if not m:
                continue
            clave, valor = m.group(1), m.group(2).split("#")[0].strip()
            if clave in campos and valor:
                setattr(actual, campos[clave], valor)
            elif clave not in campos and clave not in CAMPOS_CONOCIDOS:
                raras.add(clave)
        aviso = (f"campos no leídos: {', '.join(sorted(raras))}" if raras else "")
        return capacidades, candidato, aviso
    return [], "", ""


def contar_contratos(workspace: Path) -> dict:
    """Cuántos contratos publica el espacio, por raíz. Un número medido, no una lista larga."""
    out: dict = {}
    for raiz in RAICES_CONTRATO:
        d = workspace / raiz
        if not d.is_dir():
            continue
        n = 0
        for dirpath, dirnames, filenames in os.walk(d):
            dirnames[:] = [x for x in dirnames if x not in SKIP]
            n += sum(1 for f in filenames
                     if f.endswith((".json", ".yaml", ".yml", ".proto", ".avsc")))
        if n:
            out[raiz] = n
    return out


def medir(workspace: Path, *, profundidad: int = 3) -> Conocimiento:
    """Todo lo anterior, junto y con su procedencia."""
    k = Conocimiento(workspace=workspace)
    k.raiz_es_repo = (workspace / ".git").exists()
    k.repos, k.truncado = inventariar(workspace, profundidad=profundidad)
    k.procedencia.append(f"componentes: medidos del sistema de archivos "
                         f"(profundidad {profundidad}, `.git` como fichero O directorio)")
    k.capacidades, k.registro, k.registro_parcial = leer_registro(workspace)
    if k.registro:
        k.procedencia.append(f"capacidades: declaradas en `{k.registro}`")
    k.contratos = contar_contratos(workspace)
    if k.contratos:
        k.procedencia.append("contratos: contados por fichero de esquema")
    return k


def _planos(repos: list) -> dict:
    """Agrupa por el primer segmento de la ruta. Es la topología que el espacio ya expresa."""
    out: dict = {}
    for r in repos:
        plano = r.ruta.split("/")[0] if "/" in r.ruta else (r.ruta if r.ruta != "." else "raíz")
        out.setdefault(plano, []).append(r)
    return dict(sorted(out.items()))


def seccion(workspace: Path, *, profundidad: int = 3) -> list:
    """Las líneas del informe de sesión. Lista vacía si no hay nada que decir."""
    k = medir(workspace, profundidad=profundidad)
    if not k.repos and not k.capacidades:
        return []

    L = ["## Qué es este espacio", ""]

    if len(k.repos) > 1 and not k.raiz_es_repo:
        L += [f"**No es un repositorio: son {len(k.repos)}.** La raíz `{workspace.name}/` no "
              f"tiene `.git`; es el contenedor de una constelación de componentes, cada uno con "
              f"su propio historial, su propia rama viva y su propio CI. Antes de tocar nada, "
              f"identifica **en qué componente** estás: una orden de git ejecutada en la raíz no "
              f"aplica a ninguno.", ""]
    elif k.repos:
        L += [f"**{len(k.repos)} componente(s)** bajo `{workspace}`.", ""]

    if k.worktrees:
        L += [f"De ellos, **{k.worktrees} son árboles de trabajo** (`git worktree`): comparten "
              f"historial con su repositorio de origen y su `.git` es un FICHERO, no un "
              f"directorio. Si mides con `find -type d -name .git` no los verás — y son trabajo "
              f"real que no está en ningún otro sitio.", ""]

    if k.capacidades:
        activas = [c for c in k.capacidades if c.estado == "active"]
        L += [f"### Quién responde de qué  ·  _declarado en `{k.registro}`_", "",
              f"{len(k.capacidades)} capacidades declaradas ({len(activas)} activas). El dueño "
              f"es el componente que la posee: un cambio que cruza esa frontera **consume un "
              f"contrato**, no absorbe la responsabilidad del vecino.", "",
              "| capacidad | dueño | estado | contrato |", "|---|---|---|---|"]
        for c in k.capacidades:
            L.append(f"| `{c.nombre}` | `{c.dueno or '—'}` | {c.estado or '—'} | "
                     f"`{c.contrato or '—'}` |")
        L.append("")
        if k.registro_parcial:
            L += [f"_Aviso de lectura: {k.registro_parcial}. El registro tiene más de lo que "
                  f"esta tabla muestra; ábrelo si necesitas el resto._", ""]

    if k.repos:
        planos = _planos(k.repos)
        L += ["### Componentes y tecnología  ·  _medido por marcadores de construcción_", "",
              "La tecnología sale del fichero que la delata (`Cargo.toml` → rust, "
              "`package.json` → node/ts…). Un componente «(sin marcador)» no es un componente "
              "vacío: es uno cuya tecnología no se puede afirmar desde aquí.", ""]
        for plano, lista in planos.items():
            L.append(f"- **`{plano}/`** — {len(lista)} componente(s)")
            for r in lista:
                tec = ", ".join(r.tecnologias) or "sin marcador"
                marca = " · árbol de trabajo" if r.worktree else ""
                L.append(f"    - `{r.ruta}` — {tec}{marca}")
        L.append("")
        if k.truncado:
            L += [f"_Hay {k.truncado} componente(s) más que no se listan: el inventario se topa "
                  f"para no desbordar el informe. Están ahí aunque no aparezcan._", ""]

    if k.contratos:
        L += ["### Contratos publicados  ·  _contados_", ""]
        for raiz, n in k.contratos.items():
            L.append(f"- `{raiz}/` — {n} fichero(s) de esquema")
        L.append("")

    L += ["_Procedencia de esta sección: " + " · ".join(k.procedencia) + ". Lo **medido** es "
          "de ahora y puede estar incompleto; lo **declarado** dice lo que el proyecto cree de "
          "sí mismo, que no siempre es lo que hay. Cuando los dos discrepen, la discrepancia es "
          "el hallazgo._", ""]
    return L
