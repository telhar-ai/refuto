# -*- coding: utf-8 -*-
"""Descubrimiento del entorno, del núcleo SDD y del repositorio de trabajo.

Principio de cero suposiciones
------------------------------
Nada se asume: ni dónde está el núcleo, ni cuál es el repositorio, ni qué herramientas hay. Se
descubre, se verifica, y **se declara con qué confianza**. Cuando hay ambigüedad, se pregunta.

Una carpeta llamada `sdd` no es un núcleo SDD. Un núcleo SDD es algo que tiene un manifiesto
válido, una versión, y archivos que ese manifiesto declara. La diferencia entre las dos cosas es
toda la diferencia entre descubrir y adivinar.

Límites del recorrido, y son deliberados
----------------------------------------
Se recorre `$HOME` hasta una profundidad acotada, saltando lo que nunca contiene un núcleo
(`node_modules`, `.git`, `Library`, cachés). Un descubrimiento que tarda dos minutos se ejecuta
una vez y se desactiva. Se prefiere rápido e incompleto —diciendo dónde miró— a exhaustivo e
inutilizable.
"""

from __future__ import annotations

import json
import os
import platform
import shutil
import subprocess
import sys
from dataclasses import asdict, dataclass, field
from pathlib import Path

from core.confidence import Scored, resolve
from core.digest import sha256_file
from core.model import now, provenance
from core.proc import TEXT_IO

SKIP = {
    ".git", "node_modules", "__pycache__", ".venv", "venv", "dist", "build", "target",
    ".next", ".nuxt", "vendor", "Library", "Applications", ".Trash", ".cache", ".npm",
    ".gradle", ".m2", ".cargo", ".rustup", "Pods", ".terraform", "site-packages",
}

#: Señales de un núcleo SDD, con su peso. Cada una responde a «¿qué hace que esto sea un núcleo
#: y no una carpeta con un nombre parecido?».
CORE_SIGNALS = (
    ("manifiesto",   0.45, ("manifiesto.json", "manifest.json", "harness.manifest.json")),
    ("version",      0.15, ("VERSION",)),
    ("verificacion", 0.25, ("verificacion", "verification", "gates")),
    ("estandares",   0.15, ("estandares", "standards", "steering")),
    ("plantillas",   0.10, ("plantillas", "templates")),
    ("contratos",    0.10, ("contratos", "contracts")),
    ("decisiones",   0.05, ("decisiones", "decisions", "adr")),
)

NAME_HINTS = ("nucleo", "sdd", "sdd-core", "core", "harness-core", "framework")


# ── entorno ──────────────────────────────────────────────────────────────────────────
#: Herramientas que refuto sabe reconocer. `why` explica para qué haría falta: sin eso,
#: «falta X» es una queja, no un diagnóstico.
KNOWN_TOOLS = {
    "git":       {"category": "vcs",        "why": "procedencia, lock y trazabilidad"},
    "gh":        {"category": "forge",      "why": "PR, checks y revisión en GitHub"},
    "glab":      {"category": "forge",      "why": "MR y pipelines en GitLab"},
    "docker":    {"category": "container",  "why": "construir y escanear imágenes"},
    "kubectl":   {"category": "orchestr",   "why": "verificar despliegue y salud"},
    "helm":      {"category": "orchestr",   "why": "empaquetado de despliegue"},
    "terraform": {"category": "iac",        "why": "infraestructura declarativa"},
    "aws":       {"category": "cloud",      "why": "inspección de recursos en AWS"},
    "gcloud":    {"category": "cloud",      "why": "inspección de recursos en GCP"},
    "az":        {"category": "cloud",      "why": "inspección de recursos en Azure"},
    "python3":   {"category": "runtime",    "why": "ejecutar el propio harness"},
    "node":      {"category": "runtime",    "why": "proyectos y servidores MCP de npm"},
    "npm":       {"category": "pkg",        "why": "servidores MCP vía npx"},
    "pnpm":      {"category": "pkg",        "why": "gestor de paquetes del proyecto"},
    "yarn":      {"category": "pkg",        "why": "gestor de paquetes del proyecto"},
    "uv":        {"category": "pkg",        "why": "entornos de Python reproducibles"},
    "jq":        {"category": "data",       "why": "inspección de JSON en scripts"},
    "yq":        {"category": "data",       "why": "inspección de YAML en scripts"},
    "rg":        {"category": "search",     "why": "búsqueda rápida en el árbol"},
    "mvn":       {"category": "build",      "why": "construcción de proyectos Java"},
    "gradle":    {"category": "build",      "why": "construcción de proyectos JVM"},
    "go":        {"category": "runtime",    "why": "proyectos en Go"},
    "cargo":     {"category": "build",      "why": "proyectos en Rust"},
    "pytest":    {"category": "test",       "why": "ejecutar pruebas de Python"},
    "playwright":{"category": "browser",    "why": "validación visual y navegación"},
    "trivy":     {"category": "security",   "why": "escaneo de dependencias e imágenes"},
    "syft":      {"category": "security",   "why": "generación de SBOM"},
    "gitleaks":  {"category": "security",   "why": "detección de secretos en el árbol"},
    "cosign":    {"category": "security",   "why": "firma y atestación de artefactos"},
    "otel-cli":  {"category": "observ",     "why": "emisión de trazas OpenTelemetry"},
}


@dataclass
class ToolFact:
    name: str
    present: bool
    path: str = ""
    version: str = ""
    category: str = ""
    why: str = ""

    def to_dict(self) -> dict:
        return asdict(self)


def _version_of(binary: str, path: str) -> str:
    """Versión rápida y tolerante. Un fallo aquí no es un fallo del descubrimiento."""
    import re
    for args in (["--version"], ["version"], ["-v"]):
        try:
            p = subprocess.run([path, *args], capture_output=True, **TEXT_IO, timeout=10,
                               env={**os.environ, "NO_COLOR": "1"})
        except (OSError, subprocess.SubprocessError):
            continue
        text = ((p.stdout or "") + " " + (p.stderr or "")).strip()
        m = re.search(r"\d+\.\d+(?:\.\d+)?[\w.+-]*", text)
        if m:
            return m.group(0)
    return ""


def scan_tools(names: list | None = None, *, with_versions: bool = True) -> list:
    facts = []
    for name in sorted(names or KNOWN_TOOLS):
        meta = KNOWN_TOOLS.get(name, {})
        path = shutil.which(name) or ""
        facts.append(ToolFact(
            name=name, present=bool(path), path=path,
            version=_version_of(name, path) if (path and with_versions) else "",
            category=meta.get("category", ""), why=meta.get("why", "")))
    return facts


def scan_environment(*, with_versions: bool = True) -> dict:
    """Retrato de la máquina. No toca nada y no revela ningún secreto.

    `with_versions=False` se salta un subproceso por herramienta —treinta— cuando sólo hace
    falta saber qué hay, no en qué versión. Es la diferencia entre un comando de tres segundos
    y uno de trece, y un comando de trece segundos se deja de usar.
    """
    home = Path.home()
    return {
        "schema": "harness.environment/v1",
        "generated_at": now(),
        "os": {
            "system": platform.system(),
            "release": platform.release(),
            "machine": platform.machine(),
            "python": platform.python_version(),
            "python_executable": sys.executable,
        },
        "user": {
            "home": str(home),
            "cwd": os.getcwd(),
            "shell": os.environ.get("SHELL", ""),
        },
        # Presencia de credenciales, NUNCA su contenido. Saber que existe `~/.aws/credentials`
        # es diagnóstico; leerlo sería exfiltración.
        "credential_presence": {
            "aws": (home / ".aws" / "credentials").exists() or bool(os.environ.get("AWS_PROFILE")),
            "gcloud": (home / ".config" / "gcloud").is_dir(),
            "azure": (home / ".azure").is_dir(),
            "ssh": (home / ".ssh").is_dir(),
            "github_cli": (home / ".config" / "gh" / "hosts.yml").exists(),
            "docker": (home / ".docker" / "config.json").exists(),
        },
        "ci": {
            "in_ci": any(os.environ.get(v) for v in ("CI", "GITHUB_ACTIONS", "GITLAB_CI",
                                                     "JENKINS_URL", "BUILDKITE")),
            "provider": next((v for v in ("GITHUB_ACTIONS", "GITLAB_CI", "JENKINS_URL",
                                          "BUILDKITE") if os.environ.get(v)), ""),
        },
        "tools": [t.to_dict() for t in scan_tools(with_versions=with_versions)],
    }


# ── núcleo SDD ───────────────────────────────────────────────────────────────────────
@dataclass
class CoreCandidate:
    path: str
    manifest_path: str = ""
    name: str = ""
    version: str = ""
    commit: str = ""
    remote: str = ""
    materializes: int = 0
    integrity: str = "no comprobada"
    problems: list = field(default_factory=list)


def _read_json(path: Path):
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None


def _git_at(repo: Path, *args: str) -> str:
    try:
        p = subprocess.run(["git", "-C", str(repo), *args], capture_output=True, **TEXT_IO,
                           timeout=15)
        return p.stdout.strip() if p.returncode == 0 else ""
    except (OSError, subprocess.SubprocessError):
        return ""


def inspect_core(path: Path) -> Scored:
    """Puntúa una carpeta como posible núcleo SDD, y comprueba lo que declara.

    La comprobación de integridad es lo que separa «parece un núcleo» de «es un núcleo cuyos
    archivos coinciden con lo que su propio manifiesto dice».
    """
    cand = CoreCandidate(path=str(path))
    scored = Scored(subject=str(path))

    if any(h in path.name.lower() for h in NAME_HINTS):
        scored.add("nombre-sugerente", 0.05, f"el directorio se llama «{path.name}»")

    manifest = None
    for name in ("manifiesto.json", "manifest.json", "harness.manifest.json"):
        p = path / name
        if not p.is_file():
            continue
        doc = _read_json(p)
        # Un `manifest.json` que es una LISTA no es un manifiesto de núcleo: es otra cosa que
        # se llama igual —extensiones de VS Code, catálogos de paquetes—. Tratarlo como
        # manifiesto reventaba el descubrimiento entero por un archivo ajeno.
        if isinstance(doc, dict):
            manifest = doc
            cand.manifest_path = str(p)
            break

    if manifest is None:
        # Sin manifiesto no hay núcleo verificable. Puede haber señales, pero no llega a CIERTO
        # nunca — y esa es la protección contra confundir una carpeta con un framework.
        for label, weight, names in CORE_SIGNALS[1:]:
            if any((path / n).exists() for n in names):
                scored.add(label, weight * 0.4, "presente, pero sin manifiesto que lo declare")
        cand.problems.append("no hay manifiesto: no se puede verificar qué debería contener")
        scored.payload = asdict(cand)
        return scored

    scored.add("manifiesto", 0.45, f"{Path(cand.manifest_path).name} legible")
    cand.name = str(manifest.get("nucleo") or manifest.get("name") or path.name)
    cand.version = str(manifest.get("version", ""))
    entries = manifest.get("materializa") or manifest.get("materialize") or []
    cand.materializes = len(entries)

    if cand.version:
        scored.add("version", 0.15, cand.version)
    if entries:
        scored.add("materializa", 0.15, f"{len(entries)} archivos declarados")

    for label, weight, names in CORE_SIGNALS[1:]:
        if label == "version":
            continue
        if any((path / n).exists() for n in names):
            scored.add(label, weight, f"existe {names[0]}/")

    # Integridad: los archivos que el manifiesto declara, ¿están y coinciden?
    checked = mismatched = missing = 0
    for entry in entries[:200]:
        origin = entry.get("origen") or entry.get("from")
        digest = entry.get("sha256")
        if not origin or not digest:
            continue
        src = path / origin
        checked += 1
        if not src.is_file():
            missing += 1
        elif sha256_file(src) != digest:
            mismatched += 1

    if checked:
        if missing == 0 and mismatched == 0:
            cand.integrity = f"íntegro · {checked} archivos coinciden con su manifiesto"
            scored.add("integridad", 0.20, cand.integrity)
        else:
            cand.integrity = f"{mismatched} discrepan · {missing} ausentes de {checked}"
            cand.problems.append(cand.integrity)
            scored.add("integridad-rota", -0.30, cand.integrity)

    if (path / ".git").exists():
        cand.commit = _git_at(path, "rev-parse", "HEAD")
        cand.remote = _git_at(path, "config", "--get", "remote.origin.url")
        if cand.commit:
            scored.add("git", 0.05, f"commit {cand.commit[:12]}")

    scored.payload = asdict(cand)
    return scored


def find_cores(roots: list, *, max_depth: int = 4) -> dict:
    """Busca núcleos SDD bajo `roots`. Devuelve el resultado de `resolve`, con dónde miró."""
    seen: set = set()
    candidates: list = []
    visited_dirs = 0

    for root in roots:
        root = Path(root).expanduser()
        if not root.is_dir():
            continue
        base = len(root.resolve().parts)
        for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
            here = Path(dirpath)
            visited_dirs += 1
            if len(here.parts) - base >= max_depth:
                dirnames[:] = []
                continue
            dirnames[:] = [d for d in dirnames if d not in SKIP and not d.startswith(".")]
            marker = {"manifiesto.json", "manifest.json", "harness.manifest.json"} & set(filenames)
            looks = any(h in here.name.lower() for h in NAME_HINTS)
            if not marker and not looks:
                continue
            key = str(here.resolve())
            if key in seen:
                continue
            seen.add(key)
            candidates.append(inspect_core(here))

    out = resolve(candidates, what="el núcleo SDD")
    out["searched"] = [str(Path(r).expanduser()) for r in roots]
    out["directories_visited"] = visited_dirs
    out["max_depth"] = max_depth
    return out


# ── repositorio de trabajo ───────────────────────────────────────────────────────────
#: Marcadores de tipo de proyecto: (archivo, lenguaje, ecosistema, gestor).
STACK_MARKERS = (
    ("package.json",     "javascript", "node",   "npm"),
    ("pnpm-lock.yaml",   "javascript", "node",   "pnpm"),
    ("yarn.lock",        "javascript", "node",   "yarn"),
    ("pyproject.toml",   "python",     "python", "uv/pip"),
    ("requirements.txt", "python",     "python", "pip"),
    ("go.mod",           "go",         "go",     "go"),
    ("Cargo.toml",       "rust",       "cargo",  "cargo"),
    ("pom.xml",          "java",       "jvm",    "maven"),
    ("build.gradle",     "java",       "jvm",    "gradle"),
    ("build.gradle.kts", "kotlin",     "jvm",    "gradle"),
    ("Gemfile",          "ruby",       "ruby",   "bundler"),
    ("composer.json",    "php",        "php",    "composer"),
    ("*.csproj",         "csharp",     "dotnet", "dotnet"),
    ("Dockerfile",       "",           "container", ""),
    ("main.tf",          "hcl",        "terraform", "terraform"),
    ("Chart.yaml",       "yaml",       "helm",   "helm"),
)


def _cheap_repo_scan(path: Path, cwd: Path | None) -> Scored:
    """Fase 1 · señales que se leen del sistema de archivos. **Sin lanzar `git`.**

    Inspeccionar 251 repositorios con cuatro subprocesos de git cada uno tardaba 96 segundos.
    Un descubrimiento que tarda minuto y medio se ejecuta una vez y se desactiva. Aquí se
    puntúa con lo que cuesta un `stat`, y sólo los mejores pagan el precio de `git`.
    """
    scored = Scored(subject=str(path))
    info: dict = {"path": str(path), "inspected": False}

    scored.add("git", 0.30, "tiene .git")
    info["worktree"] = (path / ".git").is_file()

    langs, ecos, managers = set(), set(), set()
    for marker, lang, eco, mgr in STACK_MARKERS:
        hit = list(path.glob(marker))[:1] if "*" in marker else (
            [path / marker] if (path / marker).exists() else [])
        if hit:
            if lang:
                langs.add(lang)
            ecos.add(eco)
            if mgr:
                managers.add(mgr)
    info["languages"] = sorted(langs)
    info["ecosystems"] = sorted(ecos)
    info["package_managers"] = sorted(managers)
    if ecos:
        scored.add("stack", 0.15, ", ".join(sorted(ecos)))

    ci = []
    wf = path / ".github" / "workflows"
    if wf.is_dir():
        ci = sorted(p.name for p in list(wf.glob("*.y*ml"))[:10])
    if (path / ".gitlab-ci.yml").exists():
        ci.append(".gitlab-ci.yml")
    info["ci"] = ci
    if ci:
        scored.add("ci", 0.10, f"{len(ci)} definiciones")

    try:
        info["agent_configs"] = sorted(d.name for d in path.iterdir()
                                       if d.is_dir() and d.name in
                                       (".claude", ".kiro", ".gemini", ".codex", ".opencode"))
    except OSError:
        info["agent_configs"] = []
    if info["agent_configs"]:
        scored.add("configurado-para-agentes", 0.15, ", ".join(info["agent_configs"]))

    info["governed"] = (path / ".harness").is_dir()
    if info["governed"]:
        scored.add("ya-gobernado", 0.25, "tiene .harness/")

    if cwd is not None:
        try:
            cwd.resolve().relative_to(path.resolve())
            scored.settle("estás trabajando dentro de este repositorio")
            scored.add("contiene-el-directorio-actual", 0.50, str(cwd))
        except (ValueError, OSError):
            pass

    scored.payload = info
    return scored


def _enrich_with_git(scored: Scored) -> Scored:
    """Fase 2 · lo que sólo `git` sabe. Sólo para los candidatos que llegan aquí."""
    path = Path(scored.subject)
    info = scored.payload
    info["inspected"] = True
    info["remote"] = _git_at(path, "config", "--get", "remote.origin.url")
    info["branch"] = _git_at(path, "rev-parse", "--abbrev-ref", "HEAD")
    info["commit"] = _git_at(path, "rev-parse", "HEAD")
    info["dirty"] = bool(_git_at(path, "status", "--porcelain"))
    if info["remote"]:
        scored.add("remote", 0.10, info["remote"])
    if info["commit"]:
        scored.add("historia", 0.05, f"HEAD {info['commit'][:12]}")
    return scored


def inspect_repository(path: Path, *, cwd: Path | None = None) -> Scored:
    """Inspección completa de UN repositorio. Las dos fases seguidas."""
    if not (path / ".git").exists():
        s = Scored(subject=str(path), payload={"path": str(path)})
        s.add("sin-git", -1.0, "no es un repositorio git")
        return s
    return _enrich_with_git(_cheap_repo_scan(path, cwd))


def find_repositories(roots: list, *, max_depth: int = 3, cwd: Path | None = None,
                      enrich_top: int = 10) -> dict:
    """Busca repositorios en dos fases: barato para todos, caro para los mejores.

    `enrich_top` acota cuántos candidatos pagan el coste de `git`. Se **declara** en la salida
    cuántos quedaron sin inspeccionar: un recorte silencioso se lee como «no hay más».
    """
    import concurrent.futures as futures

    seen: set = set()
    candidates: list = []
    for root in roots:
        root = Path(root).expanduser()
        if not root.is_dir():
            continue
        base = len(root.resolve().parts)
        for dirpath, dirnames, _ in os.walk(root, followlinks=False):
            here = Path(dirpath)
            if len(here.parts) - base > max_depth:
                dirnames[:] = []
                continue
            dirnames[:] = [d for d in dirnames if d not in SKIP]
            if (here / ".git").exists():
                key = str(here.resolve())
                if key not in seen:
                    seen.add(key)
                    candidates.append(_cheap_repo_scan(here, cwd))
                dirnames[:] = []      # un repositorio no contiene otro repositorio de trabajo

    total = len(candidates)
    ranked = sorted(candidates, key=lambda c: (-int(c.decisive), -c.raw))
    top = ranked[:enrich_top]
    with futures.ThreadPoolExecutor(max_workers=8) as pool:
        list(pool.map(_enrich_with_git, top))

    out = resolve(ranked, what="el repositorio de trabajo")
    out["searched"] = [str(Path(r).expanduser()) for r in roots]
    out["found"] = total
    out["inspected_with_git"] = len(top)
    if total > len(top):
        out["truncated"] = (f"{total - len(top)} repositorios encontrados y NO inspeccionados "
                            f"con git: sólo se enriquecen los {enrich_top} mejores.")
    return out


def git_root(start: Path) -> Path | None:
    """El repositorio que contiene `start`, si lo hay. Es la señal más fuerte que existe."""
    out = _git_at(start, "rev-parse", "--show-toplevel")
    return Path(out) if out else None


def default_roots(cwd: Path, *, deep: bool = False) -> list:
    """Dónde buscar cuando nadie lo dice.

    El directorio actual NO basta: el núcleo suele vivir al lado del repositorio, no dentro.
    En el conjunto auditado, `proyecto/` y `nucleo/` son hermanos, y buscar sólo bajo
    `proyecto/` devolvía «no hay núcleo» estando a un directorio de distancia.

    Se suben dos niveles desde la raíz del repositorio. Más sería recorrer medio disco; menos,
    no encontrar lo que está justo al lado.
    """
    home = Path.home()
    roots = [cwd]
    base = git_root(cwd) or cwd
    for up in (base.parent, base.parent.parent):
        if up and up.is_dir() and up != home and up != Path(up.anchor):
            roots.append(up)
    if deep:
        roots += [home / n for n in ("Documents", "Projects", "src", "code", "dev", "work")]
    seen, out = set(), []
    for r in roots:
        rr = Path(r).expanduser()
        if rr.is_dir() and str(rr.resolve()) not in seen:
            seen.add(str(rr.resolve()))
            out.append(rr)
    return out


def _apply_binding(block: dict, bound: dict, kind: str) -> dict:
    """Un vínculo escrito es un HECHO: gana a cualquier heurística.

    Es lo que hace que la ambigüedad se pregunte UNA vez. Sin esto, un espacio con dos núcleos
    verificables preguntaría en cada ejecución, y preguntar siempre es la forma en que una
    pregunta se responde sin leerla.
    """
    b = (bound or {}).get(kind)
    if not b:
        return block
    target = Path(b["path"]).resolve()
    for c in block.get("candidates", []):
        if Path(c["subject"]).resolve() == target:
            return {**block, "outcome": "AUTO", "chosen": c, "question": "",
                    "note": f"vinculado en .harness/binding.json el {b.get('bound_at','')[:10]}"}
    return {**block, "outcome": "ASK", "chosen": None,
            "question": (f"el vínculo apunta a {b['path']}, que no salió en el descubrimiento. "
                         f"O se movió, o ya no es un {kind} válido. Vuelva a vincular."),
            "binding_stale": True}


def discover(cwd: Path, *, roots: list | None = None, deep: bool = False) -> dict:
    """Descubrimiento completo. No modifica nada."""
    search_roots = [Path(r).expanduser() for r in roots] if roots else default_roots(cwd, deep=deep)
    search_roots = [r for r in search_roots if r.is_dir()]

    env = scan_environment()
    cores = find_cores(search_roots, max_depth=4 if deep else 3)

    here = git_root(cwd)
    repos = find_repositories(search_roots, max_depth=3, cwd=cwd)
    if here is not None:
        # El repositorio que contiene el directorio actual manda sobre cualquier heurística.
        # Es un hecho, no una señal.
        for c in repos["candidates"]:
            if Path(c["subject"]).resolve() == here.resolve():
                repos = {**repos, "outcome": "AUTO", "chosen": c,
                         "question": "", "note": "el directorio actual está dentro de este repositorio"}
                break

    from core.binding import read as read_binding
    bound = read_binding(cwd)
    cores = _apply_binding(cores, bound, "sdd_core")
    repos = _apply_binding(repos, bound, "repository")

    return {
        "schema": "harness.discovery/v1",
        "generated_at": now(),
        "provenance": provenance(cwd),
        "bound": bool(bound),
        "environment": env,
        "sdd_core": cores,
        "repository": repos,
    }
