# -*- coding: utf-8 -*-
"""Grafo de capacidades. Qué puede hacer este entorno, y con qué evidencia.

El error que este módulo evita
------------------------------
Preguntar «¿está instalado Claude?» y actuar según la respuesta. La pregunta útil no es qué
está instalado: es **qué se puede hacer**. Una tarea que necesita navegador y salida
estructurada no necesita un agente por su nombre; necesita esas dos capacidades, las tenga
quien las tenga.

De ahí que el router seleccione por capacidad y no por nombre (`core/routing.py`).

Estados, y son siete porque hay siete situaciones distintas
-----------------------------------------------------------
    MISSING       no está y hace falta
    DETECTED      hay indicios de que existe, sin comprobar
    INSTALLED     está presente                        ← el techo de lo que `which` afirma
    AVAILABLE     presente y configurado
    FUNCTIONAL    responde a una comprobación real
    VERIFIED      completó una tarea con salida verificable
    BLOCKED       existe y NO se puede usar, con causa declarada

`BLOCKED` es la que casi nadie modela, y es la que describe a Codex en esta máquina: está,
tiene versión, y el sistema operativo lo mata. No es `MISSING` —está— ni `INSTALLED` a secas
—eso sugeriría que sirve—.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field

from core.model import FUNCTIONAL as LADDER_FUNCTIONAL, INSTALLED as LADDER_INSTALLED, rung

MISSING = "MISSING"
DETECTED = "DETECTED"
INSTALLED = "INSTALLED"
AVAILABLE = "AVAILABLE"
FUNCTIONAL = "FUNCTIONAL"
VERIFIED = "VERIFIED"
BLOCKED = "BLOCKED"

#: Orden de fuerza. `BLOCKED` va aparte: no es un peldaño, es una salida lateral.
STRENGTH = (MISSING, DETECTED, INSTALLED, AVAILABLE, FUNCTIONAL, VERIFIED)


def usable(state: str) -> bool:
    """¿Se puede contar con esta capacidad para planificar una tarea?"""
    return state in (FUNCTIONAL, VERIFIED)


def at_least(state: str, minimum: str) -> bool:
    if state == BLOCKED or minimum == BLOCKED:
        return state == minimum
    return STRENGTH.index(state) >= STRENGTH.index(minimum)


# ── catálogo de capacidades ──────────────────────────────────────────────────────────
#: Cada capacidad declara qué significa poder hacerla. El catálogo es corto a propósito: una
#: capacidad que no cambia ninguna decisión de enrutado no es una capacidad, es una curiosidad.
CATALOG = {
    # agente
    "agent.headless":      "ejecutar una tarea sin interacción humana",
    "agent.streaming":     "emitir eventos estructurados durante la ejecución",
    "agent.tool_use":      "invocar herramientas durante la tarea",
    "agent.mcp":           "consumir servidores MCP",
    "agent.acp":           "hablar Agent Client Protocol",
    "agent.sessions":      "abrir, guardar y reanudar sesiones",
    "agent.budget":        "acotar el gasto de una ejecución en dinero",
    "agent.structured_out":"devolver salida validada contra un esquema",
    "agent.sandbox":       "ejecutar de forma acotada",
    "agent.subagents":     "delegar en agentes especializados",
    # entorno
    "vcs.git":             "leer y escribir historia de git",
    "forge.github":        "operar PR, checks y revisiones en GitHub",
    "forge.gitlab":        "operar MR y pipelines en GitLab",
    "browser.automation":  "navegar, capturar e inspeccionar una página real",
    "container.build":     "construir imágenes de contenedor",
    "orchestration.k8s":   "consultar y verificar despliegues en Kubernetes",
    "iac.terraform":       "planificar y aplicar infraestructura declarativa",
    "cloud.aws":           "inspeccionar recursos en AWS",
    "cloud.gcp":           "inspeccionar recursos en GCP",
    "cloud.azure":         "inspeccionar recursos en Azure",
    "security.sbom":       "generar inventario de dependencias",
    "security.scan":       "escanear dependencias e imágenes",
    "security.secrets":    "detectar secretos en el árbol",
    "security.attest":     "firmar y atestar artefactos",
    "observability.otel":  "emitir trazas OpenTelemetry",
    "test.python":         "ejecutar pruebas de Python",
    "test.node":           "ejecutar pruebas de Node",
    "build.jvm":           "construir proyectos de la JVM",
    "build.rust":          "construir proyectos de Rust",
    "build.go":            "construir proyectos de Go",
}

#: Qué herramienta del sistema aporta cada capacidad de entorno.
TOOL_CAPABILITY = {
    "git":        ["vcs.git"],
    "gh":         ["forge.github"],
    "glab":       ["forge.gitlab"],
    "docker":     ["container.build"],
    "kubectl":    ["orchestration.k8s"],
    "terraform":  ["iac.terraform"],
    "aws":        ["cloud.aws"],
    "gcloud":     ["cloud.gcp"],
    "az":         ["cloud.azure"],
    "syft":       ["security.sbom"],
    "trivy":      ["security.scan"],
    "gitleaks":   ["security.secrets"],
    "cosign":     ["security.attest"],
    "otel-cli":   ["observability.otel"],
    "pytest":     ["test.python"],
    "npm":        ["test.node"],
    "mvn":        ["build.jvm"],
    "gradle":     ["build.jvm"],
    "cargo":      ["build.rust"],
    "go":         ["build.go"],
    "playwright": ["browser.automation"],
}


@dataclass
class Capability:
    name: str
    state: str = MISSING
    provider: str = ""
    evidence: str = ""
    detail: str = ""
    #: E ejecutado · L archivo · D --help · I inferencia · ? no verificado
    level: str = "?"

    def to_dict(self) -> dict:
        return asdict(self) | {"description": CATALOG.get(self.name, "")}


def from_probe(report) -> dict:
    """Traduce una sonda de agente a capacidades. Sólo afirma lo que la sonda demostró."""
    caps: dict = {}
    agent = report.agent
    reachable = rung(report.level) >= rung(LADDER_FUNCTIONAL)

    def put(name: str, state: str, evidence: str, detail: str = "", level: str = "E") -> None:
        caps[name] = Capability(name, state, agent, evidence, detail, level)

    if rung(report.level) < rung(LADDER_INSTALLED):
        return {}

    if not reachable:
        # Está y no sirve. Es `BLOCKED`, no `MISSING`: la diferencia importa para el router,
        # que si no propondría instalarlo cuando ya está instalado.
        for name in ("agent.headless", "agent.tool_use", "agent.mcp"):
            put(name, BLOCKED, "sonda", report.stopped_because, "E")
        return caps

    ac = report.capabilities or {}
    proto = (report.protocol or {}).get("family", "")

    put("agent.headless", FUNCTIONAL, "handshake", f"peldaño {report.level}")
    put("agent.tool_use", FUNCTIONAL, "handshake", proto)
    put("agent.streaming", FUNCTIONAL, "handshake", proto)

    if proto == "acp":
        put("agent.acp", FUNCTIONAL, "ACP initialize", f"v{report.protocol.get('version')}")
    mcp = ac.get("mcpCapabilities")
    if isinstance(mcp, dict) and any(mcp.values()):
        put("agent.mcp", FUNCTIONAL, "ACP initialize",
            "transportes: " + ", ".join(k for k, v in mcp.items() if v))
    elif ac.get("mcp_servers") is not None:
        put("agent.mcp", FUNCTIONAL, "system/init",
            f"{len(ac['mcp_servers'])} servidores en la sesión sondeada")

    sess = ac.get("sessionCapabilities")
    if (isinstance(sess, dict) and sess) or ac.get("loadSession"):
        put("agent.sessions", FUNCTIONAL, "handshake",
            ", ".join(sorted(sess)) if isinstance(sess, dict) and sess else "loadSession")

    if ac.get("agents"):
        put("agent.subagents", FUNCTIONAL, "system/init", f"{len(ac['agents'])} subagentes")
    return caps


def from_adapter(spec) -> dict:
    """Capacidades que el adapter DECLARA con evidencia documental y no se pudieron sondear.

    Se marcan con nivel `D` y estado `AVAILABLE`, nunca `FUNCTIONAL`: un `--help` prueba que la
    bandera existe, no que funcione.
    """
    caps: dict = {}
    ext = spec.native_extensions or {}
    mapping = {
        "budget_usd": "agent.budget",
        "structured_output_schema": "agent.structured_out",
        "sandbox": "agent.sandbox",
        "cloud_sandbox": "agent.sandbox",
    }
    for key, cap in mapping.items():
        if key in ext:
            caps[cap] = Capability(cap, AVAILABLE, spec.name, "--help del binario instalado",
                                   str(ext[key].get("flag") or ext[key].get("command") or ""),
                                   ext[key].get("evidence", "D"))
    for key, decl in (spec.declared or {}).items():
        cap = mapping.get(key)
        if cap and decl.get("supported") is False:
            caps[cap] = Capability(cap, MISSING, spec.name, "--help del binario instalado",
                                   decl.get("note", ""), decl.get("evidence", "D"))
    return caps


def from_tools(tool_facts: list) -> dict:
    caps: dict = {}
    for t in tool_facts:
        for cap in TOOL_CAPABILITY.get(t.name if hasattr(t, "name") else t["name"], []):
            present = t.present if hasattr(t, "present") else t["present"]
            version = t.version if hasattr(t, "version") else t.get("version", "")
            path = t.path if hasattr(t, "path") else t.get("path", "")
            name = t.name if hasattr(t, "name") else t["name"]
            state = AVAILABLE if present else MISSING
            existing = caps.get(cap)
            if existing and at_least(existing.state, state):
                continue
            caps[cap] = Capability(cap, state, name,
                                   "which + --version" if present else "which",
                                   f"{path} {version}".strip(), "E")
    return caps


@dataclass
class CapabilityGraph:
    capabilities: dict = field(default_factory=dict)
    by_provider: dict = field(default_factory=dict)

    def merge(self, caps: dict, provider: str = "") -> "CapabilityGraph":
        for name, cap in caps.items():
            current = self.capabilities.get(name)
            # Gana el estado más fuerte. Un agente que sí puede algo no queda tapado por otro
            # que no puede: la pregunta es si el ENTORNO puede, no si puede uno concreto.
            if current is None or (cap.state != BLOCKED and
                                   (current.state == BLOCKED or
                                    at_least(cap.state, current.state))):
                self.capabilities[name] = cap
            self.by_provider.setdefault(cap.provider or provider, {})[name] = cap
        return self

    def state(self, name: str) -> str:
        cap = self.capabilities.get(name)
        return cap.state if cap else MISSING

    def satisfies(self, required: list, *, minimum: str = FUNCTIONAL) -> tuple[bool, list]:
        """¿Cubre este entorno el conjunto pedido? Devuelve (sí/no, las que faltan)."""
        missing = [r for r in required if not at_least(self.state(r), minimum)]
        return (not missing, missing)

    def providers_for(self, required: list, *, minimum: str = FUNCTIONAL) -> list:
        """Qué proveedores cubren TODO el conjunto pedido. Base del enrutado por capacidad."""
        out = []
        for provider, caps in self.by_provider.items():
            if not provider:
                continue
            if all(at_least(caps.get(r).state if caps.get(r) else MISSING, minimum)
                   for r in required):
                out.append(provider)
        return sorted(out)

    def to_dict(self) -> dict:
        return {
            "schema": "harness.capabilities/v1",
            "capabilities": {k: v.to_dict() for k, v in sorted(self.capabilities.items())},
            "by_provider": {p: sorted(c) for p, c in sorted(self.by_provider.items()) if p},
            "summary": self.summary(),
        }

    def summary(self) -> dict:
        counts: dict = {}
        for cap in self.capabilities.values():
            counts[cap.state] = counts.get(cap.state, 0) + 1
        return counts


def build(probes: list, specs: dict, tool_facts: list) -> CapabilityGraph:
    graph = CapabilityGraph()
    graph.merge(from_tools(tool_facts), provider="entorno")
    for rep in probes:
        graph.merge(from_probe(rep))
        spec = specs.get(rep.agent)
        if spec is not None and rung(rep.level) >= rung(LADDER_FUNCTIONAL):
            graph.merge(from_adapter(spec))
    return graph
