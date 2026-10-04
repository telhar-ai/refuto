# -*- coding: utf-8 -*-
"""A dónde va a hablar el agente, y si eso es lo que usted cree.

El fallo que este módulo diagnostica
------------------------------------
Una sesión puede abrirse perfectamente, con el contexto puesto y el guardián enganchado, y
morir en el primer mensaje con `API Error: Invalid URL` — porque una variable de entorno del
shell la está enrutando a otro proveedor.

Es un fallo especialmente caro porque **todo lo demás parece correcto**: el agente arranca,
declara su versión, responde el handshake. Lo único que falla es el destino, y el destino no se
ve por ninguna parte hasta que se envía el primer mensaje.

La sonda de refuto llegaba a `FUNCTIONAL` en esa situación, porque `FUNCTIONAL` se comprueba
con un handshake local que no toca la red. Eso está bien —es lo que hace que la sonda sea
gratis— pero deja un hueco: **el agente funciona y no puede hablar con nadie.**

Qué mira
--------
Sólo variables de entorno y configuración de Claude Code. **No lee los dotfiles de nadie**: se
limita a decir qué variable está puesta y qué efecto tiene, para que la persona decida dónde
buscarla.
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import urlparse

#: Variables que cambian a dónde habla Claude Code, con lo que implican.
ROUTING = {
    "ANTHROPIC_BASE_URL":        "redirige TODAS las peticiones a otro endpoint",
    "ANTHROPIC_API_URL":         "redirige las peticiones a otro endpoint",
    "ANTHROPIC_AUTH_TOKEN":      "sustituye la sesión por un token propio",
    "ANTHROPIC_API_KEY":         "usa una clave de API en vez de la suscripción",
    "ANTHROPIC_MODEL":           "fuerza el modelo",
    "ANTHROPIC_SMALL_FAST_MODEL": "fuerza el modelo auxiliar",
    "ANTHROPIC_DEFAULT_OPUS_MODEL": "fuerza el modelo Opus",
    "ANTHROPIC_DEFAULT_SONNET_MODEL": "fuerza el modelo Sonnet",
    "CLAUDE_CODE_USE_BEDROCK":   "enruta por AWS Bedrock",
    "CLAUDE_CODE_USE_VERTEX":    "enruta por Google Vertex",
    "CLAUDE_CODE_USE_FOUNDRY":   "enruta por Microsoft Foundry",
    "CLAUDE_CODE_SKIP_BEDROCK_AUTH": "omite la autenticación de Bedrock",
    "CLAUDE_CODE_SKIP_VERTEX_AUTH":  "omite la autenticación de Vertex",
    "AWS_BEARER_TOKEN_BEDROCK":  "token de Bedrock",
    "CLOUD_ML_REGION":           "región de Vertex",
}

#: Prefijos que delatan una configuración de proveedor aunque el nombre exacto cambie.
PREFIXES = ("ANTHROPIC_FOUNDRY", "AZURE_AI", "AZURE_OPENAI", "FOUNDRY_")


@dataclass
class Routing:
    provider: str = "suscripción de Anthropic"
    overrides: dict = field(default_factory=dict)
    problems: list = field(default_factory=list)
    warnings: list = field(default_factory=list)

    @property
    def overridden(self) -> bool:
        return bool(self.overrides)

    def to_dict(self) -> dict:
        return {"provider": self.provider, "overrides": self.overrides,
                "problems": self.problems, "warnings": self.warnings}


def _mask(name: str, value: str) -> str:
    """El nombre y la forma, nunca el secreto."""
    if any(x in name.upper() for x in ("TOKEN", "KEY", "SECRET", "PASSWORD")):
        return f"«presente, {len(value)} caracteres»"
    return value


def inspect(env: dict | None = None) -> Routing:
    """Qué proveedor va a usar la próxima sesión, y si esa configuración es coherente."""
    env = dict(os.environ if env is None else env)
    r = Routing()

    for name, value in sorted(env.items()):
        if not value:
            continue
        if name in ROUTING or any(name.startswith(p) for p in PREFIXES):
            r.overrides[name] = {"value": _mask(name, value),
                                 "effect": ROUTING.get(name, "configuración de proveedor")}

    if any(n.startswith(("ANTHROPIC_FOUNDRY", "AZURE_", "FOUNDRY_")) or
           n == "CLAUDE_CODE_USE_FOUNDRY" for n in r.overrides):
        r.provider = "Microsoft Foundry"
    elif "CLAUDE_CODE_USE_BEDROCK" in r.overrides:
        r.provider = "AWS Bedrock"
    elif "CLAUDE_CODE_USE_VERTEX" in r.overrides:
        r.provider = "Google Vertex"
    elif "ANTHROPIC_BASE_URL" in r.overrides or "ANTHROPIC_API_URL" in r.overrides:
        r.provider = "endpoint propio"
    elif "ANTHROPIC_API_KEY" in r.overrides or "ANTHROPIC_AUTH_TOKEN" in r.overrides:
        r.provider = "clave de API de Anthropic"

    # La URL, si la hay, tiene que ser una URL. `Invalid URL` en la primera petición sale de
    # aquí, y hasta entonces todo parece correcto.
    for name in ("ANTHROPIC_BASE_URL", "ANTHROPIC_API_URL"):
        raw = env.get(name, "")
        if not raw:
            continue
        parsed = urlparse(raw)
        if parsed.scheme not in ("http", "https") or not parsed.netloc:
            r.problems.append(
                f"{name}={raw!r} no es una URL válida (falta esquema o servidor). "
                f"Es la causa habitual de «API Error: Invalid URL»: la sesión abre bien y "
                f"muere en el primer mensaje.")

    if r.overridden and r.provider != "suscripción de Anthropic":
        r.warnings.append(
            f"esta sesión NO usará su suscripción: irá a «{r.provider}». "
            f"Lo imponen variables de entorno del shell, no la configuración de Claude Code.")
    return r


#: Nombres cortos que se admiten en `provider.expect`, y a qué proveedor efectivo equivalen.
EXPECTED = {
    "subscription": "suscripción de Anthropic",
    "api-key":      "clave de API de Anthropic",
    "bedrock":      "AWS Bedrock",
    "vertex":       "Google Vertex",
    "foundry":      "Microsoft Foundry",
    "custom":       "endpoint propio",
}


def expected(workspace) -> str:
    """A qué proveedor declara este espacio que debe hablar. Vacío si no lo declara.

    Se declara una vez en el manifiesto y se acabó la ambigüedad:

        "provider": { "expect": "subscription" }

    Sin declaración, refuto no puede saber si una redirección es deliberada o un accidente
    heredado del shell — y adivinarlo sería peor que preguntarlo una vez.
    """
    from pathlib import Path
    p = Path(workspace) / ".harness" / "harness.manifest.json"
    if not p.is_file():
        return ""
    try:
        doc = json.loads(p.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return ""
    want = str((doc.get("provider") or {}).get("expect", "")).strip().lower()
    return want if want in EXPECTED else ""


def matches(expect: str, provider_actual: str) -> bool:
    return EXPECTED.get(expect, "") == provider_actual


def offending_shell_files() -> list:
    """Dónde suele vivir esa configuración. **No lee el contenido**: sólo dice dónde mirar."""
    home = Path.home()
    return [str(p) for p in (home / ".zshrc", home / ".zshenv", home / ".zprofile",
                             home / ".bash_profile", home / ".bashrc", home / ".profile")
            if p.is_file()]


def clean_env(env: dict | None = None) -> dict:
    """Entorno sin ninguna redirección de proveedor. Devuelve la sesión a la suscripción."""
    out = dict(os.environ if env is None else env)
    for name in list(out):
        if name in ROUTING or any(name.startswith(p) for p in PREFIXES):
            out.pop(name, None)
    return out


def how_to_find(names: list) -> str:
    """La orden exacta para localizar dónde se define cada variable."""
    if not names:
        return ""
    patron = "|".join(names)
    archivos = " ".join(f"'{f}'" for f in offending_shell_files())
    return f"grep -nE '{patron}' {archivos}"
