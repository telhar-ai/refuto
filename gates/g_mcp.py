# -*- coding: utf-8 -*-
"""G-MCP · Integridad referencial de la cadena MCP. (H-02)

Umbral: **toda herramienta MCP que un agente declara existe, su servidor está configurado, y
—cuando se puede interrogar— el servidor la anuncia de verdad.**

Los cinco veredictos posibles, y por qué no son dos:

    PASS      la herramienta existe y el servidor la anuncia
    FAIL      el agente exige un servidor que nadie declaró, o el servidor no arranca
    BLOCKED   el servidor está declarado pero no se puede interrogar desde aquí
              (HTTP con credencial de la sesión del agente). NO es un aprobado.
    NOT_EXEC  la puerta misma no pudo correr
    NOT_APPL  ningún agente del espacio declara herramientas MCP: no hay cadena que verificar

`BLOCKED` es la casilla que evita el fraude cómodo: sin ella, «no pude comprobarlo» acabaría
en verde, que es exactamente cómo `@navegador` sobrevivió sin existir.

`NOT_APPLICABLE` cierra el otro agujero, y es un defecto que esta puerta tuvo de verdad: con
cero referencias MCP devolvía **PASS** con la medida «nada que verificar». Un espacio sin un
solo agente MCP producía una puerta verde de integridad referencial — la misma clase de
mentira que la puerta persigue, cometida por la puerta. El umbral ya decía «resultado vacío
nunca es aprobado» y el código decía lo contrario; ahora coinciden.
"""

from __future__ import annotations

from core.mcp import (
    collect_required_refs, interrogate_http, interrogate_stdio, load_mcp_config,
    parse_tool_ref,
)
from core.model import (
    BLOCKED, CRITICAL, Evidence, FAIL, Finding, INFO, NOT_APPLICABLE, NOT_EXECUTABLE, PASS,
    Result, Scope,
)

GATE_ID = "G-MCP"
TITLE = "Integridad referencial de MCP"
THRESHOLD = ("toda herramienta declarada resuelve a un servidor configurado que la anuncia · "
             "resultado vacío nunca es aprobado")


def run(ctx) -> Result:
    required, bad_agents = collect_required_refs(ctx.workspace)
    configured, bad_configs = load_mcp_config(ctx.workspace)

    # Un archivo que no se puede leer NO se salta. Si no se sabe qué exige un agente ni qué
    # servidores hay, no se puede afirmar nada — y «no se puede afirmar» es NOT_EXECUTABLE,
    # no PASS. Encontrado por TestGateMcp::test_entrada_corrupta.
    unreadable = bad_agents + bad_configs
    if unreadable:
        return Result(
            GATE_ID, TITLE, NOT_EXECUTABLE, severity=CRITICAL, threshold=THRESHOLD,
            scope=Scope(examined=0, unknown=len(unreadable), universe="archivos de configuración MCP", declared=True, subject="configuración MCP"),
            measure=f"{len(unreadable)} archivo(s) de configuración ilegibles: no se puede "
                    f"establecer qué exige este espacio, así que no se puede aprobar",
            findings=[Finding(u["path"], u["problem"]) for u in unreadable])

    findings, observations, evidence = [], [], []
    servers_needed: dict = {}
    for raw, sources in sorted(required.items()):
        ref = parse_tool_ref(raw)
        if ref is None:
            findings.append(Finding(sources[0], f"referencia MCP con forma inválida: {raw!r}"))
            continue
        servers_needed.setdefault(ref.server, []).append((ref, sources))

    reports: dict = {}
    blocked_any = False

    for server, refs in sorted(servers_needed.items()):
        who = sorted({s for _, srcs in refs for s in srcs})
        entries = configured.get(server) or []
        if not entries:
            for ref, sources in refs:
                for src in sources:
                    findings.append(Finding(
                        src, f"declara {ref.raw} y NINGÚN mcp.json del espacio configura el "
                             f"servidor «{server}». La fase correrá sin él y devolverá nada, "
                             f"que se lee como «no hay nada que encontrar»."))
            continue

        if len(entries) > 1:
            observations.append(
                f"«{server}» está configurado en {len(entries)} archivos: "
                f"{', '.join(e['_source'] for e in entries)}. Dos verdades sobre el mismo nombre.")

        cfg = entries[0]
        if cfg.get("disabled"):
            findings.append(Finding(cfg["_source"],
                                    f"«{server}» está deshabilitado y {len(who)} agente(s) lo exigen"))
            continue

        # `--offline` no puede significar «no comprobar nada»: un servidor stdio es un proceso
        # local y no necesita red. Saltarlo en modo sin red convertía a CI —que suele correr
        # sin salida a internet— en un lugar donde esta puerta nunca comprobaba nada.
        # Encontrado por TestMcpMalicioso::test_un_servidor_que_no_arranca_falla.
        is_stdio = bool(cfg.get("command"))
        if ctx.offline and not is_stdio:
            blocked_any = True
            observations.append(
                f"«{server}» ({cfg.get('type', 'http')}) no se interrogó: modo sin red. "
                f"Los servidores stdio SÍ se comprueban en este modo.")
            continue

        if is_stdio:
            rep = interrogate_stdio(server, cfg, cwd=str(ctx.workspace))
        else:
            rep = interrogate_http(server, cfg)
        rep.declared_in = who
        reports[server] = rep
        evidence.append(Evidence(
            kind="rpc", summary=f"{server}: {rep.discovery_method or 'sin respuesta'}",
            source=cfg["_source"], excerpt=rep.error or f"{len(rep.tools)} herramientas"))

        if not rep.reachable:
            if rep.transport in ("http", "sse"):
                blocked_any = True
                observations.append(f"«{server}» ({rep.transport}): {rep.error}")
            else:
                findings.append(Finding(cfg["_source"],
                                        f"«{server}» está configurado y no responde: {rep.error}"))
            continue

        observations.append(
            f"«{server}» responde por {rep.discovery_method} · revisiones "
            f"{rep.protocol_versions or ['?']} · {len(rep.tools)} herramientas")

        for ref, sources in refs:
            if ref.wildcard:
                continue
            if rep.tools and ref.tool not in rep.tools:
                for src in sources:
                    findings.append(Finding(
                        src, f"exige {ref.raw} y el servidor «{server}» no anuncia esa "
                             f"herramienta; anuncia: {', '.join(sorted(rep.tools)[:8])}"))

    orphans = sorted(set(configured) - set(servers_needed))
    for name in orphans:
        observations.append(f"«{name}» está configurado y ningún agente lo declara. "
                            f"Superficie que nadie usa es superficie que nadie revisa.")

    measure = (f"{len(required)} referencias declaradas · {len(servers_needed)} servidores "
               f"exigidos · {len(configured)} configurados · {len(findings)} rotas")

    if findings:
        status = FAIL
    elif blocked_any:
        status = BLOCKED
    elif not servers_needed:
        # Ámbito vacío. No se comprobó nada, luego no se aprueba nada.
        return Result(
            GATE_ID, TITLE, NOT_APPLICABLE, severity=INFO, threshold=THRESHOLD,
            scope=Scope(examined=0, universe="servidores MCP declarados en el espacio",
                        declared=False, subject="mcp_servers"),
            measure="ningún agente de este espacio declara herramientas MCP: no hay cadena "
                    "referencial que verificar. No es un aprobado — es que la puerta no "
                    "tiene sujeto aquí. Declare un agente con herramientas `@servidor/…` "
                    "para que vuelva a aplicar.",
            observations=observations, evidence=evidence)
    else:
        status = PASS

    scope = Scope(
        examined=len(servers_needed) + len(required),
        unknown=len(bad_agents) + len(bad_configs),
        universe="servidores MCP y referencias a herramientas declaradas",
        declared=bool(configured or required),
        subject="configuración MCP",
        items_expected=len(servers_needed) + len(required),
        coverage=1.0 if not bad_configs else (len(configured) / (len(configured) + len(bad_configs))),
        evidence=[e.summary for e in evidence],
    )
    return Result(GATE_ID, TITLE, status, severity=CRITICAL, threshold=THRESHOLD,
                  measure=measure, findings=findings, observations=observations,
                  evidence=evidence, scope=scope)
