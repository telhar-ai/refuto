#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""refuto — plataforma de ingeniería para operar agentes de código.

  Dónde estoy
    refuto discover                entorno, núcleo SDD y repositorio, con confianza declarada
    refuto bind set|show|verify    ata este espacio a un núcleo y a un repositorio
    refuto doctor                  ¿qué hay en esta máquina y qué funciona de verdad?
    refuto probe [--deep]          escalera de ejecutabilidad de los agentes
    refuto inventory [--json]      inventario mecánico del conjunto de repositorios

  Qué voy a hacer
    refuto install                 deja el espacio operativo: política, vínculo, guardián
                                    y contexto que cualquier agente encuentra solo
    refuto init                    sólo la estructura mínima
    refuto context                 qué cree refuto que está pasando, y por qué
    refuto plan                    qué se ejecutaría, quién y con qué puertas
    refuto policy show|compile|wire|unwire|audit
    refuto lock plan|update|verify|show

  Hacerlo
    refuto work                    qué tiene pendiente, ya enrutado a su rol y su runtime
    refuto chat [--task N]         abre una sesión sobre esa tarea, con su rol y su spec
    refuto run [--execute]         conduce el ciclo; en seco salvo --execute
    refuto resume [<run-id>]       continúa, si el entorno no cambió
    refuto status                  dónde está el trabajo y qué espera a una persona

  Demostrarlo
    refuto verify [--gate G]       ejecuta las puertas y emite evidencia
    refuto mcp                     integridad referencial de la cadena MCP
    refuto evidence [--last N]     lee el diario estructurado
    refuto memory list|summary     memoria en capas; NO es evidencia
    refuto docs                    regenera la matriz de compatibilidad
    refuto selftest                el juez se prueba a sí mismo

Sólo biblioteca estándar. Se ejecuta con `python3 refuto.py` o `./refuto.py`.
"""

from __future__ import annotations

import argparse
import contextlib
import io
import json
import os
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from core import report as R                                             # noqa: E402
from core.context import Context                                         # noqa: E402
from core.evidence import read_events, verdict_of, write_run             # noqa: E402
from core.model import (                                                 # noqa: E402
    BLOCKED, FAIL, FUNCTIONAL, INCONCLUSIVE, KIND_VERIFICATION, NOT_APPLICABLE,
    NOT_EXECUTABLE, PASS, new_id, now, rung, write_json,
)
from core.proc import TEXT_IO, force_utf8_io

REPO = Path(__file__).resolve().parent

# Códigos de salida. Tres, no dos: la diferencia entre «falló» y «no se pudo comprobar» es la
# razón de ser de refuto de gobierno, y desaparecería al colapsarlos.
#
# Viven en `core.envelope` y se importan: ahora los DERIVA el estado, y tener las constantes
# junto a la tabla que las deriva es lo que impide que vuelvan a divergir. Aquí se reexportan
# con el mismo nombre para no tocar ninguna de sus ~120 apariciones.
from core.envelope import (  # noqa: E402
    AGENTE, EXIT_BLOCKED, EXIT_FAIL, EXIT_OK, EXIT_USAGE, MAQUINA, PERSONA, Siguiente,
    envelope, exit_for,
)


#: El mismo texto para las 24 órdenes. Una bandera que se explica distinto en cada sitio es una
#: bandera que se comporta distinto en cada sitio, y aquí es justo lo contrario: un contrato.
AYUDA_JSON = ("la respuesta en `harness.envelope/v1`: estado, código derivado, procedencia, "
              "carga útil y qué toca después")


def _ws(opts) -> Path:
    return Path(opts.workspace or os.getcwd()).resolve()


def responder(opts, *, command: str, status: str, payload=None, run_id: str = "",
              next: list | None = None, ws: Path | None = None) -> int:
    """Declara la respuesta ESTRUCTURADA de una orden y devuelve su código de salida.

    Por qué el sobre se construye aquí y se imprime en `main`
    --------------------------------------------------------
    Construirlo ya, en la orden, hace que un sobre mal formado —un estado que no aprueba sin
    `next`, un turno inventado— reviente **en la orden que lo cometió** y no en el emisor, que
    es donde nadie sabría de quién era. Imprimirlo en `main` hace que haya **un solo** sitio que
    decide el formato: el defecto que esto cierra era justo el contrario, veinte `json.dumps` en
    línea y por tanto veinte contratos (medido el 2026-09-24).

    Es aditivo por construcción: una orden que no llama a `responder` se comporta exactamente
    como antes, y sin `--json` lo único que cambia es que el código de salida lo deriva el
    estado en vez de elegirlo la orden a mano.
    """
    from core.model import provenance

    espacio = ws if ws is not None else _ws(opts)
    opts._sobre = envelope(
        command=command, status=status, workspace=espacio,
        payload=payload if payload is not None else {},
        run_id=run_id, next=list(next or ()),
        # La procedencia no es decorado: una cifra sin su commit y su máquina no es una
        # medición, y es lo que permite correlacionar dos respuestas del mismo espacio.
        provenance=provenance(espacio) if espacio.exists() else {},
    )
    return exit_for(status)


# ── doctor ───────────────────────────────────────────────────────────────────────────
def cmd_doctor(opts) -> int:
    from adapters.registry import all_specs
    from core.probe import probe_all

    ws = _ws(opts)
    print(R.bold(f"\nrefuto doctor · {ws}"))

    reports = probe_all(all_specs(), deep=opts.deep, workspace=ws)
    print(R.render_probes(reports))

    checks: list = []
    py = sys.version_info
    checks.append(("python", py >= (3, 10), f"{py.major}.{py.minor}.{py.micro} (mínimo 3.10)"))
    import shutil
    for tool, why in (("git", "procedencia y lock"), ("gh", "GitHub"), ("glab", "GitLab")):
        found = shutil.which(tool)
        checks.append((tool, bool(found), found or "no está en el PATH"))

    ctx = Context(workspace=ws)
    for label, path in (("manifiesto", ctx.manifest_path), ("lock", ctx.lock_path),
                        ("política", ctx.policy_path)):
        # El remedio sale de la MISMA tabla que alimenta `next`, y por eso no pueden divergir.
        # Decía «ejecute `refuto init`» para los tres, y para el lock era doblemente falso: la
        # orden es `refuto lock init` y anclar un origen es un acto de persona.
        arreglo = (_REMEDIO_ARTEFACTO.get(label) or {}).get("do", "")
        checks.append((label, path.is_file(), str(path) if path.is_file() else
                       (f"falta — ejecute `{arreglo}`" if arreglo else "falta")))

    # El lanzador del guardián, y a quién pertenece lo que escribe.
    from core import launcher
    lz = launcher.check(ws)
    checks.append(("lanzador", lz["ok"], lz.get("reason") or lz.get("harness_home", "")))
    own = launcher.ownership_report(ws)
    if own["checked"]:
        checks.append(("propiedad", own["count"] == 0,
                       "todo pertenece a quien lo usa" if own["count"] == 0 else
                       f"{own['count']} archivos de .harness/ son de otro usuario — "
                       f"el rastro de auditoría se corta en silencio"))

    print(R.bold("  Entorno"))
    for name, ok, detail in checks:
        mark = R.paint("✓", "32") if ok else R.paint("✗", "31")
        print(f"    {mark} {name:<12} {R.dim(detail)}")
    print()

    from core import provider as prov
    # `ruta` y no `r`: la variable `r` la reusa el bucle de sondas más abajo, y el resumen
    # accionable leía `r.problems` sobre un ProbeReport. Reventaba en cuanto había un agente
    # roto — es decir, siempre que el diagnóstico servía para algo.
    ruta = prov.inspect()
    print(R.bold("  A dónde habla"))
    color = "32" if not ruta.overridden else ("31" if ruta.problems else "33")
    print(f"    {R.paint('●', color)} {ruta.provider}")
    for name, info in sorted(ruta.overrides.items()):
        print(R.dim(f"      {name} = {info['value']}  ({info['effect']})"))
    for problem in ruta.problems:
        print(R.paint(f"      ✗ {problem}", "31"))
    for w in ruta.warnings:
        print(R.paint(f"      ! {w}", "33"))
    if ruta.overrides:
        print(R.dim(f"      dónde buscarlo:  {prov.how_to_find(list(ruta.overrides))}"))
    print()

    functional = [r for r in reports if rung(r.level) >= rung(FUNCTIONAL)]
    broken = [r for r in reports if rung(r.level) < rung(FUNCTIONAL)]
    # El resumen accionable se ACUMULA en vez de imprimirse suelto, y se imprime desde la lista.
    # Así la persona y el agente leen lo mismo: antes el texto decía «→ falta: lock» y la cara
    # estructurada no existía, de modo que el consejo sólo llegaba a quien mira una terminal.
    siguientes: list = []
    for r in broken:
        siguientes.append(Siguiente(why=f"{r.agent}: {_remedy(r)}",
                                    do="refuto probe --verbose", who=PERSONA))
    missing = [n for n, ok, _ in checks if not ok]
    for falta in missing:
        siguientes.append(Siguiente(**_REMEDIO_ARTEFACTO.get(
            falta, {"why": f"falta {falta}", "do": "", "who": PERSONA})))
    if ruta.problems:
        siguientes.append(Siguiente(
            why="enrutado roto: la sesión abrirá y fallará en el primer mensaje",
            do="refuto chat --provider clean", who=PERSONA))
    elif ruta.overridden:
        siguientes.append(Siguiente(
            why=f"sus sesiones van a «{ruta.provider}», no a su suscripción",
            do=prov.how_to_find(list(ruta.overrides)), who=PERSONA))
    if own.get("count"):
        siguientes.append(Siguiente(
            why=f"{own['count']} archivos de .harness/ son de otro usuario: el rastro de "
                f"auditoría se corta en silencio (secuela de una sesión con sudo)",
            do=own["fix"], who=PERSONA))

    print(R.bold("  Resumen accionable"))
    if not functional:
        print(R.paint("    ✗ ningún agente alcanza FUNCTIONAL: este espacio no puede operar", "31"))
    for s in siguientes:
        print(R.paint(f"    → {s.why}", "33"))
        if s.do:
            print(R.dim(f"       hacer  {s.do}"))
        print(R.dim(f"       quién  {s.who}"))
    if functional and not siguientes:
        print(R.paint("    ✓ nada que arreglar", "32"))
    print()

    # El estado se conserva tal cual estaba —`functional` decide— porque cambiarlo rompería a
    # quien ya encadena `refuto doctor && …`. Lo que es nuevo es que el consejo viaje: un
    # `PASS` con `next` significa «puede operar, y además tienes esto pendiente», que es
    # exactamente lo que el texto ya decía y la máquina no podía leer.
    return responder(opts, command="doctor", status=PASS if functional else FAIL, ws=ws,
                     next=siguientes,
                     payload={"schema": "harness.doctor/v1",
                              "agents": [r.to_dict() for r in reports],
                              "environment": [{"name": n, "ok": ok, "detail": d}
                                              for n, ok, d in checks],
                              "provider": {"provider": ruta.provider,
                                           "overridden": ruta.overridden,
                                           "problems": list(ruta.problems),
                                           "warnings": list(ruta.warnings)},
                              "functional": [r.agent for r in functional],
                              "broken": [r.agent for r in broken]})


#: Qué hacer cuando falta un artefacto, y **de quién es el turno**. Antes el texto decía
#: «falta — ejecute `refuto init`» para los tres por igual, y para el lock era falso por dos
#: motivos: la orden es `refuto lock init`, y anclar un origen inmutable es un acto de persona.
#: La puerta G-LOCK decía una tercera cosa. Tres instrucciones para el mismo hueco, medido el
#: 2026-09-24; aquí hay una, y la enuncia quien la puede cumplir.
_REMEDIO_ARTEFACTO = {
    "manifiesto": {"why": "no hay manifiesto: el espacio no declara qué necesita",
                   "do": "refuto install", "who": MAQUINA},
    "política": {"why": "no hay política: sin ella el guardián aplica los valores de fábrica",
                 "do": "refuto install", "who": MAQUINA},
    "lock": {"why": "no hay lock: el espacio no declara con qué origen se materializó, y "
                    "G-LOCK no puede afirmar nada",
             "do": "refuto lock init", "who": PERSONA},
    "python": {"why": "la versión de python es anterior a la mínima (3.10)",
               "do": "", "who": PERSONA},
    "git": {"why": "git no está en el PATH: sin él no hay procedencia ni lock",
            "do": "", "who": PERSONA},
    "gh": {"why": "gh no está en el PATH: las órdenes de GitHub no se podrán ejecutar",
           "do": "", "who": PERSONA},
    "glab": {"why": "glab no está en el PATH: las órdenes de GitLab no se podrán ejecutar",
             "do": "", "who": PERSONA},
    "lanzador": {"why": "el lanzador del guardián no resuelve: el espacio corre sin control "
                        "preventivo",
                 "do": "refuto policy wire --agent claude", "who": MAQUINA},
}


def _remedy(rep) -> str:
    """Un diagnóstico sin acción concreta es una queja."""
    if rep.signature.get("verdict") == "REVOKED":
        return (f"certificado de firma REVOCADO → reinstale el agente "
                f"(p. ej. `npm i -g @openai/{rep.agent}@latest`) y vuelva a sondear")
    if rep.level == "NOT_INSTALLED":
        return "no está instalado → instálelo o quítelo de `agents` en el manifiesto"
    if "sin respuesta" in rep.stopped_because or "colgado" in rep.stopped_because:
        return (f"arranca pero no responde al handshake → compruebe la sesión "
                f"(`{rep.agent} auth` / login) y los permisos del binario")
    return rep.stopped_because or "revise la sonda con `refuto probe --verbose`"


# ── probe ────────────────────────────────────────────────────────────────────────────
def cmd_probe(opts) -> int:
    from adapters.registry import ADAPTERS, all_specs
    from core.probe import probe_all

    ws = _ws(opts)
    specs = [ADAPTERS[a] for a in opts.agent] if opts.agent else all_specs()
    reports = probe_all(specs, deep=opts.deep, workspace=ws)
    print(R.render_probes(reports))
    if opts.verbose:
        for r in reports:
            print(f"  {R.bold(r.agent)}")
            for s in r.steps:
                mark = "✓" if s["ok"] else "✗"
                print(f"    {mark} {s['step']:<18} {R.dim(str(s['detail'])[:110])}")
            print()

    rotos = [r for r in reports if rung(r.level) < rung(FUNCTIONAL)]
    siguientes = [Siguiente(why=f"{r.agent}: {_remedy(r)}", do="refuto probe --verbose",
                            who=PERSONA) for r in rotos]
    # Cero agentes sondeados no es «todos funcionan». Con `--agent` de un nombre desconocido, o
    # sin ningún adapter, la comprobación `all(...)` de antes daba `True` sobre una lista vacía
    # y la sonda salía con 0 sin haber medido nada.
    if not reports:
        estado = BLOCKED
        siguientes.append(Siguiente(
            why="no se sondeó ningún agente: un ámbito vacío no aprueba",
            do="refuto probe", who=PERSONA))
    else:
        estado = FAIL if rotos else PASS
    return responder(opts, command="probe", status=estado, ws=ws, next=siguientes,
                     payload=[r.to_dict() for r in reports])


# ── discover ────────────────────────────────────────────────────────────────────────
def cmd_discover(opts) -> int:
    from core.discovery import discover

    ws = _ws(opts)
    roots = [Path(r).expanduser() for r in opts.root] if opts.root else None
    result = discover(ws, roots=roots, deep=opts.deep)

    if opts.json:
        print(json.dumps(result, ensure_ascii=False, indent=2))
        return EXIT_OK

    env = result["environment"]
    print(R.bold(f"\nrefuto discover · {ws}"))
    print(R.dim(f"  {env['os']['system']} {env['os']['release']} {env['os']['machine']} · "
                f"Python {env['os']['python']}"
                + (f" · CI: {env['ci']['provider']}" if env['ci']['in_ci'] else "")))

    for title, block, what in (("Núcleo SDD", result["sdd_core"], "núcleo"),
                               ("Repositorio de trabajo", result["repository"], "repositorio")):
        print(f"\n  {R.bold(title)}")
        outcome = block["outcome"]
        if outcome == "AUTO":
            c = block["chosen"]
            print(R.paint(f"    ✓ {c['subject']}", "32"))
            print(R.dim(f"      confianza {c['confidence']} ({c['score']}) · "
                        f"{block.get('note') or c.get('decisive_reason') or ''}"))
            _print_details(c)
        elif outcome == "ASK":
            print(R.paint(f"    ? {block['question']}", "33"))
            for c in block["candidates"][:5]:
                mark = "→" if c is block["candidates"][0] else " "
                print(f"      {mark} {c['confidence']:<9} {c['score']:.2f}  {c['subject']}")
                print(R.dim(f"          {', '.join(s['signal'] for s in c['signals'][:4])}"))
        else:
            print(R.paint(f"    ✗ no se encontró ningún {what}", "31"))
            print(R.dim(f"      buscado en: {', '.join(block.get('searched', []))}"))
        if block.get("truncated"):
            print(R.dim(f"      {block['truncated']}"))

    present = [t for t in env["tools"] if t["present"]]
    print(f"\n  {R.bold('Herramientas')} · {len(present)}/{len(env['tools'])} presentes")
    by_cat: dict = {}
    for t in env["tools"]:
        by_cat.setdefault(t["category"] or "otros", []).append(t)
    for cat in sorted(by_cat):
        # El estado va en el TEXTO, no sólo en el color. `R.dim` se anula cuando la salida
        # no es una terminal (core/report.py:11), así que en cualquier tubería o registro de
        # CI una herramienta ausente se leía IDÉNTICA a una presente — y en la dirección
        # peligrosa: hacia «sí está». El prefijo `~` sobrevive al color.
        names = [(R.paint(t["name"], "32") if t["present"] else R.dim("~" + t["name"]))
                 for t in by_cat[cat]]
        print(f"    {cat:<10} {' '.join(names)}")

    # A dónde va a hablar el agente. Es lo único que la sonda no puede ver: `FUNCTIONAL` se
    # comprueba con un handshake local que no toca la red, así que un agente correctamente
    # instalado y mal enrutado sale en verde y muere en el primer mensaje.
    creds = [k for k, v in env["credential_presence"].items() if v]
    print(f"\n  {R.bold('Credenciales presentes')} {R.dim('(presencia, nunca contenido)')}")
    print(f"    {', '.join(creds) if creds else R.dim('ninguna detectada')}")
    print()
    return EXIT_OK if result["sdd_core"]["outcome"] != "NONE" else EXIT_BLOCKED


def _print_details(c: dict) -> None:
    for key, label in (("version", "versión"), ("commit", "commit"), ("branch", "rama"),
                       ("remote", "remoto"), ("integrity", "integridad"),
                       ("ecosystems", "stack"), ("agent_configs", "agentes")):
        val = c.get(key)
        if val:
            shown = ", ".join(val) if isinstance(val, list) else str(val)
            print(R.dim(f"      {label:<11} {shown[:88]}"))


# ── context ─────────────────────────────────────────────────────────────────────────
def cmd_context(opts) -> int:
    from core.runcontext import build as build_context, report

    ws = _ws(opts)
    roots = [Path(r).expanduser() for r in opts.root] if opts.root else None
    rc = build_context(ws, roots=roots, deep=opts.deep,
                       phases=opts.phase or None, prefer=opts.prefer or None)

    if opts.json:
        print(json.dumps(rc.summary(), ensure_ascii=False, indent=2))
    written = rc.write()
    md = ws / ".harness" / "context" / "context-report.md"
    text = report(rc)
    md.write_text(text, encoding="utf-8", newline="\n")

    if not opts.json:
        print(text)
        print(R.dim(f"  Contexto: {len(written)} archivos en .harness/context/"))
        print(R.dim(f"  Informe:  {md.relative_to(ws)}\n"))

    routing = rc.parts.get("constraints") or {}
    if routing.get("blocked_roles"):
        return EXIT_BLOCKED
    unresolved = [b for b in (rc.parts["sdd_core"], rc.parts["repository"])
                  if b.get("outcome") != "AUTO"]
    return EXIT_BLOCKED if unresolved else EXIT_OK


# ── environments ────────────────────────────────────────────────────────────────────
def cmd_environments(opts) -> int:
    """Contra qué se trabaja, y si sigue siendo verdad.

    `check` vuelve a sondear porque una declaración con una fecha dentro se pudre en silencio.
    Sin esto, el informe de sesión repetiría durante meses un «200» de un día cualquiera.
    """
    from core import environments as env

    ws = _ws(opts)
    if opts.action == "show":
        inv = env.leer(ws)
        if opts.json:
            print(json.dumps({"ruta": inv.ruta, "error": inv.error,
                              "medido_el": inv.medido_el,
                              "de_trabajo": inv.de_trabajo.nombre if inv.de_trabajo else None,
                              "entornos": [e.nombre for e in inv.entornos]},
                             ensure_ascii=False, indent=2))
            return EXIT_OK if inv.entornos and not inv.error else EXIT_BLOCKED
        if inv.error:
            print(R.dim(f"  {inv.ruta} ilegible: {inv.error}"))
            return EXIT_BLOCKED
        if not inv.entornos:
            print(R.dim(f"  Este espacio no declara entornos. Cree {env.ARCHIVO} para que "
                        f"cada sesión sepa contra qué trabaja."))
            return EXIT_BLOCKED
        print("\n".join(env.seccion(ws)))
        return EXIT_OK

    res = env.verificar(ws, escribir=opts.write)
    if not res["ok"]:
        print(R.dim(f"  {res['razon']}"))
        return EXIT_BLOCKED
    ancho = max((len(r["dominio"]) for r in res["resultados"]), default=10)
    for r in res["resultados"]:
        igual = r["antes"] == r["ahora"]
        print(f"  {r['entorno']:<12} {r['dominio']:<{ancho}}  {r['ahora']}"
              + ("" if igual else R.dim(f"   (era {r['antes']})")))
    if res.get("sospecha"):
        print(f"\n  ⚠ SONDEO NO FIABLE: {res['sospecha']}")
        return EXIT_BLOCKED
    if res["cambios"]:
        print(R.dim(f"\n  {len(res['cambios'])} cambio(s) respecto a lo declarado."))
    if res["escrito"]:
        print(R.dim(f"  Actualizado {env.ARCHIVO}."))
    elif res["cambios"]:
        print(R.dim("  Nada se ha escrito. Use --write para dejarlo registrado."))
    # Un cambio no es un fallo: es algo que una persona tiene que mirar.
    return EXIT_BLOCKED if res["cambios"] and not res["escrito"] else EXIT_OK


# ── memory ──────────────────────────────────────────────────────────────────────────
def cmd_memory(opts) -> int:
    from core.memory import LAYERS, Memory

    ws = _ws(opts)
    mem = Memory(ws)
    if opts.action == "list":
        notes = mem.search(opts.query or "", layers=opts.layer or None,
                           include_superseded=opts.all)
        if opts.json:
            print(json.dumps([n.to_dict() for n in notes], ensure_ascii=False, indent=2))
            return EXIT_OK
        for layer in (opts.layer or LAYERS):
            here = [n for n in notes if n.layer == layer]
            if not here:
                continue
            print(f"\n  {R.bold(layer)}")
            for n in here:
                tag = R.dim(" · SUSTITUIDA por " + n.superseded_by) if n.superseded_by else ""
                print(f"    {n.key:<38} {R.dim(n.updated_at[:10])}{tag}")
                if n.why:
                    print(R.dim(f"        porque: {n.why[:96]}"))
        print()
        return EXIT_OK
    if opts.action == "summary":
        s = mem.summary()
        print()
        for layer, info in s.items():
            ttl = "no caduca" if info["ttl_days"] is None else f"{info['ttl_days']} días"
            print(f"  {layer:<12} {info['count']:>3} notas · {info['superseded']} sustituidas "
                  f"· {ttl}")
        print()
        return EXIT_OK
    if opts.action == "remember":
        if not (opts.layer and opts.key and opts.body):
            print("uso: refuto memory remember --layer L --key K --body TEXTO [--why POR-QUÉ]",
                  file=sys.stderr)
            return EXIT_USAGE
        p = mem.remember(opts.layer[0], opts.key, opts.body, why=opts.why or "",
                         source=opts.source or "")
        print(f"  ✓ {p.relative_to(ws)}")
        return EXIT_OK
    if opts.action == "export":
        p = mem.export(ws / ".harness" / "evidence" / "memory-export.json")
        print(f"  ✓ {p.relative_to(ws)}")
        return EXIT_OK
    return EXIT_USAGE


def _politica_inicial(ctx, ws: Path, opts) -> tuple:
    """Escribe la política de un espacio nuevo. Con `--extends`, un hijo; sin él, la copia.

    Devuelve `(ok, detalle)`. **Nunca deja escrito un documento que no resuelva**: si la cadena
    no se puede construir, no se escribe nada y se dice por qué. El orden importa — comprobar
    después de escribir dejaría un `.harness/policy.json` que existe y no gobierna, y el paso
    siguiente de `install` lo daría por hecho porque el fichero está ahí.
    """
    from core.policy import Policy, PoliticaIlegible
    from core.refinement import documento_hijo, referencia_a

    if ctx.policy_path.exists() and not getattr(opts, "force", False):
        return True, f"{ctx.policy_path.relative_to(ws)} (ya existía; `--force` la reescribe)"

    ref = getattr(opts, "extends", "") or ""
    if not ref:
        write_json(ctx.policy_path, Policy.default().to_dict())
        return True, f"{ctx.policy_path.relative_to(ws)} (copia autónoma, sin herencia)"

    padre = Path(ref).expanduser()
    if not padre.is_absolute():
        # Relativa al directorio del fichero HIJO, no al directorio actual. Es la única base
        # que no miente: `referencia_a` (abajo) guarda `extends` relativo a `harness_dir`, así
        # que con cualquier otra base lo que se teclea y lo que queda escrito son rutas
        # distintas. Con `--workspace`, CWD ni siquiera está en el árbol del espacio.
        padre = ctx.harness_dir / padre
    if not padre.is_file():
        return False, (f"`--extends {ref}` no es un fichero ({padre}). Las rutas relativas se "
                       f"resuelven desde {ctx.harness_dir}, que es el directorio del hijo. No "
                       f"se escribe nada: un espacio que dice heredar y corre sin su padre "
                       f"parece gobernado sin estarlo. Materialice la capa base con "
                       f"`refuto policy base`.")
    try:
        padre_doc = json.loads(padre.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        return False, (f"el padre «{ref}» existe y no se pudo leer ({type(exc).__name__}: "
                       f"{exc}). No poder leerlo no es no tenerlo.")

    doc = documento_hijo(ws.name, referencia_a(padre, desde=ctx.harness_dir),
                         padre_doc=padre_doc if getattr(opts, "anchor", False) else None)
    try:
        from core.refinement import politica_efectiva
        politica_efectiva(ctx.policy_path, doc)
    except PoliticaIlegible as exc:
        return False, f"la cadena no resuelve, así que no se escribe: {exc}"

    write_json(ctx.policy_path, doc)
    anclada = " · anclada al digest del padre" if "extends_digest" in doc else ""
    return True, f"{ctx.policy_path.relative_to(ws)} → hereda de «{doc['extends']}»{anclada}"


# ── install ─────────────────────────────────────────────────────────────────────────
def cmd_install(opts) -> int:
    """Deja un espacio operativo de principio a fin, en un solo comando.

    Existe porque los pasos sueltos —`init`, `bind`, `policy wire`— dejaban un espacio a medias
    con facilidad: el control enganchado y sin contexto, o el contexto puesto y sin control. Un
    espacio a medias es peor que uno sin gobernar, porque parece gobernado.
    """
    from core import binding, context_files, launcher, wire
    from core.discovery import discover

    ws = _ws(opts)
    pasos: list = []

    def paso(nombre: str, ok: bool, detalle: str = "") -> None:
        pasos.append((nombre, ok, detalle))
        mark = R.paint("✓", "32") if ok else R.paint("✗", "31")
        print(f"  {mark} {nombre:<26} {R.dim(detalle[:96])}")

    print(R.bold(f"\nrefuto install · {ws}\n"))

    # 1 · estructura y política
    ctx = Context(workspace=ws)
    try:
        ctx.harness_dir.mkdir(parents=True, exist_ok=True)
        ctx.evidence_dir.mkdir(parents=True, exist_ok=True)
    except OSError as exc:
        paso("estructura", False, f"{exc}. Compruebe permisos: `refuto doctor`.")
        return EXIT_FAIL
    ok_pol, detalle_pol = _politica_inicial(ctx, ws, opts)
    paso("política", ok_pol and ctx.policy_path.is_file(), detalle_pol)
    if not ok_pol:
        return EXIT_FAIL

    if not ctx.manifest_path.exists() or opts.force:
        from gates.base import GATES
        write_json(ctx.manifest_path, {
            "schema": "harness.manifest/v1",
            "_que_es": "Lo que este espacio declara necesitar. La otra mitad del contrato es "
                       "harness.lock.json, que dice con qué se materializó realmente.",
            "harness": {"version": "0.2.0", "min_python": "3.10"},
            "workspace": {"name": ws.name, "profile": "standard"},
            "agents": {}, "gates": sorted(GATES),
            "skills": {"roots": [".claude/skills", ".kiro/skills"],
                       "require_name_matches_directory": True},
            "mcp": {"protocol_version": "2026-07-28"},
            "provider": {"expect": opts.provider_expect},
        })
    paso("manifiesto", ctx.manifest_path.is_file(), str(ctx.manifest_path.relative_to(ws)))

    from core.session import ensure_gitignore
    ensure_gitignore(ctx.harness_dir)

    # 2 · vínculo
    if opts.no_bind:
        paso("vínculo", True, "omitido (--no-bind)")
    else:
        disc = discover(ws, deep=opts.deep)
        # Un núcleo externo sólo se busca si ESTE espacio da señales de estar gobernado por
        # uno. Sin esto, `install` en un repositorio cualquiera encontraba los núcleos del
        # disco, los declaraba ambiguos y pedía decidir algo que no aplica — la forma más
        # rápida de enseñar a la gente a ignorar una pregunta de refuto.
        #
        # La señal de primera clase es la DECLARADA (`integrations.spec_core` del manifiesto,
        # la misma que gobierna G-SDD). Los marcadores del árbol se conservan detrás porque un
        # espacio recién clonado aún no tiene manifiesto, pero ya no son la única vía: antes,
        # la lista de marcadores era la única, y estaba escrita con los nombres de un
        # repositorio privado.
        from core.context import read_manifest
        declarado = bool((read_manifest(ws).get("integrations") or {}).get("spec_core")
                         or (read_manifest(ws).get("integrations") or {}).get("sdd_core"))
        gobernado_por_sdd = bool(opts.core) or declarado or any(
            (ws / m).exists() for m in (".kiro", "verification", "verificacion"))
        objetivos = [("repository", "repository", "el repositorio", "")]
        if gobernado_por_sdd:
            objetivos.insert(0, ("sdd_core", "sdd_core", "el núcleo SDD", opts.core))
        hechos = []
        for kind, key, what, choice in objetivos:
            cand, why = binding.decide(disc[key], choice=choice, what=what)
            if cand is not None:
                maker = binding.bind_core if kind == "sdd_core" else binding.bind_repo
                hechos.append(maker(cand, by=os.environ.get("USER", "")))
        if hechos:
            existing = binding.read(ws)
            merged = [binding.Binding(**{k: v for k, v in b.items()
                                         if k in binding.Binding.__dataclass_fields__})
                      for k2, b in existing.items() if k2 not in {x.kind for x in hechos}]
            binding.write(ws, merged + hechos)
        atados = ", ".join(h.kind for h in hechos) or "ninguno"
        # No encontrar núcleo NO es un fallo: hay espacios que no están gobernados por uno.
        # Lo que sí es un fallo es encontrar varios y no decidir. Confundir «no aplica» con
        # «falta» deja `install` en rojo permanente en la mitad de los repositorios.
        atado = {h.kind for h in hechos}
        pedidos = {k for k, _, _, _ in objetivos}
        ambiguos = [k for k in pedidos if k not in atado and disc[k].get("outcome") == "ASK"]
        ausentes = [k for k in pedidos if k not in atado and disc[k].get("outcome") == "NONE"]
        detalle = f"atado: {atados}"
        if not gobernado_por_sdd:
            detalle += " · sin núcleo SDD: este espacio no está gobernado por uno"
        if ausentes:
            detalle += f" · sin {', '.join(ausentes)} en el entorno (no aplica aquí)"
        if ambiguos:
            detalle += f" · AMBIGUO: {', '.join(ambiguos)} → `refuto bind set --core <ruta>`"
        paso("vínculo", not ambiguos, detalle)

    # 3 · qué runtimes hay aquí, para no enganchar lo que nadie usa
    detectados = _runtimes_relevantes(ws, opts.agent)
    paso("runtimes", bool(detectados), ", ".join(detectados) or "ninguno detectado")

    # 4 · lanzador y ganchos
    motor = _motor_para_lanzadores(opts)
    resultados = []
    if "kiro" in detectados and (ws / ".kiro" / "agents").is_dir():
        resultados += wire.wire_kiro_agents(ws, harness_root=motor)
    if "claude" in detectados:
        resultados += wire.wire_claude(ws, harness_root=motor)
    if "antigravity" in detectados:
        resultados += wire.wire_antigravity(ws, harness_root=motor)
    if not resultados:
        launcher.install(ws, harness_home=motor, runtime="claude")
    lz = launcher.check(ws)
    paso("guardián", lz["ok"], lz.get("reason") or
         f"{len([r for r in resultados if r.action in ('wired', 'upgraded')])} ganchos · "
         f"lanzador en .harness/bin/guard")

    # 5 · contexto persistente — lo que hace que `claude` a secas SEPA dónde está
    escritos = context_files.install(ws, runtimes=[r for r in detectados
                                                   if r in context_files.TARGETS],
                                     spec=opts.spec)
    paso("contexto", True, ", ".join(sorted({w.path for w in escritos})))

    launcher.restore_ownership(ws)

    # 6 · comprobación: se ejecuta el guardián de verdad
    prueba = _probar_guardian(ws)
    paso("prueba del guardián", prueba["ok"], prueba["detail"])

    print()
    fallos = [n for n, ok, _ in pasos if not ok]
    if fallos:
        print(R.paint(f"  Incompleto: {', '.join(fallos)}", "33"))
        print(R.dim("  Ejecute `refuto doctor` para el detalle.\n"))
        return EXIT_BLOCKED
    print(R.paint("  Espacio operativo.", "32"))
    print(R.dim("  Cualquier forma de abrir el agente aquí —`refuto chat`, `claude`, "
                "`sudo claude`,\n  o la aplicación de escritorio— encuentra el contexto y el "
                "guardián.\n"))
    return EXIT_OK


def _runtimes_relevantes(ws: Path, pedidos: list | None = None) -> list:
    """Qué runtimes importan aquí, por orden de autoridad.

        1. lo que se pide en la orden      `--agent claude`
        2. lo que el espacio DECLARA       `agents` del manifiesto
        3. lo que hay instalado            último recurso

    Sondear los cinco para usar uno costaba 13,6 s en cada `refuto work`. Un comando que tarda
    catorce segundos en decir qué tienes pendiente se deja de usar, y entonces no gobierna nada.
    """
    from adapters.registry import ADAPTERS
    if pedidos:
        return [a for a in pedidos if a in ADAPTERS]
    declarados = list((Context(workspace=ws).manifest or {}).get("agents") or {})
    if declarados:
        # Primero los requeridos: son los que el espacio dice que no puede faltar.
        req = [a for a in declarados
               if (Context(workspace=ws).manifest["agents"][a] or {}).get("required")]
        ordenados = list(dict.fromkeys(req + declarados))
        return [a for a in ordenados if a in ADAPTERS] or _runtimes_presentes(ws)
    return _runtimes_presentes(ws)


def _grafo(ws: Path, runtimes: list, *, deep: bool = False):
    """Grafo de capacidades sondeando SÓLO los runtimes que importan."""
    from adapters.registry import ADAPTERS
    from core.capability import build as build_caps
    from core.discovery import ToolFact, scan_environment
    from core.probe import probe_all

    # Sin versiones: para saber si una capacidad existe basta con que la herramienta esté.
    env = scan_environment(with_versions=False)
    known = set(ToolFact.__dataclass_fields__)                          # noqa: SLF001
    facts = [ToolFact(**{k: v for k, v in t.items() if k in known}) for t in env["tools"]]
    specs = [ADAPTERS[a] for a in dict.fromkeys(runtimes) if a in ADAPTERS]
    probes = probe_all(specs, deep=deep, workspace=ws)
    return build_caps(probes, ADAPTERS, facts), probes


def _runtimes_presentes(ws: Path) -> list:
    """Qué runtimes tienen sentido en ESTE espacio: los instalados, más los que ya dejaron huella."""
    import shutil
    out = []
    for name, binario, huella in (("claude", "claude", ".claude"),
                                  ("kiro", "kiro-cli", ".kiro"),
                                  ("gemini", "gemini", ".gemini"),
                                  ("opencode", "opencode", "opencode.json"),
                                  # Antigravity es un IDE: puede no dejar binario en el PATH.
                                  # Su huella es el directorio de personalización que él mismo lee.
                                  ("antigravity", "agy", ".agents")):
        if shutil.which(binario) or (ws / huella).exists():
            out.append(name)
    if "antigravity" not in out and _antigravity_instalado():
        out.append("antigravity")
    return out


def _antigravity_instalado() -> bool:
    """¿Hay un Antigravity en esta máquina, aunque no deje binario en el PATH?

    Se comprueban las rutas de instalación habituales por sistema. Un falso negativo aquí
    significa que el guardián NO se engancha para ese agente y que trabaja sin control: por eso
    se mira también el directorio de configuración que crea al abrirse.
    """
    import os
    from pathlib import Path as _P
    candidatas = [
        _P("/Applications/Antigravity.app"),
        _P.home() / "Applications" / "Antigravity.app",
        _P.home() / ".gemini" / "antigravity",
        _P(os.environ.get("LOCALAPPDATA", "")) / "Programs" / "Antigravity" if os.name == "nt" else None,
    ]
    return any(c.exists() for c in candidatas if c is not None)


def _probar_guardian(ws: Path) -> dict:
    """Ejecuta el lanzador contra una escritura que DEBE rechazar. Sin esto, «instalado» es
    una suposición."""
    from core import launcher
    guard = ws / launcher.BIN / launcher.NAME
    if not guard.is_file():
        return {"ok": False, "detail": "el lanzador no está"}
    payload = json.dumps({"tool_name": "Write",
                          "tool_input": {"file_path": ".harness/policy.json", "content": "{}"}})
    try:
        import subprocess
        p = subprocess.run([str(guard)], input=payload, capture_output=True, **TEXT_IO,
                           cwd="/", timeout=60,
                           env={"HARNESS_GUARD_RUNTIME": "claude",
                                "HOME": os.environ.get("HOME", "/tmp")})
    except (OSError, Exception) as exc:                                  # noqa: BLE001
        return {"ok": False, "detail": f"no se pudo ejecutar: {exc}"}
    try:
        d = json.loads(p.stdout or "{}")
        decision = d["hookSpecificOutput"]["permissionDecision"]
    except (ValueError, KeyError):
        return {"ok": p.returncode != 0,
                "detail": f"salida {p.returncode} · {(p.stderr or '')[:70]}"}
    return {"ok": decision == "deny",
            "detail": f"bloqueó una escritura sobre .harness/policy.json ({decision})"}


# ── bind ────────────────────────────────────────────────────────────────────────────
def cmd_bind(opts) -> int:
    from core import binding
    from core.discovery import discover

    ws = _ws(opts)
    roots = [Path(r).expanduser() for r in opts.root] if opts.root else None

    if opts.action == "show":
        bound = binding.read(ws)
        if not bound:
            print(R.dim("\n  este espacio no está vinculado. Ejecute `refuto bind set`.\n"))
            return EXIT_BLOCKED
        print()
        for kind, b in sorted(bound.items()):
            print(f"  {R.bold(kind)}")
            for k in ("path", "commit", "version", "remote", "bound_at", "bound_by"):
                if b.get(k):
                    print(f"    {k:<16} {b[k]}")
        print()
        return EXIT_OK

    disc = discover(ws, roots=roots, deep=opts.deep)

    if opts.action == "verify":
        out = binding.verify(ws, disc)
        if not out["bound"]:
            print(R.paint("\n  sin vínculo: no hay nada que verificar\n", "33"))
            return EXIT_BLOCKED
        print()
        for n in out["notes"]:
            print(R.dim(f"  i {n}"))
        for problem in out["problems"]:
            print(R.paint(f"  ✗ {problem}", "31"))
        if not out["problems"]:
            print(R.paint("  ✓ el vínculo sigue siendo válido", "32"))
        print()
        return EXIT_OK if not out["problems"] else EXIT_FAIL

    bindings, blocked = [], []
    for kind, key, what, choice in (("sdd_core", "sdd_core", "el núcleo SDD", opts.core),
                                    ("repository", "repository", "el repositorio", opts.repo)):
        cand, why = binding.decide(disc[key], choice=choice, what=what)
        if cand is None:
            blocked.append((kind, why, disc[key]))
            continue
        maker = binding.bind_core if kind == "sdd_core" else binding.bind_repo
        b = maker(cand, by=opts.by or os.environ.get("USER", ""))
        bindings.append(b)
        print(R.paint(f"  ✓ {kind}: {b.path}", "32"))
        print(R.dim(f"      {why}"))
        if b.commit:
            print(R.dim(f"      anclado al commit {b.commit[:12]}"))

    for kind, why, block_doc in blocked:
        print(R.paint(f"\n  ? {kind}: {why}", "33"))
        for c in block_doc.get("candidates", [])[:6]:
            print(f"      {c['confidence']:<9} {c['score']:.2f}  {c['subject']}")
            extra = " · ".join(str(x) for x in (c.get("version"), c.get("integrity"),
                                                c.get("branch")) if x)
            if extra:
                print(R.dim(f"          {extra}"))
        flag = "--core" if kind == "sdd_core" else "--repo"
        print(R.dim(f"      elija con: refuto bind set {flag} <ruta>"))

    if bindings:
        existing = binding.read(ws)
        merged = [binding.Binding(**{k: v for k, v in b.items()
                                     if k in binding.Binding.__dataclass_fields__})
                  for kind, b in existing.items()
                  if kind not in {x.kind for x in bindings}] + bindings
        path = binding.write(ws, merged)
        print(f"\n  escrito {path.relative_to(ws)}")
    print()
    return EXIT_BLOCKED if blocked else EXIT_OK


# ── init ─────────────────────────────────────────────────────────────────────────────
def cmd_init(opts) -> int:
    ws = _ws(opts)
    ctx = Context(workspace=ws)
    ctx.harness_dir.mkdir(parents=True, exist_ok=True)
    ctx.evidence_dir.mkdir(parents=True, exist_ok=True)

    created = []
    ya_estaba = ctx.policy_path.exists() and not opts.force
    ok_pol, detalle_pol = _politica_inicial(ctx, ws, opts)
    if not ok_pol:
        print(R.paint(f"  ✗ política · {detalle_pol}", "31"))
        return EXIT_FAIL
    if not ya_estaba:
        created.append(ctx.policy_path)
    if not ctx.manifest_path.exists() or opts.force:
        from gates.base import GATES
        write_json(ctx.manifest_path, {
            "schema": "harness.manifest/v1",
            "_que_es": "Lo que este espacio declara necesitar. La otra mitad del contrato es "
                       "harness.lock.json, que dice con qué se materializó realmente.",
            "harness": {"version": "0.1.0", "min_python": "3.10"},
            "workspace": {"name": ws.name, "profile": "standard"},
            "agents": {},
            "gates": sorted(GATES),
            "skills": {"roots": [".claude/skills", ".kiro/skills"],
                       "require_name_matches_directory": True},
            "mcp": {"protocol_version": "2026-07-28"},
        })
        created.append(ctx.manifest_path)

    from core.session import ensure_gitignore
    if ensure_gitignore(ctx.harness_dir):
        created.append(ctx.harness_dir / ".gitignore")

    for p in created:
        print(f"  ✓ {p.relative_to(ws)}")
    if not created:
        print("  nada que crear (use --force para reescribir)")
    print(f"\n  Siguiente: {R.bold('refuto doctor')} y luego {R.bold('refuto verify')}\n")
    return EXIT_OK


# ── verify ───────────────────────────────────────────────────────────────────────────
def _version_motor() -> str:
    v = REPO / "VERSION"
    return v.read_text(encoding="utf-8").strip() if v.is_file() else ""


def _cambios_entre(desde: str, hasta: str) -> list:
    """Las entradas del CHANGELOG entre dos versiones. Vacía si no se puede leer.

    Actualizar sin poder leer qué cambia es firmar en blanco. Si el CHANGELOG no está o no se
    entiende, se dice — no se calla y se actualiza igual.
    """
    ch = REPO / "CHANGELOG.md"
    if not ch.is_file():
        return []
    lineas, dentro, out = ch.read_text(encoding="utf-8").splitlines(), False, []
    for l in lineas:
        m = re.match(r"^##\s*\[?v?([0-9]+\.[0-9]+\.[0-9]+)", l)
        if m:
            v = m.group(1)
            if v == hasta:
                dentro = True
                out.append(l.strip())
                continue
            if v == desde:
                break
            if dentro:
                out.append(l.strip())
            continue
        if dentro and l.strip():
            out.append("  " + l.strip())
    return out[:40]


def cmd_upgrade(opts) -> int:
    """Lleva un espacio a la versión del motor que hay en disco.

    Por qué existe
    --------------
    El motor detectaba deriva del núcleo SDD (`core/binding.py`, con el commit como ancla) y
    deriva de agentes y skills duplicados (`core/inventory.py`, la puerta H-07). Medía la
    deriva de todo menos la suya: el 2026-09-17 había cuatro espacios gobernados declarando
    0.1.0 y 0.2.0 contra un motor 0.2.2, y ningún camino para ponerlos al día que no fuera
    editar el manifiesto a mano.

    Qué hace, y qué NO hace
    -----------------------
    Actualiza la versión declarada y REGENERA el lanzador del guardián, que es lo que de
    verdad ata el espacio a una ubicación del motor. No toca la política: si un espacio la
    extendió, esa extensión es una decisión de una persona y no se pisa. Y no actualiza un
    espacio cuya política el motor no entiende: actualizar a ciegas lo que no se sabe leer es
    la forma más limpia de romper algo en silencio.
    """
    ws = _ws(opts)
    manifiesto = ws / ".harness" / "harness.manifest.json"
    motor = _version_motor()

    if not manifiesto.is_file():
        print(f"\n  {R.paint('✗', '31')} no hay {manifiesto.relative_to(ws)}: "
              f"este espacio no está inicializado.")
        print(R.dim(f"      python3 {REPO}/refuto.py --workspace {ws} install\n"))
        return responder(opts, command="upgrade", status=NOT_EXECUTABLE, ws=ws,
                         payload={"schema": "harness.upgrade/v1", "declared": "",
                                  "engine": motor},
                         next=[Siguiente(
                             why="el espacio no está inicializado: no hay manifiesto que "
                                 "actualizar",
                             do=f"refuto --workspace {ws} install", who=MAQUINA)])

    doc = json.loads(manifiesto.read_text(encoding="utf-8"))
    declarada = (doc.get("harness") or {}).get("version") or ""

    print(f"\n  {R.bold(str(ws))}")
    print(f"    declara  {declarada or '(nada)'}")
    print(f"    motor    {motor}")

    # Qué le falta a la política del espacio respecto de la norma del motor. Se mide siempre,
    # incluso «al día», porque la versión y la norma se mueven por separado: `upgrade` no toca la
    # política **por diseño** (una extensión es decisión de una persona), así que un espacio
    # puede estar en la versión del motor y llevar la norma de hace tres correcciones. Medido el
    # 2026-09-24: 6 de 8 espacios gobernados con una instantánea distinta de la norma.
    deriva_norma = _deriva_de_norma(ws)
    residuo_norma = _residuo_de_norma(ws)

    if declarada == motor and not deriva_norma:
        print(f"\n  {R.paint('✓', '32')} al día. Nada que hacer.\n")
        return responder(opts, command="upgrade", status=PASS, ws=ws,
                         payload={"schema": "harness.upgrade/v1", "declared": declarada,
                                  "engine": motor, "applied": False,
                                  "policy_drift": []})

    # Una política que el motor no entiende invalida la actualización: no se sabe qué se
    # estaría preservando.
    from core.policy import PoliticaIlegible, Policy
    pf = ws / ".harness" / "policy.json"
    if pf.is_file():
        try:
            Policy.load(pf)
        except PoliticaIlegible as exc:
            print(f"\n  {R.paint('✗', '31')} BLOQUEADO: {exc}")
            print(R.dim("      Se arregla la política antes de actualizar, no después.\n"))
            return responder(opts, command="upgrade", status=BLOCKED, ws=ws,
                             payload={"schema": "harness.upgrade/v1", "declared": declarada,
                                      "engine": motor, "applied": False,
                                      "policy_unreadable": str(exc)},
                             next=[Siguiente(
                                 why=f"la política no se puede interpretar, así que no se sabe "
                                     f"qué preservaría la actualización: {exc}",
                                 do="refuto policy show", who=PERSONA)])

    cambios = _cambios_entre(declarada, motor)
    if cambios:
        print(f"\n  {R.bold('Qué cambia')}")
        for l in cambios[:18]:
            print(R.dim(f"      {l}"))
    else:
        print(R.dim("\n      (el CHANGELOG no declara entradas entre esas versiones)"))

    siguientes: list = []
    if declarada != motor:
        siguientes.append(Siguiente(
            why=f"el espacio declara {declarada or '(nada)'} y el motor es {motor}",
            do=f"refuto --workspace {ws} upgrade --apply", who=MAQUINA))
    if deriva_norma:
        print(f"\n  {R.bold('La norma del espacio va por detrás del motor')}")
        for p in deriva_norma[:12]:
            print(R.paint(f"      ✗ falta  {p}", "33"))
        print(R.dim("      `upgrade` NO toca la política: una extensión es decisión de una "
                    "persona.\n      Si esa lista son patrones que su espacio copió y no "
                    "modificó, la forma de\n      volver a heredarlos es reducir su política a "
                    "su identidad y dejar que el\n      motor aporte la norma."))
        siguientes.append(Siguiente(
            why=f"la política del espacio no cubre {len(deriva_norma)} patrón(es) que la norma "
                f"del motor protege: {', '.join(deriva_norma[:4])}"
                f"{'…' if len(deriva_norma) > 4 else ''}. `upgrade` no la toca por diseño",
            do="refuto policy show", who=PERSONA))

    # El residuo va por su propio canal y con su propia palabra. Meterlo en `deriva_norma`
    # habría hecho que se imprimiera «✗ falta» sobre un patrón que SOBRA, y una lista que
    # mezcla «le falta» con «le sobra» no se puede leer: las dos se arreglan al revés.
    if residuo_norma:
        print(f"\n  {R.bold('La norma del espacio protege lo que el motor ya retiró')}")
        for p, motivo, fichero in residuo_norma[:12]:
            print(R.paint(f"      ⚑ sobra  {p}", "33"))
            print(R.dim(f"               {motivo}"))
            print(R.dim(f"               lo declara: {fichero}"))
        print(R.dim("      No es un agujero —deniega MÁS, no menos— y por eso nada lo "
                    "señalaba.\n      Es una denegación que su espacio no pidió, y que desde su "
                    "espacio no se\n      puede retirar: `protected_paths` acumula. Se quita del "
                    "fichero, a mano."))
        siguientes.append(Siguiente(
            why=f"la política del espacio mantiene {len(residuo_norma)} patrón(es) que la norma "
                f"del motor retiró: {', '.join(p for p, _, _ in residuo_norma[:4])}"
                f"{'…' if len(residuo_norma) > 4 else ''}. Acumulan, así que siguen denegando",
            do=f"editar {residuo_norma[0][2]} y quitar esos patrones",
            who=PERSONA))

    if not opts.apply:
        print(f"\n  {R.paint('·', '33')} en seco. Añada --apply para actualizar.\n")
        # En seco y con algo pendiente: `BLOCKED` es el estado honesto —no se hizo, y hay
        # trabajo— y su código es 2, el mismo que ya devolvía el resto de caminos «no se pudo».
        # Antes devolvía 0, indistinguible de «al día».
        return responder(opts, command="upgrade", status=BLOCKED, ws=ws, next=siguientes,
                         payload={"schema": "harness.upgrade/v1", "declared": declarada,
                                  "engine": motor, "applied": False,
                                  "policy_drift": deriva_norma,
                                  "policy_residue": [{"pattern": p, "reason": m,
                                                      "declared_in": f}
                                                     for p, m, f in residuo_norma],
                                  "changelog": cambios})

    copia = manifiesto.with_name(manifiesto.name + f".antes-de-{declarada or 'nada'}")
    copia.write_bytes(manifiesto.read_bytes())   # copia exacta, byte a byte

    doc.setdefault("harness", {})["version"] = motor
    doc.setdefault("_actualizaciones", []).append(
        {"desde": declarada, "hasta": motor, "cuando": now(), "por": os.environ.get("USER", "")})
    write_json(manifiesto, doc)

    # El lanzador del guardián graba la ruta del motor a fuego; regenerarlo es la mitad útil
    # de actualizar. Se regeneran TODOS los runtimes que este espacio tenga cableados, no sólo
    # Claude: antes sólo se llamaba a `wire_claude`, así que un espacio cableado para Antigravity
    # o para Kiro salía de `upgrade --apply` con punteros al motor viejo y el mensaje decía que
    # se había actualizado. Medido el 2026-09-24.
    from core import wire
    raiz_motor = _motor_para_lanzadores(opts)
    resultados = list(wire.wire_claude(ws, harness_root=raiz_motor))
    recableados = ["claude"]
    if (ws / ".agents" / "hooks.json").is_file():
        resultados += list(wire.wire_antigravity(ws, harness_root=raiz_motor))
        recableados.append("antigravity")
    if (ws / ".kiro").is_dir():
        resultados += list(wire.wire_kiro_agents(ws, harness_root=raiz_motor))
        recableados.append("kiro")

    print(f"\n  {R.paint('✓', '32')} {declarada or '(nada)'} → {motor}")
    print(R.dim(f"      copia previa: {copia.name}"))
    print(R.dim(f"      runtimes recableados: {', '.join(recableados)}"))
    for r in resultados:
        print(R.dim(f"      {r.action:<9} {r.path}"))
    print()
    # Se actualizó la versión y el cableado; si la norma sigue por detrás, eso queda dicho y con
    # turno asignado, en vez de desaparecer detrás de un ✓.
    # El residuo cuenta igual que la deriva para el estado: las dos son trabajo que queda y que
    # esta herramienta no puede hacer sola, y `PASS` con trabajo pendiente es la mentira que
    # `BLOCKED` existe para no contar.
    pendiente = bool(deriva_norma or residuo_norma)
    return responder(opts, command="upgrade", status=BLOCKED if pendiente else PASS, ws=ws,
                     next=siguientes if pendiente else [],
                     payload={"schema": "harness.upgrade/v1", "declared": declarada,
                              "engine": motor, "applied": True,
                              "rewired": recableados,
                              "policy_drift": deriva_norma,
                              "policy_residue": [{"pattern": p, "reason": m,
                                                  "declared_in": f}
                                                 for p, m, f in residuo_norma],
                              "backup": str(copia)})


def _deriva_de_norma(ws: Path) -> list:
    """En qué se queda corta la política EFECTIVA del espacio respecto de la norma del motor.

    Lo que se midió, y la corrección que trae
    -----------------------------------------
    La hipótesis de partida era que una corrección de la norma base no llega nunca a un espacio
    ya instalado, porque `init`/`install` copian la norma entera y `upgrade` no toca la política.
    **Medido el 2026-09-24 y falsado en la mitad que importa:** `Policy.load` compone toda
    política con la raíz del motor (`core.trust.componer_con_raiz`), y `protected_paths` ACUMULA,
    así que el efectivo es la UNIÓN. Con una política al estilo anterior —patrones anclados a la
    raíz— el efectivo ya trae los `**/` del motor y `repo-hijo/.harness/bin/guard` sale `deny`
    sin tocar nada. Las protecciones nuevas SÍ se propagan solas.

    La mitad que no se propaga es la que abre agujeros, y por la razón contraria:
    `writable_paths` es `REDUCE` y la lista del hijo manda, así que un espacio que declaró la
    excepción anclada a la raíz se queda con ella —`repo-hijo/.harness/memory/nota.md` sigue
    denegado— y **no lo nota**, porque nada se lo dice. No es un agujero: es una denegación
    colateral que el dueño no pidió y no sabe que tiene.

    Por eso se mide la EXCEPCIÓN, que es donde la deriva es real y silenciosa, y se comprueba por
    cobertura a dos profundidades igual que `core.refinement._cubre`: `X` y `**/X` no son la
    misma cadena y la diferencia es justo si alcanza a los repositorios hijos.

    Esto no arregla la deriva: la MIDE y la nombra. Arreglarla es decisión de persona, que es
    también el motivo de que `upgrade` no lo haga solo.
    """
    from core.policy import DEFAULT_PROTECTED, DEFAULT_WRITABLE, PoliticaIlegible, Policy

    pf = ws / ".harness" / "policy.json"
    if not pf.is_file():
        return []
    try:
        pol = Policy.load(pf)
    except PoliticaIlegible:
        return []       # ilegible se trata aparte, y con su propio estado

    def _muestras(patron: str) -> list:
        cuerpo = patron.removeprefix("**/").removesuffix("/**")
        if patron.endswith("/**"):
            return [f"{cuerpo}/sonda", f"repo-hijo/{cuerpo}/sonda"]
        suelto = cuerpo.replace("*", "sonda")
        return [suelto, f"repo-hijo/{suelto}"]

    faltan = []
    # La excepción: donde la deriva es real. Si la norma del motor la concede a cualquier
    # profundidad y la del espacio sólo en la raíz, los repositorios hijos la pierden.
    for patron in DEFAULT_WRITABLE:
        if not all(pol.is_writable(m) for m in _muestras(patron)):
            faltan.append(patron)
    # La protección: hoy se propaga por la unión con la raíz del motor, así que esto debería
    # salir vacío siempre. Se comprueba igual, y es deliberado: si alguien cambia la monotonía de
    # `protected_paths` y la unión deja de aplicarse, esta lista lo dirá en el primer `upgrade`
    # en vez de dentro de un año y en un espacio ajeno.
    for patron in DEFAULT_PROTECTED:
        if not all(pol.is_protected(m) for m in _muestras(patron)):
            faltan.append(patron)
    return faltan


def _residuo_de_norma(ws: Path) -> list:
    """Qué patrones RETIRADOS de la norma del motor sigue declarando el espacio.

    La simetría que faltaba
    -----------------------
    `_deriva_de_norma` mide lo que al espacio le FALTA. El mecanismo que hace que una protección
    nueva llegue sola —`protected_paths` es `ACUMULA` y el efectivo es la unión— hace también que
    una protección RETIRADA no se vaya nunca: `init`/`install` copiaron la norma entera, el
    fichero del espacio sigue declarando el patrón viejo, y la unión lo mantiene vivo.

    No es un agujero: deniega más, no menos. Y por eso nada lo señalaba — no rompe ninguna
    puerta. Lo que hace es impedir callando trabajo legítimo, que es el defecto que se midió el
    2026-10-03 con `policies/**`: el patrón cubría cualquier directorio `policies/` a cualquier
    profundidad, incluido el código del producto, y **desde el espacio no se podía retirar**
    (`ACUMULA` hace la retirada inexpresable y la excepción que lo compensaría es `REDUCE`, así
    que declararla rompe la cadena entera).

    Se mide leyendo los ficheros DECLARADOS, no la política efectiva. El efectivo es la unión con
    la raíz del motor, así que preguntarle a él si el patrón sigue ahí no distingue «lo trae el
    espacio» de «lo trae el motor», que es justo la distinción que decide quién lo arregla.

    Y se recorre la CADENA entera, no el fichero del espacio. Medido el 2026-10-03 sobre once
    espacios instalados: nueve declaran el patrón en su propio `.harness/policy.json`, pero uno
    —el único con herencia real de tres capas— lo declara en el documento del PADRE
    (`.harness/base-policy.json`) y su hijo no declara `protected_paths` en absoluto. Mirando
    sólo el hijo, ese espacio salía limpio teniendo el bloqueo completo. Por eso se devuelve
    también QUÉ fichero lo declara: «quítelo a mano» sin decir de dónde no es una instrucción.

    Esto no lo arregla: lo MIDE y lo nombra, igual que la deriva. `.harness/policy.json` está
    protegido, y una herramienta que se reescribiera sola el fichero que la gobierna no estaría
    gobernada por él.
    """
    from core.policy import RETIRADAS_DE_NORMA

    pf = ws / ".harness" / "policy.json"
    residuo: list = []
    vistos: set = set()
    ya: set = set()         # por CLAVE retirada, no por la forma que traiga cada capa
    while pf.is_file() and pf not in vistos:
        vistos.add(pf)
        try:
            doc = json.loads(pf.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            break       # ilegible se trata aparte, y con su propio estado
        declarados = {p for p in (doc.get("protected_paths") or []) if isinstance(p, str)}
        for patron, motivo in RETIRADAS_DE_NORMA.items():
            # Las dos formas del mismo patrón: `X` y `**/X` no son la misma cadena y un espacio
            # instalado puede llevar cualquiera de las dos según cuándo se instaló. Alcanzan
            # distinto —`policies/**` sólo cubre la raíz— y las dos sobran igual.
            formas = {patron.removeprefix("**/"), f"**/{patron.removeprefix('**/')}"}
            presentes = sorted(formas & declarados)
            if presentes and patron not in ya:
                ya.add(patron)
                residuo.append((presentes[0], motivo, str(pf)))
        ext = doc.get("extends")
        if not isinstance(ext, str) or not ext:
            break
        # `extends` se escribe relativo al `.harness/` del hijo, no al directorio de trabajo.
        pf = (pf.parent / ext).resolve()
    return residuo


def cmd_verify(opts) -> int:
    from gates.base import GATES, run_all

    ws = _ws(opts)
    ctx = Context(workspace=ws, run_id=new_id(KIND_VERIFICATION), deep=opts.deep,
                  offline=opts.offline)
    declared = (ctx.manifest or {}).get("gates")
    only = opts.gate or (declared if declared else None)
    unknown = [g for g in (only or []) if g not in GATES]
    if unknown:
        print(R.paint(f"puertas desconocidas: {', '.join(unknown)}", "31"), file=sys.stderr)
        return EXIT_USAGE

    results = run_all(ctx, only=only)
    verdict = verdict_of(results)
    print(R.render(results, verdict, verbose=opts.verbose))
    path = write_run(ws, ctx.run_id, results)
    print(f"  Evidencia: {path.relative_to(ws)}\n")

    # El estado AGREGADO de la verificación, del que se deriva el código. Antes cada rama
    # devolvía su número a mano; aquí se nombra el estado y la tabla de `core.envelope` hace la
    # proyección. Los cuatro casos dan exactamente los mismos códigos que antes —1, 2, 2, 0—,
    # comprobado en `tests/selftest/test_gates.py`.
    # `PASS ⟹ Proof(PASS)`: una puerta que aprueba sin declarar qué o cuánto observó
    # no ha demostrado nada (ADR-0023 / Teorema de No-Vacuidad). Un PASS sin scope o con
    # ámbito vacío (examined <= 0) cuenta como INCONCLUSIVE y nunca como PASS ni exit 0.
    sin_prueba = [
        r.id for r in results
        if r.status == PASS and (getattr(r, "scope", None) is None or getattr(r.scope, "examined", 0) <= 0)
    ]
    statuses = {
        INCONCLUSIVE if (r.status == PASS and (getattr(r, "scope", None) is None or getattr(r.scope, "examined", 0) <= 0))
        else r.status
        for r in results
    }
    if statuses & {FAIL, NOT_EXECUTABLE}:
        estado = FAIL
    elif BLOCKED in statuses:
        estado = BLOCKED
    elif INCONCLUSIVE in statuses:
        estado = INCONCLUSIVE
    elif not statuses:
        # Cero puertas ejecutadas. Antes esto caía en el `return EXIT_OK` final: un ámbito vacío
        # aprobando, que es justo lo que este programa existe para no hacer. La regla ya estaba
        # escrita para las suites («una suite que ejecuta 0 pruebas falla») y no se aplicaba a
        # la propia verificación.
        estado = BLOCKED
    elif statuses == {NOT_APPLICABLE}:
        # Todas las puertas evaluadas declararon legítimamente NOT_APPLICABLE en este espacio.
        # No es un fallo ni un bloqueo (no hay nada pendiente que arreglar), pero tampoco es un
        # PASS vacuo: el estado agregado es NOT_APPLICABLE.
        estado = NOT_APPLICABLE
    elif PASS not in statuses:
        # Ninguna puerta encontró sujeto. No salió mal, pero tampoco demostró nada: aprobar
        # aquí sería el aprobado vacuo que `NOT_APPLICABLE` existe para hacer visible.
        estado = BLOCKED
    else:
        estado = PASS

    siguientes: list = []

    # El ancla certificada (ADR-0017). Se toma DESPUÉS de `write_run`: la cabeza que se ancla ya
    # incluye el `run/complete` de esta corrida, así que el checkpoint certificado afirma «este
    # veredicto existía cuando el diario medía n». Es una segunda dimensión del estado, no una
    # puerta: las puertas dicen si el espacio cumple; el ancla dice si la evidencia de que cumple
    # puede sostenerse ante un tercero. Las dos se imprimen y viajan por separado en el sobre, y
    # sólo se funden en el estado agregado, donde un ancla que no se sostiene impide el PASS.
    anclaje = _anclar_desde(ws, ctx.manifest, run_id=ctx.run_id, offline=opts.offline,
                            pin_externo=_pin_externo(opts))
    if anclaje["declarado"]:
        _imprimir_anclaje(anclaje)
        if anclaje["estado"] != PASS:
            # FAIL manda sobre lo demás; después, el estado del ancla. Nunca se degrada un FAIL
            # de las puertas a BLOCKED por culpa del ancla, ni un ancla en FAIL a BLOCKED por
            # culpa de las puertas.
            if anclaje["estado"] == FAIL or estado == FAIL:
                estado = FAIL
            elif estado in (PASS, INCONCLUSIVE):
                estado = anclaje["estado"]
            siguientes.append(Siguiente(
                why=f"ancla certificada → {anclaje['estado']}: {anclaje['motivo']}",
                do="" if anclaje["estado"] in (FAIL, BLOCKED) else "refuto evidence --anchor",
                who=PERSONA if anclaje["estado"] in (FAIL, BLOCKED) else MAQUINA))
    if not statuses:
        siguientes.append(Siguiente(
            why="la verificación no ejecutó ninguna puerta: un ámbito vacío no aprueba",
            do="refuto verify", who=PERSONA))
    elif estado == NOT_APPLICABLE:
        siguientes.append(Siguiente(
            why=f"ninguna puerta encontró sujeto aplicable en este espacio ({len(results)} declarada(s) no aplicables)",
            do="revisar el manifiesto o ejecutar puertas aplicables",
            who=PERSONA))
    if sin_prueba:
        siguientes.append(Siguiente(
            why=(f"{len(sin_prueba)} puerta(s) aprueban sin declarar qué observaron o con ámbito vacío: "
                 f"{', '.join(sin_prueba[:4])}. Un PASS sin cobertura no es una demostración"),
            do="declarar scope en las puertas afectadas o revisar cobertura",
            who=PERSONA))
    for r in results:
        if r.status == PASS or r.status == NOT_APPLICABLE:
            continue
        detalle = (r.findings[0].get("detail") or r.findings[0].get("summary") or "").strip() \
            if r.findings and isinstance(r.findings[0], dict) else ""
        siguientes.append(Siguiente(
            why=f"{r.id} ({r.name}) → {r.status}" + (f": {detalle[:160]}" if detalle else ""),
            do=f"refuto verify --gate {r.id}",
            # Una puerta en rojo la arregla quien escribe el código; una BLOQUEADA suele ser un
            # instrumento ausente o una decisión pendiente, y eso no lo cierra un agente.
            who=AGENTE if r.status == FAIL else PERSONA))
    evidence_doc = {}
    try:
        if path.is_file():
            evidence_doc = json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        pass

    return responder(opts, command="verify", status=estado, ws=ws, run_id=ctx.run_id,
                     next=siguientes,
                     payload={"schema": "harness.run/v1", "run_id": ctx.run_id,
                              "verdict": verdict, "evidence": str(path),
                              "gates": [r.to_dict() for r in results],
                              "capsule": evidence_doc.get("capsule"),
                              "evidence_graph": evidence_doc.get("evidence_graph"),
                              "anchor": _resumen_anclaje(anclaje)})


# ── ancla certificada (ADR-0017) ─────────────────────────────────────────────────────
def _pin_externo(opts) -> str | None:
    """El pin que aporta el INVOCADOR, si lo aporta: la bandera manda sobre la variable."""
    from core.concordia import ENV_PIN
    valor = getattr(opts, "membership_digest", None) or os.environ.get(ENV_PIN, "")
    return valor or None


#: Lo que se escribe en `checkpoint.policy_digest` cuando no hay un digest que escribir. Era `""`
#: en los dos casos, y un campo vacío no dice «no se pudo»: no dice nada. El ancla se certificaba
#: igual, en PASS, sin que nada señalara que ese campo no ataba a ninguna política (medido el
#: 2026-09-28). Son dos hechos DISTINTOS y se nombran distinto, como ya hace `core.run` con este
#: mismo dato; fundirlos en un blanco es la pérdida de información que el vacío escondía.
POLITICA_AUSENTE = "sin-politica"          # el espacio no tiene `.harness/policy.json`
POLITICA_IRRESOLUBLE = "irresoluble"       # lo tiene y la cadena efectiva no resuelve


def _digest_politica(ws: Path) -> str:
    """El digest efectivo de la política del espacio, o la palabra que dice por qué no lo hay.

    Nunca se inventa y nunca se calla: el valor viaja DENTRO del checkpoint que firma el quórum,
    así que quien lea el ancla más tarde ve si el veredicto anclado estaba atado a una política
    concreta, a ninguna, o a una que no se pudo resolver.
    """
    from core.context import POLICY_NAME
    from core.policy import Policy

    ruta = ws / ".harness" / POLICY_NAME
    if not ruta.is_file():
        return POLITICA_AUSENTE
    try:
        pol = Policy.load(ruta)
    except Exception:                                                   # noqa: BLE001
        return POLITICA_IRRESOLUBLE
    ident = getattr(pol, "identidad_efectiva", None)
    return (ident.efectivo if ident else "") or POLITICA_IRRESOLUBLE


def _anclar_desde(ws: Path, manifest: dict | None, *, run_id: str, offline: bool,
                  pin_externo: str | None) -> dict:
    """Ancla la cabeza actual del diario si el espacio declara `anchoring`.

    Devuelve `{"declarado", "estado", "motivo", "path", "seq", "signers", "pin"}`. Un espacio que no
    declara anclaje → `declarado=False`, `NOT_APPLICABLE`: el comportamiento histórico de `verify`
    no cambia. Uno que lo declara y se ejecuta `--offline` → `BLOCKED`: no se consultó, luego no
    se comprobó.
    """
    from core import concordia as CC
    from core.evidence import verificar_cadena
    from core.trust import digest_motor

    cfg = CC.configuracion(manifest)
    base = {"declarado": cfg is not None, "estado": NOT_APPLICABLE, "motivo": "", "path": "",
            "seq": None, "signers": [], "pin": None}
    if cfg is None:
        base["motivo"] = "el espacio no declara `anchoring`"
        return base
    pin = CC.resolver_pin(cfg, externo=pin_externo)
    base["pin"] = pin["pin"]
    if pin["estado"] != PASS:
        base.update(estado=pin["estado"], motivo=pin["motivo"])
        return base
    if offline:
        base.update(estado=BLOCKED, motivo="--offline: el ancla exige consultar al clúster y no se consultó. "
                                           "Sin consulta no hay certificado, y sin certificado no hay ancla")
        return base
    r = CC.anclar(ws, cfg, run_id=run_id, engine_digest=digest_motor(),
                  policy_digest=_digest_politica(ws), manifest=manifest, pin=pin["pin"],
                  cadena=verificar_cadena(ws))
    ver = (r.get("ancla") or {}).get("verification") or {}
    entrada = {}
    try:
        entrada = json.loads((r.get("ancla") or {}).get("entry_raw") or "{}")
    except ValueError:
        entrada = {}
    base.update(estado=r["estado"], motivo=r["motivo"], path=r["path"], seq=entrada.get("seq"),
                signers=ver.get("signers") or [])
    return base


def _resumen_anclaje(a: dict) -> dict:
    return {k: a.get(k) for k in ("declarado", "estado", "motivo", "path", "seq", "signers", "pin")}


def _imprimir_anclaje(a: dict) -> None:
    color = "32" if a["estado"] == PASS else ("31" if a["estado"] == FAIL else "33")
    detalle = (f" · seq {a['seq']} · firmantes {a['signers']}" if a.get("seq") is not None else "")
    print(f"  ancla certificada     {R.paint(a['estado'], color)}{detalle}")
    if a.get("path"):
        print(R.dim(f"                        {a['path']}"))
    if a.get("motivo"):
        print(R.paint(f"    {'✗' if a['estado'] == FAIL else '⊘'} {a['motivo']}", color))
    print()


# ── telemetría ───────────────────────────────────────────────────────────────────────
def _ms(v) -> str:
    return "—" if v is None else f"{v:,.1f} ms".replace(",", " ")


def _s(v) -> str:
    return "—" if v is None else f"{v:,.2f} s".replace(",", " ")


def cmd_telemetry(opts) -> int:
    """`refuto telemetry` — qué dice el diario del día de trabajo, con la cobertura de cada cifra.

    Toda cifra lleva su `de N`. `duration_ms` y `entrada_digest` existen desde el 2026-09-28, así
    que sobre un diario viejo la cobertura será baja: decirlo es la diferencia entre una medición
    y una impresión.
    """
    from core import telemetry as T

    ws = _ws(opts)
    if opts.todos:
        censo = T.espacios_registrados()
        if not censo:
            print(R.paint(f"\n  no hay censo de espacios en {T.REGISTRO}: no se puede resumir "
                          f"«todos» sin saber cuáles son\n", "33"))
            return responder(opts, command="telemetry", status=BLOCKED, ws=ws,
                             next=[Siguiente(why="`--todos` necesita el registro de espacios",
                                             do="refuto telemetry  (sobre este espacio)",
                                             who=PERSONA)],
                             payload={"schema": "refuto.telemetry/v1", "summary": None})
        rutas = T.diarios([r for raices in censo.values() for r in raices])
        ambito = f"{len(censo)} espacio(s) del censo"
    else:
        rutas = T.diarios([ws])
        ambito = str(ws)

    if not rutas:
        print(R.paint(f"\n  no hay ningún diario bajo {ambito}: un ámbito vacío no se resume\n", "33"))
        return responder(opts, command="telemetry", status=BLOCKED, ws=ws,
                         next=[Siguiente(why="no hay diario que leer en el ámbito pedido",
                                         do="refuto install", who=PERSONA)],
                         payload={"schema": "refuto.telemetry/v1", "summary": None})

    datos = T.leer(rutas, desde=T.ventana(opts.dias))
    s = T.resumen(datos["eventos"])
    if opts.json:
        return responder(opts, command="telemetry", status=PASS if s["eventos"] else BLOCKED, ws=ws,
                         payload={"schema": "refuto.telemetry/v1", "scope": ambito,
                                  "sources": datos["fuentes"], "unreadable": datos["ilegibles"],
                                  "summary": s})

    vent = f"últimos {opts.dias} día(s)" if opts.dias else "todo el diario"
    print(R.bold(f"\nTelemetría · {ambito} · {vent}"))
    print(R.dim(f"  {len(rutas)} diario(s) · {s['eventos']} evento(s)"
                + (f" · {datos['ilegibles']} línea(s) ilegible(s)" if datos["ilegibles"] else "")
                + (f" · {s['desde'][:19]} → {s['hasta'][:19]}" if s["desde"] else "")))
    if not s["eventos"]:
        print(R.paint("\n  no hay eventos en esa ventana: nada que afirmar\n", "33"))
        return responder(opts, command="telemetry", status=BLOCKED, ws=ws,
                         next=[Siguiente(why="la ventana pedida no contiene eventos",
                                         do="refuto telemetry --dias 0", who=PERSONA)],
                         payload={"schema": "refuto.telemetry/v1", "summary": s})

    d = s["decisiones"]
    print(f"\n  {R.bold('Decisiones')}        {d['total']:,}".replace(",", " "))
    print(f"    allow               {d['allow']:,}".replace(",", " "))
    print(f"    ask                 {d['ask']:,}   ".replace(",", " ")
          + R.dim("(le paran y decide una persona)"))
    print(f"    deny                {d['deny']:,}".replace(",", " "))
    if d["friccion_pct"] is not None:
        print(f"    fricción            {d['friccion_pct']} %")

    g = s["guardian_ms"]
    print(f"\n  {R.bold('Coste de decidir')}  mediana {_ms(g['mediana'])} · p95 {_ms(g['p95'])} "
          f"· máx {_ms(g['max'])}")
    print(R.dim(f"    medido en {g['n']:,} de {g['de']:,} decisiones "
                f"({g['cobertura'] if g['cobertura'] is not None else '—'} %)".replace(",", " ")))
    if g["n"]:
        print(R.dim(f"    suman {g['total'] / 1000:,.1f} s de espera".replace(",", " ")
                    + " · NO incluye el arranque del intérprete, que se mide por fuera"))
    if g["cobertura"] is not None and g["cobertura"] < 90:
        print(R.paint("    ⚠ cobertura baja: los eventos anteriores al 2026-09-28 no llevan "
                      "duración, así que esta mediana habla de una parte", "33"))

    h = s["herramientas_s"]
    print(f"\n  {R.bold('Cuánto tardan')}     mediana {_s(h['mediana'])} · p95 {_s(h['p95'])} "
          f"· máx {_s(h['max'])}")
    print(R.dim(f"    {h['emparejados']:,} operación(es) con decisión y resultado casados; "
                f"{h['decisiones_sin_resultado']:,} decisión(es) sin resultado registrado"
                .replace(",", " ")))
    if not h["resultados"]:
        print(R.paint("    ⚠ no hay ni un `tool/result`: el gancho posterior no está cableado "
                      "en este espacio, así que no se sabe si lo permitido funcionó", "33"))
    for x in s["lentas"][:5]:
        print(f"    {x['tool']:<14} mediana {_s(x['mediana']):>10}  · {x['n']} operación(es)")

    if s["desenlace"]:
        print(f"\n  {R.bold('Cómo acabaron')}    " + " · ".join(
            f"{k} {v}" for k, v in sorted(s["desenlace"].items())))
        if s["desenlace"].get("sin determinar"):
            print(R.dim("    «sin determinar» no es «fue bien»: la respuesta del runtime no "
                        "traía con qué saberlo"))

    if s["reglas"]:
        print(f"\n  {R.bold('Lo que más le frena')}")
        for r in s["reglas"][:8]:
            print(f"    {r['outcome']:<5} {r['n']:>6}  {r['rule'][:70]}")

    if opts.todos and s["por_espacio"]:
        print(f"\n  {R.bold('Por espacio')}")
        for esp, n in list(s["por_espacio"].items())[:12]:
            print(f"    {esp:<28} {n:>8,}".replace(",", " "))
    print()

    siguientes = []
    if not h["resultados"]:
        siguientes.append(Siguiente(
            why="sin `tool/result` no se puede saber si lo que se permitió funcionó ni cuánto tardó",
            do="refuto policy wire --agent claude", who=PERSONA))
    return responder(opts, command="telemetry", status=PASS, ws=ws, next=siguientes,
                     payload={"schema": "refuto.telemetry/v1", "scope": ambito,
                              "sources": datos["fuentes"], "unreadable": datos["ilegibles"],
                              "summary": s})


# ── motor publicado ──────────────────────────────────────────────────────────────────
def _motor_para_lanzadores(opts=None) -> Path:
    """A qué `HARNESS_HOME` apunta un lanzador que se instale AHORA.

    Al publicado si lo hay; al árbol si no, **avisando**. Hasta el 2026-09-28 siempre era el
    árbol, y eso ponía 12 espacios a ejecutar los ficheros que hubiera en él en ese instante.
    """
    from core import engine

    if getattr(opts, "desde_el_arbol", False):
        print(R.paint("  ⚠ --desde-el-arbol: el lanzador apuntará al árbol de trabajo; "
                      "editarlo gobierna los espacios en caliente", "33"))
        return REPO
    d = engine.home_para_lanzadores(REPO)
    if not d["publicado"]:
        print(R.paint(f"  ⚠ {d['motivo']}", "33"))
    return d["home"]


def cmd_engine(opts) -> int:
    """`refuto engine publish|use|show|list` — qué copia del juez gobierna los espacios."""
    from core import engine

    ws = _ws(opts)
    if opts.action == "publish":
        r = engine.publicar(REPO, commit=opts.commit, verificar=not opts.sin_probar,
                            activar=not opts.sin_activar)
        print(R.bold(f"\nMotor publicado · {engine.raiz()}"))
        color = "32" if r["estado"] == PASS else ("31" if r["estado"] == FAIL else "33")
        print(f"  estado                {R.paint(r['estado'], color)}")
        if r.get("commit"):
            print(f"  commit                {r['commit'][:12]}")
        if r.get("digest"):
            print(f"  engine_digest         {r['digest'][:16]}…")
        pr = r.get("selftest") or {}
        if pr.get("ejecutada"):
            print(f"  se probó a sí mismo   {R.paint('sí' if pr.get('ok') else 'NO', '32' if pr.get('ok') else '31')}"
                  f" · {str(pr.get('resumen'))[:90]}")
        elif r["estado"] == PASS:
            print(R.paint("  se probó a sí mismo   NO — publicado con --sin-probar, "
                          "y así queda escrito en published.json", "33"))
        if r.get("motivo"):
            print(R.paint(f"  {r['motivo']}", color))
        print()
        siguientes = []
        if r["estado"] != PASS:
            siguientes.append(Siguiente(why=f"publicar el motor → {r['estado']}: {r['motivo']}",
                                        do="git commit" if r["estado"] == FAIL else "",
                                        who=PERSONA))
        elif not opts.sin_activar:
            siguientes.append(Siguiente(
                why="los espacios ya cableados siguen apuntando a donde apuntaban: el motor "
                    "publicado sólo lo toman los lanzadores que se vuelvan a escribir",
                do="refuto policy wire --agent claude --workspace <cada espacio>", who=PERSONA))
        return responder(opts, command="engine", status=r["estado"], ws=ws, next=siguientes,
                         payload={"schema": engine.SCHEMA, "engine": r})

    if opts.action == "use":
        r = engine.usar(opts.commit or "")
        print(R.bold(f"\nMotor vigente · {engine.raiz()}"))
        print(f"  {R.paint(r['estado'], '32' if r['estado'] == PASS else '31')} "
              f"{r.get('motivo') or opts.commit}")
        if r.get("aviso"):
            print(R.paint(f"  ⚠ {r['aviso']}", "33"))
        print()
        return responder(opts, command="engine", status=r["estado"], ws=ws,
                         next=[] if r["estado"] == PASS else
                         [Siguiente(why=r["motivo"], do="refuto engine list", who=PERSONA)],
                         payload={"schema": engine.SCHEMA, "engine": r})

    if opts.action == "list":
        ms = engine.publicados()
        v = engine.vigente()
        print(R.bold(f"\nMotores publicados · {engine.raiz()}"))
        if not ms:
            print(R.dim("  ninguno. Los lanzadores apuntan al árbol de trabajo."))
        for m in ms:
            marca = "→" if v and v.get("commit") == m.get("commit") else " "
            ver = m.get("verified")
            print(f"  {marca} {m.get('corto', '?'):<14} {str(m.get('published_at'))[:19]:<21}"
                  f" {'probado' if ver else ('SIN PROBAR' if ver is False else '?')}")
        print()
        return responder(opts, command="engine", status=PASS if ms else BLOCKED, ws=ws,
                         next=[] if ms else [Siguiente(
                             why="no hay ningún motor publicado: los espacios corren el árbol de "
                                 "trabajo, y editarlo los gobierna en caliente",
                             do="refuto engine publish", who=PERSONA)],
                         payload={"schema": engine.SCHEMA, "engines": ms})

    # show
    v = engine.vigente()
    d = engine.home_para_lanzadores(REPO)
    print(R.bold("\nQué motor gobierna los espacios"))
    if v is None:
        print(R.paint("  ninguno publicado", "33"))
        print(R.dim(f"  los lanzadores nuevos apuntarían a  {d['home']}"))
        print(R.paint(f"  ⚠ {d['motivo']}", "33"))
        print()
        return responder(opts, command="engine", status=BLOCKED, ws=ws,
                         next=[Siguiente(why=d["motivo"], do="refuto engine publish", who=PERSONA)],
                         payload={"schema": engine.SCHEMA, "engine": None})
    print(f"  commit                {str(v.get('commit'))[:12]}")
    print(f"  engine_digest         {str(v.get('engine_digest'))[:16]}…")
    print(f"  se probó a sí mismo   {R.paint('sí' if v.get('verified') else 'NO', '32' if v.get('verified') else '31')}")
    print(f"  publicado             {str(v.get('published_at'))[:19]} por {v.get('published_by') or '?'}")
    print(R.dim(f"  {v['home']} → {v['path']}"))
    print()
    return responder(opts, command="engine", status=PASS if v.get("verified") else BLOCKED, ws=ws,
                     next=[] if v.get("verified") else [Siguiente(
                         why="el motor vigente no se probó a sí mismo al publicarse",
                         do="refuto engine publish", who=PERSONA)],
                     payload={"schema": engine.SCHEMA, "engine": v})


# ── policy ───────────────────────────────────────────────────────────────────────────
def cmd_policy(opts) -> int:
    from adapters.registry import ADAPTERS, all_specs
    from core.policy import Policy, compile_for

    from core.policy import PoliticaIlegible

    ws = _ws(opts)
    ctx = Context(workspace=ws)

    if opts.action == "base":
        # Emite la capa 1 por la SALIDA, no la escribe. Su sitio es `policies/base.json`, que
        # la política de refuto protege: materializar la norma de la que cuelgan todos los
        # clientes es un acto de persona. Un agente que pudiera reescribirla no estaría
        # gobernado por ella — y este comando corre dentro de un agente.
        from core.policy import RUTA_BASE, documento_base

        if not opts.json:
            print(R.dim(f"\n  # la capa 1 de refuto → cliente → proyecto. Redirija a "
                        f"{RUTA_BASE} para materializarla.\n"))
        print(json.dumps(documento_base(), ensure_ascii=False, indent=2))
        return EXIT_OK

    # `Policy.load`, no `from_dict`: es la vía que resuelve `extends` y la que usa el
    # guardián. Con `from_dict` este comando mostraba y compilaba la política del hijo SIN su
    # padre — una segunda interpretación de la misma política, que es lo que este trabajo
    # existe para eliminar.
    fichero = ws / ".harness" / "policy.json"
    try:
        policy = Policy.load(fichero) if fichero.is_file() else Policy.default()
    except PoliticaIlegible as exc:
        # No revienta con un traceback: `policy refine` existe precisamente para
        # diagnosticar estos documentos, así que tiene que poder ejecutarse sobre ellos.
        print(R.paint(f"\n  ✗ NOT_EXECUTABLE · {exc}\n", "31"))
        return EXIT_FAIL

    if opts.action == "show":
        print(json.dumps(policy.to_dict(), ensure_ascii=False, indent=2))
        return EXIT_OK

    if opts.action == "refine":
        # Resuelve `extends` y MUESTRA la política efectiva con su identidad. No cambia cómo
        # se carga la política en el resto del programa: hacerlo en silencio convertiría un
        # cambio de contrato en un efecto secundario. Ver
        # docs/architecture/HERENCIA-REFUTO-CLIENTE-PROYECTO.md.
        from core.refinement import explicar

        # `explicar` llama a `politica_efectiva`, que es lo que ejecuta
        # `Policy.load` y por tanto el guardián. Una segunda PRESENTACIÓN de la
        # misma resolución es útil; una segunda SEMÁNTICA es el defecto.
        r = explicar(fichero, ctx.policy_doc or {})
        if opts.json:
            print(json.dumps(r.to_dict(), ensure_ascii=False, indent=2))
        else:
            simbolo = R.paint("✓", "32") if r.status == "PASS" else R.paint("✗", "31")
            print(f"\n  {simbolo} {R.bold(r.status)} · {r.motivo}")
            if r.identidad:
                print(f"    identidad   {r.identidad.nombre}@{r.identidad.version}")
                print(f"    digest      {r.identidad.digest[:16]}…")
                print(f"    efectivo    {r.identidad.efectivo[:16]}…  "
                      f"{R.dim('(encadena al padre: si el padre cambia, esto cambia)')}")
            for v in r.violaciones:
                print(R.paint(f"    ✗ {v}", "31"))
            print()
        return EXIT_OK if r.status == "PASS" else EXIT_FAIL

    if opts.action == "prune":
        from core import hygiene
        objetivos = [ws / ".claude" / "settings.local.json", ws / ".claude" / "settings.json"]
        vistos = 0
        for fichero in objetivos:
            if not fichero.is_file():
                continue
            vistos += 1
            res = hygiene.podar(fichero, dry_run=not opts.apply)
            cabeza = "PODARÍA" if res["dry_run"] else "PODADO"
            print(f"\n  {R.bold(str(fichero.relative_to(ws)))}")
            print(f"    {res['total']} reglas · {cabeza} {res['retiradas']} · "
                  f"quedan {res['conservadas']}")
            for motivo, n in sorted(res["por_motivo"].items(), key=lambda kv: -kv[1]):
                print(R.dim(f"      {n:5}  {motivo}"))
            for motivo, ejemplos in res["ejemplos"].items():
                for e in ejemplos:
                    print(R.dim(f"           · {e[:110]}"))
            if res["copia"]:
                print(f"    copia previa: {res['copia']}")
        if not vistos:
            print("\n  no hay ningún settings de Claude Code en este espacio.")
            return EXIT_FAIL
        if not opts.apply:
            print(R.dim("\n  Nada se ha escrito. Añada --apply para podar de verdad.\n"))
        else:
            print()
        return EXIT_OK

    if opts.action in ("wire", "unwire", "audit"):
        from core import wire
        if opts.action == "audit":
            rep = wire.audit(ws)
            print(f"\n  Kiro · guardián en la ruta del CLI: "
                  f"{rep['wired']}/{rep['agents']} agentes")
            for name, state in sorted(rep["detail"].items()):
                mark = R.paint("✓", "32") if state == "enganchado" else R.paint("✗", "31")
                print(f"    {mark} {name:<34} {state}")
            cl = wire.audit_claude(ws)
            mark = R.paint("✓", "32") if cl["wired"] else R.paint("✗", "31")
            print(f"\n  Claude Code · {mark} {cl['reason']}")
            ag = wire.audit_antigravity(ws)
            ag_usado = (ws / ".agents").is_dir()
            mark = (R.paint("✓", "32") if ag["wired"]
                    else R.paint("✗", "31") if ag_usado else R.dim("·"))
            print(f"  Antigravity · {mark} {ag['reason']}"
                  + ("" if ag_usado else R.dim("  (sin .agents/: no se exige)")))
            print()
            ok_kiro = (not rep["agents"]) or rep["wired"] == rep["agents"]
            ok_ag = ag["wired"] or not ag_usado
            return EXIT_OK if ok_kiro and cl["wired"] and ok_ag else EXIT_FAIL
        if opts.action == "unwire":
            results = wire.unwire(ws)
        else:
            targets = opts.agent or ["kiro", "claude"]
            raiz_motor = _motor_para_lanzadores(opts)
            results = []
            if "kiro" in targets:
                results += wire.wire_kiro_agents(ws, harness_root=raiz_motor, dry_run=opts.dry_run)
            if "claude" in targets:
                enganchar = (wire.wire_claude_repos if getattr(opts, "repos", False)
                             else wire.wire_claude)
                results += enganchar(ws, harness_root=raiz_motor, dry_run=opts.dry_run)
            if "antigravity" in targets:
                results += wire.wire_antigravity(ws, harness_root=raiz_motor, dry_run=opts.dry_run)
        for r in results:
            print(f"    {r.action:<9} {r.path} {R.dim(r.detail)}")
        print()
        return EXIT_OK

    specs = [ADAPTERS[a] for a in opts.agent] if opts.agent else all_specs()
    exit_code = EXIT_OK
    for spec in specs:
        out = compile_for(policy, spec)
        head = R.paint("✓", "32") if out["supported"] else R.paint("·", "33")
        print(f"\n  {head} {R.bold(spec.name)}")
        for gap in out["unenforceable"]:
            print(R.paint(f"      NO APLICA: {gap}", "33"))
        for note in out["notes"]:
            print(R.dim(f"      i {note}"))
        for rel, content in sorted(out["artifacts"].items()):
            target = ws / rel
            if opts.action == "compile":
                target.parent.mkdir(parents=True, exist_ok=True)
                # Artefacto generado: LF, como todo lo demás que escribe refuto. Se me
                # escapó en el barrido inicial y lo encontró un `compile` real.
                target.write_text(content, encoding="utf-8", newline="\n")
                print(f"      escrito {rel}")
            else:
                print(f"      generaría {rel} ({len(content)} bytes)")
    print()
    return exit_code


# ── lock ─────────────────────────────────────────────────────────────────────────────
def cmd_lock(opts) -> int:
    from core.lock import build_source_lock, plan_update, resolve_ref, verify, write_lock

    ws = _ws(opts)
    ctx = Context(workspace=ws)

    if opts.action == "show":
        print(json.dumps(ctx.lock or {}, ensure_ascii=False, indent=2))
        return EXIT_OK

    if opts.action == "verify":
        result = verify(ws, ctx.lock, check_remote=not opts.offline)
        print(R.render([result], verdict_of([result]), verbose=True))
        return EXIT_OK if result.status == PASS else (
            EXIT_BLOCKED if result.status == BLOCKED else EXIT_FAIL)

    sources = (ctx.manifest or {}).get("sources") or {}
    if not sources:
        print(R.paint("  el manifiesto no declara `sources`: no hay nada que anclar", "33"))
        return EXIT_BLOCKED

    existing = ctx.lock or {}
    new_entries = {}
    for name, decl in sorted(sources.items()):
        if opts.source and name not in opts.source:
            continue
        sha, err = resolve_ref(decl["uri"], decl["ref"])
        if err:
            print(R.paint(f"  ✗ {name}: {err}", "31"))
            return EXIT_FAIL
        dests = [m["to"] for m in (decl.get("materialize") or [])]
        entry = build_source_lock(name, decl["uri"], decl["ref"], sha, ws, dests)
        plan = plan_update(existing, entry)
        print(f"\n  {R.bold(name)}  {plan['commit_from'][:12] or '—'} → {plan['commit_to'][:12]}")
        for key, colour in (("added", "32"), ("changed", "33"), ("removed", "31")):
            for rel in plan[key][:20]:
                print(R.paint(f"      {key[:7]:<7} {rel}", colour))
        print(R.dim(f"      sin cambios: {plan['unchanged']}"))
        new_entries[name] = entry

    if opts.action == "plan":
        print(R.dim("\n  plan solamente; no se escribió nada. Use `refuto lock update` "
                    "para fijarlo.\n"))
        return EXIT_OK

    merged = {}
    from core.lock import SourceLock
    for name, entry in (existing.get("sources") or {}).items():
        merged[name] = SourceLock(name=name, **{k: v for k, v in entry.items()
                                                if k in SourceLock.__dataclass_fields__})
    merged.update(new_entries)
    write_lock(ctx.lock_path, merged)
    print(f"\n  ✓ lock escrito en {ctx.lock_path.relative_to(ws)}\n")
    return EXIT_OK


# ── mcp ──────────────────────────────────────────────────────────────────────────────
def cmd_mcp(opts) -> int:
    ws = _ws(opts)
    ctx = Context(workspace=ws, offline=opts.offline)
    from gates.base import run_gate
    result = run_gate("G-MCP", ctx)
    print(R.render([result], verdict_of([result]), verbose=True))
    # El estado de la puerta ES el estado de la orden: no hay nada que agregar, y traducirlo a
    # mano era lo que lo rompía. Con `NOT_APPLICABLE` esto devolvía **1**, es decir «algo está
    # mal», para un espacio que legítimamente no declara MCP — y la puerta dice literalmente
    # «no es un aprobado: es que la puerta no tiene sujeto aquí». Ahora lo proyecta la tabla.
    siguientes = [] if result.status in (PASS, NOT_APPLICABLE) else [Siguiente(
        why=f"G-MCP → {result.status}: {result.measure[:160]}",
        do="refuto mcp", who=AGENTE if result.status == FAIL else PERSONA)]
    return responder(opts, command="mcp", status=result.status, ws=ws, next=siguientes,
                     payload={"schema": "harness.result/v1", **result.to_dict()})


def cmd_mcp_serve(opts) -> int:
    """Sirve refuto por MCP stdio. NO lleva `--json`: aquí stdout ES el protocolo.

    Es la única orden que no puede emitir un sobre por stdout, porque su stdout está ocupado por
    JSON-RPC. Lo que devuelve un sobre es cada herramienta de dentro, que es donde el consumidor
    lo necesita.
    """
    from core.mcp_server import HERRAMIENTAS, serve

    ws = _ws(opts)
    # El aviso va a stderr a propósito: en stdout rompería el flujo del cliente en el primer
    # mensaje, que es exactamente el defecto que se midió con `doctor --json` el 2026-09-24.
    print(f"refuto mcp-serve · espacio {ws} · {len(HERRAMIENTAS)} herramientas · "
          f"sólo lectura", file=sys.stderr)
    return serve(ws)


def cmd_protocol(opts) -> int:
    """Sirve el protocolo universal Refuto Wire Protocol v1 sobre stdio (JSON-RPC 2.0).

    Permite a marcos externos (AWS AI-DLC, Kiro, Claude Code, CI/CD) verificar claims,
    obtener decision capsules y auditar la integridad del libro mayor sin acoplamiento.
    """
    from core.protocol import PROTOCOL_VERSION, serve_stdio

    ws = _ws(opts)
    print(f"refuto protocol · v{PROTOCOL_VERSION} · espacio {ws} · JSON-RPC 2.0 stdio", file=sys.stderr)
    return serve_stdio(ws)


# ── inventory ────────────────────────────────────────────────────────────────────────
def cmd_inventory(opts) -> int:
    from core.inventory import build, render_text
    ws = _ws(opts)
    inv = build(ws, depth=opts.depth)
    out_dir = REPO / "artifacts"
    print(render_text(inv))
    if opts.save:
        write_json(out_dir / "inventory.json", inv)
        (out_dir / "inventory.md").write_text(render_text(inv, markdown=True),
                                              encoding="utf-8", newline="\n")
        print(R.dim(f"\n  guardado en {out_dir}/inventory.json y .md\n"))
    return responder(opts, command="inventory", status=PASS, ws=ws,
                     payload={"schema": "harness.inventory/v1", **inv}
                     if isinstance(inv, dict) else inv)


# ── evidence ─────────────────────────────────────────────────────────────────────────
def cmd_evidence(opts) -> int:
    ws = _ws(opts)
    if getattr(opts, "anchor", False) or getattr(opts, "anchor_check", False):
        return _cmd_evidence_anchor(opts, ws)
    events = read_events(ws, kinds=opts.kind or None)
    tail = events[-opts.last:] if opts.last else events
    if opts.json:
        print(json.dumps(tail, ensure_ascii=False, indent=2))
        return EXIT_OK
    if not tail:
        print(R.dim("  el diario está vacío"))
        return EXIT_OK
    for ev in tail:
        print(f"  {R.dim(ev.get('ts',''))} {ev.get('kind',''):<18} "
              f"{ev.get('outcome') or ev.get('verdict') or ''} "
              f"{R.dim(str(ev.get('target') or ev.get('run_id') or '')[:70])}")
    print()
    return EXIT_OK


def _cmd_evidence_anchor(opts, ws: Path) -> int:
    """`refuto evidence --anchor` ancla la cabeza de AHORA; `--anchor-check` vuelve a verificar la
    última ancla OFFLINE contra el pin y el diario. Las dos existen desde el 2026-09-27: hasta
    entonces `core/evidence.py` citaba `--anchor` y la bandera no existía (C-02, R2)."""
    from core import concordia as CC
    from core.context import read_manifest
    from core.evidence import latest_verification

    manifest = read_manifest(ws) or None
    ver = latest_verification(ws) or {}
    run_id = str(ver.get("run_id") or "")
    if getattr(opts, "anchor_check", False):
        a = CC.estado_del_anclaje(ws, manifest, pin_externo=_pin_externo(opts))
        estado = a["estado"]
        det = a.get("detalle") or {}
        print(R.bold(f"\nAncla certificada · {ws}"))
        _imprimir_anclaje({"declarado": a["declarado"], "estado": estado, "motivo": a["motivo"],
                           "path": a["path"], "seq": det.get("seq"), "signers": det.get("signers") or []})
        siguientes = []
        if estado in (FAIL, BLOCKED, INCONCLUSIVE, NOT_EXECUTABLE):
            siguientes.append(Siguiente(why=f"ancla → {estado}: {a['motivo']}",
                                        do="refuto evidence --anchor" if estado == INCONCLUSIVE else "",
                                        who=MAQUINA if estado == INCONCLUSIVE else PERSONA))
        return responder(opts, command="evidence", status=estado, ws=ws, run_id=run_id, next=siguientes,
                         payload={"schema": "refuto.anchor-check/v1", "anchor": a["path"],
                                  "status": estado, "reason": a["motivo"], "pin": a["pin"],
                                  "checkpoint": det.get("checkpoint"), "seq": det.get("seq"),
                                  "signers": det.get("signers")})
    a = _anclar_desde(ws, manifest, run_id=run_id, offline=False, pin_externo=_pin_externo(opts))
    print(R.bold(f"\nAncla certificada · {ws}"))
    if not a["declarado"]:
        print(R.dim("  el espacio no declara `anchoring` en harness.manifest.json: no hay dónde anclar"))
        print()
        return responder(opts, command="evidence", status=BLOCKED, ws=ws, run_id=run_id,
                         next=[Siguiente(why="anclar exige declarar `anchoring` (endpoints y pin de "
                                             "membresía) en harness.manifest.json", do="", who=PERSONA)],
                         payload={"schema": "refuto.anchor/v1", "anchor": _resumen_anclaje(a)})
    _imprimir_anclaje(a)
    siguientes = []
    if a["estado"] != PASS:
        siguientes.append(Siguiente(why=f"ancla → {a['estado']}: {a['motivo']}",
                                    do="refuto evidence --anchor" if a["estado"] == NOT_EXECUTABLE else "",
                                    who=MAQUINA if a["estado"] == NOT_EXECUTABLE else PERSONA))
    return responder(opts, command="evidence", status=a["estado"], ws=ws, run_id=run_id, next=siguientes,
                     payload={"schema": "refuto.anchor/v1", "anchor": _resumen_anclaje(a)})


# ── docs ────────────────────────────────────────────────────────────────────────────
def cmd_docs(opts) -> int:
    from adapters.registry import ADAPTERS, all_specs
    from core.docs import build_matrix, write_docs
    from core.probe import probe_all

    ws = _ws(opts)
    reports = probe_all(all_specs(), deep=opts.deep, workspace=ws)
    matrix = build_matrix(reports, ADAPTERS)
    written = write_docs(Path(opts.out) if opts.out else REPO, matrix)
    for p in written:
        print(f"  ✓ {p}")
    unknown = sum(1 for f in matrix["features"].values()
                  for c in f["by_agent"].values() if c["value"] in ("?", "BLOQUEADO"))
    total = sum(len(f["by_agent"]) for f in matrix["features"].values())
    print(f"\n  {total - unknown}/{total} casillas verificadas · {unknown} declaradas "
          f"sin verificar. Se dicen; no se rellenan.\n")
    return EXIT_OK


# ── selftest ─────────────────────────────────────────────────────────────────────────
def cmd_selftest(opts) -> int:
    from tests.runner import run_suites
    return run_suites(only=opts.suite, verbose=opts.verbose)


# ── chat ────────────────────────────────────────────────────────────────────────────
def cmd_chat(opts) -> int:
    from core.session import launch, plan as plan_session

    ws = _ws(opts)
    sp = plan_session(ws, runtime=opts.agent, role_id=opts.role, spec=opts.spec,
                      model=opts.model, resume=opts.resume, extra=opts.pass_through,
                      provider=opts.provider, task=opts.task, repo=opts.repo)

    print(R.bold(f"\nSesión gobernada · {sp.runtime} · {ws}"))

    for w in sp.warnings:
        print(R.paint(f"  ! {w}", "33"))
    if sp.blockers:
        print()
        for b in sp.blockers:
            print(R.paint(f"  ✗ {b}", "31"))
        print(R.dim("\n  No se abre la sesión. Un modo interactivo que apaga el guardián no es "
                    "un modo:\n  es una puerta trasera con nombre amable.\n"))
        return EXIT_FAIL

    destino = (sp.routing or {}).get("provider", "?")
    SUSCRIPCION = "suscripción de Anthropic"
    if sp.clean_provider:
        # `--provider clean` limpia SIEMPRE; que hubiera algo que limpiar es otra cosa. Decir
        # «se ignoró la redirección a «suscripción de Anthropic»» cuando no había ninguna
        # redirección enseña a desconfiar de la línea entera, justo la que hay que creerse.
        detalle = f" (se ignoró la redirección a «{destino}»)" if destino not in (
            SUSCRIPCION, "?", "") else ""
        print(R.paint(f"  proveedor          {SUSCRIPCION}{detalle}", "32"))
    elif (sp.routing or {}).get("overrides"):
        print(R.paint(f"  proveedor          {destino}", "33"))
    if sp.brief_path:
        print(R.dim(f"  informe de sesión  {sp.brief_path.relative_to(ws)} "
                    f"({len(sp.brief.splitlines())} líneas)"))
    print(R.dim(f"  orden              {' '.join(sp.argv[:6])}…"))

    if opts.dry_run:
        print(R.dim("\n  (simulación: no se abre nada)\n"))
        print(sp.brief)
        return EXIT_OK

    print(R.dim("  diario             .harness/evidence/ledger.jsonl\n"))
    return launch(sp)


# ── work ────────────────────────────────────────────────────────────────────────────
def _clasificar(ws, *, repo: str = "", limit: int = 40):
    """Trabajo pendiente, ya enrutado. Devuelve (pares, error)."""
    from core.classify import classify
    from core.forge import my_tasks, repo_of
    from core.roles import load as load_roles

    destino = repo or repo_of(ws)
    tareas, err = my_tasks(repo=destino, limit=limit)
    if err:
        return [], err
    manifiesto = Context(workspace=ws).manifest or {}
    aliases = (manifiesto.get("classification") or {}).get("aliases") or {}
    disponibles = set(load_roles())
    return [(t, classify(t, roles_disponibles=disponibles, aliases=aliases))
            for t in tareas], ""


def cmd_work(opts) -> int:
    from core.forge import available, review_requests
    from core.policy import Policy
    from core.routing import route
    from adapters.registry import ADAPTERS

    ws = _ws(opts)
    forjas = available()
    if not any(f["ok"] for f in forjas.values()):
        print(R.paint("\n  Ninguna forja consultable:", "33"))
        for name, f in sorted(forjas.items()):
            print(R.dim(f"    {name}: {f['reason']}"))
        print()
        return EXIT_BLOCKED

    pares, err = _clasificar(ws, repo=opts.repo, limit=opts.limit)
    if err:
        print(R.paint(f"\n  no se pudo consultar la forja: {err}\n", "31"), file=sys.stderr)
        return EXIT_FAIL

    if opts.json:
        print(json.dumps([{"task": t.to_dict(), "classification": c.to_dict()}
                          for t, c in pares], ensure_ascii=False, indent=2))
        return EXIT_OK

    print(R.bold(f"\nTrabajo pendiente · {opts.repo or 'todas sus asignaciones'}"))
    if not pares:
        print(R.dim("  nada asignado\n"))
        return EXIT_OK

    # El runtime se resuelve una vez, y sólo se sondea el que importa aquí.
    runtimes = _runtimes_relevantes(ws, opts.agent)
    graph, _ = _grafo(ws, runtimes)
    pf = ws / ".harness" / "policy.json"
    policy = Policy.load(pf) if pf.is_file() else Policy.default()
    print(R.dim(f"  runtime: {', '.join(runtimes)}"))

    for t, c in pares:
        cabecera = R.bold(f"  {t.key or '#' + str(t.number)}")
        print(f"\n{cabecera}  {t.title[:66]}")
        print(R.dim(f"       {t.repo}#{t.number} · {t.url}"))
        for campo in ("Tipo", "Tipo / Gate", "Épica", "Horas", "Estado spec", "Ejecutor"):
            if t.fields.get(campo):
                print(R.dim(f"       {campo:<12} {t.fields[campo][:60]}"))
        if t.spec_path:
            existe = (ws / t.spec_path).is_file()
            marca = R.paint("✓", "32") if existe else R.paint("✗", "33")
            print(R.dim(f"       spec         {marca} {t.spec_path}"
                        + ("" if existe else "  (no está en este espacio)")))
        color = {"CIERTO": "32", "PROBABLE": "33"}.get(c.confidence, "33")
        print(f"       {R.paint('roles', color)}        "
              f"{', '.join(c.roles) or '—'}  "
              f"{R.dim(f'[{c.confidence} · {c.source} · evidencia {c.evidence}]')}")
        for s in c.signals[:2]:
            print(R.dim(f"                    {s[:96]}"))
        if c.primary:
            d = route(c.primary, graph, ADAPTERS, policy=policy)
            estado = {"READY": "32", "DEGRADED": "33", "BLOCKED": "31"}[d.status]
            print(f"       runtime      {R.paint(d.chosen or '—', estado)} "
                  f"{R.dim(f'[{d.status}]')}")
            if d.human_review:
                print(R.dim(f"       revisión     {d.human_review}"))
            print(R.dim(f"       abrir con    refuto chat --task {t.number}"
                        + (f" --repo {t.repo}" if opts.repo or not _es_local(ws, t) else "")))
        if c.question:
            print(R.paint(f"       ? {c.question}", "33"))

    revisiones, _ = review_requests()
    if revisiones:
        print(f"\n  {R.bold('Revisiones que le han pedido')}")
        for r in revisiones:
            print(f"    {r.repo}#{r.number}  {r.title[:60]}")
    print()
    return EXIT_OK


def _es_local(ws, task) -> bool:
    from core.forge import repo_of
    return repo_of(ws) == task.repo


# ── plan / run / resume / status ────────────────────────────────────────────────────
def _render_run(run, *, verbose: bool = False) -> None:
    from core.run import BLOCKED_, DONE, FAILED, PENDING, SKIPPED
    colour = {DONE: "32", PENDING: "2", SKIPPED: "2", FAILED: "31", BLOCKED_: "33"}
    mark = {DONE: "✓", PENDING: "·", SKIPPED: "·", FAILED: "✗", BLOCKED_: "⊘"}
    phase = None
    for s in run.steps:
        if s.phase != phase:
            phase = s.phase
            print(f"\n  {R.bold(phase)}")
        tag = R.paint(f"{mark[s.status]} {s.status:<8}", colour[s.status])
        print(f"    {tag} {s.role or '(sin rol)':<24} {R.dim(s.runtime or '—')}")
        if s.reason and (verbose or s.status in (FAILED, BLOCKED_)):
            print(R.dim(f"        {s.reason[:150]}"))
        if s.gates:
            gs = " ".join(f"{g}:{v}" for g, v in sorted(s.gates.items()))
            print(R.dim(f"        puertas  {gs}"))
        if s.human_review:
            print(R.dim(f"        revisión {s.human_review}"))
        if s.cost_usd:
            print(R.dim(f"        coste    ${s.cost_usd:.4f}"))
    print()


def cmd_plan(opts) -> int:
    from core.run import plan as plan_run
    ws = _ws(opts)
    run, _ = plan_run(ws, goal=opts.goal, phases=opts.phase or None,
                      prefer=opts.prefer or None)
    if opts.json:
        print(json.dumps(run.to_dict(), ensure_ascii=False, indent=2))
        return EXIT_OK
    print(R.bold(f"\nPlan · {run.run_id}") + (f"  «{run.goal}»" if run.goal else ""))
    _render_run(run, verbose=opts.verbose)
    blocked = [s for s in run.steps if s.status == "BLOCKED"]
    if blocked:
        print(R.paint(f"  {len(blocked)} pasos bloqueados: no se puede ejecutar el ciclo "
                      f"completo tal como está.", "33"))
        print()
    if opts.save:
        p = run.save()
        print(R.dim(f"  guardado en {p.relative_to(ws)}\n"))
    return EXIT_BLOCKED if blocked else EXIT_OK


def _prompt_of(role, workspace, goal: str = ""):
    """Texto de la tarea de un rol. Deriva del contrato, no de un prompt escrito a mano.

    Refuto gobierna el proceso; no escribe el método. Lo que se le dice al agente sale de
    lo que el rol declara, así que cambiar el contrato cambia la instrucción — y no pueden
    divergir.
    """
    from core.roles import KNOWN_CONSTRAINTS
    lines = [f"Actúa como {role.id}.", ""]
    if goal:
        lines += [f"**El encargo:** {goal}", ""]
    lines += [f"**Tu papel en él.** {role.purpose}", ""]
    if role.input_contract:
        lines += [f"**Consumes:** {', '.join(role.input_contract)}", ""]
    lines += [f"**Debes producir:** {', '.join(role.output_contract)}.",
              "Sin esos artefactos la fase NO ha terminado, digas lo que digas.",
              "Trabaja sobre los archivos del repositorio actual; no describas lo que harías.",
              ""]
    if role.constraints:
        lines += ["**No puedes:**"]
        lines += [f"- {KNOWN_CONSTRAINTS.get(c, c)}" for c in role.constraints]
        lines += ["", "Estas restricciones las aplica un guardián fuera de tu control: "
                      "intentar saltarlas produce un bloqueo registrado, no un atajo.", ""]
    if role.quality_gates:
        lines += [f"**Al terminar se ejecutan:** {', '.join(role.quality_gates)}.", ""]
    if role.human_review:
        lines += [f"**Requiere {role.human_review}**: tu salida no cierra la fase por sí sola.",
                  ""]
    if role.notes:
        lines += [f"_{role.notes}_", ""]
    return "\n".join(lines)


def cmd_run(opts) -> int:
    from core.run import execute_step, finish, plan as plan_run

    ws = _ws(opts)
    run, ctxobj = plan_run(ws, goal=opts.goal, phases=opts.phase or None,
                           prefer=opts.prefer or None)
    dry = not opts.execute
    if dry:
        print(R.paint("\n  MODO SIMULACIÓN: no se invocará a ningún agente. "
                      "Use --execute para gastar créditos.", "33"))
    print(R.bold(f"\nEjecución · {run.run_id}") + (f"  «{run.goal}»" if run.goal else ""))
    run.save()
    for step in run.steps:
        execute_step(run, step, ctxobj, dry_run=dry, budget_usd=opts.budget,
                     prompt_of=lambda r, w: _prompt_of(r, w, run.goal))
        run.save()
    finish(run)
    _render_run(run, verbose=opts.verbose)
    total = sum(s.cost_usd or 0 for s in run.steps)
    print(f"  estado: {R.bold(run.status)}"
          + (f" · coste total ${total:.4f}" if total else ""))
    print(R.dim(f"  estado guardado en {run.path().relative_to(ws)}\n"))
    return {"DONE": EXIT_OK, "BLOCKED": EXIT_BLOCKED}.get(run.status, EXIT_FAIL)


def cmd_resume(opts) -> int:
    from core.run import execute_step, finish, latest, load, resumable, plan as plan_run

    ws = _ws(opts)
    run = load(ws, opts.run_id) if opts.run_id else latest(ws)
    if run is None:
        print(R.paint("  no hay ninguna ejecución que reanudar", "31"), file=sys.stderr)
        return EXIT_USAGE

    check = resumable(run)
    print(R.bold(f"\nReanudar · {run.run_id}"))
    if check["drift"]:
        print(R.paint("\n  El entorno cambió desde que se dejó:", "31"))
        for d in check["drift"]:
            print(R.paint(f"    ✗ {d}", "31"))
        print(R.dim("\n  Reanudar aquí produciría evidencia que dice una cosa sobre un árbol "
                    "que ya es otra.\n  Use --force sólo si sabe exactamente por qué.\n"))
        if not opts.force:
            return EXIT_FAIL
    if not check["pending"]:
        print(R.dim("\n  no queda ningún paso pendiente\n"))
        return EXIT_OK
    print(R.dim(f"  {len(check['pending'])} pasos pendientes: "
                f"{', '.join(check['pending'][:6])}\n"))

    _, ctxobj = plan_run(ws, goal=run.goal, phases=run.phases)
    dry = not opts.execute
    for step in run.steps:
        if step.status in ("PENDING", "FAILED", "BLOCKED"):
            execute_step(run, step, ctxobj, dry_run=dry, budget_usd=opts.budget,
                         prompt_of=lambda r, w: _prompt_of(r, w, run.goal))
            run.save()
    finish(run)
    _render_run(run, verbose=opts.verbose)
    return {"DONE": EXIT_OK, "BLOCKED": EXIT_BLOCKED}.get(run.status, EXIT_FAIL)


def _hay_artefactos(ws: Path) -> bool:
    """¿Existe algún artefacto de corrida en este espacio?

    Es la fuente de EXPECTATIVA de `status`: un artefacto de corrida no se escribe solo, y
    escribirlo deja eventos. Si hay artefactos y no hay diario, alguien borró el diario —no es
    un espacio recién creado—. Se cuenta por presencia de fichero, no por su contenido: un
    artefacto ilegible sigue siendo prueba de que hubo una corrida.
    """
    d = ws / ".harness" / "evidence"
    if not d.is_dir():
        return False
    return any(p.name != "sbom.json" for p in d.glob("*.json"))


def _estado_de_status(cadena: dict, ver: dict | None, ilegibles: list, anclaje: dict | None = None) -> str:
    """El estado que `refuto status` declara. La tabla vive aquí para que sea auditable.

    El defecto que cierra (R-07, medido el 2026-09-25)
    -------------------------------------------------
    `status` calculaba la integridad de la evidencia, la IMPRIMÍA —«NO INTEGRABLE — la
    evidencia no se sostiene»— y acto seguido declaraba `PASS` y salía con 0. Estado calculado
    ≠ estado reportado, que es precisamente lo que el protocolo de tres caras existe para
    impedir: quien encadena `refuto status && desplegar` desplegaba sobre evidencia que el
    propio programa acababa de declarar insostenible.

    La causa no era la falta de un contrato: `core.envelope._EXIT_POR_ESTADO` ya deriva el
    código del estado, y `status` ya lo usaba. Era que sólo se le pasaban dos estados —
    `INCONCLUSIVE` si algo era ilegible, `PASS` en todo lo demás—, y la integridad, ya
    calculada y guardada en `ver["integrity"]`, no entraba en la decisión.

    La tabla
    --------
        FAIL           la evidencia se CONTRADICE, o la cadena del diario está rota,
                       desalineada o es insuficiente. Hay un hecho demostrado, no una duda.
        INCONCLUSIVE   no se pudo LEER la evidencia, o no hay con qué contrastarla.
                       «No lo sé» no es «está mal» ni «está bien».
        PASS           el resto.

    Por qué `FAIL` gana a `INCONCLUSIVE`
    ------------------------------------
    Al revés que en las puertas, donde `NOT_EXECUTABLE` manda sobre `FAIL` porque no se sabe
    cuántos fallos hay. Aquí es al contrario: una contradicción DEMOSTRADA no se degrada a «no
    pude determinarlo» porque otra fuente además fuera ilegible. Rebajarla perdería el único
    hecho firme que hay sobre la mesa.

    La excepción declarada
    ----------------------
    Una última verificación con PUERTAS EN ROJO sigue dando `PASS`. No es un descuido:
    `refuto verify` es la autoridad sobre ese veredicto y ya sale con 1. `status` responde otra
    pregunta —«¿pude establecer el estado, y se sostiene lo que reporto?»— y el trabajo
    pendiente viaja en `next`. Mapearlo a `FAIL` haría indistinguible «hay trabajo que hacer»
    de «lo que te estoy contando no se sostiene». Está probado como excepción explícita, no
    heredado por omisión.
    """
    from core.evidence import DESALINEADA, INSUFICIENTE, ROTA

    integridad = ((ver or {}).get("integrity") or {}).get("estado", "")
    # El ancla certificada (ADR-0017) entra en la MISMA tabla, con la misma regla de precedencia:
    # un hecho demostrado en contra (FAIL) manda; después, «falta la dependencia declarada»
    # (BLOCKED: no hay pin); después, «no se pudo establecer» (INCONCLUSIVE: no hay ancla, o es
    # ilegible). Un espacio que no declara anclaje trae NOT_APPLICABLE y no toca el estado.
    est_ancla = (anclaje or {}).get("estado", NOT_APPLICABLE)
    if integridad == "contradice" or cadena["estado"] in (ROTA, DESALINEADA, INSUFICIENTE) \
            or est_ancla == FAIL:
        return FAIL
    if est_ancla == BLOCKED:
        return BLOCKED
    if ilegibles or integridad == "indeterminado" or est_ancla in (INCONCLUSIVE, NOT_EXECUTABLE):
        return INCONCLUSIVE
    return PASS


def cmd_status(opts) -> int:
    from core import humanreview as HR
    from core.run import latest, resumable

    from core.evidence import latest_verification, verificar_cadena

    ws = _ws(opts)
    run = latest(ws)
    print(R.bold(f"\nEstado · {ws}"))

    # Dos fuentes, nombradas por separado. Antes sólo se leía la orquestación y `status`
    # respondía «no hay ninguna ejecución registrada» justo después de un `verify` que sí
    # había dejado evidencia. Ver ADR-0012.
    ver = latest_verification(ws)
    rojas_ver = 0
    if ver is None:
        print(R.dim("  última verificación   ninguna registrada"))
    elif ver.get("run_id"):
        rojas = rojas_ver = sum(1 for s in ver["gates"].values()
                                if s in ("FAIL", "NOT_EXECUTABLE"))
        print(f"  última verificación   {ver['run_id']} · {R.bold(ver['verdict'])}")
        print(R.dim(f"                        {len(ver['gates'])} puertas · {rojas} en rojo · "
                    f"{ver['generated_at'][:19]}"))
        print(R.dim(f"                        {ver['path']}"))
    for u in (ver or {}).get("unreadable", []):
        print(R.paint(f"    ⊘ evidencia ilegible: {u['path']} — {u['problem']}", "33"))
        print(R.dim("      «no pude leerlo» no es «no existe»: el estado queda sin determinar."))

    # El diario, como fuente por derecho propio. Hasta el 2026-09-25 `status` sólo lo miraba
    # de refilón: `reconciliar` lo consultaba, pero SÓLO si existía un artefacto de corrida
    # con el que contrastarlo. Sin artefacto, borrar el diario entero dejaba una salida
    # idéntica byte a byte a la de antes del borrado (R-06, reproducido: 5 eventos `deny`
    # destruidos, `status` PASS/0 antes y después, con el mismo `next`).
    #
    # La expectativa que convierte «no hay diario» en contradicción se deriva aquí de algo
    # material: si hay artefactos de corrida, hubo eventos que los produjeron. Es la misma
    # regla de C-02 —ausencia sólo aprueba sin expectativa— aplicada en la frontera operativa
    # en vez de dentro del motor.
    cadena = verificar_cadena(ws, eventos_minimos=1 if _hay_artefactos(ws) else 0)
    cicatrices = cadena.get("cicatrices") or []
    print(f"  diario                {R.bold(cadena['estado'])} · {cadena['eventos']} eventos"
          + (f" · {cadena['legado']} de legado" if cadena["legado"] else "")
          + (f" · {len(cicatrices)} cicatriz(ces)" if cicatrices else ""))
    if cadena["motivo"]:
        # Una cicatriz declarada NO es un fallo: es una rotura reconocida, con su causa y con
        # quién la reconoce. Pintarla en rojo la igualaría a una cadena rota de verdad, y
        # entonces la única forma de tener el diario «en verde» volvería a ser borrarlo.
        from core.evidence import CICATRIZADA
        rojo = cadena["estado"] != CICATRIZADA
        print(R.paint(f"    {'✗' if rojo else '⊘'} {cadena['motivo']}", "31" if rojo else "33"))
    for c in cicatrices:
        print(R.dim(f"      línea {c['line']}: {c['expected_head'][:12]}… → {c['found_prev'][:12]}…"
                    f" · declarada por {c['declared_by']} el {c['declared_at']}"))
        print(R.dim(f"        {c['cause'][:150]}"))

    # El ancla certificada, releída OFFLINE (ADR-0017): ¿el diario de ahora sigue conteniendo el
    # checkpoint que `≥ q` réplicas certificaron, bajo la membresía cuyo digest fija el pin?
    # `status` no habla con el clúster: verifica lo guardado. Es lo que convierte los seis
    # ataques «sólo con ancla» de `test_ledger_ataques.py` en detectados aquí.
    from core.concordia import estado_del_anclaje
    from core.context import read_manifest
    anclaje = estado_del_anclaje(ws, read_manifest(ws) or None, pin_externo=_pin_externo(opts),
                                 run_id=str((ver or {}).get("run_id") or "") or None)
    if anclaje["declarado"]:
        det = anclaje.get("detalle") or {}
        _imprimir_anclaje({"declarado": True, "estado": anclaje["estado"], "motivo": anclaje["motivo"],
                           "path": anclaje["path"], "seq": det.get("seq"), "signers": det.get("signers") or []})

    if run is None:
        print(R.dim("  última orquestación   ninguna registrada"))
    else:
        check = resumable(run)
        print(f"  última orquestación   {run.run_id} · {R.bold(run.status)} · "
              f"{run.started_at[:19]}")
        print(f"  pasos pendientes      {len(check['pending'])}")
        for d in check["drift"]:
            print(R.paint(f"    ✗ {d}", "31"))
    pend = HR.pending(ws)
    print(f"  revisiones humanas pendientes: {len(pend)}")
    for p, r in pend[:8]:
        print(R.dim(f"    {r.kind:<24} {r.subject}"))
    from core.memory import Memory
    memoria = {k: v["count"] for k, v in Memory(ws).summary().items()}
    print("  memoria: " + " · ".join(f"{k}={v}" for k, v in memoria.items()))

    # Qué toca después, por las tres fuentes que `status` ya mira.
    siguientes: list = []
    ilegibles = (ver or {}).get("unreadable", [])
    if cadena["motivo"]:
        # Una cadena CICATRIZADA sí se sostiene —por tramos, y las discontinuidades están
        # declaradas—: decir que «no se sostiene» sería llamar fallo a lo que una persona ya
        # reconoció, y quien lea eso acabará buscando la forma de que desaparezca.
        from core.evidence import CICATRIZADA
        cicatrizada = cadena["estado"] == CICATRIZADA
        siguientes.append(Siguiente(
            why=(f"la cadena del diario cierra por tramos ({cadena['estado']}): {cadena['motivo']}"
                 if cicatrizada else
                 f"la cadena del diario no se sostiene ({cadena['estado']}): {cadena['motivo']}"),
            do="", who=PERSONA))
    if anclaje["declarado"] and anclaje["estado"] != PASS:
        siguientes.append(Siguiente(
            why=f"el ancla certificada no se sostiene ({anclaje['estado']}): {anclaje['motivo']}",
            do="refuto evidence --anchor" if anclaje["estado"] == INCONCLUSIVE else "",
            who=MAQUINA if anclaje["estado"] == INCONCLUSIVE else PERSONA))
    integridad_ver = ((ver or {}).get("integrity") or {})
    if integridad_ver.get("estado") in ("contradice", "indeterminado"):
        siguientes.append(Siguiente(
            why=f"la evidencia de la última verificación no se sostiene "
                f"({integridad_ver['estado']}): {integridad_ver.get('motivo', '')}",
            do="", who=PERSONA))
    for u in ilegibles:
        siguientes.append(Siguiente(
            why=f"evidencia ilegible en {u['path']}: {u['problem']}. «No pude leerlo» no es "
                f"«no existe»: el estado queda sin determinar",
            do="", who=PERSONA))
    if ver is None:
        siguientes.append(Siguiente(
            why="no hay ninguna verificación registrada: nada afirma que este espacio cumpla",
            do="refuto verify", who=MAQUINA))
    elif rojas_ver:
        siguientes.append(Siguiente(
            why=f"la última verificación dejó {rojas_ver} puerta(s) sin aprobar "
                f"({ver['verdict']})",
            do="refuto verify", who=AGENTE))
    for _p, r in pend:
        siguientes.append(Siguiente(
            why=f"revisión humana pendiente: {r.kind} sobre {r.subject}. Sin ella no se puede "
                f"afirmar que alguien lo miró",
            do="", who=PERSONA))
    for d in (resumable(run)["drift"] if run is not None else []):
        siguientes.append(Siguiente(why=f"deriva del entorno: {d}", do="refuto doctor",
                                    who=PERSONA))

    for s in siguientes[:8]:
        print(R.paint(f"  → {s.why}", "33"))
        if s.do:
            print(R.dim(f"     hacer  {s.do}  ({s.who})"))
    print()

    estado = _estado_de_status(cadena, ver, ilegibles, anclaje)
    return responder(opts, command="status", status=estado, ws=ws, next=siguientes,
                     payload={"schema": "harness.status/v1",
                              "verification": ver,
                              "anchor": {k: anclaje.get(k) for k in ("declarado", "estado", "motivo",
                                                                      "path", "pin", "ilegibles")}
                              | {"seq": (anclaje.get("detalle") or {}).get("seq"),
                                 "signers": (anclaje.get("detalle") or {}).get("signers"),
                                 "checkpoint": (anclaje.get("detalle") or {}).get("checkpoint")},
                              "orchestration": (run.to_dict()
                                                if run is not None and hasattr(run, "to_dict")
                                                else None),
                              "human_reviews_pending": [{"kind": r.kind, "subject": r.subject}
                                                        for _p, r in pend],
                              "memory": memoria})


# ── argumentos ───────────────────────────────────────────────────────────────────────
class UsageParser(argparse.ArgumentParser):
    """Un error de uso sale con `EXIT_USAGE`, no con el 2 de argparse.

    argparse sale con **2** ante `unrecognized arguments` o un subcomando ausente. Pero 2 es
    el código que este programa reserva para BLOCKED —«se ejecutó y algo no se pudo
    comprobar»—, así que una orden mal escrita y una puerta bloqueada eran indistinguibles
    para quien sólo ve el código de salida: un guion de CI que trata el 2 como «revísalo a
    mano» daba por bloqueada una corrida que nunca llegó a ejecutarse.

    `refuto selftest --suite zzz --verbose` es el caso exacto: `--verbose` es opción del
    parser raíz, así salía 2 y parecía un bloqueo. Ahora sale 64, que es lo que dice
    `sysexits.h` para EX_USAGE y lo que ya usaba el resto del programa.

    `--help` y `--version` siguen saliendo con 0: `exit()` sólo se fuerza cuando el código
    que argparse quiere usar es el 2 de un error de uso.
    """

    def error(self, message: str) -> None:            # noqa: D401  (contrato de argparse)
        self.print_usage(sys.stderr)
        self.exit(EXIT_USAGE, f"{self.prog}: error: {message}\n")


def _args_herencia(sp) -> None:
    """Los argumentos de herencia de `init` e `install`, en un solo sitio.

    Duplicarlos en dos parsers es cómo dos comandos que deben crear el mismo documento acaban
    creando dos distintos: alguien añade una opción a uno y el otro sigue funcionando, así que
    nada falla y la divergencia no se nota hasta que un espacio nace sin heredar.
    """
    sp.add_argument("--extends", default="", metavar="RUTA",  # relativa a `<espacio>/.harness/`
                    help="ruta del documento padre, relativa a `<espacio>/.harness/` (o "
                         "absoluta). El espacio nace HEREDANDO en vez de con una copia completa "
                         "de la norma. Para un cliente, la capa base de refuto (`refuto policy "
                         "base`); para un proyecto, la política de su cliente.")
    sp.add_argument("--anchor", action="store_true",
                    help="con `--extends`: fija `extends_digest` al padre de hoy. A partir de "
                         "ahí, cualquier cambio del padre deja de resolver hasta que alguien "
                         "lo revise. Sin esta opción el hijo sigue al padre.")


def build_parser() -> argparse.ArgumentParser:
    p = UsageParser(prog="refuto", description=__doc__,
                    formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--workspace", default="", help="espacio de trabajo (por defecto, el actual)")
    p.add_argument("--verbose", action="store_true")
    sub = p.add_subparsers(dest="command", required=True)

    d = sub.add_parser("doctor", help="qué hay en esta máquina y qué funciona de verdad")
    d.add_argument("--deep", action="store_true", help="incluye VERIFIED (gasta créditos)")
    d.add_argument("--json", action="store_true", help=AYUDA_JSON)
    d.set_defaults(func=cmd_doctor)

    pr = sub.add_parser("probe", help="escalera de ejecutabilidad de los agentes")
    pr.add_argument("--agent", action="append", default=[])
    pr.add_argument("--deep", action="store_true")
    pr.add_argument("--json", action="store_true")
    pr.set_defaults(func=cmd_probe)

    di = sub.add_parser("discover", help="qué hay alrededor: entorno, núcleo SDD y repositorio")
    di.add_argument("--root", action="append", default=[],
                    help="dónde buscar (repetible). Por defecto: el directorio actual")
    di.add_argument("--deep", action="store_true",
                    help="amplía la búsqueda a los directorios habituales de $HOME")
    di.add_argument("--json", action="store_true")
    di.set_defaults(func=cmd_discover)

    co = sub.add_parser("context", help="qué cree refuto que está pasando, y por qué")
    co.add_argument("--root", action="append", default=[])
    co.add_argument("--deep", action="store_true")
    co.add_argument("--phase", action="append", default=[])
    co.add_argument("--prefer", action="append", default=[],
                    help="runtime preferido (repetible), si cumple las capacidades")
    co.add_argument("--json", action="store_true")
    co.set_defaults(func=cmd_context)

    en = sub.add_parser("environments", aliases=["entornos"],
                        help="contra qué entorno se trabaja, y si sigue respondiendo")
    en.add_argument("action", nargs="?", default="show", choices=["show", "check"])
    en.add_argument("--write", action="store_true",
                    help="con `check`, actualiza el sondeo y la fecha en el archivo")
    en.add_argument("--json", action="store_true")
    en.set_defaults(func=cmd_environments)

    me = sub.add_parser("memory", help="memoria en capas; no es evidencia")
    me.add_argument("action", choices=["list", "summary", "remember", "export"])
    me.add_argument("--layer", action="append", default=[])
    me.add_argument("--key", default="")
    me.add_argument("--body", default="")
    me.add_argument("--why", default="")
    me.add_argument("--source", default="")
    me.add_argument("--query", default="")
    me.add_argument("--all", action="store_true")
    me.add_argument("--json", action="store_true")
    me.set_defaults(func=cmd_memory)

    ins = sub.add_parser("install", help="deja este espacio operativo de principio a fin")
    ins.add_argument("--desde-el-arbol", action="store_true", dest="desde_el_arbol",
                     help="apunta el lanzador al árbol de trabajo en vez de al motor publicado (desarrollo)")
    ins.add_argument("--agent", action="append", default=[],
                     help="runtimes a enganchar; por defecto, los presentes")
    ins.add_argument("--core", default="", help="ruta del núcleo SDD, si hay ambigüedad")
    ins.add_argument("--spec", default="", help="especificación activa, si hay varias")
    ins.add_argument("--provider-expect", default="subscription",
                     choices=["subscription", "api-key", "bedrock", "vertex", "foundry",
                              "custom"],
                     help="a qué proveedor debe hablar el agente aquí")
    ins.add_argument("--no-bind", action="store_true")
    ins.add_argument("--deep", action="store_true")
    ins.add_argument("--force", action="store_true")
    _args_herencia(ins)
    ins.set_defaults(func=cmd_install)

    b = sub.add_parser("bind", help="ata este espacio a un núcleo y a un repositorio")
    b.add_argument("action", choices=["set", "show", "verify"])
    b.add_argument("--core", default="", help="ruta del núcleo SDD, si hay ambigüedad")
    b.add_argument("--repo", default="", help="ruta del repositorio, si hay ambigüedad")
    b.add_argument("--root", action="append", default=[])
    b.add_argument("--deep", action="store_true")
    b.add_argument("--by", default="")
    b.set_defaults(func=cmd_bind)

    i = sub.add_parser("init", help="crea .harness/ en este espacio")
    i.add_argument("--force", action="store_true")
    _args_herencia(i)
    i.set_defaults(func=cmd_init)

    up = sub.add_parser("upgrade", aliases=["actualizar"],
                        help="lleva este espacio a la versión del motor en disco")
    up.add_argument("--desde-el-arbol", action="store_true", dest="desde_el_arbol",
                    help="apunta el lanzador al árbol de trabajo en vez de al motor publicado (desarrollo)")
    up.add_argument("--apply", action="store_true",
                    help="escribe. Sin esto muestra qué cambiaría y no toca nada.")
    up.add_argument("--json", action="store_true", help=AYUDA_JSON)
    up.set_defaults(func=cmd_upgrade)

    v = sub.add_parser("verify", help="ejecuta las puertas y emite evidencia")
    v.add_argument("--gate", action="append", default=[])
    v.add_argument("--deep", action="store_true")
    v.add_argument("--offline", action="store_true", help="no consulta orígenes remotos")
    v.add_argument("--membership-digest", default="",
                   help="pin de membresía de concordia aportado por el invocador (ADR-0017)")
    v.add_argument("--json", action="store_true")
    v.set_defaults(func=cmd_verify)

    po = sub.add_parser("policy", help="compila la política canónica a cada runtime; `prune` retira reglas de permiso podridas")
    po.add_argument("--desde-el-arbol", action="store_true", dest="desde_el_arbol",
                    help="apunta el lanzador al árbol de trabajo en vez de al motor publicado (desarrollo)")
    po.add_argument("action",
                    choices=["show", "base", "refine", "plan", "compile", "wire", "unwire",
                             "audit", "prune"])
    po.add_argument("--agent", action="append", default=[])
    po.add_argument("--json", action="store_true",
                    help="con `refine`: la política efectiva y su identidad en JSON")
    po.add_argument("--dry-run", action="store_true")
    po.add_argument("--repos", action="store_true",
                    help="con `wire`: engancha tambien cada repositorio del espacio, todos al "
                         "MISMO guardian. Una politica, un guardian, N punteros.")
    po.add_argument("--apply", action="store_true",
                    help="sólo para `prune`: escribe. Sin esto mide y no toca nada.")
    po.set_defaults(func=cmd_policy)

    te = sub.add_parser("telemetry", help="qué dice el diario del día de trabajo, con su cobertura")
    te.add_argument("--dias", type=int, default=0,
                    help="ventana en días; 0 (por omisión) es todo el diario")
    te.add_argument("--todos", action="store_true",
                    help="todos los espacios del registro del usuario, no sólo éste")
    te.add_argument("--json", action="store_true", help=AYUDA_JSON)
    te.set_defaults(func=cmd_telemetry)

    en = sub.add_parser("engine", help="qué copia del juez gobierna los espacios")
    en.add_argument("action", nargs="?", default="show", choices=["show", "publish", "use", "list"])
    en.add_argument("--commit", default="HEAD",
                    help="qué commit publicar, o cuál usar (los 12 primeros caracteres)")
    en.add_argument("--sin-probar", action="store_true", dest="sin_probar",
                    help="publica sin ejecutar la suite en la copia; queda `verified: false`")
    en.add_argument("--sin-activar", action="store_true", dest="sin_activar",
                    help="publica sin apuntar `current` a él")
    en.add_argument("--json", action="store_true", help=AYUDA_JSON)
    en.set_defaults(func=cmd_engine)

    lo = sub.add_parser("lock", help="ancla el origen por commit inmutable")
    lo.add_argument("action", choices=["show", "verify", "plan", "update", "init"])
    lo.add_argument("--source", action="append", default=[])
    lo.add_argument("--offline", action="store_true")
    lo.set_defaults(func=cmd_lock)

    m = sub.add_parser("mcp", help="integridad referencial de la cadena MCP")
    m.add_argument("--offline", action="store_true")
    m.add_argument("--json", action="store_true", help=AYUDA_JSON)
    m.set_defaults(func=cmd_mcp)

    ms = sub.add_parser("mcp-serve", help="sirve refuto por MCP stdio (sólo lectura)")
    ms.set_defaults(func=cmd_mcp_serve)

    prot = sub.add_parser("protocol", help="servidor Refuto Wire Protocol v1 (JSON-RPC 2.0 sobre stdio)")
    prot.set_defaults(func=cmd_protocol)

    inv = sub.add_parser("inventory", help="inventario mecánico del conjunto de repositorios")
    inv.add_argument("--depth", type=int, default=3)
    inv.add_argument("--json", action="store_true")
    inv.add_argument("--save", action="store_true")
    inv.set_defaults(func=cmd_inventory)

    e = sub.add_parser("evidence", help="lee el diario estructurado; --anchor lo ancla en concordia")
    e.add_argument("--last", type=int, default=20)
    e.add_argument("--kind", action="append", default=[])
    e.add_argument("--anchor", action="store_true",
                   help="ancla la cabeza actual del diario como checkpoint certificado (ADR-0017)")
    e.add_argument("--anchor-check", action="store_true",
                   help="vuelve a verificar OFFLINE la última ancla contra el pin y el diario")
    e.add_argument("--membership-digest", default="",
                   help="pin de membresía aportado por el invocador; si discrepa del manifiesto → FAIL")
    e.add_argument("--json", action="store_true")
    e.set_defaults(func=cmd_evidence)

    dc = sub.add_parser("docs", help="genera la matriz de compatibilidad desde la máquina")
    dc.add_argument("--out", default="", help="directorio de salida (por defecto, el del repo)")
    dc.add_argument("--deep", action="store_true")
    dc.set_defaults(func=cmd_docs)

    ch = sub.add_parser("chat", help="abre una sesión interactiva con las protecciones puestas")
    ch.add_argument("--agent", default="claude",
                    choices=["claude", "kiro", "gemini", "opencode"])
    ch.add_argument("--role", default="", help="rol del registro; carga su contrato en la sesión")
    ch.add_argument("--spec", default="", help="especificación activa, si hay varias")
    ch.add_argument("--task", default="", help="número de issue: carga su contexto y su rol")
    ch.add_argument("--repo", default="", help="owner/name de la issue, si no es la de aquí")
    ch.add_argument("--model", default="")
    ch.add_argument("--resume", action="store_true", help="continúa la conversación anterior")
    ch.add_argument("--provider", default="auto", choices=["auto", "clean", "inherit"],
                    help="auto: limpia la redirección si está rota · clean: siempre limpia · "
                         "inherit: respeta el entorno tal cual")
    ch.add_argument("--dry-run", action="store_true",
                    help="enseña el informe y la orden, sin abrir nada")
    ch.add_argument("pass_through", nargs="*", default=[],
                    help="argumentos que se pasan tal cual al agente")
    ch.set_defaults(func=cmd_chat)

    wk = sub.add_parser("work", help="qué tiene pendiente, ya enrutado a su rol y su runtime")
    wk.add_argument("--repo", default="", help="owner/name; por defecto, el de este espacio")
    wk.add_argument("--agent", action="append", default=[],
                    help="runtime a considerar; por defecto, el que declara el manifiesto")
    wk.add_argument("--limit", type=int, default=40)
    wk.add_argument("--json", action="store_true")
    wk.set_defaults(func=cmd_work)

    pl = sub.add_parser("plan", help="qué se ejecutaría, quién y con qué puertas")
    pl.add_argument("--goal", default="")
    pl.add_argument("--phase", action="append", default=[])
    pl.add_argument("--prefer", action="append", default=[])
    pl.add_argument("--save", action="store_true")
    pl.add_argument("--json", action="store_true")
    pl.set_defaults(func=cmd_plan)

    ru = sub.add_parser("run", help="conduce el ciclo; en seco salvo --execute")
    ru.add_argument("--goal", default="")
    ru.add_argument("--phase", action="append", default=[])
    ru.add_argument("--prefer", action="append", default=[])
    ru.add_argument("--execute", action="store_true", help="invoca agentes de verdad")
    ru.add_argument("--budget", type=float, default=0.25, help="tope por paso, en USD")
    ru.set_defaults(func=cmd_run)

    re_ = sub.add_parser("resume", help="continúa una ejecución, si el entorno no cambió")
    re_.add_argument("run_id", nargs="?", default="")
    re_.add_argument("--execute", action="store_true")
    re_.add_argument("--budget", type=float, default=0.25)
    re_.add_argument("--force", action="store_true")
    re_.set_defaults(func=cmd_resume)

    st = sub.add_parser("status", help="dónde está el trabajo y qué espera a una persona")
    st.add_argument("--membership-digest", default="",
                    help="pin de membresía de concordia aportado por el invocador (ADR-0017)")
    st.add_argument("--json", action="store_true", help=AYUDA_JSON)
    st.set_defaults(func=cmd_status)

    s = sub.add_parser("selftest", help="el juez se prueba a sí mismo")
    s.add_argument("--suite", action="append", default=[])
    s.set_defaults(func=cmd_selftest)
    return p


def main(argv: list | None = None) -> int:
    # Antes de imprimir nada: los informes llevan ✓, ✗ y rayas largas. En una consola cp1252
    # eso no era una tabla fea, era un `UnicodeEncodeError` que se llevaba el comando entero
    # —`doctor` incluido— con un Traceback en vez de un veredicto.
    force_utf8_io()

    opts = build_parser().parse_args(argv)
    pidio_json = bool(getattr(opts, "json", False))

    # Con `--json`, stdout lleva SÓLO el sobre. Es la mitad del protocolo que no se ve y sin la
    # cual no sirve: `doctor` imprime veinte líneas de diagnóstico para una persona, y un
    # consumidor que hace `json.load(stdout)` recibe «Expecting value: line 2 column 1».
    #
    # Se captura aquí y no se guarda `if not opts.json:` en cada `print` de las 24 órdenes por
    # dos razones. La primera es que serían cientos de guardas y la que se olvide rompe el
    # protocolo en silencio. La segunda es que así el texto humano NO se pierde: se reencamina a
    # stderr, de modo que una persona que teclea `--json` en su terminal sigue viendo el
    # diagnóstico y la máquina sigue leyendo stdout limpio.
    buffer = io.StringIO()
    try:
        if pidio_json:
            with contextlib.redirect_stdout(buffer):
                codigo = opts.func(opts)
        else:
            codigo = opts.func(opts)
    except KeyboardInterrupt:
        sys.stderr.write(buffer.getvalue())
        print("\n  interrumpido", file=sys.stderr)
        return 130

    # El único sitio que serializa. Si la orden declaró su respuesta con `responder`, el sobre
    # manda: su código lo deriva el estado, no lo elige la orden.
    sobre = getattr(opts, "_sobre", None)
    if pidio_json and sobre is not None:
        sys.stderr.write(buffer.getvalue())
        print(json.dumps(sobre, ensure_ascii=False, indent=2))
        return sobre["exit"]
    # Una orden todavía sin migrar a `responder` se comporta EXACTAMENTE como antes: su salida
    # vuelve a stdout tal cual, incluido el JSON que ya emitía por su cuenta. Esto es lo que
    # hace que la migración pueda ser orden a orden sin romper a nadie por el camino.
    if pidio_json:
        sys.stdout.write(buffer.getvalue())
    return codigo


if __name__ == "__main__":
    raise SystemExit(main())
