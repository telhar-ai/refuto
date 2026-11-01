# -*- coding: utf-8 -*-
"""Motor de ejecución. Conduce el ciclo, produce evidencia y sabe reanudar.

Qué hace y qué NO hace
----------------------
Conduce: decide qué fase toca, qué rol la ejecuta, qué runtime lo hace, qué puertas corren
después y qué revisión humana hace falta. **No decide qué escribir**: eso es del agente.

La regla que gobierna la reanudación
------------------------------------
Antes de continuar una ejecución se comprueba que **el entorno sigue siendo el mismo**: el
vínculo, el lock, el commit y las capacidades. Continuar sobre un entorno cambiado es
reanudar en un sitio distinto del que se dejó, y produce evidencia que dice una cosa sobre un
árbol que ya es otra.
"""

from __future__ import annotations

import json
import math
import subprocess
import uuid
from dataclasses import asdict, dataclass, field
from pathlib import Path

from core.digest import excerpt, sha256_text
from core.evidence import append_event
from core.model import (
    BLOCKED, FAIL, KIND_ORCHESTRATION, NOT_EXECUTABLE, new_id, now, provenance,
    write_json,
)
from core.proc import TEXT_IO, spawn_kwargs

STATE_DIR = ".harness/state"

PENDING, RUNNING, DONE, SKIPPED, FAILED, BLOCKED_ = "PENDING", "RUNNING", "DONE", "SKIPPED", "FAILED", "BLOCKED"


@dataclass
class StepResult:
    phase: str
    role: str = ""
    runtime: str = ""
    status: str = PENDING
    reason: str = ""
    started_at: str = ""
    ended_at: str = ""
    duration_ms: int = 0
    cost_usd: float | None = None
    artifacts: list = field(default_factory=list)
    gates: dict = field(default_factory=dict)
    human_review: str = ""
    routing: dict = field(default_factory=dict)
    evidence: list = field(default_factory=list)

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class Run:
    run_id: str
    workspace: str
    goal: str = ""
    phases: list = field(default_factory=list)
    steps: list = field(default_factory=list)
    produced: list = field(default_factory=list)
    status: str = RUNNING
    started_at: str = ""
    ended_at: str = ""
    fingerprint: dict = field(default_factory=dict)
    context_run_id: str = ""

    def to_dict(self) -> dict:
        d = asdict(self)
        d["schema"] = "harness.run-state/v1"
        return d

    @classmethod
    def from_dict(cls, d: dict) -> "Run":
        known = {f for f in cls.__dataclass_fields__}          # noqa: SLF001
        run = cls(**{k: v for k, v in d.items() if k in known})
        run.steps = [StepResult(**s) for s in d.get("steps", [])]
        return run

    def path(self) -> Path:
        return Path(self.workspace) / STATE_DIR / f"{self.run_id}.json"

    def save(self) -> Path:
        p = self.path()
        write_json(p, self.to_dict())
        return p


def _digest_politica(ruta: Path) -> str:
    """El digest de la política EFECTIVA de `ruta`, con `extends` resuelto.

    Si la cadena no resuelve devuelve `"irresoluble"` en vez de levantar: una huella no puede
    tumbar una ejecución. Dos estados irresolubles comparan iguales, y eso no abre nada — con
    la política sin resolver el guardián deniega todo, así que no hay ejecución que reanudar.
    """
    if not ruta.is_file():
        return ""
    try:
        from core.policy import Policy
        pol = Policy.load(ruta)
    except Exception:                                           # noqa: BLE001
        return "irresoluble"
    ident = getattr(pol, "identidad_efectiva", None)
    return ident.efectivo[:16] if ident else "irresoluble"


# ── huella del entorno ───────────────────────────────────────────────────────────────
def fingerprint(workspace: Path) -> dict:
    """Lo que tiene que seguir igual para poder reanudar sin mentir."""
    from core.binding import read as read_binding
    prov = provenance(workspace)
    bound = read_binding(workspace)
    lock = workspace / ".harness" / "harness.lock.json"
    manifest = workspace / ".harness" / "harness.manifest.json"
    policy = workspace / ".harness" / "policy.json"

    def digest(p: Path) -> str:
        return sha256_text(p.read_text(encoding="utf-8"))[:16] if p.is_file() else ""

    return {
        "git_commit": prov["git_commit"],
        "git_branch": prov["git_branch"],
        "git_dirty": prov["git_dirty"],
        "binding": {k: v.get("commit", "") for k, v in bound.items()},
        "lock_digest": digest(lock),
        "manifest_digest": digest(manifest),
        # El digest de la política EFECTIVA, no el del fichero del proyecto.
        #
        # Esto digería `policy.json` a secas. Con herencia, el cliente podía cambiar entero
        # —retirar una ruta protegida, abrir una orden— sin que el fichero del proyecto se
        # tocara, y `compare_fingerprint` decía que el entorno seguía igual. La reanudación
        # afirmaba reproducibilidad sobre una política distinta, que es la clase de mentira
        # que esta huella existe para impedir.
        "policy_digest": _digest_politica(policy),
        "python": prov["python"],
        "harness_version": prov["harness_version"],
    }


def compare_fingerprint(before: dict, after: dict) -> list:
    """Qué cambió. Vacío significa que se puede reanudar sin más."""
    problems = []
    labels = {
        "git_commit": "el commit del repositorio",
        "git_branch": "la rama",
        "lock_digest": "el lock",
        "manifest_digest": "el manifiesto",
        "policy_digest": "la política",
        "harness_version": "la versión de refuto",
    }
    for key, label in labels.items():
        old, new = before.get(key), after.get(key)
        if old and new and old != new:
            problems.append(f"{label} cambió: {str(old)[:16]} → {str(new)[:16]}")
    for kind, old in (before.get("binding") or {}).items():
        new = (after.get("binding") or {}).get(kind)
        if old and new and old != new:
            problems.append(f"el vínculo de {kind} cambió: {old[:12]} → {new[:12]}")
    if after.get("git_dirty") and not before.get("git_dirty"):
        problems.append("el árbol tiene cambios sin confirmar que no había al empezar")
    return problems


# ── planificación ────────────────────────────────────────────────────────────────────
def plan(workspace: Path, *, goal: str = "", phases: list | None = None,
         prefer: list | None = None) -> tuple[Run, dict]:
    """Construye el plan sin ejecutar nada. Es lo que se enseña antes de gastar un crédito."""
    from adapters.registry import ADAPTERS, all_specs
    from core.capability import build as build_caps
    from core.discovery import ToolFact, scan_environment
    from core.lifecycle import plan_for
    from core.policy import Policy
    from core.probe import probe_all
    from core.roles import by_phase
    from core.routing import route

    env = scan_environment()
    known = set(ToolFact.__dataclass_fields__)                  # noqa: SLF001
    tool_facts = [ToolFact(**{k: v for k, v in t.items() if k in known}) for t in env["tools"]]
    # Sólo los runtimes que este espacio declara. Sondear los cinco para usar uno es tiempo
    # que se paga en cada plan y en cada corrida.
    from core.context import Context
    declarados = list((Context(workspace=workspace).manifest or {}).get("agents") or {})
    elegidos = [ADAPTERS[a] for a in (prefer or []) + declarados if a in ADAPTERS]
    probes = probe_all(list(dict.fromkeys(elegidos)) or all_specs(), workspace=workspace)
    graph = build_caps(probes, ADAPTERS, tool_facts)
    policy_file = workspace / ".harness" / "policy.json"
    policy = Policy.load(policy_file) if policy_file.is_file() else Policy.default()

    run = Run(run_id=new_id(KIND_ORCHESTRATION), workspace=str(workspace), goal=goal,
              started_at=now(), fingerprint=fingerprint(workspace))
    steps = []
    for phase in plan_for(phases):
        run.phases.append(phase.name)
        roles = by_phase(phase.name)
        if not roles:
            steps.append(StepResult(phase=phase.name, status=SKIPPED,
                                    reason="ningún rol declara esta fase"))
            continue
        for role in roles:
            d = route(role, graph, ADAPTERS, prefer=prefer, policy=policy)
            steps.append(StepResult(
                phase=phase.name, role=role.id, runtime=d.chosen,
                status=BLOCKED_ if d.status == "BLOCKED" else PENDING,
                reason="; ".join(d.rationale[-1:]) if d.status != "BLOCKED" else
                       "; ".join(d.rationale),
                human_review=role.human_review, routing=d.to_dict(),
                gates={g: "PENDING" for g in role.quality_gates}))
    run.steps = steps
    return run, {"graph": graph, "policy": policy, "specs": ADAPTERS, "probes": probes}


# ── ejecución ────────────────────────────────────────────────────────────────────────
def execute_step(run: Run, step: StepResult, ctxobj: dict, *, dry_run: bool = True,
                 budget_usd: float = 0.25, prompt_of=None) -> StepResult:
    """Ejecuta un paso. En `dry_run` no llama a ningún agente: sólo corre puertas y contratos.

    `prompt_of(role, workspace)` devuelve el texto de la tarea. Se inyecta para que el motor no
    tenga que saber nada del método concreto: refuto gobierna el proceso, no lo escribe.
    """
    import time
    from core.roles import load as load_roles

    workspace = Path(run.workspace)
    step.started_at = now()
    t0 = time.monotonic()

    if step.status == BLOCKED_:
        step.ended_at = now()
        return step

    role = load_roles().get(step.role)
    if role is None:
        step.status = FAILED
        step.reason = f"el rol «{step.role}» no existe"
        step.ended_at = now()
        return step

    # 1 · Ejecución del agente. En seco no se llama a nadie.
    if dry_run or prompt_of is None:
        step.status = SKIPPED if dry_run else FAILED
        step.reason = ("simulación: no se invocó a ningún agente"
                       if dry_run else "no se proporcionó el texto de la tarea")
    else:
        out = _invoke(role, step, workspace, budget_usd=budget_usd, prompt_of=prompt_of,
                      harness_run_id=run.run_id)
        step.status = DONE if out["ok"] else (BLOCKED_ if out.get("blocked") else FAILED)
        step.reason = out["detail"]
        step.cost_usd = out.get("cost_usd")
        step.evidence.append({"kind": "command", "command": out["command"],
                              "exit_code": out.get("exit_code"),
                              "excerpt": excerpt(out.get("output", ""), 400)})
        if out.get("prompt_reference"):
            step.evidence.append({"kind": "prompt", **out["prompt_reference"]})
        try:
            for observation in out.get("observations", []):
                append_event(workspace, {"kind": "runtime/report", "run_id": run.run_id,
                                         "phase": step.phase, "role": step.role,
                                         "runtime": step.runtime, **observation})
            append_event(workspace, {"kind": "agent/run", "run_id": run.run_id,
                                     "phase": step.phase, "role": step.role,
                                     "runtime": step.runtime, "ok": out["ok"],
                                     "cost_usd": out.get("cost_usd"),
                                     "completion_scope": "runtime_exit_only", "acceptance": None,
                                     "stream_coverage": out.get("stream_coverage")})
        except (OSError, ValueError) as exc:
            step.status = BLOCKED_
            step.reason = f"execution evidence unavailable; effects IN_DOUBT: {exc}"

    # 2 · Puertas del rol. Corren aunque la ejecución haya fallado: qué rompió es información.
    if step.gates:
        from core.context import Context
        from gates.base import GATES, run_gate
        gctx = Context(workspace=workspace, run_id=run.run_id)
        for gate_id in list(step.gates):
            if gate_id not in GATES:
                step.gates[gate_id] = NOT_EXECUTABLE
                continue
            r = run_gate(gate_id, gctx)
            step.gates[gate_id] = r.status
            if r.status in (FAIL, NOT_EXECUTABLE) and step.status == DONE:
                step.status = FAILED
                step.reason = f"la puerta {gate_id} no pasó: {r.measure}"
            elif r.status == BLOCKED and step.status == DONE:
                step.status = BLOCKED_
                step.reason = f"la puerta {gate_id} no se pudo comprobar: {r.measure}"

    # 3 · Revisión humana: se PIDE, no se da por hecha.
    if role.human_review and step.status in (DONE, BLOCKED_):
        from core import humanreview as HR
        p = HR.request(workspace, role.human_review, f"{step.phase}-{step.role}",
                       generated_by=step.runtime or "harness")
        step.evidence.append({"kind": "file", "summary": "revisión humana solicitada",
                              "source": str(p.relative_to(workspace))})
        if step.status == DONE:
            step.status = BLOCKED_
            step.reason = (f"hecho, y pendiente de {role.human_review}. Una fase con revisión "
                           f"obligatoria no termina sin ella.")

    step.duration_ms = int((time.monotonic() - t0) * 1000)
    step.ended_at = now()
    return step


def _invoke(role, step: StepResult, workspace: Path, *, budget_usd: float | None, prompt_of,
            harness_run_id: str | None = None) -> dict:
    """Llama al runtime elegido con el privilegio mínimo del rol."""
    import os
    from adapters.registry import ADAPTERS

    spec = ADAPTERS.get(step.runtime)
    if spec is None:
        return {"ok": False, "detail": f"no hay adapter para «{step.runtime}»", "command": ""}

    if budget_usd is not None:
        try:
            valid_budget = (not isinstance(budget_usd, bool) and isinstance(budget_usd, (int, float))
                            and math.isfinite(budget_usd) and budget_usd > 0)
        except OverflowError:
            valid_budget = False
        if not valid_budget:
            return {"ok": False, "blocked": True, "detail": "invalid execution budget", "command": ""}
        if ("budget_usd" not in spec.native_extensions or
                spec.declared.get("budget_usd", {}).get("supported") is False):
            return {"ok": False, "blocked": True,
                    "detail": f"{step.runtime} cannot enforce the requested native USD budget",
                    "command": ""}
    # This suffix identifies a capture file, never a logical invocation or retry.
    tmp = workspace / ".harness" / "state" / f"prompt-{uuid.uuid4().hex}.md"
    try:
        argv = spec.run_argv(prompt_file=tmp, allow_tools=_tools_for(spec, role),
                             effort="medium", headless=True, budget_usd=budget_usd)
    except ValueError as exc:
        return {"ok": False, "blocked": True,
                "detail": f"adapter cannot satisfy the requested execution contract: {exc}", "command": ""}
    except TypeError as exc:
        return {"ok": False, "detail": f"adapter execution contract rejected: {exc}", "command": ""}
    if not argv:
        return {"ok": False, "detail": f"el adapter de «{step.runtime}» no sabe ejecutar",
                "command": ""}
    prompt = prompt_of(role, workspace)
    tmp.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as capture:
        capture.write(prompt)
    prompt_reference = {"source": tmp.relative_to(workspace).as_posix(),
                        "sha256": sha256_text(prompt)}

    argv = argv + ([] if spec.prompt_from_stdin else ["--", prompt])
    env = dict(os.environ)
    # The parent agent's role/session is not the child operation's identity.
    env["HARNESS_ROLE"] = role.id
    if harness_run_id:
        env["HARNESS_RUN_ID"] = harness_run_id
    else:
        env.pop("HARNESS_RUN_ID", None)
    env.setdefault("CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC", "1")
    env.setdefault("KIRO_TELEMETRY_OPT_OUT", "1")
    try:
        p = subprocess.run(argv, cwd=str(workspace), env=env, capture_output=True,
                           input=prompt if spec.prompt_from_stdin else None, **TEXT_IO,
                           timeout=900, **spawn_kwargs())
    except (OSError, subprocess.SubprocessError) as exc:
        return {"ok": False, "detail": f"no se pudo ejecutar: {exc}",
                "command": " ".join(argv[:6]), "prompt_reference": prompt_reference}

    cost = None
    observations = []
    records = invalid = unmapped = mapping_errors = 0
    ok = p.returncode == 0
    detail = f"salida {p.returncode}"
    for index, line in enumerate((p.stdout or "").splitlines(), 1):
        if not line.strip():
            continue
        records += 1
        try:
            ev = json.loads(line)
        except json.JSONDecodeError:
            invalid += 1
            continue
        if not isinstance(ev, dict):
            invalid += 1
            continue
        try:
            mapped = spec.normalize_events(ev)
            if not isinstance(mapped, list) or not all(isinstance(x, dict) for x in mapped):
                raise ValueError("adapter returned an invalid event sequence")
        except (TypeError, ValueError, AttributeError):
            mapping_errors += 1
            mapped = []
        unmapped += not mapped
        for event in mapped:
            def identifier(value):
                return value if isinstance(value, str) and 0 < len(value) <= 512 else None
            observations.append({"reported_kind": identifier(event.get("kind")),
                                 "source_family": identifier(event.get("family")),
                                 "source_line": index, "source_block": event.get("source_block"),
                                 "source_digest": sha256_text(line), "source_preserved": False,
                                 "session_id": identifier(event.get("session_id")),
                                 "tool_call_id": identifier(event.get("tool_call_id")),
                                 "tool": identifier(event.get("tool_name"))})
        if ev.get("type") == "result":
            value = ev.get("total_cost_usd")
            try:
                cost = (float(value) if isinstance(value, (int, float)) and
                        not isinstance(value, bool) and value >= 0 and math.isfinite(value) else None)
            except OverflowError:
                cost = None
            ok = ok and not ev.get("is_error")
            detail = f"{ev.get('subtype', '')} · {ev.get('num_turns')} turnos"
    if mapping_errors:
        ok = False
        detail += f"; {mapping_errors} normalization errors; effects unverified"
    return {"ok": ok, "blocked": bool(mapping_errors), "detail": detail,
            "cost_usd": cost, "exit_code": p.returncode,
            "prompt_reference": prompt_reference,
            "command": " ".join(argv[:8]), "output": (p.stdout or "") + (p.stderr or ""),
            "observations": observations,
            "stream_coverage": {"status": "NOT_APPLICABLE" if not records else
                                          "FAIL" if mapping_errors else
                                          "INCONCLUSIVE" if invalid or unmapped else "PASS",
                                "scope": "declared_metadata_projection",
                                "records": records, "invalid_records": invalid,
                                "unmapped_records": unmapped, "mapping_errors": mapping_errors,
                                "observations": len(observations),
                                "projection": "metadata_only", "preserves_original": False}}


def _tools_for(spec, role) -> list:
    """Traduce las herramientas canónicas del rol al vocabulario del runtime."""
    mapping = {
        "claude": {"read": "Read", "write": "Write", "grep": "Grep", "glob": "Glob",
                   "shell": "Bash", "thinking": "", "browser": "", "todo": "TodoWrite"},
    }
    table = mapping.get(spec.name)
    if table is None:
        return list(role.allowed_tools)
    out = [table.get(t, "") for t in role.allowed_tools]
    return sorted({t for t in out if t})


def finish(run: Run) -> Run:
    statuses = {s.status for s in run.steps}
    run.status = (FAILED if FAILED in statuses else
                  BLOCKED_ if BLOCKED_ in statuses else
                  DONE if statuses <= {DONE, SKIPPED} else RUNNING)
    run.ended_at = now()
    run.save()
    append_event(Path(run.workspace), {"kind": "run/finish", "run_id": run.run_id,
                                       "status": run.status,
                                       "steps": {s.role or s.phase: s.status for s in run.steps}})
    return run


def load(workspace: Path, run_id: str) -> Run | None:
    p = workspace / STATE_DIR / f"{run_id}.json"
    if not p.is_file():
        return None
    try:
        return Run.from_dict(json.loads(p.read_text(encoding="utf-8")))
    except (OSError, ValueError):
        return None


#: Se leen los DOS prefijos, y así queda indefinidamente. `orq_` es lo que se emite desde el
#: 2026-09-22; `run_` es lo que hay escrito en los espacios instalados antes. Retirar el legado
#: dejaría de encontrar ejecuciones que existen, y «no hay ninguna» es exactamente la respuesta
#: falsa que la identidad tipada vino a corregir. Ver ADR-0012.
_PATRONES_ORQUESTACION = ("orq_*.json", "run_*.json")


def latest(workspace: Path) -> Run | None:
    d = workspace / STATE_DIR
    if not d.is_dir():
        return None
    runs = [p for patron in _PATRONES_ORQUESTACION for p in d.glob(patron)]
    runs.sort(key=lambda p: p.stat().st_mtime, reverse=True)
    return load(workspace, runs[0].stem) if runs else None


def resumable(run: Run) -> dict:
    """¿Se puede continuar? Comprueba el entorno ANTES de dejar seguir."""
    now_fp = fingerprint(Path(run.workspace))
    drift = compare_fingerprint(run.fingerprint, now_fp)
    pending = [s for s in run.steps if s.status in (PENDING, BLOCKED_, FAILED)]
    return {
        "can_resume": not drift and bool(pending),
        "drift": drift,
        "pending": [f"{s.phase}/{s.role}" for s in pending],
        "fingerprint_then": run.fingerprint,
        "fingerprint_now": now_fp,
    }
