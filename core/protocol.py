# -*- coding: utf-8 -*-
"""Servidor del Protocolo de Verificación e Interoperabilidad (Refuto Wire Protocol v1).

Especificación: docs/11-protocol.md
Esquema: refuto.protocol/v1
Transporte: JSON-RPC 2.0 sobre stdio o sockets IPC

Este módulo permite a orquestadores externos (AWS AI-DLC, Kiro, Claude Code, CI/CD)
interactuar con Refuto de manera desacoplada, enviando Claims formales y recibiendo
Cápsulas de Decisión inmutables y auditables.
"""

from __future__ import annotations

import hashlib
import json
import sys
import uuid
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional

from core.evidence import AUSENTE, latest_verification, read_events, verificar_cadena
from core.guard import ALLOW, evaluate
from core.evidence_graph import (
    EvidenceGraph,
    NODE_CAPSULE,
    NODE_CLAIM,
    NODE_GATE,
    NODE_POLICY,
    NODE_SUBJECT,
    REL_DERIVED_FROM,
    REL_VERIFIED_BY,
)
from core.model import (BLOCKED, FAIL, INCONCLUSIVE, NOT_APPLICABLE, NOT_EXECUTABLE, PASS,
                         VERSION, now)
from core.proc import force_utf8_io

PROTOCOL_VERSION = "1.0"
PROTOCOL_SCHEMA = "refuto.protocol/v1"
CLAIM_SCHEMA = "refuto.claim/v1"
CAPSULE_SCHEMA = "refuto.decision-capsule/v1"

# Códigos de error estándar JSON-RPC 2.0
PARSE_ERROR = -32700
INVALID_REQUEST = -32600
METHOD_NOT_FOUND = -32601
INVALID_PARAMS = -32602
INTERNAL_ERROR = -32603

# Códigos de error de aplicación Refuto
CLAIM_VERIFICATION_FAILED = 1001
EMPTY_SCOPE_REJECTED = 1002
CIRCULAR_WITNESS_REJECTED = 1003
LEDGER_INTEGRITY_COMPROMISED = 1004

#: Campos que pertenecen a `claim` y que en la raíz de `params` NO se leen (`docs/11-protocol.md`
#: §2.1, `adapters/aidlc_bridge.ts::Claim`). `context` NO está aquí: ése sí va arriba.
CAMPOS_DE_CLAIM = ("evidence_requirements", "scope_requirement", "subject", "valid_until")


def _rechazar_campos_mal_puestos(params: Dict[str, Any]) -> None:
    """Rechaza la petición si un campo de `claim` viene en la raíz de `params`.

    Ignorarlos en silencio era un APRUEBA POR AUSENCIA, y medido el 2026-09-30 no era teórico:
    con `evidence_requirements` en la raíz, una firma de testigo forjada daba `PASS` y
    `can_advance=True` — exactamente el mismo resultado que no mandar testigo alguno. El
    requisito desaparecía sin que nadie pudiera notarlo, porque lo único que distinguía los dos
    casos era la ausencia de un campo que nunca se leyó.

    Se rechaza en vez de aceptar las dos formas a propósito: normalizar que un campo con peso de
    seguridad se pueda poner en dos sitios deja la siguiente variante mal escrita volviendo a
    ignorarse en silencio. Ningún llamante legítimo usa la forma de la raíz — ni la
    especificación, ni el adaptador, ni el resto de la suite.
    """
    fuera = [k for k in CAMPOS_DE_CLAIM if k in params]
    if fuera:
        raise ProtocolError(
            INVALID_PARAMS,
            f"{', '.join(fuera)} va dentro de 'claim', no en la raíz de 'params'. En la raíz "
            f"no se lee: la afirmación se resolvería SIN ese requisito y se admitiría por su "
            f"ausencia.")


@dataclass
class DecisionCapsule:
    schema: str
    decision_id: str
    claim_id: str
    status: str
    epistemic_level: str
    scope: Dict[str, Any]
    verdict_rationale: str
    ledger_head: Optional[str]
    subject_digest: str
    timestamp: str
    gates: List[Dict[str, Any]] = field(default_factory=list)
    policy_digest: Optional[str] = None
    witness_signature: Optional[str] = None
    witness_public_key_hex: Optional[str] = None
    env_fingerprint: Optional[str] = None
    tool_digest: Optional[str] = None
    capsule_digest: Optional[str] = None

    def compute_digest(self) -> str:
        d = asdict(self)
        d.pop("capsule_digest", None)
        d.pop("witness_signature", None)
        can = json.dumps(d, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
        return hashlib.sha256(can.encode("utf-8")).hexdigest()

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        if not self.capsule_digest:
            self.capsule_digest = self.compute_digest()
            d["capsule_digest"] = self.capsule_digest
        return d


def verify_capsule_binding(
    capsule: Dict[str, Any] | DecisionCapsule,
    expected_subject_digest: Optional[str] = None,
    expected_policy_digest: Optional[str] = None,
    expected_env_fingerprint: Optional[str] = None,
    expected_tool_digest: Optional[str] = None,
    witness_public_key_hex: Optional[str] = None,
) -> Dict[str, Any]:
    """Verifica la vinculación criptográfica y detecta divergencia (drift) en una Cápsula de Decisión.

    Detecta mutaciones en:
    - claim / capsule integrity (digest manipulado)
    - subject (subject_drift)
    - policy (policy_drift)
    - scope (violación de vacuidad o manipulación de alcance)
    - evidence (manipulación de resultados de compuertas o veredicto)
    - witness (firma Ed25519 forjada o inválida)
    - env (env_drift)
    - tool (tool_drift)
    """
    if isinstance(capsule, DecisionCapsule):
        cap_dict = capsule.to_dict()
    else:
        cap_dict = dict(capsule)

    violations: List[str] = []

    # 1. Integridad de la cápsula (Digest Canónico)
    recorded_digest = cap_dict.get("capsule_digest")
    d_copy = dict(cap_dict)
    d_copy.pop("capsule_digest", None)
    d_copy.pop("witness_signature", None)
    can = json.dumps(d_copy, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    recomputed_digest = hashlib.sha256(can.encode("utf-8")).hexdigest()

    digest_valid = (recorded_digest == recomputed_digest)
    if not digest_valid:
        violations.append(
            f"Cápsula manipulada: digest registrado ({recorded_digest}) difiere del computado ({recomputed_digest})"
        )

    # 2. Divergencia del sujeto (Subject Drift)
    actual_subject = cap_dict.get("subject_digest")
    subject_drift = False
    if expected_subject_digest and actual_subject != expected_subject_digest:
        subject_drift = True
        violations.append(
            f"Divergencia de sujeto (subject drift): esperado {expected_subject_digest}, cápsula tiene {actual_subject}"
        )

    # 3. Divergencia de política (Policy Drift)
    actual_policy = cap_dict.get("policy_digest")
    policy_drift = False
    if expected_policy_digest and actual_policy != expected_policy_digest:
        policy_drift = True
        violations.append(
            f"Divergencia de política (policy drift): esperada {expected_policy_digest}, cápsula tiene {actual_policy}"
        )

    # 4. Divergencia de entorno (Env Drift)
    actual_env = cap_dict.get("env_fingerprint")
    env_drift = False
    if expected_env_fingerprint and actual_env != expected_env_fingerprint:
        env_drift = True
        violations.append(
            f"Divergencia de entorno (env drift): esperado {expected_env_fingerprint}, cápsula tiene {actual_env}"
        )

    # 5. Divergencia de herramienta (Tool Drift)
    actual_tool = cap_dict.get("tool_digest")
    tool_drift = False
    if expected_tool_digest and actual_tool != expected_tool_digest:
        tool_drift = True
        violations.append(
            f"Divergencia de herramienta (tool drift): esperado {expected_tool_digest}, cápsula tiene {actual_tool}"
        )

    # 6. Integridad de Ámbito y No-Vacuidad
    scope = cap_dict.get("scope") or {}
    items_examined = scope.get("items_examined", scope.get("examined", 0))
    status = cap_dict.get("status")
    if status == PASS and items_examined <= 0:
        violations.append(f"Violación de no-vacuidad: veredicto PASS con items_examined={items_examined}")

    # 7. Verificación de Firma de Testigo Ed25519
    witness_sig = cap_dict.get("witness_signature")
    witness_pk = witness_public_key_hex or cap_dict.get("witness_public_key_hex")
    witness_valid = True
    if witness_sig:
        if not witness_pk:
            witness_valid = False
            violations.append("Firma de testigo presente pero no se aportó clave pública para verificar")
        else:
            try:
                from core.ed25519 import verify
                pk_bytes = bytes.fromhex(witness_pk)
                sig_bytes = bytes.fromhex(witness_sig)
                msg_bytes = (recorded_digest or recomputed_digest).encode("utf-8")
                if not verify(pk_bytes, msg_bytes, sig_bytes):
                    witness_valid = False
                    violations.append("Firma de testigo Ed25519 inválida o forjada")
            except Exception as e:
                witness_valid = False
                violations.append(f"Error verificando firma de testigo: {str(e)}")

    is_valid = (
        digest_valid
        and not subject_drift
        and not policy_drift
        and not env_drift
        and not tool_drift
        and witness_valid
        and (len(violations) == 0)
    )

    return {
        "valid": is_valid,
        "digest_verified": digest_valid,
        "subject_drift": subject_drift,
        "policy_drift": policy_drift,
        "env_drift": env_drift,
        "tool_drift": tool_drift,
        "witness_verified": witness_valid,
        "violations": violations,
    }


class RefutoProtocolServer:
    """Implementación del servidor JSON-RPC 2.0 para Refuto Wire Protocol v1."""

    def __init__(self, workspace: Path):
        self.workspace = workspace.resolve()
        self.initialized = False

    def handle_request_text(self, text: str) -> Optional[str]:
        """Procesa una línea o mensaje JSON de entrada y devuelve la respuesta JSON."""
        line = text.strip()
        if not line:
            return None

        try:
            req = json.loads(line)
        except Exception as e:
            return json.dumps({
                "jsonrpc": "2.0",
                "id": None,
                "error": {"code": PARSE_ERROR, "message": f"Parse error: {str(e)}"}
            })

        if not isinstance(req, dict) or req.get("jsonrpc") != "2.0":
            return json.dumps({
                "jsonrpc": "2.0",
                "id": req.get("id") if isinstance(req, dict) else None,
                "error": {"code": INVALID_REQUEST, "message": "Invalid Request: jsonrpc must be '2.0'"}
            })

        req_id = req.get("id")
        method = req.get("method")
        params = req.get("params") or {}

        try:
            result = self.dispatch(method, params)
            return json.dumps({
                "jsonrpc": "2.0",
                "id": req_id,
                "result": result
            })
        except ProtocolError as pe:
            return json.dumps({
                "jsonrpc": "2.0",
                "id": req_id,
                "error": {"code": pe.code, "message": pe.message, "data": pe.data}
            })
        except Exception as ex:
            return json.dumps({
                "jsonrpc": "2.0",
                "id": req_id,
                "error": {"code": INTERNAL_ERROR, "message": f"Internal server error: {str(ex)}"}
            })

    def dispatch(self, method: str, params: Dict[str, Any]) -> Dict[str, Any]:
        if method == "refuto.initialize":
            return self._handle_initialize(params)
        elif method == "refuto.verify_claim":
            return self._handle_verify_claim(params)
        elif method == "refuto.evaluate_action":
            return self._handle_evaluate_action(params)
        elif method == "refuto.query_status":
            return self._handle_query_status(params)
        elif method == "refuto.anchor_checkpoint":
            return self._handle_anchor_checkpoint(params)
        elif method == "refuto.propose_change":
            return self._handle_propose_change(params)
        elif method == "refuto.authorize_change":
            return self._handle_authorize_change(params)
        elif method == "refuto.apply_change":
            return self._handle_apply_change(params)
        elif method == "refuto.verify_change":
            return self._handle_verify_change(params)
        elif method == "refuto.admit_change":
            return self._handle_admit_change(params)
        else:
            raise ProtocolError(METHOD_NOT_FOUND, f"Method '{method}' not found")

    def _handle_initialize(self, params: Dict[str, Any]) -> Dict[str, Any]:
        self.initialized = True
        return {
            "server_info": {
                "name": "refuto",
                "version": VERSION,
            },
            "protocol_version": PROTOCOL_VERSION,
            "capabilities": [
                "refuto.verify_claim",
                "refuto.evaluate_action",
                "refuto.query_status",
                "refuto.anchor_checkpoint",
                "refuto.propose_change",
                "refuto.authorize_change",
                "refuto.apply_change",
                "refuto.verify_change",
                "refuto.admit_change"
            ],
            "workspace": str(self.workspace)
        }

    def _handle_verify_claim(self, params: Dict[str, Any]) -> Dict[str, Any]:
        claim = params.get("claim")
        if not isinstance(claim, dict):
            raise ProtocolError(INVALID_PARAMS, "Missing or invalid 'claim' parameter")

        _rechazar_campos_mal_puestos(params)

        claim_id = claim.get("claim_id") or f"clm_{uuid.uuid4().hex[:12]}"
        scope_req = claim.get("scope_requirement") or {}
        evidence_req = claim.get("evidence_requirements") or {}
        subject = claim.get("subject") or {}

        # 0. Chequeo de atestación autorreferencial (Circular Witness)
        subject_agent = subject.get("agent_id")
        witness_id = evidence_req.get("witness_id")
        is_circular = bool(subject_agent and witness_id and subject_agent == witness_id)

        # 0.1 Chequeo de validez temporal (TTL / Expiración)
        valid_until = claim.get("valid_until")
        is_expired = False
        current_time = now()
        if valid_until and str(valid_until) < current_time:
            is_expired = True

        # 0.2 Chequeo criptográfico de firma de testigo Ed25519
        witness_pk_hex = evidence_req.get("witness_public_key_hex")
        witness_sig_hex = evidence_req.get("witness_signature_hex")
        witness_required = bool(
            evidence_req.get("witness_required") or
            evidence_req.get("require_witness") or
            claim.get("property") == "critical_release"
        )
        witness_sig_invalid = False
        if witness_pk_hex and witness_sig_hex:
            try:
                from core.ed25519 import verify
                pk_bytes = bytes.fromhex(witness_pk_hex)
                sig_bytes = bytes.fromhex(witness_sig_hex)
                msg_bytes = (evidence_req.get("attested_message") or claim_id).encode("utf-8")
                if not verify(pk_bytes, msg_bytes, sig_bytes):
                    witness_sig_invalid = True
            except Exception:
                witness_sig_invalid = True
        has_valid_witness = bool(witness_pk_hex and witness_sig_hex and not witness_sig_invalid)
        witness_missing = bool(witness_required and not has_valid_witness)

        # 0.3 Chequeo de digest del sujeto
        expected_subject_digest = subject.get("expected_digest")
        actual_subject_digest = subject.get("actual_digest")
        subject_mutated = bool(expected_subject_digest and actual_subject_digest and expected_subject_digest != actual_subject_digest)

        # 1. Ejecutar verificación sobre el espacio
        from core.context import Context
        from gates.base import run_all
        from core.evidence import verdict_of, write_run

        ctx = Context(workspace=self.workspace)
        gate_target = params.get("gate")
        only = [gate_target] if gate_target else None

        results = run_all(ctx, only=only)
        verdict = verdict_of(results)

        # 2. Análisis de ámbito (Scope) y Teorema de No-Vacuidad (FORMAL-MODEL §3.3)
        # Una compuerta con scope ausente, examined == 0 o unknown > 0 no puede emitir PASS legítimo.
        sin_prueba = []
        total_items_examined = 0
        for r in results:
            sc = getattr(r, "scope", None)
            examined = getattr(sc, "examined", getattr(sc, "items_examined", 0)) if sc else 0
            unknown = getattr(sc, "unknown", 0) if sc else 0
            total_items_examined += examined
            if r.status == PASS and (sc is None or examined == 0 or unknown > 0):
                sin_prueba.append(r.id)

        min_examined = scope_req.get("min_examined", 0)
        scope_violation = False
        if sin_prueba or (min_examined > 0 and total_items_examined < min_examined):
            scope_violation = True

        # Determinar estado agregado
        statuses = {r.status for r in results}
        if sin_prueba or scope_violation:
            statuses.discard(PASS)
            statuses.add(INCONCLUSIVE)

        if is_circular:
            statuses.discard(PASS)
            statuses.add(INCONCLUSIVE)

        if is_expired:
            statuses.discard(PASS)
            statuses.add(INCONCLUSIVE)

        if witness_missing:
            statuses.discard(PASS)
            statuses.add(INCONCLUSIVE)

        if witness_sig_invalid or subject_mutated:
            statuses.discard(PASS)
            statuses.add(FAIL)

        if statuses & {FAIL, NOT_EXECUTABLE}:
            estado = FAIL
        elif BLOCKED in statuses:
            estado = BLOCKED
        elif INCONCLUSIVE in statuses or scope_violation or witness_missing:
            estado = INCONCLUSIVE
        elif not statuses or PASS not in statuses:
            estado = BLOCKED
        else:
            estado = PASS

        from core.assurance import compute_assurance_level
        evidence_dict = {
            "test_status": estado,
            "suite_passed": (estado == PASS and not witness_missing),
            "tests_run": total_items_examined,
            "scope": {"examined": total_items_examined if not scope_violation else 0},
            "is_circular": is_circular,
            "is_expired": is_expired,
            "witness_missing": witness_missing,
            "integrity_failed": bool(witness_sig_invalid or subject_mutated),
            "document_path": "claim",
        }
        epistemic = compute_assurance_level(evidence_dict)

        # Registrar corrida
        write_run(self.workspace, ctx.run_id, results)

        # Leer cabeza del libro mayor si existe
        ledger_head = None
        ev = read_events(self.workspace)
        if ev:
            ledger_head = ev[-1].get("digest")

        # Calcular digest de política si existe
        pol_file = self.workspace / ".harness" / "policy.json"
        pol_digest = None
        if pol_file.exists():
            try:
                pol_digest = hashlib.sha256(pol_file.read_bytes()).hexdigest()
            except Exception:
                pass

        env_fp = hashlib.sha256(f"{sys.platform}:{sys.version.split()[0]}".encode("utf-8")).hexdigest()
        tool_dig = hashlib.sha256(VERSION.encode("utf-8")).hexdigest()

        capsule = DecisionCapsule(
            schema=CAPSULE_SCHEMA,
            decision_id=f"cap_{uuid.uuid4().hex[:12]}",
            claim_id=claim_id,
            status=estado,
            epistemic_level=epistemic,
            scope={
                "items_examined": total_items_examined,
                "min_required": min_examined,
                "unscoped_gates": sin_prueba,
                "declared": not scope_violation and len(sin_prueba) == 0
            },
            verdict_rationale=verdict,
            ledger_head=ledger_head,
            subject_digest=actual_subject_digest or ctx.run_id,
            timestamp=now(),
            gates=[r.to_dict() for r in results],
            policy_digest=pol_digest,
            witness_signature=witness_sig_hex if (has_valid_witness and not witness_sig_invalid) else None,
            witness_public_key_hex=witness_pk_hex if (has_valid_witness and not witness_sig_invalid) else None,
            env_fingerprint=env_fp,
            tool_digest=tool_dig,
        )
        capsule.capsule_digest = capsule.compute_digest()

        can_advance = (estado == PASS)
        remediations = []
        if is_circular:
            remediations.append("Atestación autorreferencial rechazada: el sujeto no puede ser su propio testigo")
        if is_expired:
            remediations.append("Cápsula de decisión o afirmación expirada por límite de tiempo (TTL)")
        if witness_missing:
            remediations.append("Aportar atestación independiente firmada con Ed25519 para afirmaciones críticas")
        if witness_sig_invalid:
            remediations.append("Firma de testigo Ed25519 no verificable o forjada")
        if subject_mutated:
            remediations.append("Divergencia de digest del sujeto: el contenido fue mutado tras la verificación")
        if sin_prueba:
            remediations.append("Declarar scope estructurado en todas las compuertas aprobadas")
        elif scope_violation:
            remediations.append(f"Ámbito examinado ({total_items_examined}) insuficiente: se exigen al menos {min_examined} elementos")
        elif estado == FAIL and not (witness_sig_invalid or subject_mutated):
            remediations.append("Resolver violaciones y defectos en compuertas en rojo")
        elif estado == BLOCKED:
            remediations.append("Comprobar dependencias requeridas del espacio")

        # Construir Grafo de Evidencia DAG (ADR-0010)
        ev_graph = EvidenceGraph()
        ev_graph.add_node(claim_id, NODE_CLAIM, digest=hashlib.sha256(claim_id.encode("utf-8")).hexdigest())
        subj_id = f"subj_{ctx.run_id[:8]}"
        ev_graph.add_node(subj_id, NODE_SUBJECT, digest=actual_subject_digest or ctx.run_id)
        ev_graph.add_dependency(child_id=subj_id, parent_id=claim_id, relation=REL_DERIVED_FROM)

        if pol_digest:
            pol_id = f"pol_{pol_digest[:8]}"
            ev_graph.add_node(pol_id, NODE_POLICY, digest=pol_digest)
            ev_graph.add_dependency(child_id=pol_id, parent_id=claim_id, relation=REL_DERIVED_FROM)

        for r in results:
            g_node_id = f"gate_{r.id}"
            g_dig = hashlib.sha256(f"{r.id}:{r.status}:{r.measure}".encode("utf-8")).hexdigest()
            ev_graph.add_node(g_node_id, NODE_GATE, digest=g_dig, status=r.status)
            ev_graph.add_dependency(child_id=g_node_id, parent_id=subj_id, relation=REL_VERIFIED_BY)

        cap_node_id = capsule.decision_id
        ev_graph.add_node(cap_node_id, NODE_CAPSULE, digest=capsule.capsule_digest or "", status=capsule.status)
        for r in results:
            ev_graph.add_dependency(child_id=cap_node_id, parent_id=f"gate_{r.id}", relation=REL_DERIVED_FROM)

        return {
            "capsule": capsule.to_dict(),
            "evidence_graph": ev_graph.to_dict(),
            "lifecycle_admissibility": {
                "can_advance": can_advance,
                "gate_passed": can_advance,
                "remediation_actions": remediations
            }
        }

    def _handle_evaluate_action(self, params: Dict[str, Any]) -> Dict[str, Any]:
        from core.policy import Policy
        policy_file = self.workspace / ".harness" / "policy.json"
        try:
            policy = Policy.load(policy_file) if policy_file.is_file() else Policy.default()
        except Exception:
            policy = Policy.default()

        action = params.get("action", "")
        tool = params.get("tool", params.get("tool_name", ""))
        target = params.get("target", params.get("path", ""))
        command = params.get("command", "")
        content = params.get("content", "")

        fact = {
            "tool": tool,
            "path": target if (action in ("write", "edit", "fs_write") or not command) else "",
            "command": command or (target if action in ("exec", "command", "bash") else ""),
            "content": content,
            "role": params.get("role", ""),
            "agent": params.get("agent", "")
        }

        decision, kind = evaluate(policy, self.workspace, fact)

        return {
            "allowed": decision.outcome == ALLOW,
            "outcome": decision.outcome,
            "reason": decision.reason,
            "elevation_required": False
        }

    def _handle_query_status(self, params: Dict[str, Any]) -> Dict[str, Any]:
        ev = read_events(self.workspace)
        chain = verificar_cadena(self.workspace)
        last_run = latest_verification(self.workspace)

        return {
            "ledger": {
                "events_count": len(ev),
                "chain_status": chain.get("estado", AUSENTE),
                "head": chain.get("cabeza")
            },
            "last_verification": last_run
        }

    def _handle_anchor_checkpoint(self, params: Dict[str, Any]) -> Dict[str, Any]:
        from core.concordia import anclar
        from core.context import read_manifest

        manifest = read_manifest(self.workspace)
        anclaje = anclar(self.workspace, manifest=manifest, offline=params.get("offline", True))

        return {
            "anchored": anclaje.get("estado") == PASS,
            "status": anclaje.get("estado", NOT_APPLICABLE),
            "details": anclaje
        }

    def _handle_propose_change(self, params: Dict[str, Any]) -> Dict[str, Any]:
        from core.change import ChangeGovernanceEngine
        engine = ChangeGovernanceEngine(self.workspace)
        prop = engine.propose(
            title=params.get("title", "Cambio propuesto"),
            author=params.get("author", "agent:unspecified"),
            author_type=params.get("author_type", "agent"),
            diff=params.get("diff", ""),
            invariants=params.get("invariants", []),
            target_files=params.get("target_files")
        )
        return {"proposal": prop.to_dict()}

    def _handle_authorize_change(self, params: Dict[str, Any]) -> Dict[str, Any]:
        from core.change import ChangeGovernanceEngine, ChangeProposal
        engine = ChangeGovernanceEngine(self.workspace)
        prop_dict = params.get("proposal")
        if not prop_dict:
            raise ProtocolError(INVALID_PARAMS, "Falta parámetro 'proposal'")
        proposal = ChangeProposal.from_dict(prop_dict)
        secret_hex = params.get("secret_key_hex")
        if not secret_hex:
            raise ProtocolError(INVALID_PARAMS, "Falta 'secret_key_hex' para autorización")
        token = engine.authorize(
            proposal=proposal,
            authorizer_id=params.get("authorizer_id", "human:operator"),
            authorizer_type=params.get("authorizer_type", "human"),
            secret_key_bytes=bytes.fromhex(secret_hex),
            ttl_seconds=params.get("ttl_seconds", 3600)
        )
        return {"token": token.to_dict()}

    def _handle_apply_change(self, params: Dict[str, Any]) -> Dict[str, Any]:
        from core.change import ChangeGovernanceEngine, ChangeProposal, AuthorizationToken
        engine = ChangeGovernanceEngine(self.workspace)
        prop_dict = params.get("proposal")
        if not prop_dict:
            raise ProtocolError(INVALID_PARAMS, "Falta parámetro 'proposal'")
        proposal = ChangeProposal.from_dict(prop_dict)
        tok_dict = params.get("token")
        token = AuthorizationToken.from_dict(tok_dict) if tok_dict else None
        res = engine.apply(proposal, token)
        return {"result": res}

    def _handle_verify_change(self, params: Dict[str, Any]) -> Dict[str, Any]:
        from core.change import ChangeGovernanceEngine, ChangeProposal
        engine = ChangeGovernanceEngine(self.workspace)
        prop_dict = params.get("proposal")
        if not prop_dict:
            raise ProtocolError(INVALID_PARAMS, "Falta parámetro 'proposal'")
        proposal = ChangeProposal.from_dict(prop_dict)
        ver = engine.verify(proposal, witness_id=params.get("witness_id"))
        return {"verification": ver.to_dict()}

    def _handle_admit_change(self, params: Dict[str, Any]) -> Dict[str, Any]:
        from core.change import ChangeGovernanceEngine, ChangeProposal, VerificationResult
        engine = ChangeGovernanceEngine(self.workspace)
        prop_dict = params.get("proposal")
        ver_dict = params.get("verification")
        if not prop_dict or not ver_dict:
            raise ProtocolError(INVALID_PARAMS, "Faltan parámetros 'proposal' o 'verification'")
        proposal = ChangeProposal.from_dict(prop_dict)
        verification = VerificationResult(**ver_dict)
        adm = engine.admit(proposal, verification)
        return {"admission": adm}


class ProtocolError(Exception):
    def __init__(self, code: int, message: str, data: Any = None):
        super().__init__(message)
        self.code = code
        self.message = message
        self.data = data


def serve_stdio(workspace: Path) -> int:
    """Bucle principal de escucha JSON-RPC 2.0 sobre stdio."""
    force_utf8_io()
    server = RefutoProtocolServer(workspace)

    for line in sys.stdin:
        resp = server.handle_request_text(line)
        if resp:
            sys.stdout.write(resp + "\n")
            sys.stdout.flush()

    return 0
