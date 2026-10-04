# -*- coding: utf-8 -*-
"""Adapter de integración para AWS AI-DLC (AI Development LifeCycle).

Especificación: docs/21-adapter-model.md
Frontera:
  - AI-DLC: orquestación de ciclo de vida (Plan, Code, Test, Deploy).
  - Refuto: oráculo de verificación, auditoría criptográfica y decisión de compuertas.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, Optional

from adapters.base import AgentSpec
from core.protocol import CAPSULE_SCHEMA, RefutoProtocolServer


class AidlcAdapter(AgentSpec):
    """Adaptador de puente entre AWS AI-DLC y Refuto."""

    def native_handshake(self, path: str, workspace: Path | None) -> dict:
        """Handshake estructurado para AI-DLC Conductor."""
        return {
            "ok": True,
            "family": "aidlc-conductor",
            "detail": "AWS AI-DLC Conductor v1.0 / refuto.protocol/v1",
            "capabilities": {
                "stage_transitions": True,
                "claim_verification": True,
                "decision_capsules": True
            }
        }

    def compile_policy(self, policy) -> Dict[str, Any]:
        """Compila directivas de verificación de compuertas para conductores de AI-DLC."""
        conductor_config = {
            "version": "1.0",
            "verification_engine": "refuto",
            "protocol": "refuto.protocol/v1",
            "stages": {
                "Plan": {"required_gates": ["G-POLICY"], "min_epistemic": "E1"},
                "Code": {"required_gates": ["G-ROLES", "G-SECURITY"], "min_epistemic": "E2"},
                "Test": {"required_gates": ["G-TESTS", "G-CONCURRENCY"], "min_epistemic": "E3"},
                "Deploy": {"required_gates": ["G-ANCHOR", "G-SECURITY"], "min_epistemic": "E4"}
            },
            "enforce_admission": True
        }
        return {
            "supported": True,
            "artifacts": {
                ".aidlc/verification-bridge.json": json.dumps(conductor_config, indent=2) + "\n"
            },
            "unenforceable": [],
            "notes": ["AI-DLC delega el juicio de avance de etapa a las cápsulas de decisión de Refuto."]
        }

    def verify_stage_transition(self, stage: str, workspace: Path,
                                claim_id: Optional[str] = None) -> Dict[str, Any]:
        """Evalúa si una transición de etapa en AI-DLC es admisible formalmente."""
        server = RefutoProtocolServer(workspace)
        req = {
            "jsonrpc": "2.0",
            "method": "refuto.verify_claim",
            "params": {
                "claim": {
                    "schema": "refuto.claim/v1",
                    "claim_id": claim_id or f"clm_aidlc_{stage.lower()}",
                    "property": f"lifecycle.stage_admissibility.{stage.lower()}",
                    "scope_requirement": {"min_examined": 1}
                },
                "stage": stage
            },
            "id": 1
        }
        resp_text = server.handle_request_text(json.dumps(req))
        if not resp_text:
            return {"admitted": False, "reason": "No response from Refuto server"}

        data = json.loads(resp_text)
        if "error" in data:
            return {"admitted": False, "error": data["error"]}

        result = data.get("result", {})
        admissibility = result.get("lifecycle_admissibility", {})
        capsule = result.get("capsule", {})

        return {
            "admitted": bool(admissibility.get("can_advance")),
            "decision_capsule": capsule,
            "remediations": admissibility.get("remediation_actions", [])
        }

    def normalize_event(self, raw: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Normaliza eventos del ciclo de vida de AI-DLC al vocabulario de Refuto."""
        event_type = raw.get("type") or raw.get("event") or ""
        if not event_type:
            return None
        return {
            "source": "aidlc",
            "family": "lifecycle",
            "kind": f"aidlc/{event_type}",
            "payload": raw
        }


SPEC = AidlcAdapter(
    name="aidlc",
    binary="ai-dlc",
    version_args=("--version",),
    start_args=("--help",),
    speaks_acp=False,
    workspace_config=(".aidlc", "lifecycle.json", "conductor.json"),
    home_config=("~/.aidlc",),
    native_extensions={
        "stages": {"values": ["Plan", "Design", "Code", "Test", "Deploy"], "evidence": "D"},
        "conductor_protocol": {"protocol": "refuto.protocol/v1", "evidence": "E"},
        "capsule_admissibility": {"schema": CAPSULE_SCHEMA, "evidence": "E"}
    },
    declared={
        "budget_usd": {"supported": True, "evidence": "D"},
        "structured_output_schema": {"supported": True, "evidence": "D"}
    }
)
