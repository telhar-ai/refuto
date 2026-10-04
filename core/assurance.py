# -*- coding: utf-8 -*-
"""Modelo normativo de niveles epistémicos (E0–E4) y agregador de estado del sistema.

Especificación: Principia Veritas / Formal Assurance Model
Regla rectora: «Ningún reporte puede elevar el aseguramiento del sistema por encima
de la evidencia ejecutada».

Niveles Epistémicos Normativos:
- E0 (Unsubstantiated): Afirmación dicha o supuesta, sin evidencia ejecutable.
- E1 (Documented): Especificación estática, documento o esquema sin verificación dinámica.
- E2 (Reproducible): Comando o guion determinista reproducible con salida observada.
- E3 (Automated Test): Prueba automatizada, regresión o suite en ejecución continua.
- E4 (Execution Witnessed): Observación de ejecución atestiguada criptográficamente
     (ledger append-only inmutable, quórum de firmas Ed25519 o checkpoint anclado).
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Any, Dict, List

from core.model import (
    BLOCKED,
    FAIL,
    INCONCLUSIVE,
    NOT_APPLICABLE,
    NOT_EXECUTABLE,
    PASS,
)

E0 = "E0"
E1 = "E1"
E2 = "E2"
E3 = "E3"
E4 = "E4"

EPISTEMIC_LEVELS = (E0, E1, E2, E3, E4)

CRITERIA_E0 = {
    "level": E0,
    "name": "Unsubstantiated",
    "description": "Afirmación puramente textual o no respaldada.",
    "min_evidence": None,
    "witness": "Ninguno",
    "scope_required": False,
    "reproducibility": "Nula",
    "independence": 0,
}

CRITERIA_E1 = {
    "level": E1,
    "name": "Documented",
    "description": "Especificación, esquema o documentación verificable estáticamente.",
    "min_evidence": "documento_o_esquema_existente",
    "witness": "Inspección estática o analizador de esquemas",
    "scope_required": True,
    "reproducibility": "Parseo estático determinista",
    "independence": 1,
}

CRITERIA_E2 = {
    "level": E2,
    "name": "Reproducible",
    "description": "Comando, guion o procedimiento reproducible con salida capturada.",
    "min_evidence": "comando_y_salida_reproducible",
    "witness": "Salida de proceso / CLI con código de retorno",
    "scope_required": True,
    "reproducibility": "Re-ejecutable en entorno documentado",
    "independence": 2,
}

CRITERIA_E3 = {
    "level": E3,
    "name": "Automated Test",
    "description": "Prueba de regresión o suite automatizada ejecutada con veredicto PASS.",
    "min_evidence": "suite_automatizada_pass",
    "witness": "Test runner (unittest / CI runner)",
    "scope_required": True,
    "reproducibility": "Ejecutable bajo demanda en suite",
    "independence": 3,
}

CRITERIA_E4 = {
    "level": E4,
    "name": "Execution Witnessed",
    "description": "Ejecución observada con atestación criptográfica (hash chain, firmas, ancla).",
    "min_evidence": "evento_en_ledger_criptografico",
    "witness": "Testigo criptográfico (Ed25519, Merkle root, Quórum)",
    "scope_required": True,
    "reproducibility": "Verificación matemática independiente de prueba",
    "independence": 4,
}


def compute_assurance_level(evidence: Dict[str, Any]) -> str:
    """Evalúa un conjunto de evidencia estructurada y calcula normativamente su nivel epistémico.

    Reglas de degradación y promoción:
    - Sin evidencia o con contradicción: E0.
    - Documento/esquema estático verificado sin ejecución: E1.
    - Comando CLI con salida y código de retorno verificado: E2.
    - Test automatizado ejecutado con PASS y scope verificado: E3.
    - Testigo criptográfico en ledger inmutable (cadena válida, ancla/firma): E4.
    - Ámbito vacío (examined == 0 o scope is None): DEGRADA a máximo E1.
    - Testigo circular (sujeto == testigo): DEGRADA a máximo E1.
    - Evidencia expirada (TTL vencido): DEGRADA a máximo E1.
    - Fallo o error de integridad: E0.
    """
    if not isinstance(evidence, dict) or not evidence:
        return E0

    # 1. Chequeos de descalificación o degradación inmediata
    if evidence.get("contradiction") or evidence.get("integrity_failed"):
        return E0

    is_expired = evidence.get("is_expired", False)
    is_circular = evidence.get("is_circular", False)
    scope = evidence.get("scope")

    # Scope vacío o ausente descalifica niveles E2, E3, E4
    scope_empty_or_missing = False
    if scope is None:
        scope_empty_or_missing = True
    elif isinstance(scope, dict):
        examined = scope.get("examined", scope.get("items_examined", 0))
        if examined <= 0:
            scope_empty_or_missing = True
    elif hasattr(scope, "examined"):
        if getattr(scope, "examined", 0) <= 0:
            scope_empty_or_missing = True

    witness_missing = bool(evidence.get("witness_missing", False))

    if is_expired or is_circular or scope_empty_or_missing or witness_missing:
        # No puede calificar a E2, E3 ni E4 si carece de alcance, tiene vicios de validez o carece de testigo requerido
        if evidence.get("document_path") or evidence.get("schema_valid"):
            return E1
        return E0

    # 2. Evaluación para E4 (Execution Witnessed)
    has_ledger_event = bool(evidence.get("ledger_event") or evidence.get("ledger_head"))
    has_crypto_witness = bool(
        evidence.get("witness_signature_valid") or
        evidence.get("anchor_verified") or
        (evidence.get("crypto_signatures", 0) >= evidence.get("required_signatures", 1) and evidence.get("crypto_signatures", 0) > 0)
    )
    chain_integrity = evidence.get("chain_integrity", "INTEGRA")
    if has_ledger_event and has_crypto_witness and chain_integrity in ("INTEGRA", True):
        return E4

    # 3. Evaluación para E3 (Automated Test)
    test_passed = evidence.get("test_status") == PASS or evidence.get("suite_passed") is True
    tests_run = evidence.get("tests_run", 0)
    mutation_killed = evidence.get("mutations_killed", True)
    if test_passed and tests_run > 0 and mutation_killed:
        return E3

    # 4. Evaluación para E2 (Reproducible Execution)
    has_command = bool(evidence.get("command"))
    has_observed_output = bool(evidence.get("observed_output") or evidence.get("output_digest"))
    exit_code_zero = evidence.get("exit_code") == 0
    if has_command and has_observed_output and exit_code_zero:
        return E2

    # 5. Evaluación para E1 (Documented)
    if evidence.get("document_path") or evidence.get("schema_valid"):
        return E1

    return E0


@dataclass
class SystemAssuranceReport:
    status: str
    epistemic_level: str
    can_advance: bool
    blocking_reasons: List[str]
    components: Dict[str, Any]
    summary: str

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


def aggregate_system_state(components: Dict[str, Any]) -> SystemAssuranceReport:
    """Calcula el estado global de aseguramiento del sistema a partir de sus componentes.

    Invariantes normativos:
    1. Si CUALQUIER componente crítico tiene FAIL o NOT_EXECUTABLE -> SYSTEM FAIL
    2. Si CUALQUIER componente obligatorio está BLOCKED (p. ej. P0-2 separación de autoridad) -> SYSTEM BLOCKED
    3. Si CUALQUIER componente tiene alcance vacío, evidencia ausente o INCONCLUSIVE -> SYSTEM INCONCLUSIVE
    4. SYSTEM PASS requiere que TODOS los componentes obligatorios estén en PASS y E3 o superior.
    5. can_advance es True SI Y SÓLO SI status == PASS.
    """
    blocking_reasons: List[str] = []
    statuses = set()
    levels = []

    for name, comp in components.items():
        if isinstance(comp, dict):
            c_status = comp.get("status", INCONCLUSIVE)
            c_level = comp.get("epistemic_level", E0)
            c_blocked_msg = comp.get("blocking_reason")
            c_is_critical = comp.get("is_critical", True)
        else:
            c_status = getattr(comp, "status", INCONCLUSIVE)
            c_level = getattr(comp, "epistemic_level", E0)
            c_blocked_msg = getattr(comp, "blocking_reason", None)
            c_is_critical = getattr(comp, "is_critical", True)

        statuses.add(c_status)
        levels.append(c_level)

        if c_status in (FAIL, NOT_EXECUTABLE) and c_is_critical:
            blocking_reasons.append(f"Componente crítico '{name}' en fallo: {c_status}")
        elif c_status == BLOCKED and c_is_critical:
            reason = c_blocked_msg or f"Componente crítico '{name}' bloqueado"
            blocking_reasons.append(reason)
        elif c_status == INCONCLUSIVE and c_is_critical:
            blocking_reasons.append(f"Componente '{name}' con evidencia inconclusa o scope ausente")

    # Derivación jerárquica del estado agregado
    if FAIL in statuses or NOT_EXECUTABLE in statuses:
        system_status = FAIL
        can_advance = False
    elif BLOCKED in statuses:
        system_status = BLOCKED
        can_advance = False
    elif INCONCLUSIVE in statuses:
        system_status = INCONCLUSIVE
        can_advance = False
    elif not statuses or PASS not in statuses:
        system_status = BLOCKED
        can_advance = False
        blocking_reasons.append("Ámbito vacío: ningún componente ejecutado con veredicto positivo")
    elif statuses <= {PASS, NOT_APPLICABLE}:
        system_status = PASS
        can_advance = True
    else:
        system_status = INCONCLUSIVE
        can_advance = False

    # Nivel epistémico global es el mínimo entre los componentes críticos
    if not levels:
        computed_level = E0
    elif any(l == E0 for l in levels) or system_status in (FAIL, BLOCKED):
        computed_level = E1 if system_status == BLOCKED else E0
    elif all(l in (E3, E4) for l in levels) and system_status == PASS:
        computed_level = E4 if all(l == E4 for l in levels) else E3
    elif all(l in (E2, E3, E4) for l in levels):
        computed_level = E2
    else:
        computed_level = E1

    summary = (
        f"Sistema en estado {system_status} (Nivel {computed_level}). "
        f"Avance permitido: {can_advance}. "
        f"Componentes evaluados: {len(components)}. "
        f"Bloqueos activos: {len(blocking_reasons)}."
    )

    return SystemAssuranceReport(
        status=system_status,
        epistemic_level=computed_level,
        can_advance=can_advance,
        blocking_reasons=blocking_reasons,
        components=components,
        summary=summary,
    )
