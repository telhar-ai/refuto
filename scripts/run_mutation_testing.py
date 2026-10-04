# -*- coding: utf-8 -*-
"""Runner de Mutation Testing para Refuto.

Introduce mutaciones sintéticas deliberadas en componentes críticos:
- Decision engine (core/assurance.py)
- Scope invariants (core/model.py)
- Protocol admission & witness checks (core/protocol.py)
- Authority separation & replay checks (core/change.py)
- Gates (gates/g_roles.py, gates/g_security.py)

Ejecuta las suites de prueba contra cada mutante para medir el Mutation Score.
"""

from __future__ import annotations

import subprocess
import sys
import time
from pathlib import Path

RAIZ = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(RAIZ))
from core.proc import TEXT_IO


MUTATIONS = [
    {
        "id": "M01_SCOPE_PERMISSIVE",
        "file": "core/model.py",
        "target": "if self.status == PASS and self.scope is not None:",
        "replacement": "if False and self.scope is not None:",
        "description": "Desactiva la verificación de scope en Result.__post_init__",
        "test_cmd": ["python3", "-m", "unittest", "tests/adversarial/test_system_non_vacuity_invariant.py"]
    },
    {
        "id": "M02_SCOPE_ZERO_ALLOWED",
        "file": "core/model.py",
        "target": "if self.scope.examined <= 0:",
        "replacement": "if self.scope.examined < 0:",
        "description": "Permite que examined == 0 apruebe en Result.__post_init__",
        "test_cmd": ["python3", "-m", "unittest", "tests/adversarial/test_system_non_vacuity_invariant.py"]
    },
    {
        "id": "M03_ASSURANCE_E4_WITHOUT_WITNESS",
        "file": "core/assurance.py",
        "target": "if has_ledger_event and has_crypto_witness and chain_integrity in (\"INTEGRA\", True):",
        "replacement": "if has_ledger_event and chain_integrity in (\"INTEGRA\", True):",
        "description": "Permite alcanzar E4 sin testigo criptográfico",
        "test_cmd": ["python3", "-m", "unittest", "tests/unit/test_assurance.py"]
    },
    {
        "id": "M04_CHANGE_SELF_AUTH_BYPASS",
        "file": "core/change.py",
        "target": "if proposal.author == authorizer_id:",
        "replacement": "if False and proposal.author == authorizer_id:",
        "description": "Permite que el proponente se auto-autorice (A01 bypass)",
        "test_cmd": ["python3", "-m", "unittest", "tests/adversarial/test_change_governance_a01_a15.py"]
    },
    {
        "id": "M05_CHANGE_REPLAY_BYPASS",
        "file": "core/change.py",
        "target": "if authorization.nonce in consumed_nonces:",
        "replacement": "if False and authorization.nonce in consumed_nonces:",
        "description": "Permite la reutilización de tokens consumidos (Replay bypass A06)",
        "test_cmd": ["python3", "-m", "unittest", "tests/adversarial/test_change_governance_a01_a15.py"]
    },
    {
        "id": "M06_PROTOCOL_CIRCULAR_WITNESS_BYPASS",
        "file": "core/protocol.py",
        "target": "is_circular = bool(subject_agent and witness_id and subject_agent == witness_id)",
        "replacement": "is_circular = False",
        "description": "Ignora la atestación autorreferencial (Circular Witness)",
        "test_cmd": ["python3", "-m", "unittest", "tests/adversarial/test_security_conformance_t01_t21.py"]
    },
    {
        "id": "M07_PROTOCOL_SUBJECT_MUTATION_BYPASS",
        "file": "core/protocol.py",
        "target": "subject_mutated = bool(expected_subject_digest and actual_subject_digest and expected_subject_digest != actual_subject_digest)",
        "replacement": "subject_mutated = False",
        "description": "Ignora la mutación de digest del sujeto tras verificación",
        "test_cmd": ["python3", "-m", "unittest", "tests/adversarial/test_security_conformance_t01_t21.py"]
    },
    {
        "id": "M08_G_ROLES_EMPTY_PASS",
        "file": "gates/g_roles.py",
        "target": "if not roles and not findings:\n        status = BLOCKED",
        "replacement": "if not roles and not findings:\n        status = PASS",
        "description": "Permite que G-ROLES apruebe ante un registro vacío",
        "test_cmd": ["python3", "-m", "unittest", "tests/adversarial/test_groles_and_gsecurity_rigorous.py"]
    },
    {
        "id": "M09_G_SECURITY_TOOL_CRASH_PASS",
        "file": "gates/g_security.py",
        "target": "if inejecutables:\n        return Result(GATE_ID, TITLE, NOT_EXECUTABLE",
        "replacement": "if inejecutables:\n        return Result(GATE_ID, TITLE, PASS",
        "description": "Permite que una herramienta caída devuelva PASS",
        "test_cmd": ["python3", "-m", "unittest", "tests/adversarial/test_groles_and_gsecurity_rigorous.py"]
    },
    {
        "id": "M10_G_SECURITY_EMPTY_WORKSPACE_PASS",
        "file": "gates/g_security.py",
        "target": "if scanned == 0:\n        return Result(GATE_ID, TITLE, BLOCKED",
        "replacement": "if scanned == 0:\n        return Result(GATE_ID, TITLE, PASS",
        "description": "Permite que el escaneo de 0 archivos devuelva PASS",
        "test_cmd": ["python3", "-m", "unittest", "tests/adversarial/test_groles_and_gsecurity_rigorous.py"]
    },
    {
        "id": "M11_DIFF_TAMPER_BYPASS",
        "file": "core/change.py",
        "target": "if calculated_hash != authorization.diff_hash or proposal.diff_hash != authorization.diff_hash:",
        "replacement": "if False and (calculated_hash != authorization.diff_hash):",
        "description": "Bypass de detección de alteración del diff (A07)",
        "test_cmd": ["python3", "-m", "unittest", "tests/adversarial/test_change_governance_a01_a15.py"]
    },
    {
        "id": "M12_TARGET_TAMPER_BYPASS",
        "file": "core/change.py",
        "target": "if sorted(proposal.target_files) != sorted(authorization.target_files):",
        "replacement": "if False and sorted(proposal.target_files) != sorted(authorization.target_files):",
        "description": "Bypass de detección de mutación en archivos objetivo (A08)",
        "test_cmd": ["python3", "-m", "unittest", "tests/adversarial/test_change_governance_a01_a15.py"]
    },
    {
        "id": "M13_DAG_CYCLE_BYPASS",
        "file": "core/evidence_graph.py",
        "target": "if not self.is_acyclic():",
        "replacement": "if False and not self.is_acyclic():",
        "description": "Permite ciclos en el grafo de evidencia (violación de invariante DAG)",
        "test_cmd": ["python3", "-m", "unittest", "tests/unit/test_evidence_graph.py"]
    },
    {
        "id": "M14_UNSCOPED_PASS_BYPASS",
        "file": "core/evidence.py",
        "target": "    if sin_prueba:\n        statuses.discard(PASS)\n        statuses.add(INCONCLUSIVE)",
        "replacement": "    if False and sin_prueba:\n        statuses.discard(PASS)\n        statuses.add(INCONCLUSIVE)",
        "description": "Permite que una corrida con compuertas sin scope emita veredicto PASS (BL-01)",
        "test_cmd": ["python3", "-m", "unittest", "tests/adversarial/test_inconclusive_scope.py"]
    },
    {
        "id": "M15_LOCK_CHECKSUM_BYPASS",
        "file": "core/lock.py",
        "target": "if actual != expected:",
        "replacement": "if False and actual != expected:",
        "description": "Permite que discrepancias de checksums en lock aprueben",
        "test_cmd": ["python3", "-m", "unittest", "tests/adversarial/test_attacks.py"]
    },
    {
        "id": "M16_INTERPRETER_DYNAMIC_EVAL_BYPASS",
        "file": "core/policy.py",
        "target": "if ef.resolucion == \"AMBIGUO\" and (\"dinámica\" in ef.motivo_opaco or \"codificación\" in ef.motivo_opaco):",
        "replacement": "if False and ef.resolucion == \"AMBIGUO\":",
        "description": "Bypass de detección de evaluación dinámica y ofuscación en intérpretes (BL-03)",
        "test_cmd": ["python3", "-m", "unittest", "tests/adversarial/test_security_conformance_t01_t21.py"]
    }
]


def run_mutation_tests():
    print("=" * 70)
    print("MUTATION TESTING SUITE — REFUTO ASSURANCE & INTEGRITY")
    print("=" * 70)

    killed = 0
    survived = 0
    results = []

    for mut in MUTATIONS:
        m_id = mut["id"]
        rel_file = mut["file"]
        target = mut["target"]
        replacement = mut["replacement"]
        desc = mut["description"]
        test_cmd = mut["test_cmd"]

        file_path = RAIZ / rel_file
        orig_content = file_path.read_text(encoding="utf-8")

        if target not in orig_content:
            print(f"[{m_id}] ERROR: target chunk not found in {rel_file}")
            survived += 1
            results.append({"id": m_id, "status": "ERROR_NOT_FOUND", "desc": desc})
            continue

        # Inyectar mutación
        mutated_content = orig_content.replace(target, replacement, 1)
        file_path.write_text(mutated_content, encoding="utf-8", newline="\n")

        # Ejecutar suite
        t0 = time.time()
        res = subprocess.run(test_cmd, cwd=str(RAIZ), capture_output=True, **TEXT_IO)
        dt = time.time() - t0

        # Restaurar inmediatamente
        file_path.write_text(orig_content, encoding="utf-8", newline="\n")

        # Si el test falla, el mutante fue asesinado (detectado)
        if res.returncode != 0:
            killed += 1
            print(f"[{m_id}] KILLED in {dt:.2f}s — {desc}")
            results.append({"id": m_id, "status": "KILLED", "time": dt, "desc": desc})
        else:
            survived += 1
            print(f"[{m_id}] SURVIVED (ALERTA: mutación no detectada) — {desc}")
            results.append({"id": m_id, "status": "SURVIVED", "time": dt, "desc": desc})

    total = len(MUTATIONS)
    score = (killed / total) * 100.0 if total > 0 else 0.0

    print("=" * 70)
    print("RESUMEN DE MUTACIÓN:")
    print(f"Total Mutantes:    {total}")
    print(f"Killed (detectados): {killed}")
    print(f"Survived (vivos):    {survived}")
    print(f"Mutation Score:     {score:.1f}%")
    print("=" * 70)

    return 0 if survived == 0 else 1


if __name__ == "__main__":
    sys.exit(run_mutation_tests())
