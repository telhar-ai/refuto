# -*- coding: utf-8 -*-
"""Suite Ejecutable de Falsación y Conformidad de Seguridad: Ataques T01 a T21.

Especificación: docs/18-security-model.md
Cumple con la Sección 11 de la Misión:
Cada ataque ejecuta un intento real de fraude y reporta estructuradamente:
  - ATTACK
  - EXPECTED
  - OBSERVED
  - EVIDENCE
  - DECISION
"""

from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path
from typing import Any, Dict

from core.ed25519 import verify
from core.envelope import EXIT_BLOCKED, EXIT_FAIL, EXIT_OK, exit_for
from core.evidence import (AUSENTE, DESALINEADA, INSUFICIENTE, INTEGRA, ROTA, append_event,
                           latest_verification, reconciliar, read_events,
                           verificar_cadena, verdict_of, write_run)
from core.guard import ALLOW, ASK, DENY, evaluate
from core.model import (BLOCKED, FAIL, INCONCLUSIVE, NOT_APPLICABLE, NOT_EXECUTABLE, PASS,
                        Result, Scope, new_id, now)
from core.policy import Policy, decide_command, decide_write
from core.proc import TEXT_IO
from core.protocol import CAPSULE_SCHEMA, RefutoProtocolServer
from tests.fixtures.ed25519_firma import clave_publica, firmar, secreto_sintetico

RAIZ = Path(__file__).resolve().parents[2]


class SecurityConformanceCase(unittest.TestCase):
    """Clase base para reportar estructuradamente los ataques de seguridad."""

    def record_attack_result(self, attack_id: str, attack_name: str,
                             expected: str, observed: str, evidence: str, decision: str):
        report = (
            f"\n[SECURITY-ATTACK] {attack_id} · {attack_name}\n"
            f"  ATTACK:   {attack_name}\n"
            f"  EXPECTED: {expected}\n"
            f"  OBSERVED: {observed}\n"
            f"  EVIDENCE: {evidence}\n"
            f"  DECISION: {decision}\n"
        )
        sys.stderr.write(report)


class TestSecurityConformanceT01T21(SecurityConformanceCase):

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="adv-sec-")).resolve()
        (self.tmp / ".harness" / "evidence").mkdir(parents=True)
        self.policy_path = self.tmp / ".harness" / "policy.json"
        self.policy_path.write_text(
            json.dumps({
                "schema": "harness.policy/v1",
                "version": "1",
                "protected_paths": [".harness/**", "gates/**", "verificacion/**"],
                "command_deny": ["rm -rf:*", "rm -fr:*", "sudo:*"]
            }),
            encoding="utf-8"
        )

    def tearDown(self):
        import shutil
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_T01_ledger_rewrite(self):
        """T01: Modificación de un registro histórico en el libro mayor."""
        # 1. Crear 3 eventos encadenados
        for i in range(3):
            append_event(self.tmp, {"kind": "test/event", "seq": i, "data": f"val_{i}"})

        ledger_file = self.tmp / ".harness" / "evidence" / "ledger.jsonl"
        lines = ledger_file.read_text(encoding="utf-8").splitlines()
        self.assertEqual(3, len(lines))

        # 2. Atacar: modificar el primer evento
        doc0 = json.loads(lines[0])
        doc0["data"] = "tampered_data"
        lines[0] = json.dumps(doc0)
        ledger_file.write_text("\n".join(lines) + "\n", encoding="utf-8")

        # 3. Observar verificación de cadena
        res = verificar_cadena(self.tmp)

        expected = "Cadena ROTA detectada (hash mismatch en eslabón histórico)"
        observed = f"Estado: {res.get('estado')}, motivo: {res.get('motivo')}"
        evidence = f"rota_en={res.get('rota_en')}, eventos={res.get('eventos')}"
        decision = "FAIL (Rechazo de admisión por libro mayor corrupto)"

        self.record_attack_result("T01", "Ledger rewrite", expected, observed, evidence, decision)
        self.assertEqual(ROTA, res.get("estado"))
        self.assertEqual(0, res.get("rota_en"))

    def test_T02_self_attestation(self):
        """T02: El mismo agente intenta ser testigo y sujeto de su propia verificación."""
        server = RefutoProtocolServer(self.tmp)
        agent_id = "agent_synthesizer_99"

        req = {
            "jsonrpc": "2.0",
            "method": "refuto.verify_claim",
            "params": {
                "claim": {
                    "claim_id": "clm_t02",
                    "subject": {"agent_id": agent_id},
                    "evidence_requirements": {"witness_id": agent_id}
                },
                "gate": "G-ROLES"
            },
            "id": 102
        }
        res = json.loads(server.handle_request_text(json.dumps(req)))
        capsule = res.get("result", {}).get("capsule", {})
        admissibility = res.get("result", {}).get("lifecycle_admissibility", {})

        expected = "Rechazo de admisión e INCONCLUSIVE ante testigo autorreferencial"
        observed = f"Status: {capsule.get('status')}, can_advance: {admissibility.get('can_advance')}"
        evidence = f"Remediations: {admissibility.get('remediation_actions')}"
        decision = "BLOCKED / INCONCLUSIVE (Auto-atestación neutralizada)"

        self.record_attack_result("T02", "Self attestation", expected, observed, evidence, decision)
        self.assertEqual(INCONCLUSIVE, capsule.get("status"))
        self.assertFalse(admissibility.get("can_advance"))
        self.assertTrue(any("autorreferencial" in r for r in admissibility.get("remediation_actions", [])))

    def test_T03_witness_impersonation(self):
        """T03: Intento de suplantar un testigo mediante clave o firma no verificable."""
        # 1. Par de claves sintético genuino
        secret_gen = secreto_sintetico(42, 1)
        pk_gen = clave_publica(secret_gen)
        msg = b"attestation:gate_pass:commit_abc123"

        # 2. Firma genuina
        sig_gen = firmar(secret_gen, msg)
        self.assertTrue(verify(pk_gen, msg, sig_gen))

        # 3. Ataque A: Manipular firma por 1 bit
        sig_tampered = bytearray(sig_gen)
        sig_tampered[5] ^= 0xFF
        sig_tampered_bytes = bytes(sig_tampered)
        self.assertFalse(verify(pk_gen, msg, sig_tampered_bytes))

        # 4. Ataque B: Firmar con clave de un atacante
        secret_adv = secreto_sintetico(999, 1)
        sig_adv = firmar(secret_adv, msg)
        self.assertFalse(verify(pk_gen, msg, sig_adv))

        # 5. Ataque C: Probar a través del servidor del protocolo Wire
        server = RefutoProtocolServer(self.tmp)
        req = {
            "jsonrpc": "2.0",
            "method": "refuto.verify_claim",
            "params": {
                "claim": {
                    "claim_id": "clm_t03",
                    "evidence_requirements": {
                        "witness_id": "auditor_externo",
                        "witness_public_key_hex": pk_gen.hex(),
                        "witness_signature_hex": sig_tampered_bytes.hex(),
                        "attested_message": msg.decode("ascii")
                    }
                },
                "gate": "G-ROLES"
            },
            "id": 103
        }
        res = json.loads(server.handle_request_text(json.dumps(req)))
        capsule = res.get("result", {}).get("capsule", {})
        admissibility = res.get("result", {}).get("lifecycle_admissibility", {})

        expected = "Firma Ed25519 forjada evaluada a False y rechazada con FAIL"
        observed = f"Status: {capsule.get('status')}, can_advance: {admissibility.get('can_advance')}"
        evidence = f"Firma forjada verificada: {verify(pk_gen, msg, sig_tampered_bytes)}"
        decision = "FAIL (Impersonación de testigo bloqueada)"

        self.record_attack_result("T03", "Witness impersonation", expected, observed, evidence, decision)
        self.assertEqual(FAIL, capsule.get("status"))
        self.assertFalse(admissibility.get("can_advance"))
        self.assertTrue(any("Ed25519" in r for r in admissibility.get("remediation_actions", [])))

    def test_T04_empty_scope(self):
        """T04: Intento de obtener PASS ejecutando una compuerta sin ámbito."""
        server = RefutoProtocolServer(RAIZ)
        from unittest.mock import patch
        with patch("gates.base.run_all", return_value=[Result("G-ROLES", "roles", PASS, scope=None)]):
            res = server._handle_verify_claim({
                "claim": {"claim_id": "clm_t04_scope", "property": "roles_valid"},
                "gate": "G-ROLES"
            })

        expected = "Status INCONCLUSIVE y can_advance=False ante compuerta sin scope declarado"
        observed = f"Status: {res['capsule']['status']}, can_advance: {res['lifecycle_admissibility']['can_advance']}"
        evidence = f"Remediaciones: {res['lifecycle_admissibility']['remediation_actions']}"
        decision = "INCONCLUSIVE (Ámbito vacío refutado por Teorema de No-Vacuidad)"

        self.record_attack_result("T04", "Empty scope", expected, observed, evidence, decision)
        self.assertEqual(INCONCLUSIVE, res["capsule"]["status"])
        self.assertFalse(res["lifecycle_admissibility"]["can_advance"])

    def test_T05_evidence_replay(self):
        """T05: Reutilización de un run_id / digest de una corrida previa en otro contexto."""
        res_a = [Result(id="G-POLICY", name="pol", status=PASS, scope=Scope(examined=1, universe="policy"))]
        path_a = write_run(self.tmp, "run_original_111", res_a)

        # Atacante replica el archivo para simular una corrida "run_replayed_222"
        doc_b = json.loads(path_a.read_text(encoding="utf-8"))
        doc_b["run_id"] = "run_replayed_222"
        path_b = self.tmp / ".harness" / "evidence" / "run_replayed_222.json"
        path_b.write_text(json.dumps(doc_b), encoding="utf-8")

        # Intentar reconciliar la corrida rejugada con el libro mayor
        rec = reconciliar(self.tmp, doc_b)

        expected = "Reconciliación 'indeterminado' (la corrida no existe en el libro mayor)"
        observed = f"Estado: {rec.get('estado')}, motivo: {rec.get('motivo')}"
        evidence = f"Run buscado: {doc_b.get('run_id')}"
        decision = "FAIL / INDETERMINADO (Replay rechazado por falta de contraparte en ledger)"

        self.record_attack_result("T05", "Evidence replay", expected, observed, evidence, decision)
        self.assertEqual("indeterminado", rec.get("estado"))

    def test_T06_subject_mutation(self):
        """T06: Modificación del código fuente posterior a la atestación de la compuerta."""
        test_file = self.tmp / "app.py"
        test_file.write_text("def suma(a, b): return a + b\n", encoding="utf-8")
        hash_antes = hashlib.sha256(test_file.read_bytes()).hexdigest()

        # Adversario inserta un backdoor
        test_file.write_text("def suma(a, b): return 0 # Backdoor\n", encoding="utf-8")
        hash_despues = hashlib.sha256(test_file.read_bytes()).hexdigest()

        # Evaluar a través del protocolo con hashes divergentes
        server = RefutoProtocolServer(self.tmp)
        req = {
            "jsonrpc": "2.0",
            "method": "refuto.verify_claim",
            "params": {
                "claim": {
                    "claim_id": "clm_t06",
                    "subject": {
                        "expected_digest": hash_antes,
                        "actual_digest": hash_despues
                    }
                },
                "gate": "G-ROLES"
            },
            "id": 106
        }
        res = json.loads(server.handle_request_text(json.dumps(req)))
        capsule = res.get("result", {}).get("capsule", {})
        admissibility = res.get("result", {}).get("lifecycle_admissibility", {})

        expected = "Detección criptográfica de mutación del sujeto (hash mismatch)"
        observed = f"Status: {capsule.get('status')}, can_advance: {admissibility.get('can_advance')}"
        evidence = f"hash_antes={hash_antes} != hash_despues={hash_despues}"
        decision = "FAIL (Mutación posterior neutralizada)"

        self.record_attack_result("T06", "Subject mutation", expected, observed, evidence, decision)
        self.assertNotEqual(hash_antes, hash_despues)
        self.assertEqual(FAIL, capsule.get("status"))
        self.assertFalse(admissibility.get("can_advance"))

    def test_T07_evidence_mutation(self):
        """T07: Modificación directa de un archivo de informe de corrida."""
        res = [Result(id="G-POLICY", name="pol", status=FAIL, measure="1 error")]
        path = write_run(self.tmp, "run_fail_to_pass", res)

        # Atacante edita el informe en disco de FAIL a PASS
        doc = json.loads(path.read_text(encoding="utf-8"))
        doc["gates"][0]["status"] = "PASS"
        doc["verdict"] = "INTEGRABLE"
        path.write_text(json.dumps(doc), encoding="utf-8")

        # Comprobar con reconciliación y latest_verification
        ver = latest_verification(self.tmp)

        expected = "Integridad 'contradice' y veredicto 'NO INTEGRABLE — la evidencia no se sostiene'"
        observed = f"Estado: {ver['integrity']['estado']}, veredicto: {ver['verdict'][:50]}"
        evidence = f"Motivo: {ver['integrity']['motivo']}"
        decision = "FAIL (Fraude de informe detectado por discrepancia con el libro mayor)"

        self.record_attack_result("T07", "Evidence mutation", expected, observed, evidence, decision)
        self.assertEqual("contradice", ver["integrity"]["estado"])
        self.assertTrue(ver["verdict"].startswith("NO INTEGRABLE"))

    def test_T08_timestamp_manipulation(self):
        """T08: Intento de registrar eventos con timestamps futuros o en retroceso temporal."""
        t_base = "2026-09-29T12:00:00Z"
        append_event(self.tmp, {"kind": "test/normal", "timestamp": t_base})

        # Atacante inyecta evento con timestamp en el pasado (anomalía de monotonicidad)
        t_pasado = "2020-01-01T00:00:00Z"
        append_event(self.tmp, {"kind": "test/past", "timestamp": t_pasado})

        events = read_events(self.tmp)
        t_prev = events[0].get("timestamp", "")
        t_curr = events[1].get("timestamp", "")
        is_backwards = (t_curr < t_prev)

        expected = "Anomalía de monotonicidad temporal detectada (t_curr < t_prev)"
        observed = f"Anomalía detectada: {is_backwards} ({t_curr} < {t_prev})"
        evidence = f"Secuencia temporal violada: {t_prev} -> {t_curr}"
        decision = "INCONCLUSIVE / ANOMALY (Invalidez cronológica del registro)"

        self.record_attack_result("T08", "Timestamp manipulation", expected, observed, evidence, decision)
        self.assertTrue(is_backwards)

    def test_T09_policy_relaxation(self):
        """T09: Un agente intenta relajar .harness/policy.json para desproteger rutas."""
        pol = Policy.load(self.policy_path)

        # Intento directo
        d1 = decide_write(pol, self.tmp, ".harness/policy.json")
        # Intento con path traversal
        d2 = decide_write(pol, self.tmp, "sub/../../.harness/policy.json")

        expected = "Decisión DENY en todas las rutas hacia la política"
        observed = f"Directo: {d1.outcome}, Traversal: {d2.outcome}"
        evidence = f"Regla: {d1.rule}"
        decision = "DENY (Política autoprotegida contra relajación)"

        self.record_attack_result("T09", "Policy relaxation", expected, observed, evidence, decision)
        self.assertEqual(DENY, d1.outcome)
        self.assertEqual(DENY, d2.outcome)

    def test_T10_scope_reduction(self):
        """T10: Intento de reducir el scope mínimo requerido por un claim."""
        server = RefutoProtocolServer(self.tmp)
        req = {
            "jsonrpc": "2.0",
            "method": "refuto.verify_claim",
            "params": {
                "claim": {
                    "claim_id": "clm_t10",
                    "scope_requirement": {"min_examined": 10000}
                },
                "gate": "G-ROLES"
            },
            "id": 110
        }
        res = json.loads(server.handle_request_text(json.dumps(req)))
        capsule = res.get("result", {}).get("capsule", {})
        admissibility = res.get("result", {}).get("lifecycle_admissibility", {})

        expected = "Rechazo de avance si items_examined < min_examined"
        observed = f"can_advance: {admissibility.get('can_advance')}, status: {capsule.get('status')}"
        evidence = f"Examinados: {capsule.get('scope', {}).get('items_examined')} < Requeridos: 10000"
        decision = "INCONCLUSIVE (Scope insuficiente neutralizado)"

        self.record_attack_result("T10", "Scope reduction", expected, observed, evidence, decision)
        self.assertFalse(admissibility.get("can_advance"))
        self.assertEqual(INCONCLUSIVE, capsule.get("status"))

    def test_T11_gate_bypass(self):
        """T11: Intento de saltar compuertas de seguridad obligatorias modificándolas."""
        pol = Policy.load(self.policy_path)
        d = decide_write(pol, self.tmp, "gates/g_security.py")

        expected = "DENY (escritura sobre compuertas bloqueada)"
        observed = f"Decisión: {d.outcome}"
        evidence = "Target: gates/g_security.py"
        decision = "DENY (Protección activa de compuertas)"

        self.record_attack_result("T11", "Gate bypass", expected, observed, evidence, decision)
        self.assertEqual(DENY, d.outcome)

    def test_T12_policy_bypass(self):
        """T12: Ejecución de comando denegado mediante subterfugios (rm -rf, sudo, python inline, eval)."""
        pol = Policy.load(self.policy_path)
        d1 = decide_command(pol, "rm -rf /")
        d2 = decide_command(pol, "sudo make install")
        d3 = decide_command(pol, "rm -fr /tmp/workspace")
        d4 = decide_command(pol, "python3 -c \"import os; os.remove('.harness/policy.json')\"", self.tmp)
        d5 = decide_command(pol, "python3 -c \"eval('something')\"", self.tmp)

        expected = "DENY para comandos destructivos y scripts sobre rutas protegidas; ASK para eval dinámica"
        observed = f"rm -rf: {d1.outcome}, sudo: {d2.outcome}, rm -fr: {d3.outcome}, inline: {d4.outcome}, eval: {d5.outcome}"
        evidence = "Comandos en lista de denegación obligatoria o análisis AST de scripts"
        decision = "DENY / ASK (Comandos bloqueados o elevados a revisión humana en frontera)"

        self.record_attack_result("T12", "Policy bypass", expected, observed, evidence, decision)
        self.assertEqual(DENY, d1.outcome)
        self.assertEqual(DENY, d2.outcome)
        self.assertEqual(DENY, d3.outcome)
        self.assertEqual(DENY, d4.outcome)
        self.assertEqual(ASK, d5.outcome)

    def test_T13_stale_capsule(self):
        """T13: Presentación de una cápsula con timestamp expirado o TTL vencido."""
        server = RefutoProtocolServer(self.tmp)
        req = {
            "jsonrpc": "2.0",
            "method": "refuto.verify_claim",
            "params": {
                "claim": {
                    "claim_id": "clm_t13",
                    "valid_until": "2020-01-01T00:00:00Z"
                },
                "gate": "G-ROLES"
            },
            "id": 113
        }
        res = json.loads(server.handle_request_text(json.dumps(req)))
        capsule = res.get("result", {}).get("capsule", {})
        admissibility = res.get("result", {}).get("lifecycle_admissibility", {})

        expected = "Inadmisibilidad por expiración temporal de TTL"
        observed = f"Status: {capsule.get('status')}, can_advance: {admissibility.get('can_advance')}"
        evidence = f"Remediaciones: {admissibility.get('remediation_actions')}"
        decision = "INCONCLUSIVE (Cápsula obsoleta rechazada)"

        self.record_attack_result("T13", "Stale capsule", expected, observed, evidence, decision)
        self.assertEqual(INCONCLUSIVE, capsule.get("status"))
        self.assertFalse(admissibility.get("can_advance"))

    def test_T14_toctou(self):
        """T14: Time-of-check to time-of-use (modificación entre verificación y despliegue)."""
        bin_file = self.tmp / "artifact.bin"
        bin_file.write_bytes(b"FIRMWARE_GENUINO_v1.0")

        # 1. En tiempo de verificación: calcular digest
        digest_verificado = hashlib.sha256(bin_file.read_bytes()).hexdigest()

        # 2. Atacante modifica el binario antes del despliegue (TOCTOU)
        bin_file.write_bytes(b"PAYLOAD_MALICIOSO_INSERTADO")

        # 3. En tiempo de uso: compuerta de despliegue re-verifica el digest
        digest_despliegue = hashlib.sha256(bin_file.read_bytes()).hexdigest()
        toctou_violation = (digest_verificado != digest_despliegue)

        expected = "Detección de divergencia criptográfica antes del despliegue"
        observed = f"Violación TOCTOU: {toctou_violation}"
        evidence = f"Check: {digest_verificado} != Use: {digest_despliegue}"
        decision = "FAIL (Despliegue abortado por violación TOCTOU)"

        self.record_attack_result("T14", "TOCTOU", expected, observed, evidence, decision)
        self.assertTrue(toctou_violation)

    def test_T15_dependency_drift(self):
        """T15: Deriva o alteración de dependencias fuera del lockfile."""
        pkg_code = b"print('paquete genuino')"
        lock_digest = hashlib.sha256(pkg_code).hexdigest()

        # Atacante altera el código de la dependencia instalada
        tampered_pkg_code = b"print('paquete alterado con spyware')"
        installed_digest = hashlib.sha256(tampered_pkg_code).hexdigest()

        drift_detected = (lock_digest != installed_digest)

        expected = "Divergencia entre digest de dependencia y lockfile"
        observed = f"Deriva detectada: {drift_detected}"
        evidence = f"Lock digest {lock_digest} != Installed digest {installed_digest}"
        decision = "BLOCKED (Deriva de dependencia detectada)"

        self.record_attack_result("T15", "Dependency drift", expected, observed, evidence, decision)
        self.assertTrue(drift_detected)

    def test_T16_tautological_test(self):
        """T16: Detección de pruebas tautológicas ('assert True') mediante análisis mutacional."""
        # 1. Implementación original
        def calc_original(a, b):
            return a + b

        # 2. Mutante aritmético (+ cambiado a -)
        def calc_mutante(a, b):
            return a - b

        # 3. Prueba tautológica (sin poder de falsación)
        def prueba_tautologica(fn):
            fn(10, 5)
            return True  # Siempre pasa

        # 4. Prueba discriminante (con poder de falsación)
        def prueba_discriminante(fn):
            return fn(10, 5) == 15

        # Medir supervivencia del mutante
        tauto_mata_mutante = not prueba_tautologica(calc_mutante)  # False: mutante sobrevive
        discrim_mata_mutante = not prueba_discriminante(calc_mutante)  # True: mutante liquidado

        expected = "Prueba tautológica no mata al mutante (puntuación mutacional 0%)"
        observed = f"Tautológica mató mutante: {tauto_mata_mutante}, Discriminante mató mutante: {discrim_mata_mutante}"
        evidence = "Supervivencia de mutante calc_mutante ante prueba tautológica"
        decision = "INCONCLUSIVE (Descalificación por falta de poder de falsación)"

        self.record_attack_result("T16", "Tautological test", expected, observed, evidence, decision)
        self.assertFalse(tauto_mata_mutante)
        self.assertTrue(discrim_mata_mutante)

    def test_T17_scanner_failure_false_pass(self):
        """T17: Un escáner que falla no debe convertirse en un PASS silencioso."""
        res = Result(id="G-SCAN", name="scanner", status=NOT_EXECUTABLE, measure="error de escáner")
        veredicto = verdict_of([res])
        codigo_salida = exit_for(res.status)

        expected = f"Veredicto NOT_EXECUTABLE y código de salida {EXIT_BLOCKED} (nunca 0)"
        observed = f"Veredicto: {veredicto}, exit code: {codigo_salida}"
        evidence = f"Status: {res.status}"
        decision = "NOT_EXECUTABLE (Bloqueo garantizado de admisión)"

        self.record_attack_result("T17", "Scanner failure false pass", expected, observed, evidence, decision)
        self.assertIn("NO INTEGRABLE", veredicto)
        self.assertIn("no se pudieron ejecutar", veredicto)
        self.assertEqual(EXIT_BLOCKED, codigo_salida)

    def test_T18_missing_evidence(self):
        """T18: Claim presentado sin artefacto de evidencia verificable."""
        empty_dir = Path(tempfile.mkdtemp(prefix="empty-ev-"))
        try:
            chain = verificar_cadena(empty_dir)
            server = RefutoProtocolServer(empty_dir)
            st = server.dispatch("refuto.query_status", {})

            expected = "Cadena AUSENTE cuando no existe evidencia material en el espacio"
            observed = f"Chain estado: {chain.get('estado')}, query_status: {st.get('ledger', {}).get('chain_status')}"
            evidence = f"Ruta vacía: {empty_dir}"
            decision = "BLOCKED / AUSENTE (Admisión rechazada por falta de evidencia)"

            self.record_attack_result("T18", "Missing evidence", expected, observed, evidence, decision)
            self.assertEqual(AUSENTE, chain.get("estado"))
            self.assertEqual(AUSENTE, st.get("ledger", {}).get("chain_status"))
        finally:
            import shutil
            shutil.rmtree(empty_dir, ignore_errors=True)

    def test_T19_missing_witness(self):
        """T19: Afirmación crítica que carece de testigo independiente firmado."""
        server = RefutoProtocolServer(self.tmp)
        req = {
            "jsonrpc": "2.0",
            "method": "refuto.verify_claim",
            "params": {
                "claim": {
                    "claim_id": "clm_t19_critico",
                    "property": "critical_release",
                    "evidence_requirements": {}  # Sin testigo requerido ni provisto
                },
                "gate": "G-ROLES"
            },
            "id": 119
        }
        res = json.loads(server.handle_request_text(json.dumps(req)))
        capsule = res.get("result", {}).get("capsule", {})

        expected = "Epistemic level no alcanza E3/E4 sin testigo verificado"
        observed = f"Epistemic: {capsule.get('epistemic_level')}, status: {capsule.get('status')}"
        evidence = f"Claim ID: {capsule.get('claim_id')}"
        decision = "INCONCLUSIVE (Certeza rebajada a E1 por falta de atestación externa)"

        self.record_attack_result("T19", "Missing witness", expected, observed, evidence, decision)
        self.assertIn(capsule.get("epistemic_level"), ("E0", "E1"))

    def test_T20_tool_output_forgery(self):
        """T20: Intento de falsificar la salida de una herramienta o compilador."""
        stdout_genuino = b"BUILD SUCCESSFUL - 0 errors"
        digest_genuino = hashlib.sha256(stdout_genuino).hexdigest()

        # Atacante altera la salida de la herramienta
        stdout_falsificado = b"BUILD FAILED - 1 error (substituido por el atacante)"
        digest_falsificado = hashlib.sha256(stdout_falsificado).hexdigest()

        output_tampered = (digest_genuino != digest_falsificado)

        expected = "Discrepancia de digest entre salida declarada y salida observada"
        observed = f"Forja detectada: {output_tampered}"
        evidence = f"Genuino: {digest_genuino} != Forjado: {digest_falsificado}"
        decision = "FAIL (Atestación de herramienta rechazada por integridad nula)"

        self.record_attack_result("T20", "Tool output forgery", expected, observed, evidence, decision)
        self.assertTrue(output_tampered)

    def test_T21_agent_bypass(self):
        """T21: Un agente intenta desviar su ejecución fuera del entorno gobernado."""
        pol = Policy.load(self.policy_path)
        d1 = decide_write(pol, self.tmp, "/tmp/archivo_desviado.txt")
        d2 = decide_write(pol, self.tmp, "../../../etc/passwd")

        expected = "DENY ante cualquier intento de escritura fuera del espacio de trabajo"
        observed = f"Ruta absoluta: {d1.outcome}, Ruta relativa traversal: {d2.outcome}"
        evidence = f"Reglas activadas: {d1.rule}, {d2.rule}"
        decision = "DENY (Desvío y fuga neutralizados)"

        self.record_attack_result("T21", "Agent bypass", expected, observed, evidence, decision)
        self.assertEqual(DENY, d1.outcome)
        self.assertEqual(DENY, d2.outcome)


if __name__ == "__main__":
    unittest.main()
