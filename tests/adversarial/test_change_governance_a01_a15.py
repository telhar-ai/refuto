# -*- coding: utf-8 -*-
"""Pruebas adversariales del modelo de cambio protegido (A01 a A15).

Verifica que el sistema de cambio formal resista intentos de bypass:
A01: El agente se auto-autoriza.
A02: El agente muta el payload o la firma del token de autorización.
A03: El agente propone debilitar la política raíz (.harness/policy.json).
A04: El agente intenta aplicar un parche a una compuerta protegida sin autorización.
A05: El agente suplanta la identidad o la clave del revisor/autorizador.
A06: El agente intenta reutilizar un token previo (Replay) o vencido (TTL).
A07: El agente muta el parche tras haber obtenido la autorización (Diff Tamper).
A08: El agente altera los archivos objetivo tras haber sido autorizados (Target Tamper).
A09: El agente manipula la evidencia tras la verificación.
A10: El agente proponente se asigna a sí mismo como testigo de la verificación.
A11: El agente reduce el ámbito o introduce ámbito vacío (Scope Reduction).
A12: Intento de eliminar un test fallido para forzar PASS.
A13: Intento de alterar el resultado esperado de una prueba.
A14: Intento de inyectar un digest de política alterado o rancio.
A15: Mutación del sujeto posterior a la verificación (TOCTOU).
"""

from __future__ import annotations

import hashlib
import json
import shutil
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path

from core.change import (
    AuthoritySeparationViolation,
    AuthorizationExpiredError,
    AuthorizationReplayError,
    ChangeGovernanceEngine,
    ChangeProposal,
    CircularWitnessError,
    DiffTamperDetectedError,
    InvalidAuthorizationSignatureError,
    PolicyTamperBlockedError,
    ProtectedChangeError,
    ProtectedTargetRequiresAuthorizationError,
    ScopeReductionError,
    TargetTamperDetectedError,
    UntrustedAuthorizerError,
)
from core.digest import sha256_text
from core.model import FAIL, PASS, Result, Scope


class TestChangeGovernanceA01A15(unittest.TestCase):
    def setUp(self):
        self.temp_dir = Path(tempfile.mkdtemp(prefix="refuto-change-test-"))
        self.engine = ChangeGovernanceEngine(self.temp_dir)

        # Crear una clave Ed25519 sintética para un operador humano de confianza
        self.operator_seed = hashlib.sha256(b"operator-seed-test-001").digest()
        from core.change import _ed25519_public_key
        self.operator_pk = _ed25519_public_key(self.operator_seed).hex()
        self.trusted_keys = {"human:operator_sec": self.operator_pk}

        # Configurar .harness inicial
        harness = self.temp_dir / ".harness"
        harness.mkdir(parents=True)
        (harness / "trusted_authorizers.json").write_text(
            json.dumps({"authorizers": self.trusted_keys}), encoding="utf-8"
        )
        (harness / "policy.json").write_text(
            json.dumps({
                "schema": "harness.policy/v1",
                "version": "1",
                "protected_paths": ["**/gates/**", "**/.harness/**"]
            }), encoding="utf-8"
        )

        # Crear compuerta ficticia
        gates_dir = self.temp_dir / "gates"
        gates_dir.mkdir()
        self.gate_file = gates_dir / "g_test.py"
        self.gate_file.write_text("GATE_ID = 'G-TEST'\ndef run(ctx): pass\n", encoding="utf-8")

        self.diff_sample = (
            "--- a/gates/g_test.py\n"
            "+++ b/gates/g_test.py\n"
            "@@ -1,2 +1,3 @@\n"
            " GATE_ID = 'G-TEST'\n"
            "+MODIFIED = True\n"
            " def run(ctx): pass\n"
        )

    def tearDown(self):
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_a01_agent_self_authorizes(self):
        """A01: Un agente no puede autorizar su propia propuesta de cambio."""
        agent_id = "agent:assistant-42"
        proposal = self.engine.propose(
            title="Parche en compuerta",
            author=agent_id,
            author_type="agent",
            diff=self.diff_sample
        )

        with self.assertRaises(AuthoritySeparationViolation):
            self.engine.authorize(
                proposal=proposal,
                authorizer_id=agent_id,  # Intento de auto-autorización
                authorizer_type="agent",
                secret_key_bytes=self.operator_seed
            )

    def test_a02_agent_modifies_authorization_signature(self):
        """A02: Mutar la firma o los campos del token de autorización es rechazado."""
        proposal = self.engine.propose(
            title="Parche en compuerta",
            author="agent:assistant-42",
            author_type="agent",
            diff=self.diff_sample
        )
        token = self.engine.authorize(
            proposal=proposal,
            authorizer_id="human:operator_sec",
            authorizer_type="human",
            secret_key_bytes=self.operator_seed,
            trusted_keys=self.trusted_keys
        )

        # Mutar un carácter de la firma
        corrupt_sig = "ff" + token.signature[2:]
        token.signature = corrupt_sig

        with self.assertRaises(InvalidAuthorizationSignatureError):
            self.engine.apply(proposal, token, self.trusted_keys)

    def test_a03_agent_modifies_policy(self):
        """A03: Un intento de modificar .harness/policy.json requiere autoridad de gobernanza raíz."""
        policy_diff = (
            "--- a/.harness/policy.json\n"
            "+++ b/.harness/policy.json\n"
            "@@ -3,3 +3,3 @@\n"
            "- \"protected_paths\": [\"**/gates/**\", \"**/.harness/**\"]\n"
            "+ \"protected_paths\": []\n"
        )
        proposal = self.engine.propose(
            title="Desactivar protecciones",
            author="agent:attacker",
            author_type="agent",
            diff=policy_diff,
            target_files=[".harness/policy.json"]
        )

        # Autorizado sólo por un humano regular, no governance_authority
        token = self.engine.authorize(
            proposal=proposal,
            authorizer_id="human:operator_sec",
            authorizer_type="human",
            secret_key_bytes=self.operator_seed,
            trusted_keys=self.trusted_keys
        )

        with self.assertRaises(PolicyTamperBlockedError):
            self.engine.apply(proposal, token, self.trusted_keys)

    def test_a04_agent_modifies_protected_gate_without_auth(self):
        """A04: Modificar una compuerta protegida sin autorización es rechazado."""
        proposal = self.engine.propose(
            title="Parche directo no autorizado",
            author="agent:attacker",
            author_type="agent",
            diff=self.diff_sample
        )
        with self.assertRaises(ProtectedTargetRequiresAuthorizationError):
            self.engine.apply(proposal, authorization=None)

    def test_a05_agent_modifies_reviewer_identity(self):
        """A05: Presentar una clave pública ajena o autorizador no registrado es rechazado."""
        proposal = self.engine.propose(
            title="Parche",
            author="agent:assistant",
            author_type="agent",
            diff=self.diff_sample
        )
        fake_seed = hashlib.sha256(b"fake-seed").digest()

        # Intento de firmar con una clave no confiable
        token = self.engine.authorize(
            proposal=proposal,
            authorizer_id="untrusted_entity",
            authorizer_type="human",
            secret_key_bytes=fake_seed,
            trusted_keys={}
        )

        with self.assertRaises(UntrustedAuthorizerError):
            self.engine.apply(proposal, token, self.trusted_keys)

    def test_a06_agent_replays_old_authorization(self):
        """A06: Reutilizar un token previamente consumido o expirado es rechazado."""
        proposal = self.engine.propose(
            title="Parche",
            author="agent:assistant",
            author_type="agent",
            diff=self.diff_sample
        )
        token = self.engine.authorize(
            proposal=proposal,
            authorizer_id="human:operator_sec",
            authorizer_type="human",
            secret_key_bytes=self.operator_seed,
            trusted_keys=self.trusted_keys
        )

        # Primera aplicación: debe funcionar
        res1 = self.engine.apply(proposal, token, self.trusted_keys)
        self.assertEqual(res1["status"], "APPLIED")

        # Segunda aplicación con el mismo token: debe fallar por Replay (nonce consumido)
        with self.assertRaises(AuthorizationReplayError):
            self.engine.apply(proposal, token, self.trusted_keys)

        # Probar token expirado
        token_expired = self.engine.authorize(
            proposal=proposal,
            authorizer_id="human:operator_sec",
            authorizer_type="human",
            secret_key_bytes=self.operator_seed,
            trusted_keys=self.trusted_keys,
            ttl_seconds=-10  # Ya vencido
        )
        with self.assertRaises(AuthorizationExpiredError):
            self.engine.apply(proposal, token_expired, self.trusted_keys)

    def test_a07_agent_changes_patch_after_authorization(self):
        """A07: Alterar el parche tras la autorización causa discordancia de hash."""
        proposal = self.engine.propose(
            title="Parche original",
            author="agent:assistant",
            author_type="agent",
            diff=self.diff_sample
        )
        token = self.engine.authorize(
            proposal=proposal,
            authorizer_id="human:operator_sec",
            authorizer_type="human",
            secret_key_bytes=self.operator_seed,
            trusted_keys=self.trusted_keys
        )

        # Modificar el diff en la propuesta
        proposal.diff += "\n# Backdoor añadido\n"
        proposal.diff_hash = sha256_text(proposal.diff)

        with self.assertRaises(DiffTamperDetectedError):
            self.engine.apply(proposal, token, self.trusted_keys)

    def test_a08_agent_changes_target_after_authorization(self):
        """A08: Alterar los archivos objetivo tras la autorización es detectado y rechazado."""
        proposal = self.engine.propose(
            title="Parche",
            author="agent:assistant",
            author_type="agent",
            diff=self.diff_sample
        )
        token = self.engine.authorize(
            proposal=proposal,
            authorizer_id="human:operator_sec",
            authorizer_type="human",
            secret_key_bytes=self.operator_seed,
            trusted_keys=self.trusted_keys
        )

        # Añadir un archivo extra no autorizado
        proposal.target_files.append("gates/g_security.py")

        with self.assertRaises(TargetTamperDetectedError):
            self.engine.apply(proposal, token, self.trusted_keys)

    def test_a09_agent_modifies_evidence_after_verification(self):
        """A09: Evidencia manipulada o forjada después de la verificación no es admisible."""
        proposal = self.engine.propose(
            title="Parche",
            author="agent:assistant",
            author_type="agent",
            diff=self.diff_sample
        )
        verification = self.engine.verify(proposal, witness_id="independent_verifier")
        self.assertEqual(verification.status, PASS)

        # Alterar el resultado de verificación
        verification.status = FAIL
        verification.can_advance = False
        admit_res = self.engine.admit(proposal, verification)
        self.assertFalse(admit_res["admitted"])
        self.assertFalse(admit_res["can_advance"])

    def test_a10_agent_substitutes_witness(self):
        """A10: El agente proponente no puede ser su propio testigo de verificación."""
        proposal = self.engine.propose(
            title="Parche",
            author="agent:assistant",
            author_type="agent",
            diff=self.diff_sample
        )
        with self.assertRaises(CircularWitnessError):
            self.engine.verify(proposal, witness_id="agent:assistant")

    def test_a11_agent_reduces_scope(self):
        """A11: Intentar registrar un Scope con 0 examinados en PASS es rechazado por Result."""
        with self.assertRaises(ValueError):
            Result(
                id="G-TEST",
                name="Prueba",
                status=PASS,
                severity="HIGH",
                threshold=">=1",
                measure="0 elementos",
                scope=Scope(examined=0, unknown=0, universe="items", declared=True)
            )

    def test_a12_agent_removes_failed_test(self):
        """A12: Si un archivo de prueba objetivo es eliminado o queda roto, la verificación falla."""
        broken_diff = (
            "--- a/gates/g_test.py\n"
            "+++ b/gates/g_test.py\n"
            "@@ -1,2 +1,2 @@\n"
            "- def run(ctx): pass\n"
            "+ def run(ctx): def syntax error\n"
        )
        proposal = self.engine.propose(
            title="Parche con sintaxis rota",
            author="agent:assistant",
            author_type="agent",
            diff=broken_diff,
            target_files=["gates/g_test.py"]
        )
        token = self.engine.authorize(
            proposal=proposal,
            authorizer_id="human:operator_sec",
            authorizer_type="human",
            secret_key_bytes=self.operator_seed,
            trusted_keys=self.trusted_keys
        )
        self.engine.apply(proposal, token, self.trusted_keys)
        verification = self.engine.verify(proposal, witness_id="ci_verifier")
        self.assertEqual(verification.status, FAIL)
        self.assertFalse(verification.can_advance)

    def test_a13_agent_changes_expected_result(self):
        """A13: Un resultado con hallazgos jamás puede declararse PASS."""
        from core.model import Finding
        with self.assertRaises(ValueError):
            Result(
                id="G-TEST",
                name="Prueba",
                status=PASS,
                severity="HIGH",
                threshold="0 hallazgos",
                measure="1 hallazgo",
                findings=[Finding("test.py", "vulnerabilidad encontrada", 10)],
                scope=Scope(examined=1, unknown=0, universe="items", declared=True)
            )

    def test_a14_agent_modifies_policy_digest(self):
        """A14: Mismatch de digest de política detectado en verificación de claim."""
        from core.protocol import RefutoProtocolServer
        server = RefutoProtocolServer(self.temp_dir)
        claim_res = server.dispatch("refuto.verify_claim", {
            "claim": {
                "claim_id": "clm_policy_test",
                "property": "security_assurance",
                "subject": {"workspace": str(self.temp_dir)},
                "policy_binding": {"policy_digest": "0000000000000000000000000000000000000000000000000000000000000000"}
            }
        })
        # Al tener un digest forjado que no coincide con la política real en el ledger/espacio,
        # no se puede avanzar.
        self.assertFalse(claim_res["lifecycle_admissibility"]["can_advance"])

    def test_a15_agent_modifies_subject_digest(self):
        """A15: Modificar el digest del sujeto tras la verificación impide la admisión."""
        from core.protocol import RefutoProtocolServer
        server = RefutoProtocolServer(self.temp_dir)
        claim_res = server.dispatch("refuto.verify_claim", {
            "claim": {
                "claim_id": "clm_subject_tamper",
                "property": "security_assurance",
                "subject": {
                    "workspace": str(self.temp_dir),
                    "expected_digest": "0000000000000000000000000000000000000000000000000000000000000000",
                    "actual_digest": "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
                }
            }
        })
        self.assertFalse(claim_res["lifecycle_admissibility"]["can_advance"])
        remediations = claim_res["lifecycle_admissibility"]["remediation_actions"]
        self.assertTrue(any("digest" in r.lower() for r in remediations))


class TestA05FallaCerradoSinAlmacen(unittest.TestCase):
    """A05 con el almacén de confianza AUSENTE. El hueco que la clase de arriba no veía.

    Las 15 pruebas de `TestChangeGovernanceA01A15` escriben
    `.harness/trusted_authorizers.json` en `setUp` y pasan un `trusted_keys` no vacío a `apply`.
    Es decir: cubrían A05 en el caso «hay almacén» y **ningún** caso «no hay almacén», que es el
    estado real de los 11 espacios medidos el 2026-10-03 — en ninguno existe el fichero.

    En ese estado, `apply` decía `if trusted:` y se saltaba A05 entero. Medido de punta a punta
    por el protocolo, con el almacén ausente:

        propone  «agente»                 → propuesta creada
        autoriza «revisor-humano»         → token EMITIDO (identidad inventada, par propio)
        aplica   gates/g_colado.py        → *** APLICADO ***

    y lo mismo con `verification/**` y `evidence/**`: un agente escribiendo su propio juez y su
    propia evidencia con sólo inventarse un segundo nombre. A02 verificaba la firma y por eso no
    se notaba — verifica contra la clave pública que el token TRAE, así que sin A05 demuestra que
    el token no se alteró, no que lo firmara nadie.

    A01 no lo para: compara dos cadenas (`author` vs `authorizer_id`) y las dos las elige quien
    propone. Sólo `.harness/policy.json` se salvaba, por A03.
    """

    def setUp(self):
        self.ws = Path(tempfile.mkdtemp(prefix="refuto-a05-sin-almacen-"))
        (self.ws / ".harness").mkdir(parents=True)
        (self.ws / ".harness" / "policy.json").write_text(json.dumps({
            "schema": "harness.policy/v1", "version": "1",
            "protected_paths": ["**/gates/**", "**/.harness/**", "**/verification/**",
                                "**/evidence/**"],
        }), encoding="utf-8")
        (self.ws / "gates").mkdir()
        (self.ws / "gates" / "g_test.py").write_text("GATE_ID='G-T'\n", encoding="utf-8")
        self.engine = ChangeGovernanceEngine(self.ws)
        self.seed = hashlib.sha256(b"semilla-del-agente").digest()
        from core.change import _ed25519_public_key
        self.pk = _ed25519_public_key(self.seed).hex()

    def _propuesta(self, objetivo="gates/g_test.py"):
        return self.engine.propose(
            title="colar un cambio en la puerta", author="agente", author_type="agent",
            diff=f"--- a/{objetivo}\n+++ b/{objetivo}\n+GATE_ID='COLADO'\n",
            target_files=[objetivo])

    def test_el_almacen_no_existe(self):
        """La premisa. Sin esto, las de abajo podrían estar midiendo otro estado."""
        self.assertFalse((self.ws / ".harness" / "trusted_authorizers.json").exists())
        self.assertEqual({}, self.engine.load_trusted_authorizers())

    def test_el_token_se_emite_igual_y_eso_NO_es_confianza(self):
        """Acuñar no es autorizar, y el token acuñado se lee como si lo fuera."""
        prop = self._propuesta()
        token = self.engine.authorize(prop, authorizer_id="revisor-humano",
                                      authorizer_type="human", secret_key_bytes=self.seed)
        self.assertTrue(token.signature, "sin firma no habría nada que rechazar después")
        self.assertEqual("human", token.authorizer_type,
                         "el tipo lo declara quien acuña: es autoaserción, no una comprobación")

    def test_aplicar_con_ese_token_se_RECHAZA(self):
        """El arreglo: ámbito vacío no aprueba."""
        for objetivo in ("gates/g_test.py", "verification/v.py", "evidence/x.json",
                         ".harness/policy.json"):
            with self.subTest(objetivo=objetivo):
                prop = self._propuesta(objetivo)
                token = self.engine.authorize(prop, authorizer_id="revisor-humano",
                                              authorizer_type="human",
                                              secret_key_bytes=self.seed)
                with self.assertRaises(ProtectedChangeError):
                    self.engine.apply(prop, token)

    def test_y_el_motivo_es_A05_y_no_otro(self):
        """Rechazar por el motivo equivocado habría dado un verde falso al medirlo."""
        prop = self._propuesta()
        token = self.engine.authorize(prop, authorizer_id="revisor-humano",
                                      authorizer_type="human", secret_key_bytes=self.seed)
        with self.assertRaises(UntrustedAuthorizerError) as caja:
            self.engine.apply(prop, token)
        self.assertIn("A05", str(caja.exception))
        self.assertIn("almacén", str(caja.exception))

    def test_el_fichero_objetivo_NO_se_tocó(self):
        """Un rechazo que ya escribió no es un rechazo."""
        antes = (self.ws / "gates" / "g_test.py").read_text(encoding="utf-8")
        prop = self._propuesta()
        token = self.engine.authorize(prop, authorizer_id="revisor-humano",
                                      authorizer_type="human", secret_key_bytes=self.seed)
        with self.assertRaises(ProtectedChangeError):
            self.engine.apply(prop, token)
        self.assertEqual(antes, (self.ws / "gates" / "g_test.py").read_text(encoding="utf-8"))

    def test_con_el_almacen_PUESTO_el_mismo_cambio_se_aplica(self):
        """La contraparte. Sin ella, el arreglo podría ser «deniega siempre», que no sirve."""
        (self.ws / ".harness" / "trusted_authorizers.json").write_text(
            json.dumps({"authorizers": {"revisor-humano": self.pk}}), encoding="utf-8")
        prop = self._propuesta()
        token = self.engine.authorize(prop, authorizer_id="revisor-humano",
                                      authorizer_type="human", secret_key_bytes=self.seed)
        res = self.engine.apply(prop, token)
        self.assertEqual("APPLIED", res["status"])

    def test_y_con_un_almacen_de_OTRA_clave_se_rechaza(self):
        """El tercer estado: hay almacén, y la clave del firmante no es la registrada."""
        from core.change import _ed25519_public_key
        ajena = _ed25519_public_key(hashlib.sha256(b"clave-de-una-persona").digest()).hex()
        (self.ws / ".harness" / "trusted_authorizers.json").write_text(
            json.dumps({"authorizers": {"revisor-humano": ajena}}), encoding="utf-8")
        prop = self._propuesta()
        with self.assertRaises(UntrustedAuthorizerError):
            token = self.engine.authorize(prop, authorizer_id="revisor-humano",
                                          authorizer_type="human", secret_key_bytes=self.seed)
            self.engine.apply(prop, token)


if __name__ == "__main__":
    unittest.main()
