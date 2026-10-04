# 11 · Protocolo de Verificación e Interoperabilidad (Refuto Wire Protocol v1)

**Fecha:** 2026-09-30  
**Transporte Oficial:** Stdio (JSON-RPC 2.0 / JSON Lines) o Unix Domain Socket local  
**Esquema de Versión:** `refuto.protocol/v1`

---

## 1. Métodos del Protocolo

El protocolo define cinco métodos universales:

| Método | Rol | Mutabilidad |
| :--- | :--- | :---: |
| `refuto.initialize` | Handshake inicial, intercambio de capacidades y versión. | No |
| `refuto.verify_claim` | Evalúa un Claim formal y emite una Decision Capsule. | Sí (escribe log) |
| `refuto.evaluate_action` | Intercepción rápida de efectos (Guard Pre-Tool Use). | Sí (escribe log) |
| `refuto.query_status` | Inspección del estado de integridad y anclaje offline. | No |
| `refuto.anchor_checkpoint` | Notifica y solicita certificación a quórum BFT. | Sí (red / ancla) |

---

## 2. Definición de Mensajes

### 2.1 Petición de Verificación (`refuto.verify_claim`)
```json
{
  "jsonrpc": "2.0",
  "method": "refuto.verify_claim",
  "params": {
    "claim": {
      "schema": "refuto.claim/v1",
      "claim_id": "clm_01J9X2K4N8M1Q5",
      "property": "correctness.test_suite",
      "subject": {
        "workspace": "/ruta/al/espacio",
        "commit": "28e796529c432504"
      },
      "scope_requirement": {
        "min_examined": 10,
        "allowed_unknown": 0,
        "universe_definition": "unit_tests"
      },
      "evidence_requirements": {
        "min_witness_tier": "W2_ISOLATED_MONITOR"
      }
    },
    "context": {
      "framework": "aidlc:v2.10.0",
      "stage": "build-and-test",
      "offline": true
    }
  },
  "id": 42
}
```

### 2.2 Respuesta Exitosa (`refuto.verify_claim` Response)
```json
{
  "jsonrpc": "2.0",
  "result": {
    "capsule": {
      "schema": "refuto.decision-capsule/v1",
      "decision_id": "cap_88e1a2b3c4d5",
      "claim_id": "clm_01J9X2K4N8M1Q5",
      "status": "PASS",
      "epistemic_level": "E3",
      "scope": {
        "examined": 535,
        "unknown": 0,
        "universe": "unit_tests",
        "declared": true
      },
      "verdict_rationale": "535 pruebas unitarias observadas sin fallos ni errores sobre ámbito verificado",
      "ledger_head": "6d90d151d3210387b83362720b7d74805884557fa2db0b128ab2d58921c00a72"
    },
    "lifecycle_admissibility": {
      "can_advance": true,
      "gate_passed": true,
      "remediation_actions": []
    }
  },
  "id": 42
}
```

---

## 3. Códigos de Error Estandarizados

Siguiendo `sysexits.h` y la semántica JSON-RPC:

| Código | Símbolo | Significado |
| :---: | :--- | :--- |
| **`-32600`** | `INVALID_REQUEST` | Petición malformada que no cumple el esquema del protocolo. |
| **`-32602`** | `INVALID_CLAIM` | El Claim carece de campos obligatorios o la especificación es incoherente. |
| **`64`** | `EX_USAGE` | Error de sintaxis en CLI o parámetros incompatibles. |
| **`2`** | `EX_BLOCKED` | Verificación bloqueada por dependencia ausente o falta de pin de membresía. |
| **`1`** | `EX_FAIL` | Fallo demostrado en una o más puertas o violación demostrada de integridad. |
