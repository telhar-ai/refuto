# 12 · Modelo Formal de Afirmaciones (Claim Model v1)

**Fecha:** 2026-09-30  
**Esquema Canónico:** `https://refuto.dev/schemas/claim/v1.json`  
**Identificador de Versión:** `refuto.claim/v1`

---

## 1. Estructura Formal del Documento de Claim

Un `Claim` representa una afirmación formalmente falsable sobre una propiedad del software:

```yaml
claim:
  # Metadatos del Claim
  schema: "refuto.claim/v1"
  claim_id: "clm_01J9X2K4N8M1Q5P9R3T7V2W4Y6"
  timestamp: "2026-09-30T02:00:00.000Z"
  version: "1.0.0"

  # Emisor de la Afirmación
  issuer:
    identity: "agent:claude-code:2.1.247"
    role: "implementation-agent"
    harness: "claude-code"
    framework_context:
      name: "aidlc"
      version: "2.10.0"
      stage: "construction:build-and-test"
      intent: "260930-auth-service"

  # Sujeto bajo Examen
  subject:
    target_type: "git_repository"
    workspace_path: "/ruta/al/espacio"
    git_commit: "28e796529c432504731a21d0ca51a6bfd9cb7db8"
    git_branch: "assurance/protocolo-tres-caras"
    dirty_tree_allowed: false
    evaluated_paths:
      - "core/**"
      - "services/**"

  # Afirmación / Propiedad Predicada
  statement:
    domain: "security"
    property: "zero_secrets_and_vulnerabilities"
    predicate: "secrets_count == 0 && critical_vulnerabilities == 0"

  # Requisitos de Cobertura (La Prueba del Vacío)
  scope_requirement:
    declared_universe: "all_tracked_source_files"
    min_examined: 50
    allowed_unknown: 0
    fail_on_empty: true

  # Política Aplicable
  policy_binding:
    policy_digest: "sha256:4b227777d4dd1fc61c6f884f48641d02b4d121d3fd328cb08b5531fcacdabf8a"
    enforce_monotonicity: true

  # Requisitos de Testigos y Frescura
  evidence_requirements:
    min_witness_tier: "W2_ISOLATED_MONITOR"
    max_age_seconds: 600
    require_consensus_anchor: false
```

---

## 2. Invariantes Semánticos del Modelo de Claim

1. **Invariante de Identidad Única:** El `claim_id` es un identificador monótonamente creciente (ULID o UUIDv7) que evita colisiones en entornos altamente concurrentes.
2. **Invariante de Sujeto Inmutable:** Un Claim predica sobre un estado estático y determinista (representado por un commit SHA o un digest criptográfico del árbol). Si el árbol está `dirty` y el claim declara `dirty_tree_allowed: false`, la evaluación retorna inmediatamente `BLOCKED`.
3. **Invariante de Vacío Explicito:** Todo claim debe definir `min_examined > 0`. Si una evaluación reporta `examined == 0`, el resultado viola el contrato del Claim y se rechaza la admisión.
