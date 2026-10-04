# 09 · Arquitectura Objetivo 2026+ (Target Reference Architecture)

**Fecha:** 2026-09-30  
**Principios de Diseño:** Framework-Agnostic, Vendor-Neutral, Cloud-Neutral, Local-First, Zero-Dependency Core (Python Standard Library), Criptográficamente Falsable.

---

## 1. Visión Arquitectónica en Cuatro Capas

Refuto 2026+ se estructura en cuatro planos estrictamente desacoplados mediante contratos formales:

```
┌────────────────────────────────────────────────────────────────────────┐
│  CAPA 3: ADAPTERS & WITNESSES PERIFÉRICOS (Interacción Externa)        │
│                                                                        │
│   [AI-DLC Adapter]  [Kiro Adapter]  [Claude Adapter]  [CI/CD Adapter]  │
│   [Runtime Witness (CloudTrail/K8s)]  [Concordia BFT Quorum Witness]   │
└────────────────────────────────────┬───────────────────────────────────┘
                                     │ JSON-RPC / CLI Contracts
                                     ▼
┌────────────────────────────────────────────────────────────────────────┐
│  CAPA 2: PROTOCOLO ESTÁNDAR Y CÁPSULAS DE DECISIÓN                     │
│                                                                        │
│   - Claim Schema (refuto.claim/v1)                                     │
│   - Decision Capsule Schema (refuto.decision-capsule/v1)               │
│   - Evidence & Observation Schema (refuto.observation/v1)              │
└────────────────────────────────────┬───────────────────────────────────┘
                                     │ Tipos Puros de Dominio
                                     ▼
┌────────────────────────────────────────────────────────────────────────┐
│  CAPA 1: VERIFICATION KERNEL (El Núcleo Invariable)                    │
│                                                                        │
│   - Reference Monitor Aislado (ADR-0018: Motor que Juzga ≠ Árbol)      │
│   - Evaluador de Cobertura y Prueba del Vacío (Scope: examined > 0)    │
│   - Motor de Políticas Jerárquico con Monotonía Parcial                │
│   - Matriz de Veredictos de 7 Estados No Colapsables                  │
│   - Grafo de Separación de Autoría (Anti-Circularity Engine)           │
└────────────────────────────────────┬───────────────────────────────────┘
                                     │ Registros Transaccionales
                                     ▼
┌────────────────────────────────────────────────────────────────────────┐
│  CAPA 0: PLANO DE EVIDENCIA E INTEGRIDAD CRIPTOGRÁFICA                 │
│                                                                        │
│   - Ledger Append-Only Encadenado (hᵢ = SHA256(hᵢ₋₁ ‖ canonical(eᵢ)))  │
│   - Bloqueo Exclusivo de OS (fcntl / msvcrt)                           │
│   - Verificador Ed25519 Pure-Python RFC 8032                           │
│   - Sistema de Cicatrices para Discontinuidades Declaradas (ADR-0019)  │
└────────────────────────────────────────────────────────────────────────┘
```

---

## 2. Descripción de Componentes del Core

### 2.1 Verification Kernel (`core/kernel/`)
* **`ClaimEngine`:** Parsea, valida esquemas y formaliza las propiedades a demostrar.
* **`ScopeValidator`:** Garantiza el cumplimiento de la Prueba del Vacío: rechaza de forma absoluta cualquier `PASS` derivado de un conjunto vacío.
* **`PolicyEngine`:** Resuelve la cadena jerárquica de políticas desde la raíz inmutable de confianza (`RootOfTrust`), verificando que cada hijo refine monótonamente las reglas de su padre.
* **`DecisionEngine`:** Agrega los resultados de las evaluaciones individuales aplicando precedencia determinista: `FAIL` tiene máxima precedencia, seguido de `BLOCKED`/`NOT_EXECUTABLE`, seguido de `INCONCLUSIVE` (ante incertidumbre o falta de cobertura).

### 2.2 Evidence & Integrity Engine (`core/evidence/`)
* **`ChainLedger`:** Mantiene `ledger.jsonl`. Toda entrada está atada a su predecesora mediante hash SHA-256 canónico sin espacios y con claves ordenadas.
* **`Reconciler`:** Cruza de forma obligatoria los artefactos de corrida con las líneas históricas del diario para detectar discrepancias y manipulaciones post-hoc.
* **`BFTAnchorClient`:** Conector con el quórum notarial Concordia BFT para ordenar checkpoints de evidencia.

### 2.3 Reference Monitor (`core/guard.py` & `core/privilegio.py`)
* Interceptor de comandos antes de su ejecución (`PreToolUse`).
* Implementa la normalización de comandos, detección posicional de elevación y análisis recursivo en argumentos `-c` de intérpretes (ADR-0020).
