# Modelo de Ecosistema y Extensibilidad

## 1. Principio de Aislamiento del Núcleo y Arquitectura de Plugins

El núcleo de Refuto (`core/`) se rige por un mandato arquitectónico irrompible:
> **Cero dependencias externas. Biblioteca estándar exclusivamente.**

Para permitir que el ecosistema se expanda e incorpore herramientas especializadas (como generadores de pruebas con IA, analizadores estáticos pesados, integraciones con nubes y librerías de formal verification), Refuto implementa un **modelo de extensibilidad desacoplada** basado en procesos aislados y el protocolo Refuto Wire Protocol v1.

```
┌────────────────────────────────────────────────────────┐
│                   NÚCLEO DE REFUTO                     │
│               (Solo Biblioteca Estándar)               │
│                                                        │
│  ┌───────────────┐ ┌───────────────┐ ┌──────────────┐  │
│  │ SemanticKernel│ │ EvidenceLedger│ │PolicyEngine  │  │
│  └───────▲───────┘ └───────▲───────┘ └──────▲───────┘  │
│          │                 │                │          │
│  ┌───────┴─────────────────┴────────────────┴───────┐  │
│  │            Refuto Wire Protocol v1               │  │
│  │         (JSON-RPC sobre stdio / IPC)             │  │
│  └─────────────────────────▲────────────────────────┘  │
└────────────────────────────┼───────────────────────────┘
                             │
            ┌────────────────┴────────────────┐
            ▼                                 ▼
┌────────────────────────┐       ┌────────────────────────┐
│  PAQUETES DE COMPUERTAS│       │ ADAPTADORES EXTERNOS   │
│  (Out-of-Process)      │       │ (AI-DLC, Kiro, CI/CD)  │
│  - SonarQube Gate      │       │ - AWS EventBridge      │
│  - Semgrep SAST Gate   │       │ - GitHub Action Agent  │
│  - Z3 SMT Solver Gate  │       │ - Kubernetes Webhook   │
└────────────────────────┘       └────────────────────────┘
```

---

## 2. Taxonomía de Componentes Extensibles

El ecosistema de Refuto clasifica las extensiones en cinco categorías bien delimitadas:

### 2.1. Compuertas Externas (`External Gates`)
Módulos ejecutables independientes que inspeccionan artefactos y devuelven observaciones estructuradas `refuto.observation/v1`.
- Se comunican mediante subprocesos aislados con comunicación vía `stdio`.
- El núcleo impone límites duros de tiempo de ejecución (`timeout`), consumo de memoria y cuotas de I/O.
- Si una compuerta externa falla por error de infraestructura o excepción no capturada, el núcleo registra `INCONCLUSIVE`, impidiendo que un fallo del plugin otorgue un falso `PASS`.

### 2.2. Testigos Personalizados (`Custom Witnesses`)
Entidades atestiguadoras que validan o auditan afirmaciones bajo condiciones especializadas:
- **Testigos Criptográficos de Hardware (HSM/TPM)**: Firman las cápsulas de evidencia utilizando claves aseguradas en silicio.
- **Notarios BFT Distribuidos**: Agentes de la red Concordia que participan en el consenso de atestación.
- **Comités Humanos de Homologación**: Interfaces que recopilan firmas multi-rol (seguridad, legal, arquitectura).

### 2.3. Paquetes de Políticas (`Policy Packs`)
Conjuntos versionados y firmados de reglas de gobernanza que definen los umbrales de admisión para dominios regulatorios específicos:
- `refuto-policy-soc2`: Requisitos de auditoría de acceso, inmutabilidad y pruebas de no-regresión.
- `refuto-policy-hipaa`: Verificación de anonimización de datos y cifrado en tránsito/reposo.
- `refuto-policy-euaiact`: Requisitos de gobernanza, trazabilidad y supervisión humana para modelos de IA según el Reglamento Europeo de IA.

### 2.4. Adaptadores de Ciclo de Vida (`Lifecycle Adapters`)
Traductores bidireccionales que integran Refuto con motores de flujo de trabajo externos (como AWS AI-DLC, Kiro, Claude Code, Tekton, GitLab CI).

### 2.5. Exportadores y Visualizadores (`Exporters`)
Módulos que consumen el libro mayor de evidencias para proyectarlo en diferentes formatos:
- Exportador SARIF (Static Analysis Results Interchange Format).
- Exportador de Grafos de Decisión en formato GSN (Goal Structuring Notation).
- Exportador de Cuadros de Mando Ejecutivos HTML/JSON.

---

## 3. Protocolo de Descubrimiento de Capacidades y Negociación

Cuando Refuto inicia una sesión con un plugin o adaptador externo, se ejecuta un apretón de manos (*handshake*) formal:

```json
// Petición de Descubrimiento enviada por Refuto al subproceso
{
  "jsonrpc": "2.0",
  "method": "refuto.plugin.handshake",
  "id": 1,
  "params": {
    "protocol_version": "1.0",
    "host_runtime": "cpython-3.14-darwin",
    "capabilities_supported": ["falsification", "streaming_evidence", "crypto_signing"]
  }
}

// Respuesta del Plugin
{
  "jsonrpc": "2.0",
  "id": 1,
  "result": {
    "plugin_name": "gate-z3-smt-verifier",
    "plugin_version": "2.4.1",
    "gate_identifiers": ["gate.formal.z3.invariant"],
    "requires_network": false,
    "sandboxed_execution": true,
    "claim_types_supported": ["claim.invariant.mathematical", "claim.state.safety"]
  }
}
```

---

## 4. Aislamiento y Sandbox de Ejecución

Para preservar la integridad del sistema anfitrión y mitigar ataques de cadena de suministro (vector T11):
1. **Ejecución sin Red por Defecto**: Todos los plugins de compuertas se ejecutan en espacios de nombres o sandboxes con conectividad de red desactivada a menos que la política declare explícitamente `network: true`.
2. **Sistema de Archivos de Sólo Lectura**: El plugin recibe acceso de sólo lectura al árbol del proyecto bajo análisis. Cualquier salida debe canalizarse exclusivamente a través de los flujos de datos estándar (`stdout`).
3. **Firmas de Integridad del Plugin**: Cada binario o script de plugin debe coincidir con el hash SHA-256 declarado en el archivo de bloqueo de gobernanza (`refuto.plugins.lock`).
