# Modelo de Adaptadores de Integración

## 1. Topología General de Adaptación

Los adaptadores en Refuto operan como traductores de impedancia semántica y protocolar entre los marcos de trabajo del mundo exterior y el núcleo de verificación de Refuto. Un adaptador no contiene lógica de juicio ni altera veredictos; simplemente:
1. Traduce intenciones, eventos de ciclo de vida o artefactos externos al formato canónico `refuto.claim/v1`.
2. Invoca el proceso de verificación a través de la CLI o el protocolo Wire.
3. Traduce la **Cápsula de Decisión** resultante al lenguaje o formato nativo del llamador.

```
┌────────────────────────────────────────────────────────┐
│                   MARCO EXTERNO                        │
│          (AI-DLC, Kiro, Claude Code, CI/CD)            │
└───────────────────────────▲────────────────────────────┘
                            │ (Directiva / Hook / Workflow)
                            ▼
┌────────────────────────────────────────────────────────┐
│                  ADAPTADOR DE REFUTO                   │
│  - Mapeo de Entidades: Target ──► Claim                │
│  - Invocación: CLI o JSON-RPC                          │
│  - Recepción: Decision Capsule                         │
│  - Traducción de Salida: Exit Code / Gate Status       │
└───────────────────────────▲────────────────────────────┘
                            │ (Wire Protocol v1)
                            ▼
┌────────────────────────────────────────────────────────┐
│                   NÚCLEO DE REFUTO                     │
│         (Veredicto Inmutable y Criptográfico)          │
└────────────────────────────────────────────────────────┘
```

---

## 2. Adaptador para AWS AI-DLC (TypeScript / Bun Engine & Conductors)

### 2.1. Frontera Arquitectónica
- **AI-DLC** gestiona el ciclo de vida: etapas (`Plan`, `Code`, `Test`, `Deploy`), directivas (`STAGE_TRANSITION`, `TASK_COMPLETE`) y asignación de agentes de IA.
- **Refuto** actúa como el comando de verificación de construcción (`Construction Verification Command`) y oráculo de compuertas. AI-DLC no puede declarar una transición de fase sin presentar un token criptográfico de decisión emitido por Refuto.

### 2.2. Implementación del Conductor de AI-DLC
En el archivo de habilidades de AI-DLC (`SKILL.md` o TypeScript Conductor):

```typescript
// aidlc-refuto-bridge.ts
import { spawn } from "node:child_process";

export async function verifyWithRefuto(stage: string, contextPath: string): Promise<{ admitted: boolean; reason?: string }> {
  return new Promise((resolve) => {
    const refuto = spawn("python3", [
      "refuto.py", "verify",
      "--capsule",
      "--stage", stage,
      "--workspace", contextPath
    ]);

    let output = "";
    refuto.stdout.on("data", (data) => { output += data; });

    refuto.on("close", (code) => {
      if (code === 0) {
        try {
          const capsule = JSON.parse(output);
          if (capsule.decision.state === "PASS") {
            return resolve({ admitted: true });
          }
          return resolve({ admitted: false, reason: `Estado epistemológico no admisible: ${capsule.decision.state}` });
        } catch (e) {
          return resolve({ admitted: false, reason: "Error de deserialización de cápsula de decisión" });
        }
      }
      resolve({ admitted: false, reason: `Fallo de verificación de compuertas (Código de salida: ${code})` });
    });
  });
}
```

---

## 3. Adaptador para Kiro y Marcos de Agentes Basados en Ganchos (Hooks)

### 3.1. Ganchos de Pre-Edición y Post-Edición
Kiro invoca ganchos antes y después de cada manipulación del sistema de archivos realizada por un agente.
- **Pre-Edición (`pre_tool_call`)**: Comprueba que el agente no intente modificar archivos protegidos (`.harness/policy.json`, compuertas congeladas, ganchos del sistema). Si lo intenta, el adaptador de Refuto rechaza la llamada antes de que toque el disco.
- **Post-Edición (`post_tool_call`)**: Ejecuta una verificación incremental rápida (`refuto preflight`) para garantizar que la edición no rompió la sintaxis, las pruebas básicas o las invariantes estáticas.

### 3.2. Configuración en `.kiro/hooks/refuto-gate.json`
```json
{
  "name": "refuto-assurance-gate",
  "trigger": "post_tool_execution",
  "tool_matcher": "write_to_file|replace_file_content",
  "command": "python3 scripts/preflight.py",
  "fail_behavior": "revert_and_notify_agent",
  "timeout_seconds": 10
}
```

---

## 4. Adaptador para Claude Code, Antigravity y Agentes de Terminal

Para agentes interactivos de terminal, el adaptador ofrece interfaces de consulta rápida y feedback procesable:
1. **Salida Sintetizada para Contexto de LLM**: Formato compacto que resalta la falla específica, la línea exacta y la mutación superviviente sin saturar la ventana de contexto del modelo con trazas irrelevantes.
2. **Recomendaciones Guiadas por el Veredicto**:
   - Ante `FAIL`: "La propiedad X fue violada por la entrada Y. Modifique el código para asegurar el invariante."
   - Ante `INCONCLUSIVE` (ámbito vacío): "Sus pruebas no ejecutaron ninguna afirmación sobre el componente modificado. Añada casos de prueba con aserciones activas."
   - Ante `BLOCKED`: "Un pre-requisito de infraestructura está fallando. Contacte a un operador humano."

---

## 5. Adaptadores para CI/CD (GitHub Actions, GitLab CI, AWS CodePipeline)

### 5.1. GitHub Action Oficial
```yaml
# .github/workflows/refuto-admission.yml
name: Refuto Continuous Verification
on: [push, pull_request]

jobs:
  verify:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Set up Python
        uses: actions/setup-python@v5
        with:
          python-version: '3.14'
      - name: Execute Refuto Verification Gate
        run: |
          python3 refuto.py verify --fail-on-inconclusive --export-sarif results.sarif
      - name: Upload SARIF to GitHub Code Scanning
        uses: github/codeql-action/upload-sarif@v3
        if: always()
        with:
          sarif_file: results.sarif
```

### 5.2. Mapeo Canónico de Códigos de Salida del Adaptador
Para garantizar que los pipelines tradicionales de CI/CD interpreten correctamente los 7 estados no colapsantes de Refuto:

| Estado de Refuto | Código de Salida CI | Acción del Pipeline CI/CD | Justificación |
| :--- | :--- | :--- | :--- |
| `PASS` | `0` | Continuar / Desplegar | Todas las compuertas aprobadas con ámbito verificado. |
| `FAIL` | `1` | Detener / Rechazar PR | Falla explícita detectada por una compuerta. |
| `INCONCLUSIVE` | `2` (o `1` si estricto) | Detener / Rechazar PR | **CRÍTICO**: Ámbito vacío o evidencia insuficiente; jamás se ignora. |
| `BLOCKED` | `3` | Detener / Alerta Infra | Falla de entorno o dependencia externa bloqueada. |
| `DEGRADED` | `4` (o warning) | Advertencia / Despliegue condicional | Pruebas intermitentes o TTL expirado; requiere revisión. |
| `NOT_RUN` | `5` | Detener / Error de Configuración | El plan de pruebas no se ejecutó. |
| `NOT_APPLICABLE` | `0` | Continuar | El componente no aplica al artefacto actual. |
