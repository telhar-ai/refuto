# 10 · Arquitectura de Integración: Coexistencia Orgánica con Múltiples Marcos

**Fecha:** 2026-09-30  
**Principio Rector:** *«Refuto se integra en los puntos naturales de decisión de cada marco, sin obligar al equipo a modificar su metodología ni sus herramientas de trabajo.»*

---

## 1. Matriz de Integración Universal

| Marco de Ingeniería | Punto de Integración de Refuto | Entrada desde el Marco | Salida emitida por Refuto | ¿Qué NO hace Refuto? |
| :--- | :--- | :--- | :--- | :--- |
| **Specification-Driven (SDD)** | Gate de Aprobación de Spec / Contrato | `spec.md` + contrato de interfaz | `Decision Capsule: G-TRACE + G-MANIFEST` | No redacta ni sustituye la especificación. |
| **Test-Driven (TDD)** | Post-ciclo Green / Refactor | Suite de tests (`pytest`, `jest`) | Evaluación de Cobertura de Scope + Detección de Vacío | No escribe las pruebas ni dicta la granularidad unitaria. |
| **Behavior-Driven (BDD)** | Aceptación de Historias de Usuario | Archivos `.feature` + trazas de pasos | `Decision Capsule: G-HUMAN + Traza de Aceptación` | No reemplaza el framework Cucumber / Behave. |
| **Domain-Driven (DDD)** | Verificación de Invariantes de Dominio | Grafo de dependencias entre módulos | Atestación de Aislamiento de Agregados | No impone el modelado de entidades ni repositorios. |
| **DevSecOps** | Pull Request / Pre-Merge Hook | Manifiestos de dependencias + SBOM | `Decision Capsule: G-SECURITY + G-LOCK` | No actúa como repositorio de paquetes ni SIEM. |
| **AWS AI-DLC** | Gate de Construcción / Checkpoint | Directiva `run-stage` / `Unit Verification` | `Decision Capsule` vinculante para avance de etapa | No orquesta swarms ni descompone requisitos. |
| **Kiro CLI / IDE** | Hook nativo ACP / MCP | Solicitud de herramienta del agente | Veredicto de Admisibilidad en `PreToolUse` | No reemplaza el editor ni el modelo LLM subyacente. |
| **Claude Code** | Settings Hook / Pre-Tool Interceptor | Comando bash invocado por el agente | Decisión de Permiso (`allow`, `deny`, `ask`) | No altera los prompts ni el flujo conversacional. |
| **CI/CD (GitHub/GitLab)** | Pipeline Gate Step | Contexto del runner git y commit SHA | Veredicto SARIF + Exit Code de Admisión | No gestiona workers ni máquinas virtuales de CI. |

---

## 2. Patrones de Integración Técnica

### 2.1 Patrón 1: Interceptación Local mediante Hooks (Zero-Friction)
El agente de IA (Claude, Kiro, Codex) opera con normalidad. En el instante previo a invocar una herramienta que produce efectos (ej. editar un archivo o correr un comando bash), el hook nativo invoca a `core.guard` en milisegundos:
```
Agente ──► Hook Local ──► core.guard ──► Decide (allow / deny / ask) ──► Retorna al Agente
```
*Garantía:* Si la orden intenta modificar rutas protegidas (`gates/**`, `.harness/policy.json`) o elevar privilegios de forma indebida, el guardián la bloquea antes de que toque el sistema operativo.

### 2.2 Patrón 2: Verificación por Delegación de Claims (Frameworks como AI-DLC)
Cuando un framework de ciclo de vida alcanza una etapa que requiere validación empírica:
1. El framework formula un `Claim` estructurado describiendo la propiedad cumplida.
2. Invoca el CLI de Refuto:
   ```bash
   refuto verify --claim claim.json --json
   ```
3. Refuto ejecuta las comprobaciones con oráculos independientes y devuelve una `Decision Capsule`.
4. El framework lee el campo `can_advance_stage: true|false` y continúa su flujo sin necesidad de reescribir su lógica interna.

### 2.3 Patrón 3: Admisión Desatendida en CI/CD
En el pipeline de integración continua, Refuto corre como una puerta estricta:
```bash
refuto verify --gate G-SECURITY,G-LOCK,G-PR
```
Si el resultado no cumple los requisitos de cobertura o contiene violaciones, el proceso retorna código de error y emite un informe estructurado que bloquea el merge en GitHub/GitLab.
