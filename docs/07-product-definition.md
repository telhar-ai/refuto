# 07 · Definición de Producto: Refuto como Infraestructura de Verificación

**Fecha:** 2026-09-30  
**Tesis de Producto:** *«Refuto mejora el proceso que ya utilizas aportando verificación, evidencia, confianza y decisión matemática, sin introducir otro ciclo de vida obligatorio.»*

---

## 1. Arquetipos de Usuario y Jobs-to-be-Done (JTBD)

| Usuario | Job-to-be-Done Principal | Dolor que Resuelve Refuto | Valor Aportado |
| :--- | :--- | :--- | :--- |
| **Developer** | Saber si mi cambio realmente cumple los requisitos antes de enviar un PR. | Falsos positivos en suites locales; pasar pruebas que no prueban nada (vacías). | Veredicto determinista instantáneo con análisis de cobertura real de scope. |
| **Architect** | Garantizar que las restricciones arquitectónicas y límites de dominio no se degraden. | La erosión arquitectónica silenciosa provocada por refactorizaciones no supervisadas. | Verificación estática y dinámica de invariantes de dependencias y aislamiento de dominio. |
| **QA / Test Engineer** | Demostrar que los casos de prueba cubren las especificaciones sin tautologías. | Pruebas end-to-end frágiles y suites que dan verde ejecutando cero aserciones reales. | Oráculos diferenciales y detección matemática de suites con ámbito vacío (`examined == 0`). |
| **Security Engineer** | Asegurar que ningún commit introduzca secretos, dependencias vulnerables o escalada de privilegios. | Escáneres que fallan silenciosamente con código 0 o scripts con bypass tipo `sudo`. | Control fail-closed de herramientas (trivy/syft/gitleaks) y monitor de privilegios estricto (ADR-0020). |
| **AI Engineer** | Integrar agentes de codificación autónomos (Claude Code, Kiro, Codex) sin perder el control. | Agentes que generan código, escriben tests a medida para que pasen y reportan falsos éxitos. | Ruptura de circularidad mediante testigos independientes y rutas protegidas inmutables. |
| **AI Agent** | Conocer con certeza matemática qué reglas y políticas rigen mi entorno de trabajo. | Instrucciones en prompts ambiguas o cambiantes que causan denegaciones imprevistas. | Contrato formal de directivas y políticas compiladas al dialecto nativo de cada harness. |
| **Auditor / Compliance** | Demostrar ante reguladores que el software cumple normas sin depender de capturas de pantalla. | Informes de auditoría redactados a posteriori fácilmente falsificables. | Diario inmutable append-only encadenado por huellas y anclado en quórum BFT (Concordia/Sigstore). |
| **Engineering Org** | Estandarizar la gobernanza de ingeniería sobre múltiples equipos, nubes y metodologías. | Fatiga metodológica: obligar a todos los equipos a reescribir sus procesos hacia un único marco. | Integración universal como capa complementaria: soporta SDD, TDD, AI-DLC, etc., simultáneamente. |

---

## 2. Flujo de Entradas, Procesamiento y Salidas

### 2.1 Entradas (*Inputs*)
1. **Sujeto de Verificación:** Repositorio git, commit SHA, árbol de trabajo o artefacto de compilación.
2. **Afirmación formal (`Claim`):** Documento JSON declarando la propiedad a demostrar (ej. `security.zero_vulnerabilities`, `correctness.tests`).
3. **Política Organizacional (`Policy`):** Reglas base y extensiones jerárquicas heredadas (`.harness/policy.json`).
4. **Contexto de Ejecución:** Variables de entorno, harness activo y perfil de permisos.

### 2.2 Procesamiento (*Kernel Processing*)
1. **Resolución de Política:** Cálculo de la política efectiva con verificación de monotonía y aciclicidad.
2. **Evaluación de Cobertura (Prueba del Vacío):** Comprobación estricta de que el universo a examinar esté declarado y que $\text{examined} > 0$.
3. **Despacho a Testigos Independientes:** Ejecución de instrumentos locales, oráculos o verificación de firmas de consenso.
4. **Validación de No-Circularidad:** Análisis del grafo de autoría entre el emisor del cambio y los autores de los tests.
5. **Encadenamiento en el Diario:** Adición del evento al libro append-only con fsync y bloqueo a nivel de OS.

### 2.3 Salidas (*Outputs*)
1. **Decision Capsule (`refuto.decision-capsule/v1`):** Artefacto inmutable y portable firmado criptográficamente con el veredicto en 7 estados.
2. **Reporte Humano Estructurado:** Diagnóstico de consola explicativo con instrucciones de remediación (`next actions`).
3. **Checkpoint de Anclaje:** Notificación al clúster de consenso con el digest del estado actual del diario.
