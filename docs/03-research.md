# 03 · Estado del Arte e Investigación Científica

**Fecha:** 2026-09-30  
**Áreas:** Métodos Formales, Runtime Verification, Assurance Cases, Proof-Carrying Code, Cadena de Suministro de Software, Gobernanza de Políticas y Evaluación de Sistemas Autónomos.

---

## 1. Corpus de Literatura Científica Primaria

### 1.1 Proof-Carrying Code (PCC)
* **Referencia:** Necula, G. C. (1997). *Proof-Carrying Code*. 24th ACM SIGPLAN-SIGACT Symposium on Principles of Programming Languages (POPL '97).
* **Clasificación:** `FORMAL RESULT` (Confianza: `1.0`).
* **Hallazgo Principal:** Un ejecutable o artefacto no confiable puede ser admitido en un entorno seguro si el productor adjunta una prueba formal de seguridad que el consumidor puede verificar de manera determinista y de bajo costo computacional sin confiar en el productor.
* **Limitaciones:** En el trabajo original de Necula, la generación de pruebas para propiedades no triviales requería demostradores de teoremas interactivos o compiladores certificadores complejos.
* **Relevancia para Refuto:** Es el fundamento directo de las **Decision Capsules**: el agente de IA no entrega sólo código, entrega una cápsula que contiene el Claim, la evidencia de los testigos y la prueba de invariantes que Refuto valida offline.

### 1.2 Assurance Cases y Notación GSN (Goal Structuring Notation)
* **Referencia:** Kelly, T., & Weaver, R. (2004). *The Goal Structuring Notation – A Safety Argumentation Grid*. Dependable Systems and Networks.
* **Clasificación:** `INDUSTRY PRACTICE` / `EMPIRICAL EVIDENCE` (Confianza: `0.9`).
* **Hallazgo Principal:** La seguridad y confiabilidad de sistemas críticos no se demuestra mediante pruebas aisladas, sino mediante una estructura jerárquica explícita de Metas (Goals/Claims), Contexto (Context), Estrategias (Strategies) y Evidencias concretas (Solutions/Evidence).
* **Limitaciones:** Tradicionalmente estático y redactado por humanos para certificaciones aeronáuticas o nucleares (DO-178C, ISO 26262), con escasa automatización en tiempo de compilación.
* **Relevancia para Refuto:** Refuto automatiza la construcción dinámica de Assurance Cases para ingeniería de software asistida por IA: Claim $\rightarrow$ Context $\rightarrow$ Policy $\rightarrow$ Evidence $\rightarrow$ Decision.

### 1.3 Runtime Verification y Monitores de Referencia
* **Referencia:** Leucker, M., & Schallhart, C. (2009). *A Brief Account of Runtime Verification*. The Journal of Logic and Algebraic Programming, 78(5), 293-303.
* **Clasificación:** `FORMAL RESULT` / `EMPIRICAL EVIDENCE` (Confianza: `0.95`).
* **Hallazgo Principal:** La verificación en tiempo de ejecución evalúa si una traza de ejecución concreta satisface una propiedad formal, complementando las pruebas estáticas con la detección in-situ de desviaciones semánticas.
* **Limitaciones:** No garantiza exhaustividad sobre estados no explorados; el monitor puede incurrir en sobrecarga computacional si no está aislado eficientemente.
* **Relevancia para Refuto:** Fundamento del Reference Monitor de Refuto ([`core/guard.py`](../core/guard.py)): intercepción de efectos sobre el sistema de archivos y ejecución de comandos en tiempo de ejecución.

### 1.4 Seguridad en la Cadena de Suministro: in-toto y SLSA
* **Referencia:** Torres-Arias, S., et al. (2019). *in-toto: Providing Farm-to-Table Guarantees for Bits and Bytes*. USENIX Security Symposium.
* **Clasificación:** `INDUSTRY PRACTICE` / `EMPIRICAL EVIDENCE` (Confianza: `0.95`).
* **Hallazgo Principal:** La integridad del software requiere registrar atestaciones criptográficas firmadas por cada actor en cada eslabón de la cadena de suministro, vinculando entradas, pasos y salidas mediante metadatos inmutables.
* **Limitaciones:** in-toto verifica el proceso de compilación y empaquetado humano/CI, pero no modela la generación de código por modelos de lenguaje ni el razonamiento de agentes autónomos.
* **Relevancia para Refuto:** Refuto extiende in-toto y SLSA (Supply-chain Levels for Software Artifacts v1.0) hacia la **Cadena de Suministro de Ingeniería Asistida por IA**: atestación del prompt, modelo, contexto, código, pruebas y decisiones de gates.

### 1.5 The Oracle Problem in Software Testing
* **Referencia:** Barr, E. T., et al. (2015). *The Oracle Problem in Software Testing: A Survey*. IEEE Transactions on Software Engineering, 41(5), 507-525.
* **Clasificación:** `EMPIRICAL EVIDENCE` (Confianza: `1.0`).
* **Hallazgo Principal:** Un test suite sin un oráculo independiente no puede distinguir entre un comportamiento correcto y un fallo silencioso. Las aserciones triviales o generadas por el mismo autor del código sufren sistemáticamente de oráculos débiles o tautológicos.
* **Limitaciones:** El estudio analizó desarrollo humano; con agentes generativos el problema se agrava exponencialmente por alucinación convergente.
* **Relevancia para Refuto:** Justifica la separación obligatoria entre el generador de código/tests y el árbitro de verificación (Anti-Circularity Graph).

---

## 2. Tecnologías de Frontera en la Industria

| Tecnología | Rol en la Industria | Aporte Reutilizable | Lo que le falta (White Space para Refuto) |
| :--- | :--- | :--- | :--- |
| **Open Policy Agent (OPA)** | Motor de políticas de propósito general (Rego). | Evaluación declarativa desacoplada del consumidor. | No modela evidencia empírica ni precondiciones de cobertura (`Scope`). |
| **Sigstore / Rekor** | Firma de artefactos y registro de transparencia append-only. | Prueba criptográfica de inclusión y no-repudio. | Se limita a atestar artefactos compilados; no audita el proceso cognitivo de ingeniería. |
| **OpenTelemetry (OTel)** | Estándar de observabilidad distribuida (trazas, métricas, logs). | Taxonomía de eventos estructurados y contexto de propagación. | Telemetría no es verificación: registrar que algo ocurrió no demuestra que sea correcto. |
| **SLSA Framework** | Niveles de seguridad de construcción (L1 a L3). | Requisitos de inmutabilidad y compilación aislada. | Ignora la validez interna del código y el rol de los agentes de IA. |
