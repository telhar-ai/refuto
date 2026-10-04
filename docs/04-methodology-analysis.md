# 04 · Análisis de Metodologías: SDD, TDD, BDD, DDD, DevSecOps, AI-DLC y AI Engineering

**Fecha:** 2026-09-30  
**Premisa Científica:** *La adhesión a una metodología no equivale a la verdad empírica ni a la corrección del sistema.*

---

## 1. Análisis Metodología por Metodología

### 1.1 Specification-Driven Development (SDD)
* **Qué aporta:** Centralidad del contrato. La especificación formal o ejecutable precede a la implementación; define las interfaces y las invariantes esperadas.
* **Qué asume:** Asume que la especificación está completa, que no contiene contradicciones internas y que las herramientas de generación o pruebas interpretan fielmente su semántica.
* **Qué NO demuestra:** No demuestra que la especificación refleje la verdadera intención del negocio, ni que el entorno de ejecución no vulnere las asunciones del contrato, ni que los tests derivados no sufran del problema del oráculo.
* **Complemento de Refuto:** Refuto evalúa la trazabilidad estricta (puerta `G-TRACE`): verifica que ningún commit introduzca código sin un requisito asociado, que la especificación sea inmutable bajo lock y que las pruebas ejecuten sobre un ámbito no vacío.

### 1.2 Test-Driven Development (TDD)
* **Qué aporta:** Diseño guiado por pruebas en bucle corto (*Red-Green-Refactor*). Fomenta código desacoplado y suites de regresión automatizadas.
* **Qué asume:** Asume que un test en verde (`PASS`) demuestra que el requisito se cumple, y que el desarrollador (o agente) no escribió una prueba tautológica o trivial.
* **Qué NO demuestra:** No demuestra adecuación de pruebas (*test adequacy*). Un test puede dar `PASS` con una aserción `assert True`, con cobertura de líneas que no ejecuta aserciones, o probando un caso no representativo.
* **Complemento de Refuto:** Refuto aplica **La Prueba del Vacío**: si la suite de tests ejecuta 0 pruebas, Refuto emite `FAIL` o `BLOCKED`. Además, mediante análisis de mutaciones e invariantes de `Scope`, Refuto comprueba si la prueba realmente observó sujetos y si el oráculo es independiente.

### 1.3 Behavior-Driven Development (BDD)
* **Qué aporta:** Lenguaje ubicuo orientado al comportamiento del usuario (*Given-When-Then* / Gherkin). Facilita la comunicación entre negocio y desarrollo.
* **Qué asume:** Asume que los pasos (*glue code*) mapean fielmente las frases de negocio a la lógica real del sistema y que las precondiciones (*Given*) se aíslan correctamente.
* **Qué NO demuestra:** No demuestra ausencia de efectos secundarios fuera del escenario probado, ni resistencia frente a atacantes adversariales que no siguen las historias de usuario estándar.
* **Complemento de Refuto:** Refuto audita la procedencia y el contexto: asegura que los escenarios de aceptación cuenten con revisión humana explícita (`G-HUMAN`) y que las aserciones no hayan sido manipuladas en la misma transacción que el código.

### 1.4 Domain-Driven Design (DDD)
* **Qué aporta:** Modelado del dominio mediante Contextos Acotados (*Bounded Contexts*), Agregados e Invariantes del dominio.
* **Qué asume:** Asume que los límites arquitectónicos se respetan en el código y que no existen fugas de abstracción a nivel de base de datos o transporte.
* **Qué NO demuestra:** No demuestra que en tiempo de ejecución las dependencias entre módulos no violen las fronteras del agregado.
* **Complemento de Refuto:** Refuto valida invariantes arquitectónicas estáticas y dinámicas: analiza grafos de importación, dependencias circulares y restricciones de acceso a través de políticas efectivas.

### 1.5 DevSecOps
* **Qué aporta:** Automatización de seguridad en el pipeline de entrega continua (SAST, DAST, SCA, SBOM, escaneo de secretos).
* **Qué asume:** Asume que la presencia de escáneres en el pipeline garantiza seguridad y que la ausencia de alertas equivale a código seguro.
* **Qué NO demuestra:** Un escáner que revienta con error, que sufre de timeout o que no soporta un lenguaje produce código de salida 0 en muchos pipelines deficientes, convirtiendo la ignorancia en falsa seguridad.
* **Complemento de Refuto:** Puerta `G-SECURITY` con modelo fail-closed: si `trivy` o `syft` no están instalados, Refuto emite `BLOCKED`; si fallan o exceden el tiempo, emite `NOT_EXECUTABLE`; si escanean 0 archivos, emite `INCONCLUSIVE`. La ausencia de hallazgos sólo aprueba si `Scope.examined > 0`.

### 1.6 AWS AI-DLC (AI-Driven Development Life Cycle)
* **Qué aporta:** Metodología estructurada de tres fases (*Inception, Construction, Operations*) para guiar agentes de IA mediante directivas deterministas, etapas, cercas (*fences*) y compresión de contexto.
* **Qué asume:** Asume que los sensores de etapa y el *Construction Verification Command* son suficientes para garantizar la verdad del producto.
* **Qué NO demuestra:** No garantiza la independencia del evaluador frente al agente, ni la inmutabilidad criptográfica del diario de auditoría, ni la resistencia matemática contra el vacío.
* **Complemento de Refuto:** Refuto actúa como el **Verification Kernel** externo al que AI-DLC consulta en cada checkpoint: Refuto valida Claims formales, atesta con quórum BFT y devuelve una `Decision Capsule` vinculante.

---

## 2. El Problema de la Confianza Circular en AI Engineering

En la ingeniería de software asistida por IA contemporánea emerge un fallo epistemológico fundamental:

$$\text{Agente Genera Código} \longrightarrow \text{Agente Genera Test} \longrightarrow \text{Agente Ejecuta Test} \longrightarrow \text{Agente Reporta: PASS}$$

Si el mismo actor cognitivo controla la implementación, el criterio de prueba y la evaluación del resultado, el sistema no produce **aseguramiento de calidad**, sino **eco y complacencia generativa**.

### La Ruptura de Circularidad de Refuto
Refuto desacopla la verdad del flujo del agente:
1. **El Árbitro Aislado:** El kernel de Refuto se ejecuta con identidad y huella independientes (`engine_digest`).
2. **Rutas Protegidas:** Las especificaciones, políticas y puertas están fuera del alcance de escritura del agente.
3. **Jerarquía de Testigos:** El reporte del agente se clasifica como testigo débil `W0` (Self-Attested) y no puede sostener una `Decision Capsule` de nivel `E3+`.
