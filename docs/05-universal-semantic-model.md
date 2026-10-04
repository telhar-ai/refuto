# 05 · Modelo Semántico Universal para Infraestructura de Verificación

**Fecha:** 2026-09-30  
**Objetivo:** Establecer el núcleo semántico mínimo universal que subyace a cualquier proceso de ingeniería de software (humano, asistido por IA o autónomo), desacoplado de sintaxis, herramientas o proveedores.

---

## 1. La Cadena de Derivación Semántica

Cualquier metodología de ingeniería existente o futura puede proyectarse sobre una secuencia formal de transformaciones epistémicas:

```
[ INTENCIÓN (Humana / Negocio) ]
               │
               ▼
       [ REQUISITO (R) ]
               │
               ▼
     [ AFIRMACIÓN / CLAIM (C) ] ◄─── [ POLÍTICA / POLICY (Π) ]
               │                                │
               ▼                                ▼
     [ PROPIEDAD / PROPERTY (P) ] ──► [ REQUISITOS DE COBERTURA (Scope Req) ]
               │
               ▼
    [ OBSERVACIÓN / WITNESS (O) ] ──► [ ÁMBITO OBSERVADO (Scope: examined > 0) ]
               │
               ▼
       [ EVIDENCIA (ε) ]
               │
               ▼
      [ DECISIÓN / VEREDICTO ] ──► [ CÁPSULA INMUTABLE (Decision Capsule) ]
               │
               ▼
       [ CONFIANZA / TRUST ]
```

---

## 2. Definición Formal de las Primitivas del Núcleo

### 2.1 Intención (*Intent*)
El propósito original formulado por un actor humano o directiva organizacional. No es directamente ejecutable ni verificable por una máquina en su estado puro.
* *Ejemplo:* «Garantizar que los datos de pago no se almacenen en texto plano».

### 2.2 Requisito (*Requirement*)
La especificación operativa, acotada y contextualizada de la intención.
* *Ejemplo en SDD:* Una sección en `spec.md`.
* *Ejemplo en BDD:* Un escenario Gherkin `Scenario: Cifrado de tarjeta`.
* *Ejemplo en DevSecOps:* Una regla de cumplimiento SOC2 / PCI-DSS.

### 2.3 Afirmación (*Claim*)
Una aserción formal, falsable y tipada que un actor realiza sobre un sujeto en un estado determinado.
* *Fórmula:* $\text{Claim}(S, P, \sigma)$ donde $S$ es el sujeto (ej. commit git), $P$ es la propiedad requerida y $\sigma$ es el contexto/alcance.

### 2.4 Propiedad (*Property*)
El predicado matemático o lógico sobre el estado o el comportamiento del sujeto.
* *Ejemplo:* $\forall f \in \text{Files}(S) : \text{Entropy}(f) < \text{Threshold} \lor \text{Encrypted}(f)$.

### 2.5 Política (*Policy - $\Pi$*)
El conjunto de reglas, restricciones e invariantes que rigen qué transiciones de estado, efectos y afirmaciones son admisibles en la organización. Debe satisfacer la propiedad de **monotonía de refinamiento**: un subentorno sólo puede restringir, nunca relajar las reglas de la raíz.

### 2.6 Ámbito de Cobertura (*Scope*)
La tupla formal $\text{Scope} = (\text{examined}: \mathbb{N}, \text{unknown}: \mathbb{N}, \text{universe}: \text{String}, \text{declared}: \mathbb{B})$ que cuantifica la observación.
* **Invariante Central:** $\text{Scope.examined} > 0 \land \text{Scope.unknown} = 0$. Si $\text{Scope.examined} == 0$, el resultado jamás puede ser `PASS`.

### 2.7 Observación y Testigo (*Observation & Witness*)
La medición empírica efectuada por un agente o instrumento evaluador independiente (*Witness*). La observación registra el método, la herramienta, la versión y la salida cruda.

### 2.8 Evidencia (*Evidence - $\varepsilon$*)
El registro inmutable, trazable y sellado criptográficamente de una o más observaciones que respaldan o refutan un Claim.

### 2.9 Decisión (*Decision*)
La evaluación lógica no colapsable que compara la evidencia recolectada frente a los requerimientos de la política:
$$\text{Decision} \in \{\text{PASS}, \text{FAIL}, \text{BLOCKED}, \text{NOT\_RUN}, \text{INCONCLUSIVE}, \text{DEGRADED}, \text{NOT\_APPLICABLE}\}$$

### 2.10 Confianza (*Trust*)
La propiedad emergente de una decisión respaldada por una cadena de evidencia íntegra, testigos independientes no circulares y anclaje criptográfico verificable por un tercero.
