# 06 · Ontología Formal de Refuto

**Fecha:** 2026-09-30  
**Clasificación:** `FORMAL RESULT` · Especificación Ontológica de Dominio

---

## 1. Entidades Primarias

| Entidad | Tipo | Definición Semántica | Representación en Datos |
| :--- | :--- | :--- | :--- |
| **Workspace ($W$)** | Objeto Físico | El árbol de trabajo gobernado en el sistema de archivos. | Ruta raíz (`Path`) + Digest del árbol |
| **Subject ($S$)** | Actor | La entidad (agente de IA, desarrollador, proceso) que produce cambios. | Identidad tipada (`uid`, modelo, versión) |
| **Judge ($J$)** | Autoridad | El motor de verificación aislado que evalúa afirmaciones y gobierna efectos. | `engine_digest` + binario firmado |
| **Policy ($\Pi$)** | Norma | Reglas de admisibilidad y rutas protegidas. | Documento JSON conforme a `harness.policy/v1` |
| **Claim ($C$)** | Proposición | La afirmación explícita sobre una propiedad verificable. | Documento JSON conforme a `refuto.claim/v1` |
| **Witness ($T$)** | Observador | El instrumento o entidad que genera una observación independiente. | Identidad de testigo tipada (W0 a W4) |
| **Artifact ($A$)** | Objeto | Salida generada por una etapa (código, binario, informe, SBOM). | Path relativo + Hash SHA-256 |
| **Ledger ($L$)** | Registro | El diario append-only inmutable encadenado por huellas criptográficas. | `ledger.jsonl` encadenado |

---

## 2. Eventos Epistémicos

1. **`ClaimSubmitted`:** Un emisor formaliza una afirmación a verificar.
2. **`ActionIntercepted`:** El guardián intercepta un efecto de consola o sistema de archivos antes de su ejecución.
3. **`ObservationRecorded`:** Un testigo completa la ejecución de un instrumento y registra la medición con su `Scope`.
4. **`DiscontinuityDeclared`:** Una persona autorizada registra formalmente una discontinuidad conocida en la cadena de auditoría (ADR-0019).
5. **`AnchorCertified`:** Un quórum BFT de réplicas independientes ordena y firma un checkpoint del diario (ADR-0017).
6. **`DecisionRendered`:** El kernel emite una `Decision Capsule` vinculante.

---

## 3. Relaciones Formales

* **`AuthoredBy(A, S)`:** El artefacto $A$ fue creado o modificado por el sujeto $S$.
* **`ObservedBy(O, T)`:** La observación $O$ fue realizada por el testigo $T$.
* **`Supports(ε, C)`:** La evidencia $\varepsilon$ satisface la demostración de la propiedad del Claim $C$.
* **`Contradicts(ε, C)`:** La evidencia $\varepsilon$ contiene al menos un hallazgo que refuta el Claim $C$.
* **`Coauthored(A, Test)`:** El sujeto $S$ modificó simultáneamente el artefacto $A$ y la prueba $Test$.  
  $$\text{Coauthored}(A, Test) \implies \text{WitnessTier}(Test) \le W1$$
* **`MonotoneRefinement}(\Pi_1, \Pi_2)`:** La política $\Pi_2$ restringe o preserva todas las restricciones de $\Pi_1$ ($\Pi_2 \sqsubseteq \Pi_1$).

---

## 4. Retículo de Estados y Semántica de Decisión

Los 7 estados forman un retículo semántico donde el orden refleja la suficiencia epistémica:

```
                  PASS (Demonstrably True with Scope)
                 /    \
         DEGRADED      \
                \      /
             INCONCLUSIVE (Uncertain / Contradictory)
             /     |    \
      NOT_RUN   BLOCKED  NOT_APPLICABLE
             \     |    /
                  FAIL (Demonstrably False)
```

* **Regla de Absorción de Fallo:** Un `FAIL` demostrado manda sobre cualquier incertidumbre (`INCONCLUSIVE`).
* **Regla de Bloqueo:** `BLOCKED` y `NOT_EXECUTABLE` impiden emitir `PASS` pero no constituyen refutación intrínseca del código, sino incapacidad operativa de evaluación.
* **Regla de Inaplicabilidad:** `NOT_APPLICABLE` exige justificante escrito; no participa en el cálculo de aprobados.
