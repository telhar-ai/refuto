# 14 · Modelo de Testigos e Independencia de Evidencia (Witness Model v1)

**Fecha:** 2026-09-30  
**Principio Fundamental:** *«Un agente diciendo PASS no es evidencia independiente de que el código funciona.»*

---

## 1. Jerarquía y Taxonomía de Testigos (Tiers W0 a W4)

Refuto clasifica formalmente la autoridad y el grado de aislamiento de todo testigo:

```
[ Tier W4: Consenso Notarial Distribuido ]  ──►  Quórum BFT (Concordia / Sigstore Rekor)
                     ▲
                     │
[ Tier W3: Ejecutor Aislado Externo ]       ──►  CI/CD Runner efímero con OIDC (GitHub/AWS)
                     ▲
                     │
[ Tier W2: Monitor de Referencia Local ]    ──►  Kernel de Refuto aislado fuera del workspace
                     ▲
                     │
[ Tier W1: Instrumento Local del Workspace ] ──►  Subprocesos locales (pytest, trivy, syft)
                     ▲
                     │
[ Tier W0: Auto-Atestación del Agente ]     ──►  LLM / Prompt reportando su propio éxito
```

| Nivel | Identificador | Grado de Aislamiento | Valor Probatorio | Vulnerabilidad Principal |
| :---: | :--- | :--- | :---: | :--- |
| **W0** | `Self-Attested` | Mismo proceso cognitivo del agente. | `0.0` | Alucinación complaciente; sesgo de confirmación. |
| **W1** | `Local Instrument` | Mismo sistema de archivos y usuario del workspace. | `0.3` | El agente puede mutar el script de prueba o el binario. |
| **W2** | `Isolated Monitor` | Proceso independiente con `engine_digest` fijo. | `0.7` | Ataques a nivel de kernel/OS si comparten `uid`. |
| **W3** | `External CI` | Máquina virtual / contenedor efímero aislado. | `0.9` | Compromiso de credenciales de CI o red externa. |
| **W4** | `BFT Consensus` | Quórum de $\ge q$ nodos con claves Ed25519 independientes. | `1.0` | Colusión de más de un tercio bizantino ($f \ge n/3$). |

---

## 2. Teoremas de Separación de Confianza (Anti-Circularity)

### 2.1 Teorema 1: No-Coautoría de Oráculos
> *«Si el conjunto de archivos modificados por el sujeto $S$ en la transacción $T$ interseca tanto la implementación $I$ como la suite de pruebas $E$, el valor probatorio de $E$ para $I$ en $T$ se degrada a W0.»*

* **Mitigación en Refuto:**  
  Refuto inspecciona el diff del commit git. Si el agente modificó `test_auth.py` y `auth.py` en el mismo cambio, la puerta `G-PR` marca la corrida como `INCONCLUSIVE` para Claims de regresión, exigiendo contraste con el oráculo del commit base o aprobación humana explícita (`HUMAN_APPROVAL`).

### 2.2 Teorema 2: Invarianza del Juez (ADR-0018)
> *«El motor que evalúa no puede residir en el mismo árbol mutable que el sujeto edita.»*

* **Mitigación en Refuto:**  
  `core/trust.py` computa en cada invocación el hash SHA-256 canónico del código fuente de Refuto (`engine_digest`). Si el hash no coincide con el digest certificado al iniciar la sesión, el veredicto es inmediatamente degradado a `INCONCLUSIVE`, reportando que el juez fue alterado.

### 2.3 Teorema 3: Separación entre Orquestación y Veredicto
> *«La entidad responsable de mover el ciclo de vida hacia adelante no puede tener autoridad para firmar la completitud de las puertas de verificación.»*

* **Mitigación en Refuto:**  
  AI-DLC o el Conductor de Claude Code solicitan la verificación; es el kernel de Refuto quien de forma autónoma evalúa las reglas y emite la `Decision Capsule`.
