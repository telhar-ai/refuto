# 15 · Modelo de Confianza e Integridad (Trust Model v1)

**Fecha:** 2026-09-30  
**Principio Rector:** *«Confianza verificable mediante matemática y criptografía, no mediante reputación ni asunciones implícitas.»*

---

## 1. Raíz de Confianza y Políticas Efectivas

La confianza en Refuto se construye como una cadena acíclica y monótona desde una **Raíz de Confianza (`RootOfTrust`)** inmutable:

$$\text{RootOfTrust} \longrightarrow \Pi_{\text{organizacion}} \longrightarrow \Pi_{\text{equipo}} \longrightarrow \Pi_{\text{proyecto}}$$

### Propiedad de Monotonía de Refinamiento
Para toda política hija $\Pi_{\text{hijo}}$ que hereda de $\Pi_{\text{padre}}$ mediante `extends`:
$$\Pi_{\text{hijo}} \sqsubseteq \Pi_{\text{padre}}$$

* **Regla:** Un hijo sólo puede **añadir restricciones** (añadir rutas a `protected_paths`, añadir comandos a `command_deny`, reducir tiempos de expiración).
* **Invariante Duro:** Si un hijo intenta retirar una denegación o desproteger una ruta del padre, el motor de políticas ([`core/policy.py`](../core/policy.py)) aborta con error de validación (`ViolaciónDeMonotonía`).

---

## 2. Anclaje Criptográfico por Consenso (ADR-0017)

Para evitar los ataques de manipulación local del diario (reescritura coherente, truncación de cola, sustitución total), Refuto implementa el **Anclaje Certificado en Concordia**:

### 2.1 Estructura del Checkpoint Anclado
```json
{
  "schema": "refuto.checkpoint/v1",
  "origin": "repo:example-org/auth-service",
  "run_id": "ver_4e56404815c8465e",
  "size": 3352,
  "root": "6d90d151d3210387b83362720b7d74805884557fa2db0b128ab2d58921c00a72",
  "engine_digest": "eaa89b646d0e150fed85ead2a4ed2063c3cd4631c8824f87efefd57b5410babf",
  "policy_digest": "4b227777d4dd1fc61c6f884f48641d02b4d121d3fd328cb08b5531fcacdabf8a",
  "membership_digest": "88a1b2c3d4e5f6..."
}
```

### 2.2 Verificación Offline en Python Puro
Refuto no delega la verificación del certificado en librerías externas o demonios:
1. Reconstruye el sujeto canónico de 140 bytes en [`core/concordia.py`](../core/concordia.py).
2. Valida las firmas de las réplicas mediante el motor Ed25519 pure-Python ([`core/ed25519.py`](../core/ed25519.py)) implementado conforme a RFC 8032 utilizando únicamente `hashlib`.
3. Comprueba que el quórum de firmantes válidos satisfaga $\ge q$ bajo el pin de membresía congelado en el manifiesto (`anchoring.membership_digest`).
4. Reconcilia que la cabeza del diario local coincida exactamente con el `root` y `size` certificados.

---

## 3. Discontinuidades Declaradas y Cicatrices (ADR-0019)

Una cadena con una rotura accidental (por ejemplo, provocada por una caída de energía durante una escritura concurrente) no debe quedar inservible para siempre ni forzar al operador a borrar el diario.

* **El Mecanismo:** Una persona autorizada registra en `.harness/evidence/discontinuities/declared.json` la discontinuidad:
  ```json
  {
    "line": 142,
    "found_prev": "3a1b4c...",
    "expected_head": "88e1a2...",
    "cause": "Caída de proceso durante carrera de escritura",
    "declared_by": "persona@example.org",
    "declared_at": "2026-09-28T15:30:00Z"
  }
  ```
* **Invariante Antifraude:** La declaración sólo surte efecto si coincide exactamente con el byte y línea rotos. La cadena se marca como `CICATRIZADA`, permitiendo que la verificación continúe de forma transparente y auditable, sin simular una integridad perfecta falsa.
