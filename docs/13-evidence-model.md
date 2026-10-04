# 13 · Modelo Formal de Evidencia (Evidence Model v1)

**Fecha:** 2026-09-30  
**Esquema:** `refuto.observation/v1` & `refuto.evidence-pack/v1`

---

## 1. ¿Qué separa la Evidencia de los Datos Simples?

En la arquitectura de Refuto, **los datos no son evidencia**. Un archivo de log o una salida en consola sólo asciende a la categoría epistémica de **Evidencia ($\varepsilon$)** si satisface cinco propiedades formales:

1. **Atribución de Testigo Identificable:** Se conoce qué entidad o instrumento la produjo, bajo qué versión y con qué nivel de aislamiento.
2. **Contexto de Procedencia Estricto:** Lleva asociadas las coordenadas exactas de ejecución: commit git, rama, dirty flag, plataforma OS, digest del intérprete y digest del motor que juzgó (`engine_digest`).
3. **Inmutabilidad y Sellado Criptográfico:** Su contenido está protegido por huella hash canónica (JSON canónico sin espacios) y encadenado al diario `ledger.jsonl`.
4. **Declaración Explícita de Cobertura (`Scope`):** Declara cuántos elementos del universo examinó y cuántos no pudo observar (`unknown`).
5. **No Falsabilidad de Vacío:** No puede derivarse de una verdad matemática vacua sobre un conjunto vacío de observaciones.

---

## 2. Esquema Formal de una Observación

```yaml
observation:
  schema: "refuto.observation/v1"
  observation_id: "obs_01J9X2P5A6B7C8"
  claim_id: "clm_01J9X2K4N8M1Q5P9R3T7V2W4Y6"
  timestamp: "2026-09-30T02:00:15.120Z"

  # Identidad del Testigo
  witness:
    tier: "W2_ISOLATED_MONITOR"
    identity: "refuto.core.guard"
    binary_digest: "sha256:eaa89b646d0e150fed85ead2a4ed2063c3cd4631c8824f87efefd57b5410babf"

  # Método y Entorno de Medición
  method:
    kind: "subprocess_execution"
    tool: "trivy"
    tool_version: "0.58.0"
    command_executed: "trivy fs --quiet --format json --severity CRITICAL,HIGH ."
    environment:
      os: "darwin-arm64"
      python: "3.14.6"
      hostname_digest: "bc2dd04ada705d02"

  # Cobertura Empírica
  scope:
    examined: 396
    unknown: 0
    universe: "source_and_dependency_files"
    declared: true

  # Medición y Resultados
  outcome: "OK"
  measured_summary: "396 archivos recorridos · 0 críticas · 0 altas"
  findings: []
  raw_output_sha256: "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
```

---

## 3. Invariante del Encadenamiento Hash

Toda evidencia se registra en el diario persistente mediante la función de transición:

$$h_0 = \text{SHA256}(\text{"harness.ledger/v1"})$$
$$h_i = \text{SHA256}(h_{i-1} \parallel \text{"\n"} \parallel \text{CanonicalJSON}(e_i))$$

Donde $\text{CanonicalJSON}(e)$ ordena lexicográficamente las claves y excluye el campo de huella `$h$`.
* **Propiedad:** Alterar, eliminar o reordenar un evento intermedio rompe todos los hashes posteriores, dejando la cadena en estado `ROTA` de forma demostrable.
