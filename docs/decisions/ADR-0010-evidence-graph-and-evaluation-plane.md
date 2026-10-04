# ADR-0010 · Grafo de Evidencia y Plano de Evaluación Epistémica

**Estado:** aceptado · **Fecha:** 2026-09-22 · **Decide:** modelo epistémico y verificación formal de afirmaciones en refuto

---

## Contexto

Los marcos tradicionales de aseguramiento de software y evaluación de LLMs operan sobre una abstracción binaria (`true`/`false` o `pass`/`fail`). Esta simplificación es insuficiente cuando un agente genera código, modifica configuraciones o formula aseveraciones de rendimiento y seguridad.

## Problema

1. **La Verdad Vacía (*Vacuous Truth*):** Si una suite de pruebas busca `tests/**/*.py` pero la carpeta no existe, el runner sale con código 0. Los sistemas convencionales reportan `PASS`, ocultando que nada fue probado.
2. **Colapso de Niveles Epistémicos:** Un agente que afirma "la función no tiene dependencias externas" recibe el mismo valor en un informe si lo dedujo de su entrenamiento (E0) o si se ejecutó un analizador AST sobre el código en la máquina (E3/E4).
3. **Pérdida de Linaje:** Cuando una puerta de calidad falla, no se puede auditar qué artefacto exacto, versión de compilador o commit git produjo la evidencia discordante.

## Decisión

Se establece formalmente la **Escalera Epistémica E0–E4**, la **Lógica Hexavalente de Estados** y el **Grafo de Evidencia Criptográfico**:

### 1. La Escalera Epistémica (Epistemic Levels)

Toda afirmación técnica debe llevar un nivel explícito:

| Nivel | Definición | Requisito de Validación |
|---|---|---|
| **E0** · Dicho | Generado por el modelo o afirmado verbalmente. | Sin verificación; valor meramente conjetural. |
| **E1** · Documentado | Consta en especificaciones primarias o manuales. | Referencia bibliográfica o hash de archivo formal. |
| **E2** · Reproducible | Receta de ejecución determinística documentada. | Dependencias fijadas, pasos aislables. |
| **E3** · Probado | Ejecutado con suite de aserciones automatizadas. | Código de salida 0, aserciones evaluadas > 0. |
| **E4** · Observado | Medido en runtime bajo telemetría directa. | Registro de proceso, kernel trace o medición física. |

### 2. Estados Hexavalentes de Verificación

Se prohíbe el uso de "Pendiente" o booleanos simples. Los únicos estados válidos son:

- **`PASS`**: Condición verificada positivamente con ámbito no vacío ($N > 0$).
- **`FAIL`**: Condición refutada empíricamente o ámbito evaluado con violaciones.
- **`BLOCKED`**: No se puede evaluar debido a un fallo previo en dependencias o entorno.
- **`NOT_RUN`**: Paso planificado pero omitido intencionalmente por configuración.
- **`INCONCLUSIVE`**: Datos contradictorios o mediciones ruidosas que no permiten decidir.
- **`NOT_APPLICABLE`**: La puerta no aplica al contexto del proyecto (ej. gate MCP en proyecto sin MCP).

> **Axioma Fundamental:** *Un ámbito vacío nunca aprueba.* Si una puerta evalúa 0 elementos aplicables, su estado es `NOT_APPLICABLE` o `FAIL` (si la prueba requería elementos obligatorios), pero **jamás** `PASS`.

### 3. Grafo de Evidencia (Evidence Graph)

La evidencia se estructura como un grafo acíclico dirigido (DAG) inmutable:

- **Nodos:**
  - `AssertionNode`: Afirmación sujeta a verificación.
  - `ArtifactNode`: Archivo o estado del sistema con hash SHA-256.
  - `ExecutionNode`: Ejecución determinística (comando, runtime, timestamp, exit code).
  - `GateResultNode`: Veredicto emitido por una puerta de refuto.
- **Aristas:** `VERIFIED_BY`, `DERIVED_FROM`, `REFUTES`, `BLOCKED_BY`.

### 4. Plano de Evaluación (Evaluation Plane)

El motor de puertas (`gates/`) actúa como un evaluador puro que recibe el grafo de evidencia y la política compilada, produciendo un dictamen inmutable firmado con su huella de ejecución.

## Consecuencias

- **Garantía Criptográfica:** Imposibilidad de que un agente falsifique o alucine pruebas sin generar las trazas reales en el sistema de archivos.
- **Transparencia en Auditoría:** Cualquier auditor externo puede inspeccionar el grafo y verificar las pruebas paso a paso de manera determinística.
