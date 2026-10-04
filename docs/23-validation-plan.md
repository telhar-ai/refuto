# Plan de Validación Científica y Aseguramiento de Calidad

## 1. Filosofía de Auto-Verificación: "Refuto Verificando a Refuto"

El estándar de integridad de Refuto exige que el sistema sea su propio primer caso de prueba riguroso. Ningún componente o compuerta entra en producción sin haber sido sometido a:
1. Su propia suite de compuertas de aseguramiento (`refuto selftest`).
2. Una batería de pruebas mutacionales sobre su código fuente.
3. Pruebas de estrés y adversariales que intentan vulnerar sus invariantes fundamentales.

```
┌────────────────────────────────────────────────────────┐
│             CICLO DE AUTO-VERIFICACIÓN DE REFUTO       │
└────────────────────────────────────────────────────────┘
                           │
                           ▼
          [Código de Refuto (core/, gates/)]
                           │
                           ▼
          [Compilación y Chequeo de Esquemas]
          - check_stdlib_only.py (0 dependencias)
          - check_schemas.py (Esquemas válidos)
          - check_wiring.py (Conexiones activas)
                           │
                           ▼
          [Suite de Pruebas Unitarias y Contratos]
          - 535 Unit Tests
          - 62 Contract Tests
          - 80 Selftest Tests
                           │
                           ▼
          [Suite Adversarial (T01 - T21)]
          - Intentos de forzar estados no válidos
          - Falsación mutacional activa
                           │
                           ▼
          [Libro Mayor de Auto-Atestación Firmado]
```

---

## 2. Batería de Pruebas Adversariales (Validación de Vectores T01 - T21)

Cada vector de ataque identificado en el Modelo de Seguridad (`docs/18-security-model.md`) cuenta con una suite de pruebas dedicada en `tests/adversarial/`:

| Prueba Adversarial | Vector Objetivo | Condición de Aprobación de la Prueba |
| :--- | :--- | :--- |
| `test_tamper_ledger_hash` | **T01** | La modificación de un byte en `evidence.jsonl` hace que `refuto status` aborte con código 1 y detecte corrupción de cadena. |
| `test_reject_self_witness` | **T02** | Si un claim tiene `witness_id == subject_agent_id`, el sistema lanza `CircularityError` y no registra la evidencia. |
| `test_empty_scope_refusal` | **T04** | Una compuerta que reporte `status=PASS` pero `scope.items_examined == 0` es forzada a veredicto `INCONCLUSIVE`. |
| `test_replay_stale_capsule` | **T05** | Una cápsula con hash de commit diferente al actual o con TTL expirado es rechazada con código de error de admisión. |
| `test_policy_downgrade_revert` | **T06** | Cualquier intento de relajar umbrales de compuertas sin clave de firma de seguridad aborta el proceso de inmediato. |
| `test_tautological_test_rejection` | **T17** | Una suite de prueba que aprueba mutantes con mutaciones lógicas elementales recibe puntaje $MS = 0$ y veredicto `FAIL`. |
| `test_flaky_test_quarantine` | **T13** | Pruebas no deterministas ejecutadas 5 veces con resultados mixtos reciben estado `DEGRADED`, impidiendo el paso a producción. |
| `test_bft_split_brain_recovery` | **T21** | Una partición de red con $f < n/3$ nodos desincronizados resuelve consenso hacia el estado más estricto sin bifurcar el registro. |

---

## 3. Benchmarks de Rendimiento y Escalabilidad

Para operar en entornos de alta demanda (como pipelines masivos o inferencia de IA en producción), Refuto se evalúa contra umbrales estrictos de rendimiento:

### 3.1. Métricas de Rendimiento Operativo
- **Latencia de Registro en el Libro Mayor**:
  $$\text{Tiempo de Inserción y Hash (SHA-256)} < 2.0 \text{ ms por registro}$$
- **Rendimiento de Evaluación de Compuertas**:
  $$\text{Rendimiento Mínimo} \ge 1.000 \text{ claims/segundo en modo local}$$
- **Sobrecarga de Memoria del Núcleo**:
  $$\text{Consumo Máximo de Memoria RSS} < 64 \text{ MB en ejecuciones estándar}$$

### 3.2. Pruebas de Escalabilidad del Libro Mayor
- Se evalúa la integridad y tiempo de verificación de un archivo `evidence.jsonl` con **1.000.000 de registros**.
- La verificación de la cadena completa debe completarse en menos de 5 segundos en hardware estándar mediante cálculo de hash en bloque sin cargar el archivo completo en memoria.

---

## 4. Modelado Formal y Verificación de Estados (TLA+ / Alloy)

Para garantizar matemáticamente la ausencia de bloqueos (*deadlocks*), condiciones de carrera y estados imposibles, la máquina de estados de Refuto y el protocolo Concordia se modelan en especificaciones formales:

### 4.1. Invariantes Demostrados en el Modelo Formal:
1. **Ausencia de Falso Positivo por Ámbito Vacío**:
   $$\Box \neg (\text{DecisionState} = \text{PASS} \land \text{ObservedScope} = \emptyset)$$
2. **Monotonía del Historial**:
   $$\Box (H_{t+1} = \text{SHA256}(R_{t+1} \parallel H_t))$$
3. **Consistencia de Decisión**:
   $$\Box (\text{AnyGate}(\text{FAIL}) \implies \text{GlobalVerdict}(\text{FAIL}))$$

---

## 5. Calibración de Falsos Positivos y Falsos Negativos

En sistemas de verificación, existe un compromiso entre **exhaustividad** (detectar todas las fallas) y **precisión** (no generar alertas falsas que fatiguen al desarrollador):

$$\text{Recall de Falsación} = \frac{\text{Fallas Reales Detectadas}}{\text{Fallas Reales Totales}} \ge 0.99$$
$$\text{Tasa de Falsas Alarmas (FPR)} = \frac{\text{Falsos Positivos}}{\text{Ejecuciones Válidas}} \le 0.01$$

Refuto prioriza la seguridad estricta: ante cualquier ambigüedad, el sistema elige `INCONCLUSIVE` antes que un falso `PASS`, garantizando que jamás se asuma certeza donde sólo hay ausencia de evidencia.
