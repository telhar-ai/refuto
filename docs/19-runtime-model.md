# Modelo de Verificación en Tiempo de Ejecución (Runtime Model)

## 1. El Cierre del Bucle: De la Construcción al Funcionamiento Real

La verificación convencional de software concluye erróneamente en el pipeline de CI/CD: una vez que el binario compila y las pruebas pasan, se asume que las propiedades verificadas persisten indefinidamente. En la ingeniería de sistemas asistidos por IA y microservicios modernos, esta asunción es falsa.

Refuto extiende el ciclo de vida de la evidencia cerrando el bucle completo:
$$\text{Intención} \longrightarrow \text{Especificación} \longrightarrow \text{Código} \longrightarrow \text{Prueba} \longrightarrow \text{Construcción} \longrightarrow \text{Despliegue} \longrightarrow \mathbf{Tiempo\ de\ Ejecución\ (Runtime)}$$

```
     ┌────────────────────────────────────────────────────────┐
     │              CICLO DE EVIDENCIA CERRADO                │
     └────────────────────────────────────────────────────────┘
          ▲                                              │
          │ Retroalimentación                            │
          │ de Deriva Semántica                          ▼
     ┌─────────────┐                             ┌─────────────┐
     │  INTENCIÓN  │                             │ CONSTRUCCIÓN│
     │  Y DISEÑO   │                             │  Y PRUEBAS  │
     └─────────────┘                             └─────────────┘
          ▲                                              │
          │                                              │ Cápsula de Decisión
          │                                              ▼
     ┌─────────────┐                             ┌─────────────┐
     │ OBSERVACIÓN │◄────────────────────────────│  DESPLIEGUE │
     │ EN RUNTIME  │        Monitores eBPF /     │   ADMISIÓN  │
     │    (E4)     │        OpenTelemetry        └─────────────┘
     └─────────────┘
```

---

## 2. Continuidad Epistémica y Expiración de Atestaciones

Un `Claim` verificado en tiempo de compilación posee una validez temporal y ambiental finita. Refuto introduce el concepto de **Tiempo de Vida de la Evidencia (Evidence TTL)** y **Degradación Epistémica**:

1. **Veredicto en Despliegue ($t_0$)**: Un componente es admitido con estatus `PASS` y nivel epistémico $E3$ (probado en integración).
2. **Período de Gracia ($t_0 < t \le t_0 + \tau$)**: El veredicto se mantiene vigente si las condiciones ambientales (versión del kernel, modelos conectados, configuración) coinciden con la atestación de compilación.
3. **Degradación a `DEGRADED`**: Si transcurre el tiempo $\tau$ sin observaciones directas en ejecución, el estado decae automáticamente de `PASS` a `DEGRADED`.
4. **Elevación a $E4$ (Observado en Producción)**: Al vincular telemetría en vivo, la afirmación se consolida en el nivel epistémico más alto posible ($E4$).

---

## 3. Vinculación de Telemetría (OpenTelemetry y eBPF) con Afirmaciones

Refuto no reemplaza los sistemas de observabilidad existentes (como Prometheus, Jaeger o Datadog); en su lugar, **vincula unívocamente las trazas y métricas con los Claims formales**:

### 3.1. Inyección de Encabezados de Atestación
En cada petición o transacción distribuida, los adaptadores de Refuto inyectan el identificador del `Claim` correspondiente:
```http
X-Refuto-Claim-ID: claim-pci-tokenization-042
X-Refuto-Evidence-Digest: sha256:8f4c2e...
X-Refuto-Expected-Invariant: latency_ms < 250 AND unmasked_pan == FALSE
```

### 3.2. Sondas eBPF para Invariantes Críticos del Núcleo
Para sistemas de alta seguridad, Refuto utiliza sondas del kernel eBPF para observar invariantes sin sobrecarga en el código de aplicación:
- **Invariante de Aislamiento de Red**: Garantizar que un modelo de inferencia local no abra sockets salientes no autorizados.
- **Invariante de Acceso a Archivos**: Garantizar que las claves criptográficas sólo sean leídas por el proceso designado.
Si la sonda eBPF detecta una violación, emite un evento de observación estructurado (`refuto.observation/v1`) con veredicto `FAIL`, invalidando de inmediato la Cápsula de Decisión activa.

---

## 4. Detección de Deriva de Modelos de IA (AI Drift & Hallucination Monitors)

En componentes basados en agentes o modelos de lenguaje, el comportamiento puede divergir a lo largo del tiempo debido a:
- Actualizaciones no anunciadas de la API del proveedor de LLM.
- Deriva en la distribución de las entradas de los usuarios (data drift).
- Degradación del alineamiento o degradación por retroalimentación estocástica.

Refuto implementa **Vigilantes de Runtime (Runtime Observers)** que evalúan periódicamente:
1. **Deriva Semántica**: Distancia de coseno entre las respuestas históricas certificadas y las respuestas en vivo ante casos de sondeo canónicos.
2. **Índice de Alucinación**: Tasa de fallas en comprobaciones de hechos deterministas dentro de las respuestas generadas.
3. **Violación de Restricciones Estructurales**: Validaciones de esquema JSON en tiempo real sobre las salidas estructuradas del agente.

Si la tasa de anomalías supera el umbral estipulado en la política, el estado del subsistema en el libro mayor de Refuto cambia de `PASS` a `BLOCKED`, disparando el aislamiento automático del agente o el retorno a un modo seguro (*fail-safe fallback*).

---

## 5. Atestaciones de Cadena de Suministro y Control de Admisión (SLSA e in-toto)

Para garantizar que sólo el software formalmente admitido por Refuto pueda ejecutarse en producción, se implementa un **Controlador de Admisión (Kubernetes Admission Controller / Lambda Authorizer)**:

```
[Artefacto OCI] ──► [K8s Admission Webhook]
                             │
                             ▼
               ¿Posee Cápsula de Decisión
               de Refuto firmada con estado PASS?
                     ├── SÍ ──► [ADMITIDO / POD RUNNING]
                     └── NO ──► [RECHAZADO: 403 Forbidden]
                                (Veredicto no integrable)
```

1. **Generación de SLSA Provenance v1.0**: Durante el paso final de `refuto verify`, se genera una atestación in-toto conteniendo el digest criptográfico del binario, la lista de compuertas ejecutadas y las firmas de los testigos.
2. **Verificación Criptográfica en Despliegue**: El clúster verifica la firma de la atestación antes de iniciar cualquier contenedor. Si el artefacto fue alterado tras la verificación (ataque TOCTOU, vector T15), la admisión es rechazada de forma fulminante.
