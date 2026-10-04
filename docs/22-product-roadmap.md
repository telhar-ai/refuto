# Hoja de Ruta Estratégica del Producto (Roadmap Fases 0 a 8)

## 1. Visión y Cronograma de Maduración

La evolución de Refuto desde una herramienta de línea de comandos basada en pruebas unitarias hacia una infraestructura de frontera para la verificación y confianza en ingeniería de IA se estructura en 9 fases incrementales. Cada fase se define por objetivos técnicos concretos, pre-requisitos estrictos y criterios de salida cuantificables con niveles epistémicos formales ($E0$ a $E4$).

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                       CRONOGRAMA DE EVOLUCIÓN DE REFUTO                     │
├─────────────────────────────────────────────────────────────────────────────┤
│ Fase 0: Auditoría Empírica y Cimientos (Semana 1 - 2)                       │
│ Fase 1: Núcleo Semántico y Protocolo Wire v1 (Mes 1)                        │
│ Fase 2: Motor de Falsación Activa y Mutaciones (Mes 2 - 3)                  │
│ Fase 3: Adaptadores Nativos para AI-DLC y Agentes (Mes 4)                   │
│ Fase 4: Red Notarial BFT y Anclaje Concordia (Mes 5 - 6)                    │
│ Fase 5: Trazabilidad de Cadena de Suministro (SLSA/in-toto) (Mes 7)         │
│ Fase 6: Observabilidad en Runtime y Monitores de Deriva (Mes 8 - 9)         │
│ Fase 7: Gobernanza Empresarial y Federación Multiespacio (Mes 10 - 11)      │
│ Fase 8: Ecosistema Abierto y Estándar de Frontera (Mes 12+)                 │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## 2. Definición Detallada de Fases y Criterios de Salida

### Fase 0: Auditoría Empírica y Cimientos
- **Objetivos**:
  - Subsanar la discrepancia de agregación en la CLI (`refuto.py:1206-1223`) donde `INCONCLUSIVE` generaba código de salida 0 (ADR-0023).
  - Instrumentar las compuertas de producción en `gates/` para que emitan `Scope` verificado.
  - Asegurar cumplimiento al 100% de `scripts/check_stdlib_only.py` y `scripts/check_wiring.py`.
- **Criterio de Salida**: `refuto selftest` al 100% PASS, 0 compuertas aprobando con ámbito vacío, suite adversarial sin fallas inesperadas. Nivel epistémico: **$E4$ observado en ejecución local**.

### Fase 1: Núcleo Semántico y Protocolo Wire v1
- **Objetivos**:
  - Implementar los esquemas canónicos `refuto.claim/v1` y `refuto.observation/v1` en `core/schemas.py`.
  - Crear el servidor de protocolo RPC sobre `stdio` (`refuto server`) para integración por procesos desacoplados.
  - Estandarizar la emisión de **Cápsulas de Decisión** firmadas.
- **Criterio de Salida**: Comunicación RPC verificada entre un cliente Python y un cliente de prueba en TypeScript/Node sin dependencias en el servidor. Nivel epistémico: **$E3$ probado por contratos**.

### Fase 2: Motor de Falsación Activa y Mutaciones
- **Objetivos**:
  - Integrar el motor de pruebas de propiedades universales y generación estocástica de contraejemplos.
  - Implementar operadores de mutación sintáctica y semántica para evaluar suites de pruebas.
  - Condicionar veredictos críticos a un puntaje de mutación $MS \ge 0.80$.
- **Criterio de Salida**: Capacidad de refutar automáticamente pruebas tautológicas generadas por IA (`assert True`) en suites adversariales. Nivel epistémico: **$E3$ corroborado**.

### Fase 3: Adaptadores Nativos para AI-DLC y Agentes
- **Objetivos**:
  - Crear el adaptador oficial para AWS AI-DLC v2.10+ (Conductor TypeScript y skill de integración).
  - Implementar ganchos pre/post ejecución para Kiro, Claude Code y OpenAI Codex.
  - Desplegar la compuerta de verificación de construcción como paso obligatorio de admisión.
- **Criterio de Salida**: Ejecución de un ciclo completo de AI-DLC gobernado por Refuto, donde una falla en Refuto bloquee la transición de etapa de AI-DLC con justificación causal. Nivel epistémico: **$E4$ observado en integración**.

### Fase 4: Red Notarial BFT y Anclaje Concordia
- **Objetivos**:
  - Consolidar la red de notarios Concordia con consenso PBFT para el anclaje del libro mayor de evidencias.
  - Soporte de firmas asimétricas múltiples (multi-signature) para testigos $W1$ a $W4$.
  - Generación de pruebas de inclusión Merkle de evidencias históricas.
- **Criterio de Salida**: Resistencia demostrada a bifurcaciones de red y particiones bizantinas (hasta $f$ nodos maliciosos) en pruebas adversariales. Nivel epistémico: **$E3$ validado en red simulada**.

### Fase 5: Trazabilidad de Cadena de Suministro (SLSA/in-toto)
- **Objetivos**:
  - Emisión de atestaciones de procedencia compatibles con el estándar SLSA v1.0 e in-toto v1.0.
  - Desarrollo del Webhook de Admisión para Kubernetes que valide la firma de Refuto antes de iniciar pods.
  - Enlace de digest criptográfico entre el commit de Git, la cápsula de decisión y la imagen OCI.
- **Criterio de Salida**: Despliegue en clúster K8s bloqueando con código 403 imágenes no firmadas o modificadas tras la prueba (TOCTOU). Nivel epistémico: **$E4$ operativo**.

### Fase 6: Observabilidad en Runtime y Monitores de Deriva
- **Objetivos**:
  - Implementar la inyección y extracción de encabezados `X-Refuto-Claim-ID` en trazas OpenTelemetry.
  - Sondas de kernel eBPF para verificación continua de invariantes de aislamiento y seguridad.
  - Vigilantes de deriva semántica y alucinación para modelos de IA en producción con degradación automática a `DEGRADED`.
- **Criterio de Salida**: Transición automática del estado de un claim en el libro mayor ante la detección de anomalías en telemetría de producción. Nivel epistémico: **$E4$ continuo**.

### Fase 7: Gobernanza Empresarial y Federación Multiespacio
- **Objetivos**:
  - Repositorio centralizado de paquetes de políticas (`Policy Packs`) con firma criptográfica institucional.
  - Federación de libros mayores entre múltiples repositorios y microservicios de una organización.
  - Cuadro de mando de cumplimiento regulatorio continuo (EU AI Act, SOC2, ISO 26262).
- **Criterio de Salida**: Auditoría de cumplimiento generada en segundos a partir de trazas criptográficas auditables sin muestreo manual. Nivel epistémico: **$E2$ reproducible**.

### Fase 8: Ecosistema Abierto y Estándar de Frontera
- **Objetivos**:
  - Publicación del estándar abierto *Evidence & Decision Protocol* en consorcios internacionales (W3C/IETF/Linux Foundation).
  - SDKs ligeros oficiales en Go, Rust, Java y C#.
  - Marketplace de paquetes de falsación y compuertas comunitarias.
- **Criterio de Salida**: Adopción de Refuto como estándar de facto para la verificación de agentes autónomos en múltiples plataformas industriales. Nivel epistémico: **$E1$ estandarizado**.
