# Propuestas Formales de Registros de Decisión Arquitectónica (ADR-0021 a ADR-0028)

Este documento recopila las especificaciones formales de los Registros de Decisión Arquitectónica (ADR) propuestos para formalizar la evolución de Refuto como infraestructura de frontera.

---

## ADR-0021: Separación Estricta de Estados Epistémicos no Colapsantes

- **Estado**: Propuesto
- **Fecha**: 2026-09-30
- **Nivel Epistémico**: E2 (especificado formalmente)

### Contexto
Los pipelines tradicionales de integración y verificación colapsan la evaluación a un valor booleano (`PASS` / `FAIL`). Esto oculta la diferencia crítica entre una prueba que verificó exhaustivamente un componente y una que no se ejecutó, que fue bloqueada por falta de entorno, o que no examinó ningún archivo.

### Decisión
Adoptar de manera canónica en todo el sistema los 7 estados epistémicos no colapsantes:
1. `PASS`: Afirmación corroborada con evidencia positiva y ámbito no vacío.
2. `FAIL`: Afirmación formalmente refutada mediante contraejemplo.
3. `BLOCKED`: Verificación imposibilitada por falla de infraestructura o dependencias.
4. `NOT_RUN`: La compuerta o prueba estaba planificada pero no se ejecutó.
5. `INCONCLUSIVE`: La prueba se ejecutó pero la evidencia es insuficiente o el ámbito fue vacío.
6. `DEGRADED`: Verificación superada pero con inestabilidad intermitente o TTL expirado.
7. `NOT_APPLICABLE`: El componente o compuerta no aplica al artefacto evaluado.

### Consecuencias
- Queda prohibido convertir automáticamente `INCONCLUSIVE` o `NOT_RUN` en `PASS`.
- Los adaptadores externos mapean estos 7 estados a sus respectivos sistemas de salida sin pérdida de información.

---

## ADR-0022: Especificación del Protocolo Refuto Wire Protocol v1 y Cápsula de Decisión

- **Estado**: Propuesto
- **Fecha**: 2026-09-30
- **Nivel Epistémico**: E2 (especificado formalmente)

### Contexto
Refuto debe integrarse con herramientas de diversos lenguajes y entornos (TypeScript/Bun en AI-DLC, Rust en Kiro, Bash en CI/CD, etc.) sin introducir dependencias en su núcleo estándar.

### Decisión
Estandarizar el protocolo **Refuto Wire Protocol v1** basado en mensajes JSON-RPC 2.0 intercambiados sobre flujos estándar (`stdio`) o sockets de dominio Unix. Toda verificación emite un artefacto inmutable denominado **Cápsula de Decisión** conteniendo el estado global, el nivel epistémico alcanzado, el vector de compuertas y las firmas de los testigos.

### Consecuencias
- Interoperabilidad total entre procesos independientes de la plataforma.
- El núcleo de Refuto permanece completamente desacoplado de los harnesses externos.

---

## ADR-0023: Subsanación de Códigos de Salida de la CLI ante Veredicto Inconcluso y Ámbito Vacío

- **Estado**: Propuesto (Remediación Crítica)
- **Fecha**: 2026-09-30
- **Nivel Epistémico**: E4 (reproducido y verificado empíricamente)

### Contexto
En la implementación actual (`refuto.py:1206-1223`), el comando `cmd_verify` agrega los estados de las compuertas directamente desde `r.status`. Cuando una compuerta emite `PASS` pero `verdict_of()` en `core/evidence.py:660` la reclasifica como `INCONCLUSIVE` por falta de ámbito (`sin_prueba`), la CLI imprime el texto `"NO INTEGRABLE"` pero asigna `estado = PASS` y finaliza con código de salida `0`. Esto permitiría que un script de despliegue (`refuto verify && deploy`) admita código sin verificar.

### Decisión
Modificar `cmd_verify` para que el código de salida de la CLI refleje estrictamente el veredicto consolidado de `verdict_of()`. Si existen compuertas marcadas como `sin_prueba` o el veredicto es `INCONCLUSIVE`, el comando debe:
1. Imprimir la lista explícita de compuertas sin ámbito verificado.
2. Finalizar con código de salida no nulo (`exit code 2` por defecto, o `1` en modo estricto).

### Consecuencias
- Cierre inmediato de la brecha de seguridad del vector T04 (Vacuous Truth Exploitation).
- Ningún despliegue automatizado podrá continuar si una compuerta aprueba sin ámbito.

---

## ADR-0024: Cadena Criptográfica del Libro Mayor y Anclaje Notarial Concordia BFT

- **Estado**: Propuesto
- **Fecha**: 2026-09-30
- **Nivel Epistémico**: E3 (diseño criptográfico)

### Contexto
El libro mayor local `evidence.jsonl` es susceptible de manipulación directa si un agente o atacante con acceso al sistema de archivos reescribe líneas pasadas (vector T01).

### Decisión
Estructurar cada entrada del libro mayor como un bloque encadenado por hash SHA-256 (`PrevHash`). Implementar puntos de control periódicos (*checkpoints*) anclados en la red distribuida de notarios **Concordia** mediante consenso tolerante a fallas bizantinas (PBFT), creando un registro verificable públicamente similar a *Certificate Transparency* (RFC 6962).

### Consecuencias
- Detección inmediata de cualquier alteración retrospectiva en el historial de evidencias.
- Pruebas matemáticas de inclusión y consistencia del historial verificables externamente.

---

## ADR-0025: Arquitectura del Motor de Falsación Activa y Pruebas Mutacionales

- **Estado**: Propuesto
- **Fecha**: 2026-09-30
- **Nivel Epistémico**: E2 (diseño del motor)

### Contexto
Las pruebas escritas por modelos de lenguaje tienden a ser confirmatorias y tautológicas, aprobando mutantes elementales y creando una falsa sensación de cobertura.

### Decisión
Incorporar el **Motor de Falsación de Refuto** como parte integral del ciclo de evaluación. El motor inyecta mutaciones sintácticas y semánticas en el código bajo prueba y ejecuta generadores de propiedades universales. Ningún `Claim` puede superar el nivel epistémico $E2$ si su suite de pruebas no alcanza un puntaje de mutación $MS \ge 0.80$.

### Consecuencias
- Eliminación de pruebas tautológicas o decorativas generadas por agentes de IA.
- Elevación del rigor de las suites de prueba hacia estándares científicos de falsabilidad.

---

## ADR-0026: Integración Orgánica y no Subordinada con AWS AI-DLC

- **Estado**: Propuesto
- **Fecha**: 2026-09-30
- **Nivel Epistémico**: E3 (interfaz de arquitectura)

### Contexto
AWS AI-DLC proporciona un ciclo de vida para ingeniería de IA pero carece de un motor de atestación criptográfica, independencia de testigos y prevención de ámbito vacío. Refuto no debe convertirse en un ciclo de vida competidor ni subordinarse a AI-DLC.

### Decisión
Definir la frontera arquitectónica donde AI-DLC actúa como el orquestador del flujo y Refuto como la **Autoridad de Decisión y Verificación**. AI-DLC invoca a Refuto como su *Construction Verification Command*, y ninguna transición de fase en AI-DLC puede ejecutarse sin presentar una Cápsula de Decisión válida emitida por Refuto.

### Consecuencias
- Máxima sinergia: AI-DLC aporta la orquestación y Refuto la confianza demostrable.
- Portabilidad garantizada: Refuto se integra igualmente con cualquier otro framework presente o futuro.

---

## ADR-0027: Independencia Multi-Nivel de Testigos (W0 - W4) y Protocolo Anti-Circularidad

- **Estado**: Propuesto
- **Fecha**: 2026-09-30
- **Nivel Epistémico**: E2 (modelo formal)

### Contexto
La auto-atestación en agentes autónomos crea bucles circulares donde el generador del defecto es el mismo que certifica su ausencia (vector T02).

### Decisión
Establecer la taxonomía formal de testigos ($W0$ auto-reporte, $W1$ determinista estático, $W2$ ejecutable en sandbox, $W3$ testigo externo independiente, $W4$ notaría multipartita) y aplicar el teorema de anti-circularidad en el núcleo: ningún veredicto de compuerta crítica puede basarse en un testigo que comparta identidad, proceso o modelo con el agente sujeto de la afirmación.

### Consecuencias
- Eliminación matemática de la circularidad en la verificación de código asistido por IA.
- Graduación transparente de los niveles de certeza según la independencia de los testigos.

---

## ADR-0028: Vinculación de Telemetría en Tiempo de Ejecución y Monitoreo Continuo

- **Estado**: Propuesto
- **Fecha**: 2026-09-30
- **Nivel Epistémico**: E2 (diseño de runtime)

### Contexto
La validez de las afirmaciones decae con el tiempo en producción debido a cambios ambientales y deriva estocástica de los modelos de IA.

### Decisión
Extender el alcance de Refuto al tiempo de ejecución mediante la vinculación de trazas OpenTelemetry y sondas eBPF a los identificadores canónicos de `Claim`. Si la telemetría en vivo detecta anomalías o transcurre el tiempo de vida de la evidencia (TTL), el estado del componente decae automáticamente a `DEGRADED`, alertando a la infraestructura de despliegue.

### Consecuencias
- Cierre total del bucle de aseguramiento entre diseño, compilación y operación real.
- Capacidad de auditoría y revocación de confianza en tiempo real.
