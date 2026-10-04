# Modelo de Falsación de Refuto

## 1. Fundamento Filosófico y Epistemológico: Karl Popper en la Ingeniería de IA

La ingeniería de software tradicional y, de manera aún más acusada, el desarrollo asistido por modelos de lenguaje (LLMs) sufren de un sesgo cognitivo y arquitectónico endémico: **el sesgo de confirmación**. Los desarrolladores y agentes sintéticos escriben pruebas diseñadas para pasar; buscan casos de éxito que validen su implementación previa, ignorando o bordeando el espacio de estados no explorado donde habitan los fallos catastróficos.

Refuto adopta como axioma motor la epistemología falsacionista de **Karl Popper** (*Logik der Forschung*, 1934):

> *Una teoría (o afirmación de software) nunca puede ser demostrada de manera concluyente mediante un número finito de observaciones positivas; sólo puede ser corroborada provisionalmente mientras resista intentos sistemáticos, severos e implacables de falsación.*

En el contexto de Refuto, un `Claim` no se "demuestra verdadero" porque un conjunto de pruebas unitarias emita `PASS`. Una afirmación se considera **corroborada** si y sólo si:
1. Ha sido sometida a una batería de **operadores de falsación** diseñados específicamente para encontrar contraejemplos.
2. El espacio de búsqueda explorado es medible y no nulo (`Scope != ∅`).
3. Los oráculos de verificación son independientes del generador del código (evitando la circularidad).

```
   ┌────────────────────────────────────────────────────────┐
   │                    Paradigma Tradicional               │
   │   [Hipótesis] ──► [Prueba Confirmatoria] ──► [PASS ✓]   │
   │                 (Busca el caso feliz)                  │
   └────────────────────────────────────────────────────────┘

   ┌────────────────────────────────────────────────────────┐
   │                Motor Falsacionista Refuto              │
   │   [Claim C] ──► [Generador de Mutantes / Ataques]      │
   │                       │                                │
   │                       ▼                                │
   │           ¿Sobrevive algún contraejemplo?              │
   │               ├── SÍ ──► [FALSIFIED / FAIL ✗]          │
   │               └── NO ──► [CORROBORATED / PASS ✓]       │
   │                          (Sujeto a severidad S > 0)    │
   └────────────────────────────────────────────────────────┘
```

---

## 2. Taxonomía de Operadores de Falsación

Refuto estructura la falsación activa en cinco clases formales de operadores ejecutables:

### 2.1. Falsación Mutacional (Mutation Testing)
Introduce perturbaciones sintácticas y semánticas controladas en el código bajo prueba ($P \to P'$) para verificar si la suite de pruebas es capaz de detectar la mutación ("matar al mutante").
- **Operadores de Mutación de Primer Orden**:
  - Mutación Aritmética: Reemplazo de operadores (`+` $\leftrightarrow$ `-`, `*` $\leftrightarrow$ `/`).
  - Mutación Relacional: Mutación de límites (`<` $\leftrightarrow$ `<=`, `==` $\leftrightarrow$ `!=`).
  - Mutación Lógica: Inversión booleana (`and` $\leftrightarrow$ `or`, `True` $\leftrightarrow$ `False`).
  - Mutación de Flujo: Retorno prematuro (`return None`, `break` $\leftrightarrow$ `continue`).
  - Mutación de Excepciones: Supresión de capturas (`except Exception: pass`).
- **Métrica de Falsación**:
  $$\text{Puntaje de Mutación} (MS) = \frac{\text{Mutantes Matados}}{\text{Mutantes Totales} - \text{Mutantes Equivalentes}}$$
  Un `Claim` de corrección funcional sobre un componente no puede alcanzar nivel de confianza superior a $E2$ si $MS < 0.80$.

### 2.2. Falsación Basada en Propiedades (Property-Based Falsification)
Inspirada en QuickCheck y Hypothesis. En lugar de verificar pares puntuales de entrada-salida $(x, y)$, se formulan invariantes universales sobre el dominio:
$$\forall x \in \mathcal{D}, \quad \Phi(x) \implies \Psi(f(x))$$
El motor de falsación ejecuta generadores estocásticos y guiados por cobertura para encontrar el contraejemplo mínimo $x_{min}$ tal que $\Phi(x_{min}) \land \neg \Psi(f(x_{min}))$.
- **Reducción de Contraejemplos (Shrinking)**: Cuando se halla una falla, el motor reduce iterativamente la entrada hasta aislar la mínima precondición de falla, registrándola como evidencia `E4`.

### 2.3. Falsación Metamórfica (Metamorphic Testing)
Diseñada para resolver el **Problema del Oráculo** en dominios donde el resultado exacto es desconocido a priori (p. ej., embeddings de IA, algoritmos de clustering, optimizadores estocásticos).
Se definen **Relaciones Metamórficas (MR)** que deben mantenerse entre múltiples ejecuciones:
$$x_2 = T(x_1) \implies f(x_2) = R(f(x_1))$$
*Ejemplo*: Si se permutan los elementos de un conjunto de entrada no ordenado, la cardinalidad de la salida de un clasificador debe ser invariante. Si la relación no se cumple, el `Claim` queda automáticamente refutado.

### 2.4. Falsación Diferencial (Differential Testing)
Compara la ejecución de la unidad bajo prueba frente a:
1. Una implementación de referencia o previa conocida.
2. Un modelo alternativo o sintetizado por un agente independiente.
3. Versiones previas del software (detección de regresión semántica).
Cualquier divergencia en salidas, códigos de error o consumo de recursos genera una hipótesis de defecto que Refuto eleva a veredicto `FAIL` o `INCONCLUSIVE`.

### 2.5. Falsación Adversarial Guiada por Agente (Red-Teaming Sintético)
Un agente especializado con rol antagónico (`Adversarial Probe Agent`) recibe el `Claim` y la especificación formal con el único objetivo de generar entradas que violen los límites operativos.
- Pruebas de inyección de prompts.
- Pruebas de colisión de límites de memoria.
- Reordenamiento temporal de eventos concurrentes para provocar carreras (TOCTOU).

---

## 3. Severidad de la Prueba y Resistencia a la Falsación

Refuto formaliza la **Severidad de la Prueba** ($S$) según la teoría de Mayo y Spanos:
Una prueba $T$ de una hipótesis $H$ frente a una alternativa $H_{alt}$ es severa si y sólo si:
1. Si $H$ es falsa, la probabilidad de que $T$ detecte una discrepancia es muy alta:
   $$P(\text{Falla de } T \mid H \text{ es falsa}) \approx 1$$
2. Si $H$ es verdadera, la probabilidad de que $T$ pase es alta:
   $$P(\text{Paso de } T \mid H \text{ es verdadera}) \approx 1$$

| Nivel de Severidad | Batería de Falsación Requerida | Estado si Pasa | Estado si Falla |
| :--- | :--- | :--- | :--- |
| **Baja ($S_0$)** | Pruebas unitarias confirmatorias convencionales | `INCONCLUSIVE` (no califica para decisión crítica) | `FAIL` |
| **Media ($S_1$)** | Pruebas unitarias + Falsación de propiedades (1.000 iteraciones) | `PASS` (E3) | `FAIL` (con contraejemplo) |
| **Alta ($S_2$)** | Propiedades + Análisis Mutacional ($MS > 0.85$) + Metamórfica | `PASS` (E3 corroborado) | `FAIL` (mutantes supervivientes) |
| **Máxima ($S_3$)** | $S_2$ + Falsación Diferencial + Red-Teaming Adversarial | `PASS` (E4 verificado) | `FAIL` (bloqueo inmediato) |

---

## 4. El Teorema del Ámbito Vacío en la Falsación

En un marco falsacionista, una prueba que no observa ninguna parte del dominio o cuyo ámbito de medición es nulo ($\text{Scope} = \emptyset$) tiene **poder de falsación exactamente cero**:
$$P(\text{Detectar Falla} \mid \text{Scope} = \emptyset) = 0$$

Por ello, el axioma de Refuto se sostiene matemáticamente:
> *Si el poder de falsación de un procedimiento es cero, el paso de la prueba es informativamente idéntico a no haber ejecutado la prueba.*

Cualquier prueba con ámbito vacío debe ser catalogada como `NOT_APPLICABLE` (si el componente no existía en el diseño) o `INCONCLUSIVE` (si la prueba omitió instrumentar la observación), **jamás como `PASS`**.

---

## 5. Algoritmo del Motor de Falsación de Refuto

```python
# Algoritmo conceptual del Falsification Engine (stdlib-only)
def evaluate_falsification(claim, unit_under_test, properties, mutants):
    counterexamples = []
    
    # Paso 1: Ejecución de propiedades universales
    for prop in properties:
        result = prop.search_counterexample(unit_under_test, iterations=1000)
        if result.failed:
            counterexamples.append(result.counterexample)
            
    if counterexamples:
        return FalsificationResult(
            status="FAIL",
            verdict="FALSIFIED",
            evidence=counterexamples,
            severity="HIGH"
        )
        
    # Paso 2: Ejecución de mutantes
    killed_mutants = 0
    surviving_mutants = []
    for mutant in mutants:
        if mutant.killed_by_test_suite(unit_under_test.suite):
            killed_mutants += 1
        else:
            surviving_mutants.append(mutant)
            
    mutation_score = killed_mutants / len(mutants) if mutants else 0.0
    if mutation_score < 0.80:
        return FalsificationResult(
            status="INCONCLUSIVE",
            verdict="INSUFFICIENT_FALSIFICATION_POWER",
            mutation_score=mutation_score,
            evidence=surviving_mutants
        )
        
    return FalsificationResult(
        status="PASS",
        verdict="CORROBORATED",
        mutation_score=mutation_score,
        epistemic_level="E3"
    )
```

Este modelo garantiza que Refuto no sea un mero aprobador burocrático de builds, sino un adversario metodológico continuo que eleva la resistencia y certeza de cualquier artefacto producido por humanos o agentes de IA.
