# 16 · Modelo de Decisión y Lógica Epistémica (Decision Model v1)

**Fecha:** 2026-09-30  
**Clasificación:** `FORMAL RESULT` · Teoría de Decisión de Refuto

---

## 1. Los 7 Estados Epistémicos No Colapsables

Refuto rechaza categóricamente la reducción binaria (`PASS / FAIL`). La verdad en ingeniería asistida por IA exige una semántica enriquecida que preserve las condiciones operativas de la observación:

```
┌─────────────────┬──────────────────────────────────────────────────────────────┬──────────────────┐
│ Estado          │ Significado Epistémico Riguroso                              │ ¿Permite Merge?  │
├─────────────────┼──────────────────────────────────────────────────────────────┼──────────────────┤
│ PASS            │ Se comprobó, hubo sujetos reales (examined > 0), y cumple.    │ SÍ               │
│ FAIL            │ Se comprobó y existe fallo, o se demostró violación grave.  │ NO (Bloqueante)  │
│ BLOCKED         │ No se pudo intentar: falta una dependencia declarada o pin.  │ NO (Bloqueante)  │
│ NOT_EXECUTABLE  │ Se intentó pero la herramienta falló, abortó o dio timeout.  │ NO (Bloqueante)  │
│ INCONCLUSIVE    │ Hay contradicción o no se pudo demostrar cobertura (Scope). │ NO (Bloqueante)  │
│ DEGRADED        │ Cumple bajo excepción temporal explícitamente autorizada.    │ CONDICIONAL      │
│ NOT_APPLICABLE  │ Se intentó y no hay sujeto aplicable en este espacio.       │ NEUTRAL          │
└─────────────────┴──────────────────────────────────────────────────────────────┴──────────────────┘
```

---

## 2. Máquina de Estados y Reglas de Transición

```
             ┌─────────────────┐
             │     NOT_RUN     │
             └────────┬────────┘
                      │ Inicia Evaluación
                      ▼
             ┌─────────────────┐
             │ Sonda / Target  │
             └────────┬────────┘
       ┌──────────────┼──────────────┐
       │ Sin sujeto   │ Falta dep    │ Herramienta
       ▼              ▼              ▼
┌──────────────┐┌──────────────┐┌────────────────┐
│NOT_APPLICABLE││   BLOCKED    ││ NOT_EXECUTABLE │
└──────────────┘└──────────────┘└────────────────┘
                      │
                      │ Ejecuta Instrumentos
                      ▼
             ┌─────────────────┐
             │   Observation   │
             └────────┬────────┘
       ┌──────────────┼──────────────┐
       │ examined = 0 │ Hallazgos    │ examined > 0
       ▼              ▼              ▼
┌──────────────┐┌──────────────┐┌────────────────┐
│ INCONCLUSIVE ││     FAIL     ││      PASS      │
└──────────────┘└──────────────┘└────────────────┘
```

---

## 3. Demostración Matemática: La Prueba del Vacío

Sea una propiedad universal $P(x)$ predicada sobre un conjunto de entidades $S \subseteq U$:

$$\phi \equiv \forall x \in S : P(x)$$

En lógica proposicional clásica:
$$S = \emptyset \implies \phi \equiv \text{True}$$

### El Teorema de Demostración Empírica de Refuto
> *«La verdad matemática sobre un conjunto vacío no constituye evidencia empírica de una propiedad en ingeniería de software.»*

$$\text{EvidenciaPositiva}(P) \iff \text{Scope.examined} > 0 \land \text{Scope.unknown} = 0 \land \forall x \in S : P(x)$$

* **Consecuencia:**  
  Si un escáner analiza 0 archivos o una suite de pruebas ejecuta 0 tests:
  $$\text{Scope.examined} = 0 \implies \text{Status} \ne \text{PASS}$$
  Refuto genera `INCONCLUSIVE` (si la prueba no declaró el universo) o `BLOCKED` (si el espacio declaraba que debía contener sujetos pero se encontraron cero).
