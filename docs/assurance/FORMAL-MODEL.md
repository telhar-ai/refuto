# Modelo formal de refuto

> Este documento define **qué significa `PASS`** en refuto, y qué hay que demostrar para
> emitirlo. Se escribió después de una auditoría adversarial que produjo cuatro contraejemplos
> contra la implementación anterior; cada invariante de aquí nombra el contraejemplo que lo
> motiva.
>
> La regla que ordena todo lo demás:
>
> ```
> PASS  ⟹  existe una justificación verificable de PASS
> ```
>
> y **nunca** `PASS ⟸ no encontré FAIL`.

---

## 1 · Entidades

| Símbolo | Entidad | Dónde vive |
|---|---|---|
| `W` | **Workspace** — el árbol gobernado | sistema de archivos |
| `S` | **Subject** — el agente evaluado | proceso, uid del operador |
| `J` | **Judge** — lo que determina la evaluación: motor, política, puertas, evidencia | `core/`, `gates/`, `.harness/` |
| `Π` | **Policy** — documento de política efectiva | `.harness/policy.json` + cadena |
| `R` | **RootOfTrust** — la norma de la que cuelga toda cadena | constantes de `core/policy.py` |
| `a` | **Action** — lo que el sujeto pide hacer | carga del gancho |
| `E(a)` | **Effects** — el conjunto de efectos de `a` sobre el sistema de archivos | derivado |
| `o` | **Observation** — lo que una puerta llegó a mirar | `Scope` |
| `ε` | **Evidence** — el registro de lo observado | artefacto + diario |
| `v` | **Verdict** — el estado emitido | `Result.status` |

## 2 · Estados, y por qué son seis

```
PASS             se comprobó, hubo sujeto, y cumple
FAIL             se comprobó y no cumple  — o la integridad se violó de forma demostrada
BLOCKED          no se intentó: falta una dependencia declarada
NOT_EXECUTABLE   se intentó y no se pudo correr (error, timeout, salida inválida)
NOT_APPLICABLE   se intentó, no hay sujeto, y hay justificación formal de que no aplica
INCONCLUSIVE     hay evidencia contradictoria, o la integridad no se pudo establecer
```

`NON_PASSING = {FAIL, BLOCKED, NOT_EXECUTABLE, NOT_APPLICABLE, INCONCLUSIVE}`.

Las cinco últimas son semánticamente distintas y **ninguna se convierte en `PASS`**. La
distinción que más daño hacía al colapsarse:

```
UNKNOWN  ≠  PASS          ∅  ≠  prueba realizada
ERROR    ≠  PASS          ausencia de evidencia  ≠  evidencia positiva
TIMEOUT  ≠  PASS          monotonía local  ≠  cadena de confianza válida
```

## 3 · Relaciones

### 3.1 · Autorización

```
Authorized(a, Π)  ⟺  ∀ (p, WRITE) ∈ E(a) :  ¬Protected(p, Π)
```

Nótese que el cuantificador es sobre **efectos**, no sobre la sintaxis de `a`. Una regla que
mire el texto de la orden decide sobre `a`; la propiedad se predica de `E(a)`.

### 3.2 · Confianza de la política

```
Trusted(Π)  ⟺  Reachable(Π, R)  ∧  Monotone(chain(Π))  ∧  Acyclic(chain(Π))
```

con

```
Monotone(P₀ → P₁ → … → Pₙ)  ⟺  ∀i :  Pᵢ ⊒ Pᵢ₊₁      (el hijo restringe al menos tanto)
Reachable(Π, R)             ⟺  Pₙ ⊒ R                (la cima atenúa la raíz, no la sustituye)
```

`⊒` («al menos tan restrictiva como») es un **preorden parcial** sobre políticas, definido
campo a campo según su clase de monotonía (`ACUMULA`, `REDUCE`, `ENDURECE`, `MODO`).

### 3.3 · Observación completa

La verdad vacua es el defecto que esta sección existe para cerrar. Una propiedad

```
∀x ∈ Sᵤ : P(x)
```

es **matemáticamente verdadera** cuando `Sᵤ = ∅`, y eso **no** es evidencia empírica de `P`.
Se separan tres nociones que la implementación anterior confundía:

```
verdad matemática     ∀x ∈ ∅ : P(x)   es cierto
evidencia empírica    requiere haber observado sujetos
cobertura             cuántos del universo se llegaron a observar
```

Se introduce el tipo `Scope`:

```
Scope = (examined: ℕ, unknown: ℕ, universe_declared: 𝔹, why: String)
```

y se define

```
CompleteObservation(P, ε)  ⟺  Scope.examined > 0  ∧  Scope.unknown = 0
```

`unknown` cuenta lo que se intentó mirar y no se pudo (fichero ilegible, herramienta que
falló, salida inválida). Un solo `unknown` impide `PASS`: no se sabe qué había ahí.

Y la disyunción del ámbito vacío:

```
Sᵤ = ∅  ∧  universe_declared = false   ⟹  NOT_APPLICABLE   (con justificación escrita)
Sᵤ = ∅  ∧  universe_declared = true    ⟹  BLOCKED          (debía haber sujetos y no los hubo)
```

### 3.4 · Resultado de una herramienta externa

```
ToolOutcome ∈ { OK(data), ABSENT, ERROR(e), TIMEOUT, INVALID_OUTPUT }
```

con la única traducción admisible:

```
OK(data)        → aporta evidencia
ABSENT          → BLOCKED          (dependencia declarada que no está)
ERROR | TIMEOUT | INVALID_OUTPUT
                → NOT_EXECUTABLE   (se intentó y no se pudo correr)
```

Ninguna produce `PASS`. Un escáner instalado que revienta es **epistémicamente idéntico** a
uno ausente: en los dos casos no se sabe qué había.

### 3.5 · Integridad y procedencia de la evidencia

El diario es una cadena:

```
h₀ = H("")
hᵢ = H( hᵢ₋₁ ‖ canonical(eventᵢ) )
```

```
Integrity(ε)   ⟺  la cadena recomputa  ∧  head(diario) = commitment(artefacto)
Provenance(ε)  ⟺  ε lleva commit, rama, máquina, motor, política efectiva
```

Y la regla de reconciliación, que es la que convierte la redundancia en detección:

```
artefacto ≠ diario, ambos legibles   ⟹  FAIL          (contradicción demostrada)
integridad no establecible            ⟹  INCONCLUSIVE  (no se sabe)
```

Nunca `INTEGRABLE` cuando las dos fuentes de verdad discrepan.

## 4 · Propiedad fundamental

```
PASS(P)  ⟹   Trusted(Π)
           ∧ CompleteObservation(P, ε)
           ∧ Integrity(ε)
           ∧ Provenance(ε)
           ∧ ε ⊨ P
```

Contrapositiva, que es la forma operativa: si **cualquiera** de los cinco conyuntos no se
puede establecer, el veredicto no es `PASS`.

## 5 · Invariantes

| # | Invariante | Cómo se sostiene | Contraejemplo que lo motiva |
|---|---|---|---|
| `I1` | `PASS ⟹ Proof(PASS)` | `Result.__post_init__` exige `Scope` con `examined>0` | B-2 |
| `I2` | `PASS ⟹ Trusted(Π)` | `core/trust.py::componer_con_raiz`, raíz = baseline del motor | extends |
| `I3` | `PASS ⟹ CompleteObservation` | `Scope.unknown = 0` exigido al construir | B-2, B-3 |
| `I4` | `PASS ⟹ Integrity(ε)` | cadena de huellas + reconciliación artefacto↔diario | B-4 |
| `I5` | `PASS ⟹ ε ⊨ P` | `findings = ∅` (invariante previo, ya existente) | — |
| `I6` | `S ∉ Authority(J)` | **NO DEMOSTRABLE en proceso** — ver §6 | B-1 |
| `I7` | `S` no modifica `R` | `R` son constantes del motor; su digest se atesta | extends |
| `I8` | `S` no modifica `ε` de su propio veredicto | tamper-**evidente**, no tamper-proof | B-4 |
| `I9` | `UNKNOWN ↛ PASS` | `ToolOutcome` + `Scope.unknown` | B-3 |
| `I10` | `Πhijo ⊒ Πpadre ∧ Reachable(Πcima, R)` | `core/trust.py` | extends |

## 6 · `I6` — por qué la prevención no es demostrable, y qué se pone en su lugar

### 6.1 · Imposibilidad de la vía sintáctica

Sea `Cmd` el conjunto de órdenes de consola y `E : Cmd → 𝒫(Path × {READ, WRITE})`.

**Proposición.** `E` no es computable.

*Demostración.* Para cualquier máquina de Turing `M` y entrada `w`, la orden

```
python3 -c 'if M(w) para: open("gates/base.py","w")'
```

escribe en `gates/base.py` si y sólo si `M` para sobre `w`. Decidir
`(gates/base.py, WRITE) ∈ E(c)` decide el problema de la parada. ∎

**Corolario.** Todo analizador estático `Ê` sobre órdenes es **incorrecto** (deja pasar
escrituras) o **incompleto** (rechaza órdenes inocuas). Un `Ê` correcto debe denegar toda
orden cuya inocuidad no pueda demostrar — lo que incluye `python3`, `make`, `npm` y cualquier
binario compilado. Un control así se desactiva, y un control desactivado no protege de nada;
el propio código lo documenta (`core/policy.py::_partir`).

### 6.2 · Imposibilidad en la frontera actual

El sujeto corre con el uid del operador, sobre el mismo sistema de archivos, y puede
ejecutar procesos. Toda escritura que el sujeto puede hacer, la puede hacer un hijo suyo. El
guardián es un **hook consultivo**: una vez el runtime ejecuta `bash -c …`, la única autoridad
es el núcleo del sistema operativo.

```
uid(S) = uid(J)  ∧  writable(J, uid(S))  ⟹  ¬ Enforceable(I6) en espacio de usuario
```

`ADR-0011` declara `TB-3` «inmutable y protegido contra escritura de TB-1 y TB-2». **Tal como
está enunciado, eso no es implementable** sin soporte del sistema operativo: uid distinto y
permisos, `chflags schg` / `chattr +i`, montaje de sólo lectura, o espacio de nombres.

### 6.3 · Lo que sí se puede demostrar

Se sustituye la prevención por una propiedad más débil y **sí demostrable**:

```
I6'  :  Modified(J)  ⟹  ¬PASS
```

«Si el sujeto tocó al juez, ningún veredicto posterior puede ser `PASS`.»

Es demostrable porque no depende de impedir la escritura, sino de que el veredicto **dependa
de un dato que el sujeto no puede falsificar sin ser detectado**: el digest del motor y de la
política efectiva, anclados en el artefacto y en la cadena del diario, y recomputables por un
verificador independiente (CI sobre rama protegida, o `refuto verify` fuera de la sesión).

Se conserva además, **como defensa en profundidad y declarada incompleta**, un modelo de
efectos `Ê` sobre órdenes (`core/effects.py`) que cubre lo que de verdad ocurre a diario:
redirecciones, `tee`, edición en sitio, copia y movimiento. `Ê` **no** es una garantía y
este documento no la presenta como tal.

## 7 · Separación de autoridad

La implementación anterior mezclaba cinco papeles en un proceso y un uid:

```
Executor · Observer · PolicyEngine · EvidenceStore · VerdictEngine
```

La frontera mínima que hace falta **no** es un proceso nuevo: es que el `VerdictEngine`
dependa sólo de entradas que el sujeto no pueda forjar sin dejar rastro. Con `I4`, `I7` e
`I6'` el veredicto queda atado al digest del motor, al digest de la política efectiva y a la
cabeza de la cadena del diario. Quien ejecuta sigue siendo quien observa; **quien decide ya no
puede alterar en silencio lo que justifica la decisión.**

## 8 · Lo que este modelo NO demuestra

- `I6` en su forma fuerte (prevención). Estado: **`NOT_PROVEN`**, con imposibilidad
  demostrada en §6.2 para la frontera actual.
- Que `Ê` sea completo. Por §6.1, no puede serlo. Estado: **`NOT_APPLICABLE`** como garantía;
  se declara como reducción de superficie.
- Integridad frente a un adversario que reescriba la cadena entera **y** todas sus copias
  publicadas. Tamper-evidencia ≠ tamper-proofing.
