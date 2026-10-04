# ADR-0013 · Raíz de confianza, modelo de efectos y prevención frente a detección

**Estado:** aceptado · **Fecha:** 2026-09-23 · **Decide:** qué garantiza refuto sobre el
control de escrituras, y qué no

---

## Contexto

Una auditoría adversarial produjo cuatro contraejemplos reproducibles contra la
implementación de `c2755f2`. Dos de ellos no eran defectos de código sino de **modelo**:

1. **El canal de órdenes no pasaba por la política de rutas.** `core.guard.evaluate`
   decidía por `command` **o** por `path`, nunca por ambos. Misma ruta, misma política,
   misma sesión: `Write gates/base.py` → `deny`; `Bash echo x > gates/base.py` → `allow`, y
   el fichero se escribía.

2. **La monotonía de `extends` era relativa y el hijo elegía el padre.** Se demostraba
   `hijo ⊒ padre` en cada arista y nada exigía que la CIMA atenuara nada. Tres pasos —todos
   permitidos por el propio guardián— vaciaban el gobierno sin violar una sola arista.

Y `ADR-0011` declaraba `TB-3` «inmutable y protegido contra escritura de TB-1», que **no es
implementable tal como está enunciado**.

## Decisión

### 1 · La prevención de `I6` no se afirma. Se sustituye por `I6'`

`I6` es «el sujeto no está en la autoridad del juez». No se puede garantizar, y hay dos
razones independientes:

**Indecidibilidad.** `Effects : Cmd → 𝒫(Path × {R,W})` no es computable: para cualquier
máquina `M` y entrada `w`, la orden `python3 -c 'if M(w) para: open("gates/base.py","w")'`
escribe en el juez si y sólo si `M` para. Todo analizador estático es incorrecto (deja pasar)
o incompleto (rechaza lo inocuo). Uno correcto tendría que denegar `python3`, `make`, `npm` y
cualquier binario compilado.

**Frontera de proceso.** El sujeto corre con el uid del operador sobre el mismo sistema de
archivos y puede ejecutar procesos. El guardián es un gancho **consultivo**: una vez el
runtime ejecuta `bash -c …`, la única autoridad es el núcleo del sistema operativo.

En su lugar se afirma:

```
I6'  :  Modified(J)  ⟹  ¬PASS
```

Demostrable porque no depende de impedir la escritura sino de que el veredicto dependa de un
dato que el sujeto no puede falsificar sin dejar rastro: `engine_digest` (`core.trust`),
`policy_digest` y la cabeza de la cadena del diario, todos anclados en el artefacto.

### 2 · El modelo de efectos es reducción de superficie, declarada

`core.effects` calcula `Ê ⊆ Effects`: las escrituras **demostrables** desde la sintaxis
(redirecciones, `tee`, edición en sitio, copia, movimiento, borrado). `decide_command` las
pasa por la misma regla de rutas que `decide_write`.

Lo que `Ê` no puede demostrar se marca `opaco=True` y **se permite**, dejando constancia en
el diario. Denegar todo intérprete haría inusable la herramienta, y un control inusable se
desactiva — el propio `core.policy` lo documenta. La garantía no descansa aquí.

### 3 · La raíz de confianza es la línea base del motor, y se compone

```
Trusted(Π)  ⟺  Reachable(Π, R)  ∧  Monotone(cadena)  ∧  Acyclic(cadena)
```

`R` = `Policy.default()`, materializada por `core.trust.documento_raiz()`. **Toda** política
—tenga `extends` o no— se compone con `R` como padre implícito.

Se eligió **componer** y no sólo **validar** porque en los campos `ACUMULA` el efectivo es la
unión: vaciar `protected_paths` o `command_deny` deja de ser una violación que haya que cazar
y pasa a ser **inexpresable**. Es la tesis que `core.refinement` ya defendía para las aristas
—«no poder expresar la violación es más fuerte que detectarla»— aplicada por fin a la raíz.

Se descartó un `policies/base.json` en disco, que es lo que la prueba de V6 proponía: un
fichero es material y, por tanto, editable por quien pueda escribir en el árbol. La norma
raíz viaja con el código, y su integridad la cubre `engine_digest`.

### 4 · La evidencia es tamper-evidente, no tamper-proof

Cadena de huellas en el diario (`hᵢ = H(hᵢ₋₁ ‖ canonical(eventoᵢ))`) y reconciliación
artefacto ↔ diario al leer. Discrepancia demostrada → el veredicto reportado pasa a
`NO INTEGRABLE`; integridad no establecible → `INCONCLUSIVE`, que es el sexto estado y se
añadió para esto.

**Límite declarado:** cortar la COLA del diario deja los eslabones restantes consistentes. No
es detectable dentro de un fichero mutable. Se cierra con un ancla publicada fuera del árbol
(`verificar_cadena(ws, ancla)`); sin ella queda `NOT_PROVEN`.

### 5 · La autoridad de veredicto se separa de la de observación

`gates/**` está protegido, así que el sujeto no puede editar a su juez — y eso incluye al
agente que implementó esto, al que el guardián rechazó la edición en el acto. Por eso el
invariante de cobertura no se exige al construir `Result` sino en `core.evidence.verdict_of`:
**una puerta que aprueba sin declarar qué observó no produce una corrida integrable.** El
observador propone; el motor de veredicto dispone.

## Qué lo haría cambiar

- Que aparezca una frontera de proceso real (uid distinto, montaje de sólo lectura, espacio
  de nombres). Entonces `I6` pasaría de `NOT_PROVEN` a demostrable y `I6'` sería una
  defensa en profundidad en vez de la garantía principal.
- Que `Ê` empiece a producir falsos positivos en trabajo normal. Sería señal de que el
  modelo de efectos se está usando como si fuera completo.
- Que alguien publique la cabeza del diario por defecto en CI: cerraría la truncación de
  cola y `FORMAL-MODEL.md` §8 perdería una entrada.

## Consecuencias

- `ADR-0011` queda **corregido**: `TB-3` no es «inmutable», es «tamper-evidente». Su
  invariante «un agente nunca puede autorizarse a sí mismo» se sostiene para el canal
  estructurado y para las escrituras demostrables de consola, y **no** para una orden opaca.
- `DEFINITION-OF-COMPLETE` #6 pasa de `PASS` a `PASS` acotado: enforcement preventivo
  demostrado para `Ê`, con `I6` declarado `NOT_PROVEN`.
- `README` y `SECURITY.md` dejan de afirmar prevención sin acotarla.
