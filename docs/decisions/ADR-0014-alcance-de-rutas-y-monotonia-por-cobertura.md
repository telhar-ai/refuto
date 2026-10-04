# ADR-0014 — Una protección y su excepción se mueven juntas, o el espacio queda sin arreglo

```yaml
decision: los patrones de ruta de la norma base cubren cualquier profundidad, y la monotonía
          de `REDUCE` se comprueba por cobertura demostrada en vez de por igualdad de cadena
date: 2026-09-24
status: IMPLEMENTADA — 629/629 pruebas pasan (`python3 refuto.py selftest`, 2026-09-24)
refina: ADR-0006 (política única compilada), ADR-0013 (raíz de confianza y modelo de efectos)
question: >
  ¿Por qué la norma base no se podía corregir sin dejar ungobernables los espacios ya
  instalados, y por qué añadir una protección producía denegaciones que el espacio no podía
  reparar?
```

## Contexto — lo medido, no lo recordado

Auditoría de un espacio gobernado real el 2026-09-24: raíz que **no** es repositorio, dos
hijos que sí, cada uno con su `.harness/`. 176 decisiones en su diario.

**Hecho 1 · el alcance.** Los patrones de `DEFAULT_PROTECTED` estaban anclados al primer nivel:

    Write  .harness/bin/guard                    →  deny   («.harness/**»)
    Write  repo-hijo/.harness/bin/guard           →  ALLOW

Desde la raíz se podía reescribir el guardián, la política y la evidencia de cada hijo. El
dueño del espacio lo detectó y añadió los `**/` **a mano en su propia política**. Que un
espacio tenga que parchear la norma base para no tener un agujero es el diagnóstico: el agujero
era de la norma base, no del espacio.

**Hecho 2 · la reparación imposible.** `protected_paths` es `ACUMULA` y `writable_paths` es
`REDUCE` (ADR-0006, `core.refinement.REGLAS`). Al añadir `**/.harness/**`, el espacio protegió
también `hijo/.harness/memory/` — pero la excepción heredada era `.harness/memory/**`, anclada
a la raíz. Resultado medido: los hijos sin memoria de agente. Y el espacio **no podía
arreglarlo**: añadir la excepción levanta `HerenciaIrresoluble`, y un guardián cuya política no
carga deniega todo. Medido:

    writable_paths: [".harness/memory/**", "dossier/**"]
      →  HerenciaIrresoluble: el hijo añade 1 entrada(s) que el padre no tiene

Es decir: **toda protección que cubra más profundidad que su excepción produce una denegación
colateral irreparable desde el espacio.** La asimetría no es un descuido de quien escribió esa
política; es una propiedad del modelo.

**Hecho 3 · la corrección se bloqueaba a sí misma.** Al corregir `DEFAULT_WRITABLE` a
`**/.harness/memory/**`, toda política existente que declarara el valor anterior dejó de
resolverse — y el instalador de refuto escribía exactamente ese valor. `REDUCE` comparaba
cadenas (`hijo - padre`), y por cadena `.harness/memory/**` es una entrada «nueva» respecto de
`**/.harness/memory/**`, cuando por cobertura es un **subconjunto estricto**. La norma base era
incorregible: cualquier arreglo dejaba ungobernables los espacios ya instalados.

## Decisión

1. **Los patrones de la norma base llevan `**/`.** No son patrones nuevos: `_path_matches` ya
   define `**/X` como «X en la raíz o a cualquier profundidad» (para un patrón `**/…` prueba
   además sin el prefijo). Es el alcance corregido de los que ya había, y el cambio es
   estrictamente restrictivo, luego compatible con `ACUMULA`.
2. **`DEFAULT_WRITABLE` se mueve con ellos**, a `**/.harness/memory/**`. La simetría entre una
   protección y su excepción pasa a ser contrato probado (`tests/unit/test_policy.py`:
   `test_protege_A_CUALQUIER_PROFUNDIDAD_no_solo_en_la_raiz` y
   `test_la_memoria_del_agente_es_escribible_a_cualquier_profundidad`, que es la contraparte
   sin la cual la primera se satisface denegando todo).
3. **`REDUCE` se comprueba por cobertura demostrada**, no por igualdad de cadena
   (`core.refinement._cubre`). Comparar globs no es decidible en general, así que `_cubre`
   devuelve `True` **sólo** cuando la inclusión se puede demostrar, y ante la duda `False` — la
   entrada se trata como añadida y se rechaza. Rechazar un estrechamiento legítimo se nota y se
   arregla; aceptar un ensanchamiento no se nota nunca.
4. **El efectivo de `REDUCE` es la lista del hijo**, no la intersección. Ya está demostrado que
   cada entrada suya está cubierta por el padre, luego su lista *es* el estrechamiento. La
   intersección por cadena daba el conjunto **vacío** con padre `**/X` e hijo `X`, dejando al
   espacio sin ninguna excepción en vez de con la que declaró. Para toda política que ya
   cumplía por igualdad, las dos formas coinciden.

## Alternativas consideradas

**Duplicar cada patrón en sus dos formas** (`X/**` y `**/X/**`). Funciona y no toca el motor,
pero duplica la lista que el informe de sesión enumera una a una, y el informe es lo que el
agente lee en el turno cero. Una norma que se lee al doble de largo se lee peor.

**Dejar que el hijo añada excepciones libremente.** Es la relajación que `REDUCE` existe para
impedir: un agujero heredado en silencio a través de dos capas es indetectable en revisión.
Rechazada.

**Comprobar el invariante real de rutas** — `Deny(hijo) ⊇ Deny(padre)`, con
`Deny = protegido ∖ escribible` — en vez de campo por campo. Es la formulación correcta y
admite más refinamientos legítimos: un hijo que protege una región nueva y exime parte de ella
es estrictamente más restrictivo que su padre. **No se implementa aquí**: requiere decidir la
inclusión entre globs arbitrarios, que es justo lo que `_cubre` evita hacer. Queda anotado como
la evolución natural, con su coste.

## Tradeoff aceptado

Una excepción escribible **dentro de una región que el padre protege sigue siendo
inexpresable**. Un espacio que protege `dossier/**` y quiere `dossier/borrador/**` abierto no
puede declararlo. Es deliberado: es el mismo mecanismo que impide que un espacio se exima de
`evidence/**`, y ahí la respuesta correcta no es abrir la regla sino **renombrar el destino**
—medido: el espacio auditado tenía todo lo demás escribible y sólo colisionaba con un nombre
reservado—. Si aparece un caso legítimo, la vía es la alternativa tercera, no aflojar `REDUCE`.

`_cubre` es **incompleto por construcción** (`_cubre ⊆ ⊆`), igual que `Ê ⊆ Effects` en
ADR-0013. Reconoce hoy una sola forma de inclusión: `**/X ⊇ X`. Otras inclusiones ciertas se
rechazarán como violaciones hasta que alguien las demuestre y las añada. Se prefiere el falso
rechazo, que es visible, al falso permiso, que no lo es.

## Verificación — qué prueba que esto funcionó

```sh
python3 refuto.py selftest                 # 629/629 · 2026-09-24
python3 -m unittest tests.unit.test_policy tests.adversarial.test_documento_aqui
```

- `test_protege_A_CUALQUIER_PROFUNDIDAD_no_solo_en_la_raiz` — 7 rutas × 2 profundidades; falla
  contra los patrones anclados a la raíz.
- `test_la_memoria_del_agente_es_escribible_a_cualquier_profundidad` — la contraparte.
- `tests/adversarial/test_efectos_cruzados.py` — la tabla `mecanismo × ruta protegida` incluye
  ahora el documento aquí citado y con sangría: el arreglo de `_sin_cuerpos_citados` no abre
  una vía hacia el juez.
- `test_ensanchar_un_agujero_se_rechaza_entero` — sigue rechazando la relajación real
  (`writable_paths` con `gates/**`) después del cambio de `REDUCE`.
