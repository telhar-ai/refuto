# Ejecución de extremo a extremo

Ejecutada el **2026-08-27** en macOS arm64, sobre un repositorio de prueba, con un agente real y
créditos reales. Nivel: **`E4` de un caso** (`n=1`). No demuestra una propiedad del producto;
demuestra que el mecanismo puede ocurrir, una vez, con esas versiones.

**Sobre la fidelidad de lo pegado.** Las salidas son las de aquella ejecución, **editadas** para
acortar rutas y quitar ruido; en el bloque final de `verify` se conservó además una puerta que la
orden no pidió, y se marca. Donde una tabla y una salida no coinciden, manda la salida.

**El repositorio de la demo no está publicado** (vivía en `/tmp`), así que esto **no es
reproducible por un tercero** tal cual: es una observación fechada, no una guía. Lo reproducible
es [`examples/espacio-minimo`](../../examples/espacio-minimo/).

## El entorno

```
Darwin 25.4.0 arm64 · Python 3.14.6
claude 2.1.247 · kiro 2.20.0 · gemini 0.55.1 · opencode 1.2.27 · codex 0.103.0 (BLOQUEADO)
```

## El repositorio

`/tmp/e2e-demo` — «conversor de divisas»: dominio en JavaScript sin dependencias, dos pruebas,
tres requisitos. `REQ-003` (catálogo de divisas ordenado) **no tenía prueba**.

```
rama       feat/REQ-003-catalogo-de-divisas
commit     9fe6bd90655b
stack      node
```

---

## 1 · Descubrimiento

```
$ refuto discover

  Núcleo SDD
    ✗ no se encontró ningún núcleo
      buscado en: /private/tmp/e2e-demo, /private/tmp, /private

  Repositorio de trabajo
    ✓ /private/tmp/e2e-demo
      confianza CIERTO (1.0) · el directorio actual está dentro de este repositorio
      commit      9fe6bd90655b2784037b0c7c04150079f1f2d038
      rama        feat/REQ-003-catalogo-de-divisas
      stack       node

  Herramientas · 24/30 presentes
```

**No hay núcleo SDD aquí, y eso no es un fallo**: este repositorio no está gobernado por uno.
refuto lo dice y sigue; lo que no hace es inventarse uno.

## 2 · Vínculo

```
$ refuto bind set
  ✓ repository: /private/tmp/e2e-demo
      el directorio actual está dentro de este repositorio
      anclado al commit 9fe6bd90655b

  ? sdd_core: no se encontró el núcleo SDD. Buscado en: …
      elija con: refuto bind set --core <ruta>
```

Vincula lo que puede resolver y **pregunta lo que no**. El ancla es el commit, no la ruta.

## 3 · Política compilada y enganchada

```
$ refuto policy compile --agent claude
  ✓ claude
      i Claude aplica deny sobre patrones de ruta y de orden; el gancho cubre el contenido,
        que el patrón no ve.
      escrito .claude/settings.harness.json
```

El gancho de Claude apunta al **guardián canónico** — el mismo programa que engancha Kiro. Gemini
**no** lo engancha: `policy wire` no lo cubre (comprobado el 2026-09-22 en `refuto.py`). Compilar
la política para Gemini produce un artefacto; que Gemini lo lea no está verificado.

## 4 · Plan, antes de gastar nada

```
$ refuto plan --goal "REQ-003 …" --phase TEST

Plan · run_28859f7151d94af2  «REQ-003: el catálogo de divisas necesita una prueba que lo cite»

  TEST
    · PENDING  test-engineer            claude
        puertas  G-SDD:PENDING G-TRACE:PENDING
    · PENDING  performance-engineer     claude
```

`claude` no se eligió por su nombre: se eligió porque cubre `agent.headless` y `agent.tool_use`
**y aplica la política entera**, cosa que `opencode` no hace.

## 5 · Estado antes

```
requisitos: ['REQ-001', 'REQ-002', 'REQ-003']
sin prueba: ['REQ-003']
```

## 6 · Ejecución real

```
$ refuto run --execute --budget 0.40 --phase TEST --goal "REQ-003 no tiene prueba…"
```

La instrucción que recibió el agente **se deriva del contrato del rol**, no de un prompt
escrito a mano — así que cambiar el contrato cambia la instrucción y no pueden divergir:

```
Actúa como test-engineer.

**El encargo:** REQ-003 no tiene prueba. Escribe en pruebas/dominio.test.js …

**Tu papel en él.** Escribe y ejecuta pruebas que citan el requisito que comprueban.

**Consumes:** code, test-strategy

**Debes producir:** tests, coverage, test-report.
Sin esos artefactos la fase NO ha terminado, digas lo que digas.
Trabaja sobre los archivos del repositorio actual; no describas lo que harías.

**No puedes:**
- no puede tocar lo que lo evalúa
- no puede tocar la evidencia

Estas restricciones las aplica un guardián fuera de tu control: intentar saltarlas produce
un bloqueo registrado, no un atajo.

**Al terminar se ejecutan:** G-SDD, G-TRACE.

_La cita del requisito va en el NOMBRE de la prueba: sin eso, la trazabilidad es un documento
en vez de una propiedad._
```

**Matiz sobre la frase «las aplica un guardián fuera de tu control».** Es el texto que el motor
inyecta, y es exacto para **estas dos** restricciones concretas —`no_modify_verifier` y
`no_modify_evidence`— porque coinciden con rutas que la política protege. El guardián **no conoce
el rol activo** (comprobado el 2026-09-22): lo que bloquea es la ruta, no el contrato del rol. Ver
[`../agents/`](../agents/).

### Lo que el agente escribió

```diff
+test('[REQ-003] devuelve el catálogo de divisas soportadas en orden', () => {
+  assert.deepEqual(divisasSoportadas(), ['EUR', 'MXN', 'USD']);
+});
```

```
$ node --test pruebas/dominio.test.js
✔ [REQ-001] convierte de MXN a USD
✔ [REQ-002] devuelve nulo ante una divisa desconocida
✔ [REQ-003] devuelve el catálogo de divisas soportadas en orden
ℹ tests 3 · pass 3 · fail 0
```

### Lo que registró refuto

```
TEST/test-engineer → claude  [BLOCKED]
  motivo   la puerta G-SDD no se pudo comprobar: este espacio no tiene verificacion/verificar.py
  coste    $0.2800 · 66 694 ms
  puertas  {'G-SDD': 'BLOCKED', 'G-TRACE': 'PASS'}
```

El paso quedó **`BLOCKED`, no `DONE`**: el trabajo está bien y una de sus puertas no se pudo
comprobar. `G-SDD` es `BLOCKED` porque este repositorio no tiene puertas SDD — *no aplica aquí*,
que no es lo mismo que *pasa*.

### Un segundo intento agotó el presupuesto

```
TEST/test-engineer → claude  [FAILED]
  motivo   error_max_budget_usd · 20 turnos
  coste    $0.4245
```

El tope de gasto funcionó, se registró, y el paso quedó `FAILED`. Es el tipo de resultado que un
arnés de gobierno tiene que poder contar sin adornos.

## 7 · Reanudación, y su guardia

```
$ refuto resume
Reanudar · run_379bffb3979b48d3
  2 pasos pendientes: TEST/test-engineer, TEST/performance-engineer
    ⊘ BLOCKED  test-engineer   puertas  G-SDD:BLOCKED G-TRACE:PASS
```

Y con el entorno cambiado a propósito:

```
$ refuto resume       # tras modificar .harness/policy.json

  El entorno cambió desde que se dejó:
    ✗ la política cambió: 55fa140187950649 → c4b799d8d283952f

  Reanudar aquí produciría evidencia que dice una cosa sobre un árbol que ya es otra.
  Use --force sólo si sabe exactamente por qué.
```

## 8 · Cierre del ciclo

```
$ git commit -m "test: prueba de REQ-003, catálogo de divisas ordenado"
$ # revisión humana registrada a nombre de otra persona (user@example.com)
$ refuto verify --gate G-TRACE --gate G-PR --gate G-HUMAN --gate G-ROLES

  ✓ PASS      G-TRACE   3 requisitos · 21 citas · 0 fantasmas · 0 sin prueba
  ✓ PASS      G-PR      rama «feat/REQ-003-…» · requisitos citados en los commits: REQ-003
  ⊘ BLOCKED   G-HUMAN   ningún rol ejecutado exige revisión humana
                        (roles ejecutados: test-engineer)
  ✓ PASS      G-ROLES   22 roles · 0 problemas
  ⊘ BLOCKED   G-SECURITY  syft NO está: sin SBOM no se puede responder «¿qué contiene esto?»
                          ante un CVE. → BLOCKED, no PASS

  VEREDICTO: NO INTEGRABLE TODAVÍA — hay puertas que no se pudieron comprobar
```

**Discrepancia declarada:** la orden pide **cuatro** puertas y la salida muestra **cinco**
(`G-SECURITY` de más). Con `--gate`, `gates/base.py` ejecuta sólo las pedidas, así que ese bloque
mezcla dos ejecuciones distintas de aquel día. Se deja a la vista en vez de recortarlo: el `PASS`
y los `BLOCKED` de las otras cuatro son de la orden escrita arriba.

---

## Qué demuestra esta ejecución

| | |
|---|---|
| **Descubrimiento** | repositorio resuelto por hecho decisivo; ausencia de núcleo declarada, no inventada |
| **Vínculo** | ancla por commit; pregunta lo que no puede resolver |
| **Enrutado por capacidad** | `claude` elegido por cubrir las capacidades **y** aplicar la política entera |
| **Contrato → instrucción** | lo que se le dice al agente se deriva del contrato del rol |
| **Trabajo real** | prueba escrita, citando el requisito, y pasa |
| **Puertas honestas** | `G-TRACE` PASS · `G-SDD` BLOCKED por no aplicar · `G-SECURITY` BLOCKED por falta de `syft` |
| **Coste medido** | `$0.2800` el intento bueno; `$0.4245` el que agotó el tope. Una ejecución, 2026-08-27, `claude 2.1.247`, macOS arm64. Los precios del proveedor cambian: no lo lea como el coste de su ejecución |
| **Presupuesto** | el tope cortó la ejecución y quedó registrado como `FAILED` |
| **Reanudación** | detecta el cambio de política y se niega a continuar |
| **Revisión humana** | **no se demostró.** La salida dice `BLOCKED G-HUMAN: ningún rol ejecutado exige revisión humana`. Que `G-HUMAN` rechace la auto-aprobación está probado en la suite (`E3`), no aquí |
| **Veredicto** | `NO INTEGRABLE TODAVÍA` — el estado bloqueado existe y se usa |

## Qué NO demuestra

- **El ciclo completo de trece fases.** Se ejecutó **una** fase, `TEST`. Ejecutar las trece con
  agentes reales cuesta dinero y no se ha hecho: `NOT_RUN`.
- **`VALIDATE` con navegador.** Este repositorio no tiene interfaz.
- **`RELEASE`.** No hay nada que publicar.
- **Codex.** No arrancaba en aquella máquina, en aquella versión (H-01). Con la versión reinstalada
  la sonda sube sola de peldaño; conducir trabajo con Codex sigue `NOT_RUN`.
- **Nada estadístico.** `n=1`, una máquina, un día, un agente.
