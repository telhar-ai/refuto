# ADR-0021 — El gobierno se protege por autoridad, no por nombre de directorio

```yaml
decision: los artefactos de gobierno se declaran en `authority_paths` y se comparan contra la
          ruta relativa a cada RAÍZ DE AUTORIDAD que contenga al objetivo, no contra la ruta
          relativa al espacio; y A05 falla cerrado cuando no hay almacén de autorizadores
date: 2026-10-03
status: IMPLEMENTADA — 1439/1439 pruebas pasan (`python3 refuto.py selftest`, 2026-10-03,
        macOS arm64 Darwin 25.4.0, Python 3.14.6)
refina: ADR-0014 (alcance de rutas y monotonía por cobertura), ADR-0013 (raíz de confianza)
question: >
  ¿Por qué un patrón de `protected_paths` no podía distinguir el documento de norma de un
  espacio del código fuente que vive en un directorio llamado igual, y por qué eso no se
  arreglaba cambiando el patrón?
```

## Contexto — lo medido, no lo recordado

`protected_paths` tiene **un solo vocabulario**: un glob sobre la ruta relativa al espacio. Por
ahí se estaban forzando dos semánticas que no son la misma:

- **(a) «este artefacto esté donde esté».** `.harness/`, `.claude/`, `.kiro/`: nombres que el
  arnés o un runtime **reservan**. Globearlos con `**/` es correcto porque nadie más los usa.
- **(b) «el artefacto de gobierno de un espacio, en SU raíz».** `policies/`: una palabra común
  que el producto también usa para su propio código.

Con sólo (a) disponible, la norma tenía que elegir entre dos errores. Los dos se midieron.

**Hecho 1 · el error de sobre-bloqueo.** Con `**/policies/**`, en un espacio real:

    Write  security/policies/acceso.rego      →  deny  («**/policies/**»)
    Write  apps/web/policies/rate-limit.ts    →  deny  («**/policies/**»)

Censo de ese espacio: **61 directorios `policies/` clasificables, 46 de código y 15 de
gobierno** — ~75 % de error. Y el espacio **no podía retirarlo**:

    redeclarar `protected_paths` sin el patrón  →  deny: el efectivo es la UNIÓN (`ACUMULA`)
    declarar la excepción en `writable_paths`   →  HerenciaIrresoluble: el guardián deniega TODO

**Hecho 2 · el error de infra-bloqueo.** Con `policies/**` anclado a la raíz, el documento de
norma de cada repositorio hijo quedaba reescribible. Es el agujero que ADR-0014 cerró para
`.harness/` añadiendo `**/`, y que para `policies/` no se podía cerrar igual sin reabrir el
Hecho 1.

**Hecho 3 · lo que esto NO es.** Ninguno de los dos es un problema de datos. Los dos son el
mismo patrón intentando decir algo que su vocabulario no puede decir. Cambiar el patrón mueve el
error de sitio; no lo quita.

## Decisión

### 1 · `authority_paths`, anclado a raíces de autoridad

Un campo nuevo cuyos patrones se comparan contra la ruta relativa a cada **raíz de autoridad**
que contenga al objetivo. Raíz de autoridad = directorio con `.harness/` dentro (la raíz de un
espacio gobernado), y la raíz del espacio **siempre**, tenga `.harness/` o no.

De fábrica: `authority_paths = ("policies/**",)`. Medido el 2026-10-03:

| objetivo | decisión | por qué |
|---|---|---|
| `policies/reglas.rego` | **deny** | raíz del espacio: es gobierno |
| `policies/base.json` | **deny** | la capa 1 de la cadena de herencia |
| `repo-hijo/policies/base.json` | **deny** | raíz de autoridad `repo-hijo` |
| `ai/…/src/kernel/mk/policies/x.rs` | **allow** | ninguna raíz lo ancla: es código |
| `domain/governance/policies/x.yaml` | **allow** | ídem |
| `security/policies/acceso.rego` | **allow** | ídem |

Sobre **40.327 ficheros reales en 11 espacios instalados**: cero denegados por una regla
`policies`.

### 2 · Se evalúa en TODAS las raíces, no en la más cercana

Con «la más cercana», el mecanismo se evade plantando una raíz: creado `policies/.harness/`, la
ruta relativa de `policies/base.json` pasa a ser `base.json`, que no casa con `policies/**`.

Evaluando en todas las raíces que contienen al objetivo, añadir una raíz más profunda sólo puede
**añadir** coincidencias, nunca quitarlas. La evasión deja de ser improbable y pasa a ser
**inexpresable**, que es la única clase de control que no hay que defender caso por caso.
Prueba: `tests/adversarial/test_autoridad_por_raiz.py::test_plantar_una_raiz_no_desprotege`.

### 3 · Monotonía `ACUMULA`

Un cliente declara **sus** artefactos de gobierno (`gobierno/**`, `normas/**`) y sus proyectos no
pueden retirárselos. Vaciar el campo es inexpresable, igual que en `protected_paths`.

### 4 · A05 falla cerrado cuando no hay almacén de autorizadores

Encontrado al ejercer el ciclo de cambio protegido como vía legítima de administración —lo que
hay que hacer antes de declarar `BLOCKED`—. `core/change.py::apply` decía `if trusted:`, así que
un almacén **ausente o vacío** saltaba A05 entero. Medido de punta a punta por el protocolo:

    propone  «agente»            →  propuesta creada
    autoriza «revisor-humano»    →  token EMITIDO (identidad inventada, par de claves propio)
    aplica   gates/g_colado.py   →  *** APLICADO ***

Lo mismo con `verification/**` y `evidence/**`: un agente escribiendo **su propio juez y su
propia evidencia** con sólo inventarse un segundo nombre. Sólo `.harness/policy.json` se
salvaba, por A03 (quórum de gobernanza).

A02 verificaba la firma y por eso no se notaba: verifica contra la clave pública que el **token
trae**, así que sin A05 demuestra que el token no se alteró, no que lo firmara nadie. Una firma
sin almacén de confianza es un sello sin registro.

Un almacén vacío es un **ámbito vacío**, y aquí un ámbito vacío no aprueba: la misma regla que
hace fallar una suite de 0 pruebas y que impide a `G-SECURITY` aprobar con el escáner caído.

Las 15 pruebas de `TestChangeGovernanceA01A15` escribían el almacén en `setUp`: cubrían A05 en el
caso «hay almacén» y **ningún** caso «no hay», que es el estado real de los 11 espacios medidos.

## Consecuencias

**Lo que mejora.** `policies/` deja de ser una palabra prohibida en el árbol. El documento de
norma de cada espacio y de cada hijo está protegido por su autoridad y no por su nombre. Y el
ciclo de cambio protegido deja de poder usarse sin autoridad real.

**Lo que cuesta, declarado.**

1. El `policies/` **de la raíz** de un espacio gobernado está protegido entero. Un espacio que
   quiera código fuente ahí tiene que renombrarlo. Es deliberado: ahí vive la norma de la que
   cuelgan sus hijos.
2. `raices_de_autoridad` **mira el sistema de archivos** (un `is_dir()` por ancestro). Es la
   frontera impura del mecanismo; `is_authority` se mantuvo pura para poder probarla sin árbol.
3. Un espacio sin `.harness/trusted_authorizers.json` ya **no** puede aplicar cambios sobre
   superficie protegida por el ciclo. Registrar al primer autorizador es un acto de persona, y
   ese fichero está bajo `.harness/**` justo por eso. Hoy no rompe ningún uso: el almacén no
   existe en ninguno de los 11 espacios, luego nadie usaba esa vía con autoridad real.
4. **Riesgo residual, no cerrado:** quien pueda escribir `.harness/trusted_authorizers.json`
   puede autoinscribirse. Es la misma frontera de confianza que la política misma —`.harness/**`
   está protegido— y no se puede estrechar más desde dentro del espacio.
5. Una protección retirada de `protected_paths` **no se va** de un espacio ya instalado: su
   fichero la declara y `ACUMULA` la mantiene viva. `refuto upgrade` lo nombra como residuo
   (`policy_residue`), con el fichero que lo declara. Retirarlo es acto de persona.

## Qué probar antes de creérselo

| afirmación | la prueba que la sujeta |
|---|---|
| el código anidado se escribe | `test_autoridad_por_raiz.py::TestA_…` |
| el gobierno no, en la raíz y en cada hijo | `TestB_…` |
| el nombre no concede permisos por coincidencia | `TestC_…` |
| `..` no escapa ni desancla | `TestD_…` |
| un enlace no convierte permitido en protegido | `TestE_…` |
| la caja se trata según la plataforma, y se declara | `TestF_…` |
| relativa y absoluta dan la misma decisión | `TestG_…`, `TestH_…` |
| plantar una raíz no desprotege | `TestI_…` |
| el hijo no puede retirarlo, ni vaciándolo | `TestJ_…` |
| el mecanismo no es vacuo, y es ÉL quien deniega | `TestElMecanismoNoEsVacuo` |
| A05 falla cerrado sin almacén, y aplica con él | `test_change_governance_a01_a15.py::TestA05FallaCerradoSinAlmacen` |
