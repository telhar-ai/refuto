# Refuto contra sistemas de frontera

**Fecha:** 2026-09-25 · **Sujeto:** `e948152` + remediación C-02 · **Método:** especificaciones
primarias (E1) contrastadas con mediciones sobre este árbol y sobre esta máquina (E4,
`LIMITATION: single-host`, macOS 26.4.1 arm64).

> Este documento **no** es una tabla de «mejor/peor». Para cada familia se responde qué problema
> resuelve, qué frontera establece, qué garantía da, **qué no cubre**, qué transfiere a refuto y
> qué no transfiere. Copiar una arquitectura por autoridad es la forma más rápida de importar sus
> límites sin sus garantías.

El comparativo previo (`harness-ecosystem-comparative.md`) sitúa a refuto frente a **runtimes de
agentes** — Claude Code, Kiro, LangGraph, SWE-bench. Ése es su mercado. Este documento lo sitúa
frente a su **disciplina**: sistemas que existen para sostener afirmaciones sobre efectos.

---

## 1 · Transparency logs — el problema del ancla

### Qué resuelve

Que el productor de un registro no sea la única autoridad capaz de afirmar que su registro no fue
alterado. Es literalmente el problema abierto de refuto: `uid(productor) = uid(verificador)`.

### La frontera que establece

Un **checkpoint** es una cabeza de árbol firmada cuyo cuerpo tiene tres líneas obligatorias:

```
origin        identificador único del log
tree size     número de hojas, decimal ASCII
root hash     raíz del árbol de Merkle RFC 6962 a ese tamaño
```

Y un **witness** es un servicio HTTP separado que cosigna el checkpoint, declarando que a una hora
dada ésa es la cabeza consistente de mayor tamaño que ha observado para ese `origin`.

### El detalle que cambia el diseño de refuto

**El tamaño va dentro del ancla firmada.**

Hoy `core/evidence.py::verificar_cadena` recibe dos parámetros separados:

```python
verificar_cadena(ws, esperado="<hash>", eventos_minimos=5)
```

`esperado` es la raíz; `eventos_minimos` es el tamaño. **Son las dos mitades de un checkpoint,
implementadas por separado y sin firmar.** Al llegar a `eventos_minimos` en C-02 no conocía la
especificación; el contraste muestra que la forma canónica los une en un objeto, y que unirlos no
es cosmético: un ancla que sólo lleva la raíz obliga a *buscar* ese hash en la cadena, mientras
que una que lleva el tamaño detecta la truncación por comparación directa.

### Qué NO cubre

Un transparency log no impide la escritura de un registro falso: hace que sea **descubrible**. Es
tamper-evidence, no tamper-proofing — la misma honestidad que `core/evidence.py` ya declara. Y el
witness sólo vale si es **independiente**: un witness en la misma máquina y con el mismo uid no
añade nada, y eso es exactamente lo que refuto no puede resolver solo.

### Qué transfiere

1. **Fusionar `esperado` + `eventos_minimos` en un checkpoint** con `origin`, `size`, `root`.
2. **Un comando para obtenerlo.** Hoy no existe: `refuto evidence` tiene `--last`, `--kind` y
   `--json`, y `core/evidence.py` llegó a citar un `--anchor` inexistente. Sin orden que lo
   produzca, los 7 de 12 ataques que dependen del ancla están cerrados en el motor y abiertos en
   la práctica.
3. **La separación log ↔ witness como dos identidades**, aunque al principio las dos sean el
   mismo proceso: lo que importa es que el modelo pueda expresar la diferencia.

### Qué NO transfiere

El árbol de Merkle en tiles, la red pública de witnesses y el protocolo HTTP completo. Refuto
tiene un diario lineal de una sola máquina; adoptar tiles resolvería un problema de escala que no
tiene. **La firma sí; la infraestructura no.**

---

## 2 · Admission control (Kubernetes) — el contrato de entrada

### Qué resuelve

Que una petición que no se puede decodificar no se confunda con una petición inocua.

### La frontera que establece

Dos mecanismos que refuto no tiene:

- **`admissionReviewVersions`** — lista ordenada de versiones que el webhook entiende. Si el
  servidor no soporta ninguna, **la validación falla**; no se asume compatibilidad.
- **`failurePolicy`**, con valor por omisión **`Fail`**.

### El matiz que importa más que el mecanismo

`failurePolicy` cubre exactamente cuatro situaciones: *timeout*, respuesta no-2xx, **contenido que
no se puede interpretar como `AdmissionReview`**, y `AdmissionReview` de respuesta inválida. **No**
cubre que el webhook responda correctamente denegando.

Esa distinción —«no pude interpretar» frente a «interpreté y decido»— es precisamente la que
`core/guard.py` no hacía, y sigue sin hacer del todo: medido el 2026-09-25, cinco de dieciséis
formas de carga declaran `tool_name: Write` con una ruta que no se puede extraer, y se aprueban.

### El caso real que valida el hallazgo

No es teórico. El issue kubernetes/kubernetes#108155 documenta un webhook de **OPA** fallando
**abierto** por una conversión `v1beta1.AdmissionReview` → `v1.AdmissionReview` desconocida, con
`failurePolicy: Ignore`. Es la misma clase de defecto que `R-03` en refuto —deriva de esquema
tratada como permiso— ocurrida en un sistema de frontera desplegado.

### Qué transfiere

Un contrato de admisión con **versión** y **campos obligatorios por operación**. La versión no es
burocracia: es lo único que convierte «el runtime cambió su formato» de indetectable en detectable.

### Qué NO transfiere

El modelo de webhook remoto y su `blast radius`. La documentación de Kubernetes advierte que un
`failurePolicy: Fail` apuntando a un backend caído hace fallar **toda** creación de pods. Refuto
debe aprender la lección inversa: su equivalente de `Fail` tiene que ser `ask`, no `deny`, o el
primer cambio de esquema deja el espacio inutilizable y el control se desengancha.

---

## 3 · PDP/PEP (OPA) — separar decidir de impedir

### Qué resuelve

Que la política se evalúe en un sitio y se aplique en otro, de modo que cambiar la norma no exija
tocar el punto de aplicación.

### Lo que la medición dice de refuto

Contra lo esperado, **esta separación ya existe en la capa correcta**:

```
core/policy.py    0 apariciones de «tool»
core/effects.py   0
core/grants.py    0
```

La decisión se toma sobre una ruta o una orden; nunca sobre el nombre de la herramienta. El único
uso de `tool` es en `guard.py`, para registrar el evento. **El acoplamiento está en la extracción,
no en la decisión**, y eso abarata mucho el trabajo de admisión: no hay que rehacer la política.

Lo que falta es el otro lado: el PEP de refuto es **consultivo**. `deny` es una recomendación que
el runtime honra. `FORMAL-MODEL §6.2` ya demuestra por qué no puede ser otra cosa con un solo uid.

### Qué transfiere

La política como **artefacto versionado y recuperable por digest**. Hoy `policy_digest` se
registra en cada evento y **no existe almacén que resuelva ese digest a un documento**: tres
digests distintos en 2015 eventos, ninguno recuperable. Un identificador que no resuelve no hace
reproducible una decisión.

### Qué NO transfiere

Rego. Refuto no necesita un lenguaje de políticas: necesita que sus 64 reglas dejen de ser
constantes de Python. `RUTA_BASE = "policies/base.json"` está declarado y **el fichero no existe**.

---

## 4 · in-toto / SLSA — identidad de lo actuado

### Qué resuelve

Atar una afirmación al objeto concreto sobre el que se hizo, de forma que no se pueda reapuntar a
otro.

### La frontera que establece

```json
{ "subject": [{ "name": "…", "digest": { "sha256": "…" } }],
  "predicateType": "https://slsa.dev/provenance/v0.2",
  "predicate": { "builder": { "id": "…" } } }
```

`subject.digest` es **la identidad de lo actuado, direccionada por contenido**. Verificar es hashear
lo que tienes delante y comparar. Una atestación no se puede reapuntar sin invalidar el hash.

### Lo que le falta a refuto

`core.policy.Decision` tiene `outcome`, `reason`, `rule`, `opaco`, `escrituras`. **No tiene
sujeto.** Medido en `R-04`: se autoriza `obra/salida.txt` en T1 con inode `186387287`, el sujeto
sustituye la ruta por un enlace al juez, y en T2 el inode es `186387285`. La autorización se emitió
sobre una cadena de caracteres, no sobre un objeto.

### El límite honesto de SLSA, que aplica igual a refuto

La propia especificación lo dice: *«el builder es de confianza por haber registrado fielmente la
procedencia; no hay más opción que confiar en él»*. Es la misma posición de refuto. Añadir
`subject.digest` **no** elimina la confianza en el productor — hace que la afirmación sea
**verificable por un tercero que tenga el objeto**, que es un escalón distinto y alcanzable.

### Qué transfiere

Un campo `subject` en la decisión y en el evento, con la identidad del objeto (dev/inode y, cuando
proceda, digest del contenido). Sin él, `R-04` no se puede ni **detectar**, y detectar es lo que
está al alcance sin privilegio.

---

## 5 · Enforcement a nivel de kernel — y por qué aquí refuto está BLOQUEADO

### Qué resuelve

La ventana TOCTOU: que lo autorizado en T1 sea lo afectado en T5.

### La frontera que establece

`openat2(2)` (Linux ≥ 5.6) con banderas evaluadas **atómicamente durante el recorrido del path**:
`RESOLVE_BENEATH`, `RESOLVE_NO_SYMLINKS`, `RESOLVE_NO_MAGICLINKS`, `RESOLVE_NO_XDEV`. El modelo
cambia de «confiar en cadenas» a **«confiar en descriptores»**: se abre un dirfd del raíz y todo se
resuelve bajo él con `*at`. Es un modelo de capacidades.

### Medición en la plataforma real de refuto

macOS no tiene `openat2`, pero sí bits análogos. Medido el 2026-09-25 en macOS 26.4.1 arm64, con un
enlace simbólico en un componente **intermedio**:

```
O_RDONLY                    → ABRIÓ el fichero a través del enlace
O_RDONLY | O_NOFOLLOW       → ABRIÓ el fichero a través del enlace     ← insuficiente
O_RDONLY | O_NOFOLLOW_ANY   → rechazó (ELOOP)                          ← sí protege
```

`os.O_NOFOLLOW_ANY` está expuesto por Python en esta plataforma. `O_NOFOLLOW` **sólo cubre el
último componente**, lo que refuta cualquier defensa basada en él.

### La trampa que obliga a verificar el instrumento

```
flag inventado 0x400000 → ACEPTADO EN SILENCIO
```

**El kernel ignora los bits de flag desconocidos.** En un macOS donde `O_NOFOLLOW_ANY` no exista,
el flag se ignoraría y el código creería estar protegido. Cualquier uso de estas banderas en refuto
exige una **comprobación de arranque** —abrir a través de un enlace intermedio y exigir que
falle— y declarar `DEGRADED` si no falla. Es el mismo principio que la sonda de mutación aplica a
sí misma con `NC1`/`NC2`: sin control negativo, el instrumento puede estar roto y parecer excelente.

### Qué NO transfiere

El enforcement real. Refuto es un hook **previo** a una herramienta que ejecuta **otro proceso**; no
abre el fichero. Puede vincular la decisión a una identidad de objeto y **detectar** la sustitución
después, no impedirla. `R-04` es por tanto `DEGRADED` en el mejor caso alcanzable, nunca `PASS`,
mientras el modelo sea un hook consultivo.

---

## 6 · Síntesis — qué se transfiere, ordenado por coste

| origen | principio | coste | qué cierra |
|---|---|---|---|
| tlog-checkpoint | el ancla lleva `size`, no sólo la raíz | bajo | 7 ataques que hoy son teoría |
| tlog-witness | log y witness como identidades distintas | bajo (modelo) | expresar `PASS/LOCAL` vs `PASS/ANCHORED` |
| admission K8s | contrato versionado, campos obligatorios | medio | `R-03`, `A` |
| K8s failurePolicy | «no pude interpretar» ≠ «interpreté» | bajo | la distinción que falta en `evaluate` |
| in-toto | `subject.digest`: identidad de lo actuado | medio | detección de `R-04` |
| OPA | política como artefacto recuperable por digest | alto | reproducibilidad de `B` y `C` |
| openat2 / O_NOFOLLOW_ANY | confiar en descriptores, no en cadenas | **BLOCKED** | nada, con un hook previo |

## 7 · Lo que ninguna de estas familias resuelve por refuto

Las cinco familias comparten un supuesto que refuto no cumple: **el punto de aplicación tiene más
privilegio que el sujeto**. El apiserver de Kubernetes no corre con el uid del pod; el kernel no
corre con el uid del proceso; el witness no corre en la máquina del log.

En refuto, `uid(sujeto) = uid(guardián) = uid(evidencia) = 501`.

Por eso ninguna importación de arquitectura cierra `D` ni `G`. Lo que sí hacen —y no es poco— es
dar la forma correcta a lo que **sí** es alcanzable: un contrato de admisión que no confunda
ignorancia con permiso, un ancla que lleve su tamaño, una decisión que nombre su objeto, y un
vocabulario que distinga lo verificado localmente de lo atestiguado fuera.

---

## Fuentes

- [Transparency Log Checkpoints (C2SP tlog-checkpoint v1.0.0)](https://c2sp.org/tlog-checkpoint@v1.0.0)
- [Transparency Log Witness Protocol (C2SP tlog-witness v1.0.0)](https://c2sp.org/tlog-witness@v1.0.0)
- [C2SP tlog-cosignature](https://github.com/C2SP/C2SP/blob/main/tlog-cosignature.md)
- [ValidatingWebhookConfiguration — Kubernetes API reference](https://v1-31.docs.kubernetes.io/docs/reference/kubernetes-api/extend-resources/validating-webhook-configuration-v1)
- [kubernetes/kubernetes#108155 — webhook failing open on unknown AdmissionReview conversion](https://github.com/kubernetes/kubernetes/issues/108155)
- [openat2(2) — Linux manual page](https://man7.org/linux/man-pages/man2/openat2.2.html)
- [SLSA — Provenance](https://slsa.dev/spec/v0.1/provenance)
- [in-toto and SLSA](https://slsa.dev/blog/2023/05/in-toto-and-slsa)
