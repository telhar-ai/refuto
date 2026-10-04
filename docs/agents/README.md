# Roles y agentes

## La distinción

```
ROL     una unidad de trabajo con contrato          22 roles en roles/registry.json
AGENTE  un runtime capaz de ejecutar roles          5 adapters en adapters/
```

«5 adapters» es cuántos agentes se pueden **sondear**. Cuántos abren sesión gobernada (4) y
cuántos tienen el guardián enganchado (3) son cifras distintas: tabla de capacidades en el
[`README.md`](../../README.md).

Un rol declara qué consume, qué produce, qué herramientas puede usar, qué **no** puede hacer,
qué puertas corren al terminar y qué revisión humana hace falta. Un agente declara cómo se
sondea, cómo se le habla y qué parte de la política sabe aplicar.

**El router los empareja por capacidad, nunca por nombre** (`core/routing.py`).

## Los 22 roles

| Grupo | Roles |
|---|---|
| management | `product-strategist` `delivery-manager` |
| specification | `requirements-engineer` `acceptance-engineer` |
| architecture | `solution-architect` `security-architect` `data-architect` |
| ux | `ux-designer` `accessibility-engineer` |
| development | `backend-engineer` `frontend-engineer` `data-engineer` |
| quality | `test-strategist` `test-engineer` `visual-validator` `performance-engineer` `reviewer` |
| security | `security-engineer` `adversarial-reviewer` |
| devops | `release-engineer` `observability-engineer` |
| documentation | `technical-writer` |

No hay cincuenta. Un rol que no cambia ninguna decisión de enrutado, ninguna puerta y ningún
artefacto no es un rol: es un nombre.

## Las diez restricciones, y cómo se aplican de verdad

Una restricción que el sistema no sabe aplicar es una restricción que **no existe**, y declararla
es peor que no tenerla: se cita en las revisiones como si protegiera. Por eso conviene decir con
exactitud qué ocurre hoy con cada una.

| Restricción | Significa |
|---|---|
| `no_write_code` | no puede escribir en el producto |
| `no_shell` | no puede ejecutar órdenes |
| `no_modify_verifier` | no puede tocar lo que lo evalúa |
| `no_modify_evidence` | no puede tocar la evidencia |
| `no_modify_product` | observa; no repara |
| `no_secret_access` | no puede leer rutas de credencial |
| `no_self_approval` | no puede aprobar lo que él mismo produjo |
| `no_fix_what_it_reviews` | no puede arreglar lo que critica |
| `read_only_infrastructure` | sólo verbos de lectura contra infraestructura |
| `destructive_requires_approval` | toda operación destructiva pasa por una persona |

Tres de ellas merecen énfasis porque son decisiones de diseño, no higiene:

- **`requirements-engineer` no tiene consola.** Esa fase no ejecuta nada, y dársela sería
  regalar superficie a cambio de nada.
- **`adversarial-reviewer` no puede arreglar lo que critica.** Un revisor que arregla deja de
  criticar con dureza, porque arreglar es más cómodo que derribar.
- **`visual-validator` observa y no repara.** Si el mismo agente pudiera corregir lo que juzga,
  el ciclo se queda sin juez independiente y converge a «ya está bien» sin haberlo estado.

### Qué aplica cada una, hoy

**Medido el 2026-09-22 (`E2`, `grep` sobre el árbol):** los diez nombres existen en
`core/roles.py` y `G-ROLES` rechaza el registro si aparece uno que no está en la lista. Pero
**ninguno de los diez se consulta en `core/guard.py` ni en `core/policy.py`**: el guardián no sabe
qué rol está ejecutando. Su aplicación real es esta:

| Vía | Qué hace | Nivel |
|---|---|---|
| `refuto chat --role <rol>` | las restricciones se inyectan como **texto** en el informe de sesión (`core/session.py`). Las cumple el agente si quiere | `E1` |
| `refuto run` | sólo `allowed_tools` se traduce a una bandera real: `--tools` de Claude Code (`core/run.py` → `adapters/claude.py`). El resto no viaja | `E1` |
| `G-ROLES` | valida que el nombre exista, que los traspasos apunten a roles reales y que las puertas citadas estén implementadas | `E3` |
| Guardián | **no las ve**. Lo que impide una escritura prohibida es la política del espacio, igual para todos los roles | `E2` |

Dicho de otra forma: las restricciones son **contrato declarado y verificado en su forma**, no
control ejecutado por rol. Un rol con `no_shell` que abre sesión y ejecuta una orden no encuentra
un muro; encuentra una instrucción. El muro —el guardián y la política— es el mismo para todos, y
por eso esta sección no dice «las diez son aplicables», que es lo que decía antes y era falso.

Hacer que el guardián conozca el rol activo es trabajo pendiente y bienvenido.

## Cómo se elige el runtime

```
capacidades del rol → quién las cubre → quién deja MENOS restricciones sin aplicar → elegido
```

La aplicabilidad de la política manda sobre todo lo demás. La primera versión ordenaba por
«menor superficie» y eligió sistemáticamente el único runtime donde la política **no** se
aplica — exactamente al revés.

Toda decisión explica por qué eligió, por qué descartó a los demás, y qué queda sin aplicar:

```
$ refuto context
| Rol | Fase | Runtime | Estado | Revisión humana |
| requirements-engineer | SPECIFY | claude | READY | HUMAN_APPROVAL |
| visual-validator | VALIDATE | claude | READY | HUMAN_VISUAL_REVIEW |
```

## Fallback

Si el runtime elegido falla, se sustituye — **nunca hacia más privilegio**, y nunca en silencio
si el sustituto deja sin aplicar restricciones que el original sí aplicaba. En ese caso se pide
confirmación humana.

## Añadir un rol

Un objeto en `roles/registry.json`. `G-ROLES` valida el esquema, que las restricciones existan,
que los traspasos apunten a roles reales y que las puertas citadas estén implementadas.

No hace falta tocar ningún adapter.
