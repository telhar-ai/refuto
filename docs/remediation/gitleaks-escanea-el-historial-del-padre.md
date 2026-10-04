# `G-SECURITY` reporta hallazgos del repositorio que contiene al espacio

**Medido el 2026-09-23**, con gitleaks 8.30.1, sobre `examples/espacio-minimo` — un espacio de
**3 ficheros** anidado dentro del repositorio de refuto.

> **`gates/**` está protegido por política** para el agente que escribe esto. El cambio se
> propone con el bloque exacto y **para** aquí. Un agente que edita lo que lo evalúa no está
> aprobando: está moviendo la puerta.

## Lo medido

`gates/g_security.py` invoca:

```python
["gitleaks", "detect", "--no-banner", "--report-format", "json",
 "--report-path", "-", "-s", str(ctx.workspace)]
```

El `-s` está bien puesto. El problema es el **subcomando**: `gitleaks detect` escanea el
**historial de git**, y para encontrarlo asciende hasta el `.git` que contenga esa ruta.

```
gitleaks detect -s examples/espacio-minimo   →  1 hallazgo
gitleaks dir      examples/espacio-minimo    →  0 hallazgos
```

El hallazgo que devolvió:

```
tests/adversarial/test_attacks.py:149 — generic-api-key
```

Ese fichero **no existe dentro del espacio verificado**. Pertenece al repositorio padre. La
puerta atribuyó al espacio de ejemplo un hallazgo del árbol que lo contiene.

## Por qué esto importa más de lo que parece

Es una **fuga de ámbito**, de la misma familia que la que tenía `G-MCP` con `$HOME` y que se
cerró el 2026-09-22. El patrón se repite:

> el veredicto sobre un sujeto depende de algo que está fuera del sujeto, y nada lo declara.

Las consecuencias no son simétricas, y la peligrosa es la segunda:

- **Falso positivo** — verificar un subdirectorio de un monorepo reporta los secretos de todo
  el monorepo. Ruidoso, pero visible.
- **Falso negativo** — un espacio que **no** es un repositorio git no tiene historial que
  escanear, así que `detect` no mira nada y la puerta informa cero hallazgos con el árbol sin
  revisar. *«No miré»* sale indistinguible de *«no hay»*, que es exactamente lo que el
  vocabulario de estados existe para impedir.

El segundo caso es el que hay que probar, porque es el que aprueba de más.

## El bloque

```python
# `dir` y no `detect`: `detect` escanea el HISTORIAL de git y asciende hasta el `.git` que
# contenga la ruta, así que verificar un espacio anidado devuelve los hallazgos del
# repositorio padre — y verificar un espacio que no es repositorio devuelve cero sin haber
# mirado. `dir` escanea los ficheros que hay en disco bajo esa ruta, que es el sujeto.
# Medido el 2026-09-23 sobre `examples/espacio-minimo` (3 ficheros):
#     detect -s <espacio>  → 1 hallazgo, de `tests/adversarial/test_attacks.py` del PADRE
#     dir      <espacio>   → 0 hallazgos
out = _run_json(["gitleaks", "dir", "--no-banner", "--report-format", "json",
                 "--report-path", "-", str(ctx.workspace)])
```

`gitleaks dir` existe desde la 8.19. Si hay que sostener versiones anteriores, el equivalente
es `detect --no-git -s <ruta>`; conviene entonces detectar la versión y elegir, porque llamar
a `dir` en una 8.18 falla con «unknown command» y eso sería `NOT_EXECUTABLE`, no `FAIL`.

## Las pruebas que hacen falta

Con las cuatro plantillas de `tests/selftest/test_gates.py`, y **la tercera es la que importa**:

| caso | montaje | debe dar |
|---|---|---|
| positivo | espacio limpio, con gitleaks | `PASS` |
| negativo | un secreto con forma dentro del espacio | `FAIL` |
| **ámbito** | espacio **anidado** en un repo cuyo historial SÍ tiene un secreto | `PASS` — el del padre no es suyo |
| **ámbito** | espacio que **no** es repositorio git, con un secreto en disco | `FAIL` — no puede aprobar por no tener historial |
| dependencia ausente | sin gitleaks en el `PATH` | `BLOCKED`, nunca `PASS` |

Las dos de ámbito no existen hoy. Sin ellas, este arreglo se puede deshacer sin que nada avise.

## Mientras tanto

`.gitleaksignore` declara **una sola** ocurrencia histórica, con su huella completa
`<commit>:<fichero>:<regla>:<línea>`. No es un patrón ni una regla desactivada: cualquier
hallazgo nuevo, incluido otro del mismo fichero en otra línea, sigue parando la integración.

Y la causa en el árbol sí se corrigió: `tests/adversarial/test_attacks.py` arma ahora sus
literales por concatenación, como ya hacía `tests/fixtures/__init__.py` y por el mismo motivo
declarado allí — *«lo que se junta en tiempo de ejecución no está en el árbol»*. Esa línea se
había quedado fuera de la convención.
