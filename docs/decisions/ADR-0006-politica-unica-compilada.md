# ADR-0006 · Una política canónica, N compilaciones, un guardián

**Estado:** aceptado · **Fecha:** 2026-08-27

## Problema, medido

«Proteger al juez» estaba escrito **dos veces**, en dos vocabularios:

| | `.kiro/hooks/proteger-el-juez.json` | `hooks{}` de cada agente |
|---|---|---|
| Disparadores | `PreToolUse`, `PostTaskExec`, `PostFileSave` | `preToolUse`, `stop`, `agentSpawn` |
| Matcher | `(fsWrite\|fsReplace\|strReplace\|fsAppend)` | `fs_write` |
| Comandos | `guarda_rutas.py` **y** `vc_datos.py` | **sólo** `vc_datos.py` |
| Lo lee | el IDE | `kiro-cli chat --agent` |

El orquestador siempre llama al CLI. Medición en el espacio real: **0 de 5 agentes** tenían el
guardián de rutas en la ruta que se usa.

Una política escrita dos veces no es una política duplicada: son dos políticas, y divergen.

## Decisión

Una fuente (`.harness/policy.json`) y N compilaciones. Cada adapter traduce **y declara qué
parte no puede aplicar** (`unenforceable`), con la regla contractual —probada— de que un adapter
que no soporta política no puede devolver esa lista vacía.

Y un solo guardián (`core/guard.py`) que todos los ganchos invocan. Traducir la **carga** del
gancho es un problema de veinte líneas por runtime; traducir la **regla** es un problema que
diverge. Se traduce la carga.

## Por qué el guardián resuelve la ruta antes de compararla

Porque comparar la ruta tal como la escribió el agente deja pasar tres cosas:

- `verificacion/../verificacion/v1.py`
- `docs/atajo/comun.py`, donde `docs/atajo` es un enlace simbólico a `verificacion/`
- `../../../etc/passwd`

Las tres tienen prueba adversarial. `os.path.realpath` antes de comparar las cierra.

## Por qué `wire` es un verbo aparte de `compile`

Compilar produce **artefactos nuevos** que refuto puede sobrescribir sin pensar. Enganchar
toca **archivos ajenos**: agentes que alguien escribió a mano. Riesgos distintos, verbos
distintos, y para `wire`: copia de seguridad obligatoria, idempotencia, y `unwire`.

Generar sólo el archivo del IDE habría repetido el error original con un archivo más moderno.

## Consecuencias

- Tres capas, y **ninguna se presenta como suficiente**. Las dos primeras viven en el
  repositorio y el agente puede editarlas. La tercera —rama protegida y CI— es la única fuera
  de su alcance, y por eso las otras se declaran *preventivas*, no *garantías*.
- El guardián **bloquea la carga que no entiende**. Un guardián que aprueba lo que no entiende
  no es un guardián.
- Toda decisión del guardián entra al diario, **redactada**: el diario no puede convertirse en
  el sitio donde vive el secreto. Tiene prueba.
