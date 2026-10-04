# ADR-0018 · El motor que juzga no es el árbol que se edita, y el diario mide lo que cuesta

**Estado:** aceptado · **Fecha:** 2026-09-28 · **Implementación:** `core/engine.py`,
`core/telemetry.py`, `core/guard.py` (`digest_entrada`, `resultado_de`, `--post`),
`core/launcher.py`, `core/wire.py`, `refuto.py` (`engine`, `telemetry`).

## Contexto

Dos mediciones del 2026-09-28 sobre la instalación real, no sobre el diseño.

**La primera.** `.harness/bin/guard` no es una copia del motor: es un lanzador que hace
`cd $HARNESS_HOME && exec python3 -m core.guard`, y `HARNESS_HOME` era **el árbol de trabajo de
refuto**. Medido: **12 espacios** apuntaban al mismo árbol. Cada decisión del guardián en
cualquiera de ellos ejecutaba los ficheros que hubiera en ese directorio en ese instante — sin
commit, sin instalación, sin aviso. Mientras alguien edita `core/policy.py`, los doce espacios
corren la versión a medias; el lanzador falla cerrado, así que el síntoma no es un guardián
permisivo sino doce espacios parados a la vez, o peor, doce gobernados por una política que
nadie llegó a probar.

Esa sesión lo esquivó por suerte, no por diseño: el guardián carga `core.guard`, `core.policy` y
`core.proc`, y lo que se editaba era `core/concordia.py` y `core/ed25519.py`.

**La segunda.** Había **52.131 eventos** en 13 espacios y ninguna herramienta que los leyera. Y
lo que llevaban no bastaba para la pregunta que se les hacía: se sabía **qué** se decidió y
**cuándo**, no **cuánto costó** ni **si funcionó**. Un `allow` y una orden que reventó eran el
mismo evento; «el guardián es lento» no era comprobable, y su contraria tampoco.

## Decisión

1. **Un motor publicado, y el árbol para editar.** `refuto engine publish` copia un commit
   —`git archive`, no el directorio— a `<raíz>/<commit>`, y `current` dice cuál gobierna. Los
   lanzadores apuntan ahí. Editar deja de mover a nadie; mover exige `publish` y `use`, que
   dejan escrito quién, cuándo y qué commit.
2. **No se publica lo que no se puede reconstruir.** Árbol sucio → `FAIL` antes de copiar nada.
   Un motor que no está entero en ningún commit no se puede volver a construir para comprobar
   qué juzgó.
3. **No se activa lo que no se prueba.** La copia ejecuta su propia suite antes de recibir a
   nadie. Saltárselo se puede, y entonces queda `verified: false` en `published.json`: publicar
   sin probar es una decisión legítima, esconderla no.
4. **Sin motor publicado se sigue funcionando, avisando.** El comportamiento anterior no
   desaparece —rompería las doce instalaciones— pero deja de heredarse en silencio: cada
   `install`, `upgrade` o `policy wire` dice a qué apunta y qué implica.
5. **Cada decisión dice cuánto costó** (`duration_ms`) y **qué operación es** (`entrada_digest`).
   El reloj empieza dentro del proceso: **no** incluye el arranque del intérprete, y esa
   separación es el dato — medido, decidir cuesta 12,2 ms de 82 ms totales, así que el 85 % es
   arrancar Python y optimizar la decisión no serviría de nada.
6. **Un gancho posterior registra el desenlace** (`--post` → `tool/result`). No decide y no
   bloquea: corre después de que la herramienta actuara, así que bloquear no desharía nada y sí
   rompería la sesión. `ok` tiene **tres** valores, y el tercero es el importante: la carga de
   `PostToolUse` no promete un código de salida, y `sin determinar` no es `fue bien`.
7. **La duración de una herramienta es la distancia entre sus dos eventos**, casados por
   `entrada_digest` y no por cercanía: con varias operaciones en vuelo, la cercanía empareja la
   de otra.
8. **Toda cifra con su cobertura.** `refuto telemetry` nunca publica una mediana sin el `de N`
   al lado. Sobre el diario existente la cobertura de latencia es del 0,2 %, y decirlo es la
   diferencia entre una medición y una impresión.

## Alternativas descartadas

| opción | por qué no |
|---|---|
| A · dejar el acoplamiento y documentarlo | es lo que había; el riesgo no lo quita un párrafo |
| B · copiar el motor a cada espacio | 12 copias que divergen, y actualizar pasa a ser 12 actos |
| C · instalar una biblioteca de telemetría (LangGraph, OpenTelemetry SDK) | rompe ADR-0002. Medido: LangGraph no está instalado y no lo usa ningún agente de esta máquina — los runtimes que decide el guardián son `claude` (51.387), `antigravity` (246) y `kiro` (87). Un exportador OTLP **por HTTP con `urllib`** cumple lo mismo sin dependencia, y queda como trabajo siguiente |
| D · emparejar decisión y resultado por proximidad temporal | con varias herramientas en vuelo es adivinar; por eso existe `entrada_digest` |

## Límites que esta decisión NO cierra

- **No es aislamiento.** El motor publicado vive con el mismo `uid` que el sujeto: quien pueda
  escribir en el árbol puede escribir en la copia. Lo que separa es la **intencionalidad** —«lo
  que escribo» de «lo que juzga»—, que era la confusión. Para lo otro hace falta otro `uid`.
- **Los espacios ya cableados siguen apuntando a donde apuntaban** hasta que se vuelva a
  escribir su lanzador. Publicar no los mueve; `refuto policy wire` sí.
- **Tokens y coste monetario no pasan por el guardián** y siguen sin medirse.
- **Lo que el guardián no ve no está en el diario**, y su ausencia no es evidencia de que no
  ocurriera.
- **La cobertura de latencia será baja durante un tiempo**: sólo la tienen los eventos nuevos.

## Qué la haría cambiar

Que el coste de arrancar un proceso por decisión pese de verdad: 82 ms × ~2.500 decisiones/día
son 3,4 min/día, y el 85 % es arranque. Si eso molesta, la respuesta no es optimizar
`core.policy` sino un guardián residente — y entonces el motor publicado pasa de conveniencia a
requisito, porque un proceso vivo no puede recargar el árbol a media sesión.
