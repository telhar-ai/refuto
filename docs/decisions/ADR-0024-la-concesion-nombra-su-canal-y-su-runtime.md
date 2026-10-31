# ADR-0024 — La concesión nombra su canal y su runtime

```yaml
decision: una concesión de privilegio declara QUÉ canal levanta (`lifts`) y EN QUÉ runtimes
          vale (`runtimes`); los dos campos son obligatorios y sin ellos no concede nada
date: 2026-10-31
status: IMPLEMENTADA · motor, esquema, informe de sesión y `doctor`
refina: ADR-0016 (monitor de referencia con sujeto), que introdujo `privilege_grants`
question: >
  La concesión era el único camino declarado para una orden restringida, y no alcanzaba al
  canal que más lo necesitaba. ¿Cómo se extiende al canal de consulta sin convertirla en una
  lista de permisos, y sin que arreglar un runtime degrade a otro?
```

## Contexto — lo medido

Medido el **2026-10-31** sobre el espacio `telhar` y contra el binario de Codex 0.166.0.

**La concesión no alcanzaba `command_ask`.** `core.grants.buscar` se consultaba en el bucle de
`command_deny` y en el bloque de elevación no nombrada. El bucle de `command_ask` no preguntaba.
`git push:*` y `glab mr:*` son `command_ask`, así que ninguna concesión podía autorizarlos:

```
[sin concesión] git push -u origin fix/…   →  ask   regla=git push:*
[con concesión] git push -u origin fix/…   →  ask   regla=git push:*
```

**Y en Codex `ask` no pregunta.** Del binario, no de su documentación:

```
PreToolUse hook returned unsupported permissionDecision:ask
PreToolUse hook returned unsupported permissionDecision:allow
```

`PreToolUse` implementa `deny` y nada más, de modo que `core/dialect.py` degrada `ask` a `deny`
y lo declara. Compuestas las dos cosas: desde Codex, publicar no tenía **ningún** camino —
ni ejecutar, ni pedirlo. Es exactamente la situación que ADR-0016 nombra como la que hace que un
control se rodee, y por la que nace `privilege_grants`.

**`PermissionRequest` no lo arregla.** `core/dialect.py` lo señalaba como la pieza pendiente.
Existe en el binario (`PermissionRequestDecisionWire`, `PermissionRequest hook denied approval`),
pero se dispara cuando Codex **ya decidió** preguntar: un gancho puede auto-responder su
pregunta, no provocarla. Implementarlo no le devuelve a refuto la capacidad de pedir una decisión
humana desde `PreToolUse`. Esa capacidad no existe en Codex hoy, y conviene dejarlo escrito para
que nadie vuelva a planificar contra ella.

## Decisión

**1 · La concesión levanta también `ask`, y lo dice.** Se consulta en los tres sitios donde una
regla restringe. La asimetría que ADR-0016 fijó se conserva intacta: una concesión sigue sin
autorizar lo que la política **no** restringía — `ls -la` se decide por la política aunque la
concesión diga `commands: ["*"]`. Lo que cambia es qué restricción se puede levantar, no que la
tabla se convierta en una lista de permisos.

**2 · `lifts: ["ask"] | ["deny"]`, obligatorio.** Lo encontró una prueba adversarial de este
mismo cambio, no una revisión. Los patrones son `fnmatch` y **no tienen negación**:

```
concesión  commands: ["git push *"]   escrita para la consulta `git push:*`
allow  git push -u origin rama          ← lo que se quería
allow  git push --force origin main     ← lo que no
allow  git push -f origin main
```

«Empuja, pero no forzado» no se puede escribir como patrón. Sin `lifts`, la única forma de dar
camino a la publicación era abrir de paso el empuje forzado, que es justo lo que `command_deny`
existe para impedir. Con él, el canal de rechazo ni siquiera considera la concesión — y no la
anota como descarte, para que el motivo de un `deny` no arrastre concesiones que nadie escribió
para ese canal.

**3 · `runtimes`, obligatorio.** No es simetría con `roles` y `hosts`: los runtimes **no tienen
el mismo repertorio de respuestas**, así que la misma concesión no significa lo mismo en todos.
En Codex devuelve un camino que no existía; en Claude Code, donde `ask` sí pregunta, **quita** esa
pregunta. Sin el campo, arreglar un runtime degradaba el otro en silencio. `runtime` llega a
`decide_command` por parámetro y no por el entorno: el guardián ya lo tiene en `--runtime` y es el
dato con el que serializa la respuesta, así que leerlo de una variable permitiría que la decisión
y su traducción hablaran de runtimes distintos.

**4 · El informe de sesión filtra por runtime.** Listar una concesión que esta sesión no puede
usar sería prometer autoridad que no hay, y el informe es el peor sitio para eso: lo que dice se
toma por cierto el resto de la sesión. Es el mismo criterio con el que ADR-0016 ya excluía las
caducadas y las de otro host.

**5 · Una concesión mal formada deja de ser silenciosa.** `problemas_declarados` existía desde
ADR-0016 y **nadie la llamaba** fuera de las pruebas — el defecto que su propia docstring
describe. `refuto doctor` la ejecuta ahora y la enumera con su remedio.

## Consecuencias

- **Migración ruidosa a propósito.** Toda concesión existente queda mal formada hasta declarar
  los dos campos, y una mal formada no concede nada. Medido el 2026-10-31: **2 concesiones vivas
  en esta máquina**, las dos en `telhar`. El coste de la migración es proporcional al censo, y el
  censo se midió antes de decidir.
- **Lo que esto sigue sin ser.** Un modelo de privilegio del sistema operativo. El agente corre
  con el uid del operador y una concesión no le da nada que no pudiera tomar rodeando el guardián
  con un intérprete opaco. Lo que da es que el camino **declarado** exista, esté acotado y deje
  rastro: `I6'`, no `I6`.
- **Lo que la concesión NO sustituye.** Devolver `allow` en Codex no quita la aprobación humana:
  la pide el propio Codex, cuyo `sandbox_mode: workspace-write` con red cerrada escala toda orden
  de red al operador. refuto deja de ser el guardián que no puede preguntar y cede esa pregunta a
  uno que sí. Si algún día Codex dejara de escalarlas, esta concesión pasaría a ser una
  aprobación automática real — y entonces `expires` es lo que obliga a revisarla.
