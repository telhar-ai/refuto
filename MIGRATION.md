# Adopción

Cómo poner `refuto` encima de un conjunto de repositorios que ya funciona, sin parar el trabajo.

Esta guía es **genérica**. La versión anterior de este documento describía la adopción concreta
de un entorno privado, con sus repositorios y sus decisiones; eso no le sirve a nadie más y se
retiró. Lo que queda es el método, con los comandos reales.

## La regla

**No hay big-bang.** Lo que ya funciona sigue funcionando; `refuto` se adopta encima, no en lugar
de. Todo componente tiene estado, y sólo se retira algo cuando hay evidencia de que su sustituto
funciona.

```
LEGACY → COMPATIBILIDAD → CANÓNICO → MIGRADO → DEPRECADO → RETIRADO
```

Un componente **no pasa de estado por decisión**: pasa cuando hay una comprobación que lo
demuestra. «Ya está migrado» sin una puerta en verde es `E0`.

## Fase 1 — Observar sin cambiar nada

```bash
refuto inventory --save     # inventario mecánico de lo que hay
refuto doctor               # qué funciona de verdad en esta máquina
refuto init && refuto verify --offline
```

No modifica nada del trabajo existente. Produce la línea base contra la que se compara todo lo
demás. Guárdela: sin línea base, la fase 2 no puede demostrar que mejoró nada.

Lo que suele salir aquí, y conviene anotar antes de tocar nada: cuántas copias divergentes del
mismo agente o de la misma skill hay, y cuántas referencias absolutas están rotas.

## Fase 2 — Gobernar un espacio

Empiece por **uno**, y que no sea el más crítico.

1. Declarar el manifiesto: agentes, orígenes, skills, MCP.
2. `refuto lock update` — anclar el origen por commit.
3. `refuto policy compile && refuto policy wire` — con copia de seguridad.
4. `refuto verify` — la línea base con puertas.

**Reversible, con un límite que conviene conocer:** `refuto policy unwire` restaura desde
`.harness/backup/`, que sólo guarda archivos que **ya existían**. Un archivo que `wire` creó
—típicamente `.claude/settings.local.json` en un espacio que no lo tenía— sobrevive al `unwire` y
hay que borrarlo a mano. Después, `rm -r .harness` retira el resto.

## Fase 3 — Varios repositorios con copias divergidas

El caso general: N repositorios con copias del mismo agente o de la misma skill, editadas por
separado. El orden importa:

1. **Decidir cuál copia es canónica.** `refuto inventory` dice cuáles divergen y en qué; **cuál
   gana es una decisión de las personas**, no de la herramienta.
2. Publicar la canónica como origen, con etiqueta y manifiesto.
3. En cada repositorio consumidor: `refuto init`, declarar `sources`, `refuto lock update`.
4. `refuto verify --gate G-FLEET` en la CI de todos.
5. Retirar las copias sólo cuando todos estén en verde.

**El paso 1 es el caro**, y no es técnico: hay que leer los diffs y decidir qué versión gana.
Ninguna herramienta puede hacerlo por usted, y una que lo intentara elegiría la más reciente, que
es el criterio equivocado.

## Fase 4 — Integrar con un método propio, si lo tiene

Si su equipo ya tiene un guion o un proceso de entrada (un `make verify`, un script de release),
lo razonable es que siga siendo el punto de entrada y **delegue** en `refuto` la comprobación
previa, la política y la evidencia.

Lo que **no** debe pasar es que `refuto` absorba el modelo de fases de su método: el método es del
espacio (`.harness/pipeline.json`), no de la plataforma. `refuto` lo lee y lo pone delante del
agente; no lo sustituye.

## Compatibilidad hacia atrás

Lo que `refuto` **no** rompe, deliberadamente:

- Un verificador propio del espacio sigue ejecutándose por su cuenta; `G-SDD` lo envuelve, no lo
  reimplementa (ADR-0007).
- Un lock propio del espacio puede convivir con `harness.lock.json`.
- Los ganchos que ya tuviera el IDE siguen ahí.
- El contexto se escribe en **bloques delimitados**: lo de fuera de los marcadores no se toca.

Y lo que sí toca, para que no haya sorpresas: `policy wire --agent claude` **fusiona** el gancho en
`.claude/settings.local.json` (copia previa si existía), `policy compile` escribe
`.claude/settings.harness.json` aparte, y `policy prune --apply` **reescribe**
`.claude/settings.json` retirando reglas podridas (también con copia). Tres rutas de escritura
distintas, tres riesgos distintos.

## Antes de adoptar, léase esto

- Ningún runtime tiene el guardián enganchado salvo `claude`, `kiro` y `antigravity`. Si su equipo
  trabaja con `gemini` o `opencode`, la política **se compila y no se aplica**, y por eso `chat`
  se niega a abrirlos salvo declaración explícita: la capa efectiva sigue siendo la rama protegida
  y la CI. Ver la tabla de capacidades del
  [`README.md`](README.md).
- Todo lo medido está en macOS arm64. Linux y Windows, `NOT_RUN`.
- `.harness/` contiene estado del espacio y datos de su máquina. Desde 0.3.0 el `.gitignore`
  que se escribe por defecto cubre las siete rutas de estado (`evidence/`, `state/`, `context/`,
  `memory/`, `backup/`, `bin/`, `binding.json`) y sólo se versionan `policy.json`, el manifiesto
  y el propio `.gitignore`. Compruébelo igualmente antes del primer `git add`: en versiones
  anteriores cubría dos, y por ese hueco se versionaron notas internas.
