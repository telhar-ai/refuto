# Tres capas — `refuto → cliente → proyecto`

Estructura de referencia, **validada ejecutando el guardián real**, no dibujada.

```
base/.harness/policy.json                     CAPA 1 · la norma
example-org/
  .harness/policy.json                        CAPA 2 · el cliente   extends: ../../base/…
  proyecto-alfa/
    .harness/policy.json                      CAPA 3 · el proyecto  extends: ../../.harness/…
```

`extends` es una **ruta relativa al directorio del propio fichero de política**. El padre
legítimo vive por encima del espacio, así que la ruta asciende.

## Qué declara cada capa, y por qué ésa y no otra

La regla para decidir dónde va algo: **si cambiarlo sólo afecta a un proyecto es del
proyecto; si afecta a todos los de un cliente es del cliente; si cambiaría el significado de
`PASS`, es de la norma.**

| capa | declara | no declara |
|---|---|---|
| **base** | lo que ningún cliente puede retirar: el juez, la evidencia, las órdenes destructivas, las rutas de credencial | nada del negocio de nadie |
| **cliente** | su frontera de datos, las órdenes que su contrato prohíbe, el modo de interacción que exige | lo que ya dice la base — lo hereda |
| **proyecto** | lo suyo y sólo lo suyo | **casi todo**: un proyecto sin nada propio que declarar NO necesita este fichero |

Esa última fila es el punto. Un proyecto que no tiene restricciones propias **no debe tener
`policy.json`**: le basta con que su repositorio use el guardián del cliente. Crear el fichero
«por simetría» produce una copia que nadie vuelve a comparar, y la primera que alguien recorta
deja de estar gobernada sin que ningún comando lo diga.

## Validación — E4, medido desde el proyecto

```
python3 -m core.guard --runtime claude --stdin \
  --workspace examples/tres-capas/example-org/proyecto-alfa --command "…"
```

| qué | de qué capa viene | decisión |
|---|---|---|
| `sudo ls` | base, 2 niveles arriba | `DENY` |
| `terraform apply -auto-approve` | cliente, 1 nivel arriba | `DENY` |
| escribir `contratos/x.md` | cliente | `DENY` |
| escribir `infra/main.tf` | proyecto | `DENY` |
| escribir `src/app.js` | — | `ALLOW` |
| `ls -la` | — | `ALLOW` |

Las dos últimas filas son el control que impide cerrar esto con un «deniega todo». Sin ellas,
una cadena rota —que deniega por no resolver— sería indistinguible de una que funciona.

## Cómo se da de alta un espacio con esta forma

```sh
# el cliente hereda de la norma
python3 /ruta/a/refuto/refuto.py --workspace /ruta/al/cliente \
    init --extends ../../base/.harness/policy.json

# un proyecto, SÓLO si tiene algo propio que declarar
python3 /ruta/a/refuto/refuto.py --workspace /ruta/al/cliente/proyecto \
    init --extends ../../.harness/policy.json

# y se comprueba lo que de verdad va a aplicarse
python3 /ruta/a/refuto/refuto.py --workspace /ruta/al/cliente/proyecto policy refine
```

**La ruta que se teclea es la que queda escrita.** `--extends` se resuelve desde
`<espacio>/.harness/`, el directorio del fichero hijo — no desde el directorio actual. Por eso
los ejemplos de arriba funcionan tal cual estando en cualquier sitio: con `--workspace`, que es
como se da de alta un espacio ajeno, el directorio actual ni siquiera está en el árbol del
espacio. Hasta el 2026-09-23 la validación usaba el directorio actual y el documento guardaba
la otra base, así que la forma relativa —la única que sobrevive a mover o clonar el árbol—
fallaba siempre con `--workspace`. Falló cerrado, que es lo único que impidió que fuera grave.

`init --extends` escribe un hijo con **cuatro claves** (`schema`, `name`, `version`, `extends`)
en vez de una copia de la norma entera. `--anchor` añade una quinta, `extends_digest`: con ella,
cualquier cambio del padre deja de resolver hasta que alguien lo revise. Es lo que se quiere de
una capa que no debe moverse sola, y demasiado rígido para una que evoluciona — así que lo
decide quien crea la capa.

## Lo que esta estructura todavía NO resuelve

- **No hay norma en disco.** La capa 1 de refuto vive como constantes en `core/policy.py`; el
  `base/` de este ejemplo es un ejemplo. Mientras no exista una norma versionada, la cima de
  toda cadena real es el cliente, y **nadie vigila lo que la cima retira**. Su sitio natural es
  `policies/base.json`, que está protegido: crearla es un acto de persona.
- **`policy wire --repos` colapsa la capa de proyecto.** El guardián instalado fija
  `--workspace` al espacio que lo aloja, y `core/guard.py` no asciende. Con un guardián por
  cliente, la política del proyecto no se lee. Correcto para dos capas; para tres hace falta
  que el guardián ascienda desde el directorio real.
- **`extends` no comprueba dónde vive el padre.** Una ruta absoluta o un enlace simbólico
  resuelven a cualquier sitio del disco. Explotarlo exige escribir el `policy.json` del hijo,
  que está protegido — es defensa en profundidad, no una escalada. Declarado en
  `tests/adversarial/test_violaciones_refinamiento.py`.
