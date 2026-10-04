# Instalación

Lo que sigue está escrito para una **máquina limpia**: sin `pip`, sin entorno virtual, sin
alias heredados. Cada paso trae la comprobación que dice si funcionó.

## 1 · El intérprete

`refuto` necesita **Python 3.10 o superior** y nada más. No hay dependencias de terceros
(ADR-0002).

```bash
python3 --version
```

| Lo que sale | Qué hacer |
|---|---|
| `Python 3.10.x` o superior | seguir |
| `Python 3.9.6` | **es el Python de sistema de macOS.** No sirve. Instale 3.10+ y use ese intérprete |
| `command not found` | instale Python 3.10+ |

**macOS, en detalle.** `/usr/bin/python3` es `3.9.6` en macOS 15 y 26 y lo seguirá siendo:
Apple no lo actualiza. Con 3.9 el CLI arranca —`--help` responde— y falla más tarde, en la
sintaxis de un módulo que 3.9 no parsea. Es el peor modo de fallar, porque el primer minuto
parece correcto. Instale otro intérprete y compruebe cuál está ganando:

```bash
brew install python@3.12         # o pyenv, o el instalador de python.org
which -a python3                 # el primero de la lista es el que se va a usar
python3 --version
```

Si `which -a python3` pone `/usr/bin/python3` primero, ajuste el `PATH` o invoque el intérprete
por su ruta: `/opt/homebrew/bin/python3 refuto.py …`.

**Windows.** La suite **no se ha ejecutado nunca en Windows sobre este árbol** (`NOT_RUN`): hay
código de portabilidad y una prueba omitida en macOS por ser sólo de Windows, pero ninguna
medición propia. Trátelo como no verificado.

**Linux.** Igual: `NOT_RUN`. No hay medición.

## 2 · Traer el código

```bash
git clone <url-del-repositorio> refuto
cd refuto
python3 --version                # confirme otra vez: aquí es donde importa
python3 refuto.py --help
```

`git` no es sólo para clonar: `refuto` lo usa para la procedencia de la evidencia y para el
lock. `gh` y `glab` son opcionales (sólo para `refuto work`).

## 3 · Que `refuto` sea un comando

El resto de la documentación escribe `refuto verify`, `refuto chat`, `refuto policy wire`. Para
que eso sea literal:

```bash
export PATH="$PWD/bin:$PATH"     # POSIX; añádalo a su perfil para que sobreviva al terminal
```

```powershell
$env:PATH = "$PWD\bin;$env:PATH"      # PowerShell, esta sesión
setx PATH "$PWD\bin;$env:PATH"        # PowerShell, permanente
```

Los dos lanzadores —`bin/refuto` y `bin/refuto.cmd`— se resuelven **por su propia ubicación**,
así que funcionan invocados desde el espacio gobernado, que es donde se usan. Sin `PATH`, todo
funciona igual escribiendo `python3 /ruta/a/refuto/refuto.py …`.

Comprobación:

```bash
refuto --help                    # debe imprimir la lista de subcomandos
```

Si responde `permission denied`, el bit de ejecución se perdió al clonar:
`chmod +x bin/refuto refuto.py`.

## 4 · Comprobar la instalación antes de gobernar nada

```bash
refuto doctor                    # qué hay en esta máquina y qué funciona de verdad
refuto selftest                  # el juez se prueba a sí mismo
```

`selftest` debe terminar en `OK` y con el recuento completo. Medido el **2026-09-22** en macOS
arm64 (Darwin 25.4.0) con Python 3.14.6 y con 3.12: **478/478, 1 omitida** (una prueba que sólo
corre en Windows). Si su recuento difiere, diga con qué intérprete y en qué sistema: la cifra no
es del producto, es de la ejecución.

`doctor` puede declarar agentes ausentes o bloqueados y **eso no es un fallo de `refuto`**: es
su respuesta. Un agente que no arranca se declara, no se supone.

## 5 · Gobernar un espacio de trabajo

Un espacio es el directorio raíz del trabajo que quiere gobernar (un repositorio, o un
directorio que contiene varios).

```bash
cd /ruta/al/espacio
refuto install
```

`install` deja el espacio operativo de principio a fin —política, vínculo, guardián, contexto—
y **lo comprueba ejecutando el guardián** contra una escritura que debe rechazar. Existe porque
los pasos sueltos dejaban un espacio a medias con facilidad, y un espacio a medias es peor que
uno sin gobernar: parece gobernado.

Después, y sólo si su espacio los necesita:

```bash
refuto lock plan                 # qué se anclaría, antes de anclar nada
refuto lock update               # fija el commit inmutable y las huellas
refuto policy compile            # traduce la política a cada runtime
refuto policy wire               # engancha el guardián (claude y kiro por defecto)
```

## 6 · Comprobar que quedó gobernado de verdad

Tres comprobaciones, de menos a más concluyente:

```bash
refuto policy audit              # ¿el gancho está donde el runtime lo lee?
refuto verify                    # ¿qué dicen las puertas? 0 integrable · 1 rojo · 2 bloqueado
refuto evidence --last 20        # ¿quedó rastro?
```

Y la única que demuestra algo de verdad (E4): pedirle al agente una escritura que debe rechazar.
Con Claude Code, dentro del espacio:

```bash
claude -p "Escribe HECHO en .kiro/steering/PRUEBA.md" \
       --output-format stream-json --verbose --include-hook-events \
       --tools "Write" --permission-mode dontAsk --max-budget-usd 0.20
```

Debe aparecer `permission_denials: 1`, el archivo **no** debe crearse, y la decisión debe
constar en `.harness/evidence/ledger.jsonl`. Si el archivo se crea, el gancho no se cargó: no lo
dé por bueno porque `policy audit` diga que sí.

> Esa orden **sí gasta créditos** (tope `$0.20`). Es la diferencia entre comprobar que el gancho
> está escrito y comprobar que actúa.

## 7 · Qué escribe `refuto` y dónde

| Dónde | Qué |
|---|---|
| `<espacio>/.harness/` | política, manifiesto, lock, vínculo, guardián, evidencia y estado |
| `<espacio>/.claude/settings.local.json` | el gancho, **fusionado** con lo que ya hubiera (hay copia en `.harness/backup/`) |
| `<espacio>/.kiro/agents/*.json` | `hooks.preToolUse` de cada agente de Kiro |
| `<espacio>/CLAUDE.md`, `AGENTS.md`, `GEMINI.md`, `.kiro/steering/zz-harness.md` | un **bloque delimitado** con el contexto; lo de fuera de los marcadores no se toca |

Nada se escribe fuera del espacio salvo las raíces declaradas en
`Policy.external_write_allow`.

## 8 · Deshacer

```bash
refuto policy unwire             # restaura desde .harness/backup/
```

**Límite conocido** (E1, `core/wire.py`): `unwire` restaura lo que existía antes; un archivo que
`wire` **creó** —típicamente `.claude/settings.local.json` en un espacio que no lo tenía— no se
borra. Compruébelo y bórrelo a mano si quiere volver al estado exacto. Después, `rm -r .harness`
retira el resto.

## Problemas frecuentes al instalar

| Síntoma | Causa | Arreglo |
|---|---|---|
| `SyntaxError` en un módulo de `core/` | Python 3.9 | usar 3.10+ (§1) |
| `refuto: command not found` | `bin/` no está en el `PATH` | §3, o invocar `python3 refuto.py` |
| `permission denied` al ejecutar `bin/refuto` | bit de ejecución perdido | `chmod +x bin/refuto` |
| `policy audit` dice `0/N` justo después de `wire` | ver [`TROUBLESHOOTING.md`](TROUBLESHOOTING.md) | |
| La sesión abre y el primer mensaje da `API Error: Invalid URL` | una variable del shell redirige el agente a otro proveedor | `refuto chat --provider clean`; ver [`TROUBLESHOOTING.md`](TROUBLESHOOTING.md) |
