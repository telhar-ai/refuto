# Espacio mínimo

El espacio más pequeño que refuto puede gobernar. Existe para que la tubería tenga algo
real que verificar sin depender de ningún repositorio privado, y para que quien llega nuevo
pueda ver el ciclo completo en treinta segundos:

```bash
python3 refuto.py --workspace examples/espacio-minimo init
python3 refuto.py --workspace examples/espacio-minimo verify --offline
```

**Ojo:** `init` **escribe dentro de este repositorio** (crea y completa
`examples/espacio-minimo/.harness/`). Es deliberado —la CI lo usa así— pero le dejará el árbol
sucio: `git status` después, y `git checkout`/`git clean` sobre ese directorio si no quiere
conservarlo. Si prefiere no tocar el repositorio, copie el directorio a `/tmp` y apunte
`--workspace` allí.

No declara agentes requeridos ni orígenes: **varias puertas salen `BLOCKED`**, y ese es el
resultado correcto. Un espacio recién creado no debe salir en verde —no ha demostrado nada— ni en
rojo —no ha incumplido nada—. Sale bloqueado, y eso es información.

`verify` saldrá por tanto con **código 2**, no con 0. No es un fallo de la instalación.

La salida exacta depende de su máquina y de la versión, así que aquí no se pega ninguna: lo que
debe comprobar es que **ninguna puerta sin ámbito aparece en verde**.
