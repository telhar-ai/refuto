# ADR-0020 · La regla habla de la elevación, no del nombre del binario

**Estado:** aceptado · **Fecha:** 2026-09-29 · **Implementación:** `core/privilegio.py`,
`core/policy.py` (`decide_command`, `_segmentos`, `_ordenes_internas`, `_patron_de_elevacion`,
`DEFAULT_COMMAND_DENY`).

## Contexto

Medido el 2026-09-29 con el guardián real y la política de fábrica. De **23** formas de invocar
privilegio, **12 pasaban sin freno**:

```
deny   sudo id                    allow  /usr/bin/sudo id      allow  'sudo' id
deny   command sudo id            allow  ../../usr/bin/sudo id allow  "sudo" id
deny   bash -c "sudo id"          allow  /usr/bin/env sudo id  allow  su'do' id
deny   echo hola; sudo id         allow  $(which sudo) id      allow  \sudo id
                                  allow  doas id · su root -c id · sudoedit /etc/hosts
                                  allow  osascript -e '… with administrator privileges'
```

Dos familias. Ocho eran **el mismo programa escrito de otra manera**: `command_deny` compara el
TEXTO del segmento contra `sudo:*`, así que sólo cazaba el nombre desnudo. Cuatro eran
**programas que la lista no nombraba** — y el último eleva sin escribir «sudo» en ninguna parte,
así que ampliar la lista de nombres tampoco lo habría cazado.

Y había un quinto canal, encontrado por una prueba de este mismo trabajo: **el cuerpo de `-c`**.
La regla cubría `sh -c` y exigía que el intérprete fuera el primer token literal y que el `-c`
estuviera en la posición 1 ó 2. Pasaban enteros `su <u> -c '…'`, `sudo -u <u> -c '…'`,
`doas -u <u> -c '…'` y `xargs -I{} sh -c '…'`: un canal por el que pasaba **cualquier** orden sin
examinar.

## El dato que impide el arreglo obvio

De **3.624** invocaciones reales medidas en 13 espacios, **3.405 son `su <usuario> -c …`** y 19
más son `sudo -u <usuario> -H env -i …`. Eso **no es escalar**: es una sesión con privilegios
ejecutando el trabajo como la persona para no dejar ficheros de root detrás — exactamente lo que
pide el aviso de `SessionStart`, y la razón de que `core.launcher.restore_ownership` exista.

Añadir `su:*` a la lista de rechazos habría puesto en rojo el camino correcto. Este repositorio
ya midió dos veces ese modo de muerte: `_partir` rechazando `grep -rn "rm -rf"`, y `dd:*`
rechazando `ddev up`. Un control que salta con el texto y no con la acción se desactiva en una
semana, y entonces no protege de nada.

## Decisión

1. **El programa se normaliza antes de comparar.** `core/privilegio.py` reduce el primer token a
   su nombre —quitando ruta, comillas, escapes y envoltorios con sus opciones— y el patrón se
   prueba contra la forma normalizada además de contra el texto. Sólo se toca el PRIMER token:
   las reglas hablan del resto tal cual (`rm -rf`, `git push --force`).
2. **Elevar y ceder son cosas distintas, y se clasifican.** `ELEVA` · `BAJA` · `NINGUNO` ·
   `INDETERMINADO`. Una regla de elevación **no se aplica a una cesión**: `sudo -u <no-root>` y
   `su <no-root>` siguen pasando, y ahora por decisión, no por omisión.
3. **`INDETERMINADO` no es `NINGUNO`.** `$(which sudo) id` no se puede comprobar contra ninguna
   tabla. Antes salía `allow` — una certeza falsa sobre un programa que nadie conocía. Ahora es
   `ask`, por el mismo motivo que `destino-sin-resolver`: rechazar en duro se rodea con
   `python3 -c`, que es opaco, y entonces el canal deja de mirarse.
4. **La regla se lee por lo que dice.** Si la política rechaza pedir privilegio y la orden pide
   privilegio, se rechaza — aunque ningún patrón nombre ese binario. Eso es lo que cierra
   `osascript … with administrator privileges` sin enumerar cada programa de cada sistema. No
   abre nada: sólo se llega con una política que ya tiene alguna regla de elevación.
5. **Lo que un elevador o un intérprete va a ejecutar se examina, por los dos canales y
   recursivamente.** El cuerpo de `-c` —con el programa buscado **en posición de mando** y el
   `-c` en cualquier posición— y la orden **posicional**, que es la que un elevador recibe como
   argumentos sin `-c` ninguno. Y la expansión es una **cola**, no una pasada: lo que sale de un
   segmento vuelve a entrar. Ceder privilegio no amnistía lo que se ejecuta; envolverlo en
   `xargs` tampoco; y añadir una capa más, tampoco.
6. **El camino legítimo es el que ya existía.** `privilege_grants` (ADR-0016, `core/grants.py`):
   la concesión vive en la política, que el agente no puede escribir; `effects: read-only` se
   **verifica** contra `Ê` y no aplica si la orden escribe **ni si es opaca**; `expires`,
   `roles` y `hosts` son obligatorios. Lo único que se añadió es que valga también para los
   elevadores que ningún patrón nombra — si no, la misma orden sería autorizable o no según qué
   binario usara, que es la dependencia que el punto 4 quita.

## Lo que falsar el propio arreglo encontró

El primer arreglo cerró los doce rodeos medidos y **abrió o dejó abiertos otros cuatro**. Se
midieron el 2026-09-29 atacando la versión ya corregida, con la política de fábrica, y ninguno
lo habría encontrado una prueba escrita desde el diseño: los cuatro salen de preguntarle al
código «¿y si lo escribo de otra manera?».

| # | Rodeo | Medido | Por qué pasaba |
|---|---|---|---|
| 1 | **Orden posicional** — `sudo -u persona rm -rf /` | `allow`, con `rm -rf /` desnudo en `deny` | el canal `-c` se cerró y el posicional no; un elevador no necesita `-c`. `clasificar` ya calculaba la orden en `resto` y **nadie la miraba** |
| 2 | **Un nivel más de anidamiento** — `sh -c 'sh -c "rm -rf /"'` | `allow`, con un solo nivel en `deny` | la expansión era de UNA pasada: el cuerpo se extraía y no se volvía a expandir |
| 3 | **La caja del nombre** — `SUDO id` | `allow`, y `/usr/bin/SUDO` **existe y es ejecutable** en APFS | la comparación respetaba la caja, así que el mismo programa con otra caja era otro programa |
| 4 | **Una regla que se ignora en silencio** — `sudo -u nadie:*` en `command_deny` | `sudo -u nadie id` → `allow` | `_patron_de_elevacion` clasificaba sólo el PRIMER token del patrón, así que leía como «regla de elevación» a una que nombra un usuario concreto — y las reglas de elevación se saltan para las cesiones |

Los cuatro tienen el mismo defecto de método detrás, y merece quedar escrito: **se arregló el
caso que se había medido en vez de la propiedad**. «El cuerpo de `-c` se examina» es un caso;
«lo que un elevador va a ejecutar se examina» es la propiedad, y sólo la segunda cierra el
posicional. «El nombre se normaliza» es un caso; «dos formas del mismo programa comparan igual»
es la propiedad, y sólo la segunda cierra la caja.

El cuarto es de otra clase y es el peor: una regla presente en la política, compilada al
dialecto del agente y leída en el informe de sesión, **que no hacía nada**. Eso es peor que no
tener la regla, porque quien la escribió cree estar protegido.

## Qué NO cambia

Nada de esto da ni quita privilegio del sistema operativo: el agente sigue corriendo con el uid
del operador. Lo que cambia es que el camino **declarado** exista, esté acotado y deje rastro
—`I6'`, no `I6`—, y que los doce rodeos medidos dejen de ser gratis. Una ofuscación decidida
—armar el nombre en una variable, codificarlo— sigue atravesando esto, como `_segmentos` ya
declara: es una barandilla contra el resbalón, no una caja de arena contra un adversario.

## Límites que esta decisión NO cierra

- **El riesgo medido no era `sudo`.** De 52.763 decisiones, **30.278 (57 %)** se tomaron con
  `euid=0`, concentradas entre el 14 y el 21 de septiembre; 79 de ellas **sin `SUDO_USER`**, que
  es la sesión root sin nadie que repare al salir. Contra eso actúan `restore_ownership` y el
  aviso de `SessionStart`, no esta tabla. Endurecer la decisión **dentro** de una sesión root
  —por ejemplo, exigir más para escribir fuera del espacio— queda sin hacer y sin medir.
- **`sudo` con un intérprete sigue siendo opaco**, así que ninguna concesión `read-only` lo
  cubre. Es deliberado, y significa que el diagnóstico privilegiado hay que escribirlo con
  órdenes modeladas si se quiere que una concesión lo alcance.
- **La lista de elevadores es finita.** `ELEVADORES` nombra ocho; el punto 4 cubre a los que
  `clasificar` reconoce, no a los que no. Un mecanismo de elevación que no esté ahí ni use
  `sudo` pasa.
- **La expansión está acotada, y un tope es un límite.** `_TOPE_EXPANSION = 400` existe porque el
  guardián corre en el camino crítico de **cada** orden y la expansión es una cola: sin tope, una
  carga construida a propósito sería la manera de colgar la sesión. El tope se eligió midiendo
  —sobre las 161 órdenes del corpus de pruebas la mediana es 1 segmento y el máximo 4— pero una
  cadena que supere 400 segmentos se examina sólo hasta ahí. Coste medido el 2026-09-29: **≤1,5 ms**
  por decisión en las formas de uso reales, **57 ms** para una cebolla adversarial de 40 capas.
  No hay corpus real que medir contra esto: el diario guarda **claves y no valores**, así que sus
  3.143 eventos no contienen ninguna orden — y esa propiedad es deliberada y correcta, pero es
  también la que impide calibrar el tope con tráfico de verdad. El corpus de pruebas es lo que hay.

## Qué la haría cambiar

Que el agente deje de correr con el uid del operador. Con otra identidad, la elevación dejaría
de ser una cuestión de qué cadena se escribe y pasaría a ser una del sistema operativo, que es
donde de verdad se decide.
