# Auditoría del ancla certificada por concordia

**Fecha:** 2026-09-28 · **Sujeto:** `0fa7ceb`, árbol limpio · **Máquina:** Darwin 25.4.0 arm64,
Python 3.14.6, rustc 1.90.0 · **Peer:** `ai/concordia` en `e57bc7a`, binario `hicon` construido
para esta auditoría.

La pregunta no era «cómo integrar concordia»: **ya estaba integrado** (ADR-0017, commits
`3dd76e2` y `0fa7ceb`, del 2026-09-27). Era si esa integración se sostiene cuando se intenta
falsificarla. Cuatro cosas no se sostuvieron; están cerradas abajo con su prueba. Lo que sí se
sostuvo también está, porque un informe que sólo cuenta los fallos no dice si el sistema sirve.

---

## 1 · Qué se midió, y con qué

| medición | resultado | cómo |
|---|---|---|
| suite completa | 1030/1030 (4 skip, 4 xfail) · 326 s | `refuto.py selftest` |
| vectores canónicos | 21/21 **idénticos byte a byte** al origen | `diff -rq` contra `ai/concordia/contracts/vectors` |
| conformidad con el oráculo Rust | 19/19 **sin skips**, 200 mutaciones incluidas | con `HICON_BIN` puesto |
| E2E contra clúster real | 15/15 | 4 procesos `hicon node` generados para la auditoría |
| latencia de un anclaje | **0,26 s** (clúster sano) | 3 corridas, plazo 30 s |
| estabilidad del clúster | 25/25 anclajes en 25 min, 0,25–0,32 s | un anclaje por minuto |
| coste del peer en reposo | **90 MB RSS** los 4 nodos, ~1,2 % CPU cada uno | `ps` |

**La copia de los vectores no ha derivado del origen** (el origen sigue en `3843613`, el commit
que la copia declara). Y el diferencial con Rust **no corre en la suite normal**: sin `HICON_BIN`
queda declarado `NOT_RUN`, que es honesto, pero significa que la cifra 1030/1030 por sí sola no
incluye la conformidad con el oráculo. Hay que pedirla.

---

## 2 · La frontera que introduce, y lo que resistió

Refuto no *usa* concordia: la desconfía por construcción. Manda un `refuto.checkpoint/v1` a
`POST /v1/order` y después **ignora el código HTTP y el `accepted: true`**. Lo único que cuenta
es que `≥ q` firmas Ed25519 de miembros distintos verifiquen, con su propio Ed25519 en Python
puro, sobre los 140 bytes que él reconstruye desde la especificación, bajo una membresía cuyo
digest fijó una persona fuera de banda.

Esa decisión se ganó en vivo durante esta auditoría, sin que nadie la buscara: el clúster se
degradó solo a los 7,4 min —el primario entró en `InsufficientPeers` y cambio de vista
perpetuo— mientras `/health` seguía respondiendo `{"status":"ok"}` y `POST /v1/order` seguía
devolviendo `accepted: true`. **Ninguna orden se ejecutó.** Refuto respondió `NOT_EXECUTABLE`,
no `PASS`. Un verificador que se hubiera creído el `accepted` habría anclado contra un clúster
muerto.

La degradación **no se reprodujo**: una segunda ventana de 25 minutos con un anclaje por minuto
dio 25/25. Queda como episodio observado, no como patrón — y como recordatorio de que
`/health` de ese peer no refleja la liveness del consenso.

Otros intentos que fallaron (es decir, el sistema aguantó):

- **Concurrencia.** Dos `evidence --anchor` simultáneos sobre el mismo diario: una sola ancla
  escrita, el diario `INTEGRA`. El nombre del fichero lleva el `entry_digest`, así que
  sobrescribir es idempotente.
- **Sólo-loopback.** El filtro de `es_local` decide antes de abrir ninguna conexión, y es
  fail-closed: lo que no sabe analizar, no es local.
- **Contención del guardián**, comprobada de rebote al auditar: rechazó un `rm -rf` y una
  redirección de shell a una ruta de `/tmp` fuera de la permitida.

---

## 3 · Los cinco huecos, y cómo se cierran

Dos de ellos —C-A4 y C-A5— son la misma historia contada dos veces: la integración del ancla
dejó en rojo dos controles que el propio repositorio ya tenía puestos, y nadie los miró. No los
encontró un análisis nuevo: los encontró **ejecutar los que ya existían**.


### C-A1 · El `engine_digest` se certificaba y nadie lo volvía a mirar

```
PROPERTY             el veredicto anclado se puede atribuir al motor que juzga
PREVIOUS_FAILURE     se ancló con un motor y se releyó el ancla con otro MUTADO: PASS, sin
                     una palabra. El ADR-0017 afirma que engine_digest «ata I6' a terceros»;
                     era cierto sólo si un tercero lo comparaba a mano, y ninguna orden de
                     refuto lo hacía. Las pruebas pasaban engine_digest="e"*64: grababan.
DESIGN               `verificar_ancla(..., engine_digest)` compara, y la discrepancia es
                     INCONCLUSIVE — no FAIL: el certificado sigue siendo válido y el diario
                     sigue conteniendo el checkpoint; lo que no se puede establecer es a quién
                     atribuir el veredicto. Se cierra volviendo a anclar.
                     `estado_del_anclaje` lo obtiene de `digest_motor()` si no se lo dan:
                     omitir el parámetro NO desactiva el control.
ADVERSARIAL_TEST     tests/adversarial/test_ancla_presupuesto.py::TestAtribucion (6 casos)
EVIDENCE             el motor original 9ce374b9… y el mutado 6550823…, el segundo releyendo
                     el ancla del primero
REMAINING_LIMITATION actualizar refuto deja el primer `status` en INCONCLUSIVE hasta que se
                     vuelve a anclar. Es el precio de que un cambio de juez sea visible.
```

### C-A2 · Un `policy_digest` vacío se certificaba sin decir nada

```
PROPERTY             lo que no se pudo determinar se declara dentro de la carga que firma el
                     quórum
PREVIOUS_FAILURE     sin `.harness/policy.json`, el checkpoint llevaba `""` y el ancla era
                     PASS. Un campo en blanco no dice «no se pudo»: no dice nada.
DESIGN               dos palabras para dos hechos distintos — `sin-politica` (no hay fichero)
                     e `irresoluble` (lo hay y la cadena efectiva no resuelve), que es la
                     distinción que `core/run.py` ya hacía para este mismo dato. Fundirlos en
                     un blanco era la pérdida de información.
ADVERSARIAL_TEST     …::TestPolicyDigestDeclarado (4 casos, uno de ellos vigila que ninguno de
                     los dos valores pueda volver a ser `""`)
```

### C-A3 · `timeout_s` no acotaba nada

```
PROPERTY             el plazo declarado acota la duración del anclaje
PREVIOUS_FAILURE     34,4 s declarando 2 s con UNA réplica que gotea la respuesta; 104,7 s con
                     cuatro (52×). El plazo de `urllib` es por operación de socket y se
                     reinicia con cada byte recibido, y el bucle de espera sólo miraba el reloj
                     ENTRE pasadas. El estado final era correcto (NOT_EXECUTABLE) y aun así un
                     `verify` se colgaba dos minutos.
DESIGN               `Plazo`: UN presupuesto para la operación entera —membresía, orden y
                     espera del certificado—, del que cada petición toma lo que queda.
                     Y, porque con eso NO bastaba (medido: `buscar_entrada` seguía tardando
                     226 s con un presupuesto de 1 s, porque una sola respuesta de 1,1 KB
                     goteada son 220 s que nadie cortaba), la respuesta se lee a TROZOS con
                     `read1`, mirando el presupuesto entre uno y otro. 226 s → 1,02 s.
                     De paso, `LIMITE_RESPUESTA`: el presupuesto acota el tiempo, no la
                     memoria, y una réplica que empieza a servir gigabytes es tan indisponible
                     como una caída.
ADVERSARIAL_TEST     …::TestPresupuesto (5 casos). Miden la DURACIÓN, no sólo el estado: el
                     estado ya era correcto cuando el defecto estaba vivo.
REMAINING_LIMITATION la granularidad es la de un `read1`; una réplica puede pasarse del
                     presupuesto por lo que tarde una sola lectura de socket.
```

### C-A4 · El E2E existía y no lo corría nadie

```
PROPERTY             una comprobación que existe, se ejecuta — y si no se puede, se dice
PREVIOUS_FAILURE     `scripts/check_wiring.py` salía con 1 en HEAD y con 0 en el commit
                     anterior (`e948152`): la propia integración introdujo la desconexión.
                     Además, los dos commits de concordia nunca pasaron por CI (última corrida
                     remota: 2026-09-26; los commits son del 2026-09-27).
DESIGN               el guion termina declarando un estado del vocabulario de refuto, con el
                     código que le corresponde por la tabla del protocolo: PASS (0), FAIL (1),
                     NOT_EXECUTABLE (2) cuando no hay `hicon` o el clúster no levanta. CI lo
                     ejecuta y publica lo que salga; tolera el 2 **diciéndolo** en un aviso, y
                     un FAIL con binario presente rompe el trabajo.
                     Lo que NO se hizo: sustituir el clúster por un doble en CI. Eso eliminaría
                     justo la frontera que el E2E existe para cruzar.
REMAINING_LIMITATION en CI la propiedad sigue sin demostrarse: queda declarada como no medida.
                     `hicon` vive en otro repositorio y en otro lenguaje. Para cerrarlo de
                     verdad hace falta un runner que pueda construirlo.
```

### C-A5 · Un `assert` sosteniendo la única comprobación del punto base

```
PROPERTY             el punto base de Ed25519 está en la curva, y eso se comprueba SIEMPRE
PREVIOUS_FAILURE     `scripts/preflight.py` salía en FAIL desde `3dd76e2` por B101 en
                     core/ed25519.py:52. Un `assert` desaparece con `python -O`: en el módulo
                     que decide si una firma vale, la única comprobación del punto base se
                     quedaba sin ejecutar justo en el modo en que nadie la mira.
DESIGN               un `if` con `RuntimeError`. Si esa constante falla, el módulo está
                     corrupto y no hay verificación que ofrecer; callarlo sería peor.
EVIDENCE             `bandit` 0 hallazgos · preflight PASS, 15 controles · `python3 -O`
                     importa el módulo y sigue comprobando · 19/19 con el oráculo Rust
REMAINING_LIMITATION ninguna conocida; es un cambio de forma, no de aritmética.
```

---

## 4 · Lo que esta auditoría NO puede afirmar

- **Que funcione fuera de esta máquina.** Todo lo medido es Darwin 25.4.0 / Python 3.14.6 /
  un solo host. Linux y Python 3.10/3.13: `NOT_RUN`.
- **Que el anclaje esté en uso.** El manifiesto de refuto **no declara `anchoring`**: en este
  repositorio todo `verify` da ancla `NOT_APPLICABLE`. La capacidad está en el motor y apagada
  en el sujeto que la produce. Activarla es una decisión de persona, y hace que cada `verify`
  dependa de un clúster local vivo.
- **Que el clúster sea fiable.** Se le vio degradarse una vez y aguantar 25 minutos otra. Dos
  ventanas no son una medición de disponibilidad.
- **Nada sobre la hora, la durabilidad del log de concordia ni el anclaje Merkle.** Sigue igual
  que lo declara ADR-0017.

## 5 · Hallazgo colateral, fuera del ancla

`refuto verify` con un `gates` de objetos en vez de cadenas termina en `TypeError`
(`refuto.py:1189`) en lugar de devolver un estado del protocolo. Es **preexistente** —se
reproduce igual sin `anchoring`— y queda abierto: no se toca en esta tanda para no mezclar dos
propósitos en un cambio.
