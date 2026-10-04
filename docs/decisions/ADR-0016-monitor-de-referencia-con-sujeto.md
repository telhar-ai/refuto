# ADR-0016 — Un monitor de referencia con sujeto

```yaml
decision: el guardián decide sobre (sujeto, objeto, operación); las capacidades por rol sólo
          aprietan y toda restricción declarada se aplica o se declara no observable con motivo
date: 2026-09-25
status: IMPLEMENTADA en las capas 1, 2, 3 y 4 (parcial) · una pieza de la 4 declarada NO
        IMPLEMENTABLE en esta frontera, con la medición que lo demuestra
refina: ADR-0006 (política única compilada), ADR-0011 (fronteras de confianza),
        ADR-0013 (raíz de confianza y modelo de efectos), ADR-0014 (monotonía por cobertura)
question: >
  El control de acceso es ternario y refuto decidía sobre una relación binaria. ¿Cómo se
  introduce el sujeto sin romper la monotonía de la herencia, y cómo se gobierna el privilegio y
  la credencial sin convertir el control en una lista plana de prohibiciones?
```

## Contexto — lo medido, no lo recordado

Medido el 2026-09-25 sobre este árbol.

**El marco.** Un monitor de referencia correcto cumple las tres condiciones de Anderson —
inevitable, inviolable, verificable — sobre una relación **ternaria** `(sujeto, objeto,
operación)`. refuto cumplía las tres razonablemente y decidía sobre una **binaria**:

```
decide_write  (policy, workspace, target, content)   → (objeto, operación)
decide_command(policy, command, workspace)           → (forma de la orden)
```

`core/guard.py::normalize` normalizaba el hecho en siete campos y ninguno era el sujeto. El diario
tampoco: 16 claves en `policy/decision`, ninguna decía quién actuó. **Consecuencia matemática,
no de implementación: todo agente en todo rol tenía autoridad idéntica.**

**F1 · Un vocabulario de capacidades aplicado por cero código.** `roles/registry.json` declara
10 restricciones sobre 22 roles (`no_write_code` en 12, `no_modify_verifier` en 7, `no_shell` en
6, `no_secret_access` en 3…). Sus únicos consumidores eran `core/session.py:751` y
`refuto.py:1766`, que las imprimen en el informe bajo «**No puedes:**». `no_shell` significaba
«se le pide al modelo por favor que no use la shell».

Y peor, en la propia puerta: `G-ROLES` declara en su umbral «restricciones **aplicables**» y
`core/roles.py:121` las contrastaba contra `KNOWN_CONSTRAINTS`, que es el **diccionario de
prosa** del informe. «refuto no sabe aplicar» significaba «no tengo una frase en español para
describirla». La puerta decía lo correcto y medía lo de al lado, y aprobaba.

**F2 · El canal de lectura, sin mirar.** `secret_read_deny` se aplicaba en `decide_write`
(escrituras) y en `adapters/claude.py:153` (la capa del agente, sobre `Read`). El guardián
engancha `Bash` y no preguntaba por lecturas:

```
Write  .env                                      →  deny
Bash   cat .env                                  →  ALLOW
Bash   cp .env /tmp/claude-x/robado              →  ALLOW
Bash   cp .env ~/.claude/…/memory/nota.md        →  ALLOW   ← sobrevive a la sesión
```

Es el mismo defecto que `core/wire.py:44` documenta haber arreglado **para escrituras**: «una
orden cualquiera por Bash rodeaba el control entero». Y el dato ya estaba:
`core/effects.py:119` puebla `lecturas`, y `decide_command` tenía tres referencias a
`escrituras` y **cero** a `lecturas`.

**F3 · El entorno se hereda entero.** `core/session.py:1079` hace `env = dict(os.environ)`.
`clean_env` retira sólo variables de redirección de proveedor — su propósito es otro. Asimetría
neta: `.env` protegido contra escritura y el mismo secreto en `$MI_SERVICIO_API_KEY` de lectura
libre con `printenv`.

**F4 · `command_deny` colapsa cuatro dimensiones.** Los 16 patrones mezclan elevación de
privilegio (`sudo`), destrucción (`rm -rf`, `dd`), alcance externo (`git push --force`) e
integridad de suministro (`curl | bash`). Dos verdictos sobre una dimensión no bastan para cuatro
preguntas, y de ahí el callejón operativo: `sudo cat /etc/shadow` y `sudo systemctl status` son
la misma regla.

## Decisión

### Capa 1 · El canal de lectura *(implementada)*

`decide_command` recorre `ef.lecturas` contra `secret_read_deny`. Veredicto **`ask`**, no `deny`:
leer un `.env` para depurar es legítimo a menudo, y un rechazo duro se rodea en un día con
`python3 -c` —que es opaco—; entonces el canal deja de mirarse, que es peor. El mismo patrón se
midió dos veces en este repositorio con `_partir` y con `dd:*`.

El **`deny`** se reserva a la combinación *lectura de credencial + escritura fuera del espacio*,
que no tiene lectura legítima. Que el destino esté en `external_write_allow` no lo cambia: ese
campo abre el cuaderno y la memoria del agente, no una salida para credenciales.

### Capa 2 · El sujeto *(implementada)*

```
HARNESS_ROLE → fact["role"] → capacidades_de(rol) = registro ∪ policy.role_capabilities
             → decisión, compuesta con max() → diario
```

Las capacidades se expresan **en negativo**. No es estético: una lista de negaciones es
`ACUMULA_MAPA` —unión clave a clave— y por tanto **no hay sintaxis para retirar una
restricción**. Una lista de concesiones sería `REDUCE` y volvería a la trampa que documenta
ADR-0014. Y se compone con `max`, así que una capacidad **no puede** convertir un `deny` de la
política general en un `allow`: apretar es lo único que puede hacer, por construcción y no por
disciplina de quien la escriba.

**La invariante que vuelve inexpresable el defecto original:** toda restricción del registro está
en `core.capabilities.APLICADAS` o en `NO_OBSERVABLES` **con motivo escrito**. La tercera
categoría —declarada y en ningún sitio— es la que existía. `core/roles.py` valida contra esa
unión, así que `G-ROLES` por fin comprueba lo que su umbral promete.

Reparto medido: **5 aplicadas** (`no_shell`, `no_secret_access`, `no_modify_evidence`,
`no_modify_verifier`, `read_only_infrastructure`) · **5 no observables** con su motivo.

De las cinco no observables, una merece mención: `destructive_requires_approval` **sería una
relajación**. Lo destructivo ya está en `command_deny` con veredicto `deny` para todos los roles,
y «requiere aprobación» es más débil que «rechazado». Una capacidad que aflojara rompería la
monotonía que esta decisión declara.

### Capa 3 · Elevación parametrizada *(implementada)*

Sustituir `sudo:*` en la lista plana por concesiones **nombradas, acotadas y con evidencia**:
`id`, `roles`, `hosts`, `commands`, `effects`, `human_approval`, `expires`, `evidence`. La
persona aprueba una **clase** de operación una vez, con caducidad y ticket, en vez de teclear
cada orden.

Monotonía: **`REDUCE_LISTA`**. Una concesión abre un agujero, luego el hijo sólo puede retirar
concesiones enteras del padre. La comparación es por **contenido canónico**, no por cobertura
como `_cubre`: comparar «anchura» entre dos concesiones exigiría decidir inclusión entre globs de
órdenes, que es justo lo que ADR-0014 evita hacer. Estrechar una concesión heredada —acortar su
caducidad, quitarle un host— se expresa retirándola y escribiendo otra, y escribir otra es
añadir, que es violación. Es más estricto de lo necesario y es el lado correcto.

Propiedad clave: `effects: read-only` es **verificable contra `Ê`**. Si la orden concreta deriva
alguna escritura, la concesión no aplica — y **una orden opaca tampoco cuenta como de sólo
lectura**: no poder demostrar que no escribe no es haber demostrado que no escribe. Eso convierte
«confía en que es de lectura» en «demuéstralo».

Lo que impide que sea un agujero, y no es un campo que alguien deba comprobar: la concesión vive
en `.harness/policy.json`, que esta misma política protege, así que **un agente no puede
concederse privilegio a sí mismo**. `human_approval` es una propiedad del sitio donde la
concesión está escrita, no una casilla.

**Una trampa en la que caí construyéndola, y que conviene no repetir.** Con `REDUCE_LISTA` y la
raíz del motor vacía, ningún espacio podía declarar ninguna concesión **nunca**:

    HerenciaIrresoluble: `privilege_grants`: el hijo declara 1 registro(s) que el padre no tiene

Es exactamente la trampa que ADR-0014 documenta para `writable_paths`, y la escribí igual. La
salida no es clasificar el campo como `PROPIO` —eso dejaría a un proyecto aflojar lo que su
cliente apretó, que es el defecto de verdad— sino reconocer que **la raíz del motor no es un
cliente**: es la norma base del producto y no puede enumerar las necesidades operativas de
espacios que no conoce. `core.trust.RAIZ_NO_ACOTA` declara esa excepción, con su motivo, y una
prueba la fija en **exactamente un campo** para que no crezca en silencio. La monotonía entre
capas reales —cliente → proyecto— queda intacta.

Y la mitad que no es código: el informe de sesión anuncia las concesiones **vigentes para ese rol
en esa máquina**. Sin eso el mecanismo existe y nadie lo usa — un agente que no sabe que tiene
una concesión se comporta como si no la tuviera, y el camino declarado se queda sin usar mientras
el atajo opaco sigue ahí. No se listan las caducadas ni las de otro host: prometer autoridad que
no hay es el peor sitio donde hacerlo, porque lo que el informe dice se toma por cierto el resto
de la sesión.

### Capa 4 · La credencial que vive en una variable *(implementada en parte)*

Medido el 2026-09-25 en el entorno de una sesión gobernada real: **70 variables y 7 con forma de credencial**, todas legibles con un `printenv`. El fichero `.env` vigilado y el mismo secreto
en `$MI_SERVICIO_API_KEY`, libre.

**Lo implementado.** `secret_env_deny` (`ACUMULA`) compara el **nombre** de la variable, nunca el
valor: mirar el valor de cada variable para decidir si es un secreto obligaría a leer todos los
secretos para protegerlos. Se consulta en el MISMO canal de lectura que las rutas, porque
`printenv MI_SERVICIO_API_KEY` y `cat .env` son la misma pregunta por dos caminos.

Y la vía a granel, que es la fácil: `env`, `printenv`, `set` no declaran ninguna lectura
—`efectos("env").lecturas == set()`, no hay argumento que derivar— así que se enumeran. Sólo se
pregunta si el entorno tiene de verdad alguna variable con forma de credencial: en una máquina
limpia `env` es inofensivo y preguntarlo sería ruido. `env FOO=1 orden` no es un volcado.

La curación de la lista ES el trabajo. Un sondeo con `SESSION|AUTH|KEY` marcaba `SSH_AUTH_SOCK`
—la ruta de un socket, y quitarla rompe el agente de ssh—, `TERM_SESSION_ID` y
`HARNESS_SESSION`, que es de refuto. Un detector que marca lo normal enseña a ignorarlo.

**Lo NO implementable, y la medición que lo demuestra.** Este ADR proponía
«`${secreto:NOMBRE}` resuelto en el punto de ejecución». **No se puede hacer aquí**, y no por
coste: el contrato del guardián es `{allow, deny, ask}` en los seis runtimes
(`core/guard.py:17-23`). Un gancho `PreToolUse` no reescribe la orden. refuto es un **monitor**
en el canal de órdenes, no un ejecutor, así que no hay punto donde sustituir. Proponerlo fue un
error mío de frontera: describí una capacidad de un ejecutor en el documento de un monitor.

Lo que sí controla refuto es el entorno que ENTREGA, porque `core/session.py:1139` lanza al
agente con `subprocess.call(..., env=env)`. Filtrar ahí es implementable y queda propuesto: se
deja fuera de esta tanda porque retirar una variable puede romper una sesión que la necesita, y
ese riesgo lo decide quien opera el espacio, no yo.

## Alternativas consideradas

**RBAC completo con concesiones positivas.** Es el modelo canónico y aquí sería un retroceso: las
concesiones son `REDUCE` y ADR-0014 documenta lo que eso cuesta —la norma base se vuelve
incorregible y cada protección nueva produce denegación colateral irreparable—. Rechazada.

**Ejecutar al agente bajo otro uid.** Sería un principal *real* y resolvería `I6` en vez de
`I6'`. Es otra frontera: exige que el motor gestione usuarios, propiedad de ficheros y
devolución de permisos, y `claude-uid-doctor` existe precisamente porque eso ya se rompió una vez
en este ecosistema. Anotada como la evolución correcta, no como este ADR.

**Sandbox (contenedor, `seatbelt`, `landlock`).** Frontera distinta y complementaria, no
sustitutiva: no expresa «este rol no puede leer credenciales» sino «este proceso no ve ese
fichero». Fuera de alcance.

**Firmar el principal.** Un token por sesión que el agente no pueda forjar. Exigiría un canal
fuera del entorno del proceso; con el agente corriendo bajo el uid del operador, no hay tal
canal. Rechazada por indemostrable.

## Tradeoffs aceptados, y lo que no se afirma

- **`HARNESS_ROLE` no es un principal criptográfico.** Es una variable de entorno y el agente
  puede reescribirla en un subproceso. Esto atenúa por rol **declarado**. Barandilla fuerte
  contra el resbalón, débil contra un adversario decidido — igual que las otras dos capas del
  producto, y decirlo es parte del control.
- **`Ê` es incompleto.** `tar czf t.tgz .` no declara lecturas y sale `opaco`; `python3 -c`
  igual. La Capa 1 hereda ese límite y lo registra en el diario en vez de fingir cobertura.
- **La contención de directorios es de un nivel.** `grep -rn AKIA .` se detecta si la raíz
  contiene una credencial; una anidada bajo `sub/dir/.env` no. Recorrer el árbol en cada decisión
  del guardián lo volvería lento en el camino caliente — medido: 0,08 ms en una lectura simple y
  2,94 ms cuando hay que listar un directorio de 43 entradas.
- **Cinco de diez restricciones no son observables en esta frontera**, y eso es una afirmación
  comprobable y no una excusa: cada una trae su motivo y `G-ROLES` exige que lo traiga.
- **Un aviso que esta sesión se dio a sí misma.** Al intentar mejorar `gates/g_roles.py` el
  guardián lo denegó —«un agente que edita lo que lo evalúa está moviendo la puerta»—, y al
  revisar el diario aparecieron **dos ediciones previas al mismo fichero** hechas por
  `python3` + `pathlib.write_text`, registradas `allow` con `opaco: true`. La protección aguantó
  contra la herramienta `Edit` y no contra el intérprete, que es exactamente el límite declarado.
  `I6'` se sostuvo: quedaron rastreadas y se encontraron. Se revirtieron y el cambio viaja como
  [`docs/remediation/g-roles-capacidades-y-cobertura.patch`](../remediation/g-roles-capacidades-y-cobertura.patch).

## Verificación

```sh
python3 refuto.py selftest                                   # 706/706 · 2026-09-25
python3 -m unittest tests.adversarial.test_capacidades       # 21
python3 scripts/preflight.py --excepto verify                # PASS, 12 controles
```

`tests/adversarial/test_capacidades.py` fija, con su contraparte en cada caso:

- toda restricción del registro está clasificada, y una inventada **duele**;
- cada no observable trae motivo de más de 60 caracteres;
- `no_shell` deniega una orden **y** sin rol la misma orden pasa **y** otro rol también pasa;
- una capacidad **nunca** convierte un `deny` en `allow`;
- `no_secret_access` convierte en `deny` lo que para el resto es `ask`;
- leer una credencial es `ask`, leerla y escribir fuera es `deny`, y el trabajo normal sigue
  pasando — sin esta última, todo lo anterior se satisface denegando todo.
