# refuto

Una capa de gobierno para agentes de código, independiente del proveedor. No decide qué hace el
agente: decide **si lo que dice que hizo se puede demostrar**, y deja el rastro con el que
comprobarlo después.

Sólo biblioteca estándar. Python 3.10 o superior. Sin `pip install`.

---

## El problema

Un agente de código bajo presión de contexto hace lo que sea por terminar la tarea, y «editar la
verificación para que pase» es una forma perfectamente razonable de terminarla si nadie lo
impide. A eso se suma que los agentes cambian de nombre, de banderas y de precio cada trimestre,
y que cada uno expresa sus permisos en un vocabulario distinto.

`refuto` responde a las dos cosas con la misma pieza: **una política escrita una vez**, compilada
al dialecto de cada runtime y aplicada por **un único guardián** que todos los ganchos invocan; y
un contrato de estados donde «no pude comprobarlo» no acaba en verde.

La regla que ordena el resto: **un agente no puede ser juez de sí mismo.**

## Arranque en 60 segundos, en una máquina limpia

```bash
python3 --version            # hace falta 3.10 o superior
git clone <url-del-repositorio> refuto
cd refuto
python3 refuto.py doctor     # qué hay en esta máquina y qué funciona de verdad
python3 refuto.py selftest   # el juez se prueba a sí mismo
```

**Aviso para macOS:** `/usr/bin/python3` es **3.9.6** en macOS 15 y 26, y no sirve. Compruébelo
con `python3 --version` antes que nada; si sale `3.9.x`, instale 3.10+ (`brew install python@3.12`
u otro medio) y use ese intérprete. Con 3.9 algunos subcomandos arrancan y fallan más tarde, que
es el peor de los modos de fallar. Los detalles, en [`INSTALL.md`](INSTALL.md).

Después, sobre el espacio que quiera gobernar:

```bash
cd /ruta/al/espacio
python3 /ruta/a/refuto/refuto.py install   # política, vínculo, guardián y contexto
python3 /ruta/a/refuto/refuto.py verify    # ejecuta las puertas y emite evidencia
```

El resto de la documentación escribe `refuto verify` a secas. Para que eso sea un comando y no
una abreviatura, ponga `bin/` en el `PATH`; si no, escriba `python3 /ruta/a/refuto/refuto.py` en
su lugar. Ver [`INSTALL.md`](INSTALL.md).

## Las tres capas

**1 · Motor de sesión.** Lanzador, informe de sesión, **una política canónica** compilada al
gancho `PreToolUse` de cada runtime, y un diario de evidencia (`.harness/evidence/ledger.jsonl`,
sólo añadir, con procedencia). El informe de sesión llega al agente antes del primer turno: dónde
está, qué no puede tocar, y que lo aplica un programa fuera de su control.

**2 · Método por etapas.** El espacio declara su método en `.harness/pipeline.json` y `refuto` lo
**lee**; no lo impone. El método de referencia con el que se construyó esto tiene siete etapas
—`AUDIT → DESIGN → IMPLEMENT → TEST → E2E → DEPLOY → RUNTIME`— y una escala de evidencia
`E0…E4`. Un espacio que no declara método no recibe uno inventado: la sección simplemente no
aparece. Aparte, y sin relación con esa escala, el motor de ejecución de `refuto` tiene su propio
ciclo de **13 fases** con criterio de entrada y de salida (ver [`docs/lifecycle/`](docs/lifecycle/)).

**3 · Contrato de estados.** `PASS` · `FAIL` · `BLOCKED` · `NOT_RUN` · `INCONCLUSIVE` ·
`NOT_APPLICABLE`, y la regla de la que se derivan las demás: **un ámbito vacío nunca aprueba**.
Una comprobación que no encontró nada que comprobar no ha pasado.

> Estado medido del vocabulario, 2026-09-23 (E2, `core/model.py::STATUSES`): el motor
> implementa **`PASS` `FAIL` `BLOCKED` `NOT_EXECUTABLE` `NOT_APPLICABLE` `INCONCLUSIVE`** —
> seis. `INCONCLUSIVE` se añadió para poder decir «las dos fuentes de verdad no coinciden»,
> que es el estado en el que queda un artefacto de evidencia que contradice al diario. `NOT_RUN`
> sigue siendo vocabulario del método, no del tipo: describe una comprobación que nadie lanzó,
> y el tipo sólo existe cuando algo se ejecutó. Varias puertas siguen usando `BLOCKED` para
> decir «aquí no aplica» (`gates/g_sdd.py`): divergencia conocida, no capacidad.
>
> Y la regla tiene ahora forma ejecutable: **`PASS` exige cobertura declarada**
> (`Result.scope`). Una puerta que aprueba sin decir cuántos sujetos observó no produce una
> corrida integrable. Ver [`docs/assurance/FORMAL-MODEL.md`](docs/assurance/FORMAL-MODEL.md).

## Qué hace, concretamente

**`which` no es prueba de nada.** Un agente pasa por cinco peldaños —`NOT_INSTALLED`,
`INSTALLED`, `STARTABLE`, `FUNCTIONAL`, `VERIFIED`— y `refuto` declara en cuál se detuvo y por
qué, incluida la firma del binario nativo (`VALID`, `UNSIGNED`, `INVALID`, `REVOKED`). Un caso
observado el 2026-08-27 en macOS arm64: un agente resolvía en el `PATH`, declaraba versión y
macOS lo mataba al arrancar porque su certificado estaba revocado. `command -v` decía que sí.

**Se le pregunta al agente qué sabe hacer, con un handshake local.** ACP `initialize` sobre stdio
para quien lo habla; `system/init` del flujo `stream-json` para Claude Code; `initialize` de MCP
para Codex. Ninguno llama a un modelo. Para Claude Code el sondeo **sí envía un prompt** (`-p hi`)
con tope `--max-budget-usd 0.05`: el coste no está medido y no se afirma que sea cero.

**Una política, N compilaciones, un guardián.** La regla se escribe una vez; cada adapter la
traduce a su vocabulario **y declara qué parte no puede aplicar**. El guardián resuelve la ruta
(`realpath`) antes de compararla, así que un enlace simbólico no la sortea. Qué runtimes lo tienen
enganchado de verdad, abajo.

**La política se hereda hacia abajo y sólo se puede apretar.** Un espacio declara `extends` y
refina a su padre en la cadena `refuto → cliente → proyecto`: un hijo **añade y endurece, nunca
retira ni ensancha**. No es un merge — un merge deja que el hijo sustituya cualquier clave, y
sustituir es relajar cuando la clave es una restricción. En las listas de restricción el efectivo
es la unión, así que **no hay sintaxis para retirar una regla heredada**: no poder expresar la
violación es más fuerte que detectarla. La identidad va encadenada (el digest del hijo incluye el
del padre), de modo que un cliente que afloja cambia la identidad de todos sus proyectos aunque
ninguno se haya tocado, y cada evento del diario dice bajo qué política efectiva se decidió. Si la
cadena no resuelve —padre ausente, ilegible, en ciclo, o anclado a un digest que ya no coincide—
el guardián **deniega**: un espacio que dice heredar y corre sin su padre parece gobernado sin
estarlo. Estructura de referencia en [`examples/tres-capas/`](examples/tres-capas/), validada
ejecutando el guardián real. Un límite medido y no cerrado: con `policy wire --repos` el guardián
no asciende, así que la tercera capa no se lee — ver
[`docs/architecture/HERENCIA-REFUTO-CLIENTE-PROYECTO.md`](docs/architecture/HERENCIA-REFUTO-CLIENTE-PROYECTO.md).

**El lock ancla por commit, y se verifica antes de escribirse.** Nunca
`traer → reescribir el lock → comparar`, que es una tautología. Una etiqueta de git es mutable.

**Rol ≠ agente.** Un rol es una unidad de trabajo con contrato (22 en `roles/registry.json`); un
agente es un runtime que puede ejecutarlo. El router los empareja por capacidad y prefiere el
runtime donde la política sí se aplica.

## Qué runtime puede qué — y no es el mismo conjunto

Medido el 2026-09-22 sobre este árbol (E1/E2: lectura de código y `--help` del propio CLI; **no**
ejecución contra los agentes). Los cuatro verbos son independientes y confundirlos es el error que
esta tabla existe para impedir.

| Runtime | Sondeable (`probe`) | Sesión gobernada (`chat --agent`) | Guardián enganchable (`policy wire --agent`) | Dialecto de gancho (`core.guard --runtime`) |
|---|---|---|---|---|
| `claude` | sí | sí | **sí** | sí |
| `kiro` | sí | sí | **sí** | sí |
| `gemini` | sí | sí | **no** | sí |
| `opencode` | sí | sí | **no** | sí |
| `codex` | sí | no | **no** | no |
| `antigravity` | no (no hay adapter) | no | **sí** | sí |

Lecturas obligadas de esta tabla:

- **`gemini` y `opencode` no tienen guardián enganchable.** La política se compila a un
  artefacto (`.gemini/hooks/harness-guard.json`, `opencode.harness.json`) y `policy wire` no lo
  engancha; que el agente lea esa ruta no está verificado. Por eso **`chat` se niega a abrirlos**:
  una sesión con informe y contexto pero sin control preventivo no es una sesión gobernada, y
  llamarla así sería el aprobado vacuo de siempre. Si acepta ese riesgo a sabiendas, decláralo en
  el manifiesto (`agents.<runtime>.unguarded: true`) y la sesión abre con un aviso, no en silencio.
- **`codex` tiene adapter y compila política** (sandbox y aprobación, `adapters/codex.py`), pero
  no abre sesión con `chat` ni tiene gancho. Sus reglas de `command_deny` se listan para el
  operador; **no las aplica el agente**.
- **`antigravity` tiene gancho y dialecto, y no tiene adapter ni sonda**: no aparece en la matriz
  de compatibilidad ni en `chat --agent`.
- La capa que ningún agente puede tocar sigue siendo la tercera: **rama protegida y CI**.

## Qué está probado y a qué nivel (E0–E4)

`E0` dicho · `E1` documentado o leído en el código · `E2` reproducible con un comando · `E3`
probado por la suite automática · `E4` observado en ejecución, fechado.

| Afirmación | Nivel | Evidencia |
|---|---|---|
| La suite pasa entera | **E3** | `python3 refuto.py selftest` → **1453/1453, 12 omitidas** (1 sólo Windows; 3 declaradas `NOT_RUN` cuando `HICON_BIN`/`CONCORDIA_VECTORS` no apuntan al verificador Rust y a los vectores de concordia, y **7 más** el diferencial de la regla de validez de `CERTIFICATE-SPEC §11`, que también necesita `HICON_BIN`) y **4 fallos esperados**, con código de salida 0. Las dos que estaban en rojo el 2026-09-30 **no eran el desacuerdo semántico que esta fila les atribuyó**: ver la fila siguiente. 2026-10-04, macOS arm64 (Darwin 25.4.0), Python 3.14.6 |
| **Una firma de testigo forjada se ignoraba en silencio**, y las pruebas que decían cubrirla pasaban por el motivo equivocado | **E4** | `core/protocol.py` leía `evidence_requirements` sólo DENTRO de `claim`; `test_V13_fake_ed25519_witness_signature` y `test_E2E_F_malicious_agent_combined_attack` lo mandaban en la **raíz de `params`**, donde no se lee. Medido con `gates.base.run_all` fijado en `PASS` para apartar el ruido de puertas: la forma de la raíz daba **`PASS` y `can_advance=True`** — idéntico a no mandar testigo alguno— frente a `FAIL`/`False` de la forma normativa (`docs/11-protocol.md` §2.1, `adapters/aidlc_bridge.ts::Claim`). El `BLOCKED` que se observaba venía de las puertas, no del control. Arreglado rechazando la forma mal puesta con `INVALID_PARAMS` en vez de tolerar las dos, y la guarda se comprobó **portante**: neutralizándola en memoria, sin tocar el fichero, V13 cae. Mismo diagnóstico destapó que `test_p6_mutated_evidence_invalidates_decision` era **vacua** —usaba `witness_signature`/`witness_public_key` sin el sufijo `_hex` que el protocolo lee, y sólo afirmaba sobre `can_advance`, ya `False` por las puertas—: pasaba igual con firma válida y sin firma. Las tres llevan ahora **control negativo**. 2026-09-30, macOS arm64 |
| Reparto de la suite | **E2** | unit 610 · contract 79 · selftest 97 · adversarial 667 = **1453**, según el cargador de `unittest`, que es quien decide qué se ejecuta. `grep -rc "def test_"` no sirve para esto: da uno de más porque el texto aparece dentro de una cadena. 2026-10-04 |
| **Hay 4 defectos abiertos, y están escritos** | **E4** | `tests/adversarial/test_brechas_de_assurance.py` — seis brechas medidas el 2026-09-25, cada una con su reproducción. Quedan **4** con `@unittest.expectedFailure`: se cerraron **R-02** (C-02), **R-03** (admisión), las **dos de R-01** (resolución de efectos) y **R-04** (identidad de objeto, **con una retractación de alcance del 2026-09-30**: la identidad atestigua en todas las plataformas, pero **distinguir** una sustitución que reúsa el inodo es `NOT_APPLICABLE` en ext4 — se midió sólo en APFS y se afirmó para todas; ver `docs/assurance/REMEDIATION-LOG.md` §R-04 · RETRACTACIÓN), y sus reproducciones siguen ahí como regresión permanente, sin el decorador y con las mismas cargas. No rompen la corrida y **el día que alguien las cierre, `unittest` lo reporta como `unexpectedSuccess` y `tests/runner.py` invalida la corrida**: el arreglo no puede pasar inadvertido. Verde aquí no significa «sin defectos conocidos» |
| **Estas cifras siguen dando eso** | **E3** | `python3 scripts/check_mediciones.py` compara la tabla con el árbol y CI lo ejecuta. Se añadió el 2026-09-25 porque las anteriores llevaban cinco commits desfasadas **con fecha del día**: declaraban 685 pruebas y 13 controles cuando eran 748 y 14 |
| La suite pasa en **Linux** y en **Python 3.10**, el mínimo declarado | **E4** | GitHub Actions, corrida [36186362072](https://github.com/osvalois/refuto/actions/runs/36186362072) sobre `cc7278a` (PR [#6](https://github.com/osvalois/refuto/pull/6)), `ubuntu-latest`, matriz 3.10 y 3.13. **5 trabajos en verde**, incluido el preflight completo. 2026-09-25 |
| El preflight está verde | **E4** | `python3 scripts/preflight.py` → **PASS, 15 controles**. Incluye `ruff`, `bandit`, `gitleaks`, `actionlint`, `shellcheck`, datos personales y `refuto verify`. 2026-09-25, macOS arm64 |
| La regla de validez de concordia se **consume**, y refuto **diverge en una sonda de once** | **E4** | `HICON_BIN=…/hicon python3 -m unittest tests.contract.test_regla_validez_conformidad` → 7 pruebas, diferencial contra el binario Rust de verdad. `core/regla_validez.py` recomputa la forma canónica de `CERTIFICATE-SPEC §11.4` (1 532 bytes) con sólo `hashlib`, y reproduce los digests que concordia publica de sus **dos** reglas, la estricta y la permisiva. Discrepa en `05-noncanonical-y-encoding-admitted`: una clave cuya `y` codifica `2^255−1 > p` no es canónica, y refuto la rechaza **al admitirla** mientras `ed25519-dalek` la admite y falla después en la firma. refuto rechaza **más** —la dirección segura— pero es **otra regla**, y se reporta como divergencia con su sonda, nunca como «firma inválida»: eso sería indistinguible de una réplica bizantina, que es el error que el mecanismo existe para eliminar. Sin `HICON_BIN` las 7 quedan `NOT_RUN`, nunca aprobadas por omisión. Se lee en `core.concordia.diagnosticar_endpoint`, donde **no coacciona** el `status`. 2026-09-30, macOS arm64 |
| El cliente MCP de refuto interroga a su propio servidor | **E3** | `tests/adversarial/test_mcp_server.py::TestElClientePropioLoInterroga` — `server/discover`, las dos revisiones de protocolo, la identidad y las 7 herramientas |
| 13 puertas · 22 roles · 13 fases · 5 adapters | **E2** | `gates/base.py::GATES`, `roles/registry.json`, `core.lifecycle.PHASES`, `adapters/registry.py`. 2026-09-22 |
| Sin dependencias de terceros | **E2** | `python3 scripts/check_stdlib_only.py` en local, 2026-09-22 |
| `Result` no se construye `PASS` con hallazgos | **E3** | `tests/contract/test_result_contract.py` |
| Un adapter sin política no puede devolver `unenforceable: []` | **E3** | `tests/contract/test_result_contract.py` |
| Los tres invariantes del lock | **E3** | `tests/adversarial/test_attacks.py` |
| El guardián bloquea la escritura sobre el juez, con Claude Code y con Kiro | **E4**, n=1 | 2026-08-27, macOS arm64, `claude 2.1.247` y `kiro 2.20.0`. Una ejecución. Ver [`docs/validation/informe.md`](docs/validation/informe.md) |
| Un agente real escribió una prueba que pasa, bajo puertas | **E4**, n=1 | 2026-08-27, `claude 2.1.247`, fase `TEST`. Ver [`docs/examples/end-to-end-run.md`](docs/examples/end-to-end-run.md) |

Y lo que **no** está probado, con su estado:

| Sujeto | Estado | Por qué |
|---|---|---|
| Ejecución en **Windows** | `NOT_RUN` | los arreglos de portabilidad existen y se midieron en una rama aislada; sobre este árbol no se han ejecutado. 1 prueba queda omitida en macOS por ser sólo de Windows |
| **`I6`: el agente no puede escribir al juez** | `NOT_PROVEN` | no es demostrable en esta frontera: el efecto de una orden no es computable y el agente corre con el uid del operador. Se afirma `I6'` en su lugar — ver [`SECURITY.md`](SECURITY.md) |
| **Truncar la cola del diario** | `NOT_PROVEN` | la cadena de huellas no lo ve sin un ancla publicada fuera del árbol |
| **Cobertura declarada en las 13 puertas** | `NOT_RUN` | `core/lock.py` ya la declara; `gates/**` está protegido y el cambio va propuesto en [`docs/remediation/gates-cobertura.patch`](docs/remediation/gates-cobertura.patch). Hasta que se aplique, una puerta sin cobertura no produce corrida integrable |
| `codex` en ejecución real | `NOT_RUN` | hay adapter y sonda; no hay ejecución observada conduciendo trabajo |
| `antigravity` en ejecución real | `NOT_RUN` | el dialecto se derivó de la documentación embebida en el binario 2.15.1 (leída el 2026-09-21); no se observó una decisión suya en vivo |
| `gemini` / `opencode` con guardián | `NOT_RUN` | no hay enganche que verificar |
| Ciclo completo de las 13 fases | `NOT_RUN` | se ejecutó `TEST` |

## Consumirlo desde un agente: `refuto mcp-serve`

Toda orden migrada emite `harness.envelope/v1` con `--json` —estado de los seis, código de
salida **derivado** del estado, procedencia, y `next` con qué hacer, por qué y de quién es el
turno (`persona` · `maquina` · `agente`)—. Y esa misma respuesta se sirve por MCP stdio:

```json
{ "mcpServers": {
    "refuto": { "command": "python3",
                "args": ["/ruta/a/refuto/refuto.py", "mcp-serve"] } } }
```

Siete herramientas: `refuto_doctor`, `refuto_status`, `refuto_verify`, `refuto_probe`,
`refuto_mcp_check`, `refuto_inventory`, `refuto_upgrade_plan`. Habla `server/discover`
(2026-07-28) y cae a `initialize` (2025-06-18), igual que el cliente de refuto — que es el que
lo verifica en la suite.

**Tres cosas que esta superficie no hace, y son contrato probado:**

- **No ejecuta órdenes arbitrarias.** El `argv` sale de una tabla fija; el modelo sólo aporta una
  ruta de espacio y booleanos, validados uno a uno. No hay concatenación de cadenas.
- **No escribe lo que gobierna.** Ni `--apply`, ni `--force`, ni `wire`/`unwire`, ni `install`.
  `upgrade` se expone sólo como **plan**. Un agente que pudiera actualizar su propio arnés o
  recablear su propio guardián sería otra vez juez de sí mismo. `verify` sí emite evidencia, que
  es su función: un diario de sólo añadir y encadenado — emitir una verificación no es
  falsificarla.
- **No gasta dinero.** `--deep` no se expone: el sondeo profundo envía un prompt de pago y su
  coste no está medido.

Un servidor **stdio** corre en la máquina de quien lo usa, así que no hay nada que alojar ni que
pagar, y no tiene superficie entrante: no escucha, lo arranca el cliente. Un servidor remoto
tendría además que exponer el diario y la política, que es exactamente lo que el modelo de
confianza protege. La decisión y sus alternativas, en
[ADR-0015](docs/decisions/ADR-0015-un-vocabulario-tres-consumidores.md).

## Qué no es

No es un orquestador de prompts ni un marco de agentes. No sustituye a la revisión humana ni a la
rama protegida: los declara como la capa que el agente no puede tocar. Y no detecta inyección de
prompt por patrones — limita lo que el agente puede hacer si la obedece.

## Documentación

| | |
|---|---|
| [`INSTALL.md`](INSTALL.md) | instalar en una máquina limpia y comprobar que quedó bien |
| [`docs/estado-del-proyecto.md`](docs/estado-del-proyecto.md) | qué está probado, a qué nivel, y los riesgos abiertos |
| [`ARCHITECTURE.md`](ARCHITECTURE.md) | qué es núcleo, qué es adapter y por qué |
| [`OPERATIONS.md`](OPERATIONS.md) | gobernar un espacio, ejecutar, actualizar, diagnosticar |
| [`TROUBLESHOOTING.md`](TROUBLESHOOTING.md) | fallos observados, con su fecha, su causa y su arreglo |
| [`SECURITY.md`](SECURITY.md) | modelo de amenaza, pruebas adversariales y cómo reportar |
| [`MIGRATION.md`](MIGRATION.md) | adoptarlo sobre un conjunto de repositorios que ya funciona |
| [`SUPPORT_MATRIX.md`](SUPPORT_MATRIX.md) | salida de ejemplo de `refuto docs`, fechada |
| [`docs/lifecycle/`](docs/lifecycle/) | las 13 fases, con entrada, salida y revisión humana |
| [`docs/agents/`](docs/agents/) | los 22 roles, sus contratos y cómo se elige el runtime |
| [`docs/decisions/`](docs/decisions/) | 12 ADRs, cada uno con qué lo haría cambiar |
| [`docs/architecture/HERENCIA-REFUTO-CLIENTE-PROYECTO.md`](docs/architecture/HERENCIA-REFUTO-CLIENTE-PROYECTO.md) | la cadena `refuto → cliente → proyecto`, sus reglas de monotonía y lo que aún no resuelve |
| [`examples/tres-capas/`](examples/tres-capas/) | la misma cadena en tres directorios, validada con el guardián real |
| [`docs/research/`](docs/research/) | investigación primaria, con fechas y versiones |
| [`CONTRIBUTING.md`](CONTRIBUTING.md) | cómo extenderlo sin romperlo |

## Idioma

La documentación y la prosa del código están en **español**. Los identificadores, las rutas, las
salidas de comando y el vocabulario técnico establecido (`PASS`, `commit`, `stdio`) van en
inglés. No hay traducción al inglés todavía.

## Nombres

El producto es `refuto`. «Harness» aparece como **nombre común** para el concepto de arnés de
gobierno, nunca como nombre del producto. Se conservan sin renombrar, porque son contrato con
espacios ya instalados: el directorio `.harness/`, las variables `HARNESS_*`, los identificadores
de esquema `harness.*/v1` y el prefijo `harness-guard` con el que el guardián firma sus mensajes.

## Estado

Versión en `VERSION`. **No hay ninguna etiqueta de git publicada todavía**, así que lo que un
`clone` obtenga puede no coincidir con lo que el `CHANGELOG` describe: compruebe `VERSION` en su
copia. Ver [`docs/estado-del-proyecto.md`](docs/estado-del-proyecto.md).
