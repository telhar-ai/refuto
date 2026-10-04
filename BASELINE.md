# BASELINE — estado medido de refuto antes de tocar nada

> Todo lo de aquí es **medido**, no leído de la documentación. Cada cifra lleva la orden que la
> produjo. Lo que no se pudo medir se declara `BLOCKED` o `NOT_RUN`, nunca se rellena.

| | |
|---|---|
| commit | `e28249c2677a446dee7825a5baccd045f0512441` |
| rama | `main` (sucia: 6 rutas) |
| fecha de la medición | 2026-09-22, 14:20–15:30 (-06:00) |
| máquina | Darwin 25.4.0 arm64 · Python 3.14.6 · usuario sin privilegios (**no root**) · CI no |
| árbol | `/ruta/al/espacio` (workspace único) |

**Una sola máquina.** Toda propiedad sensible al host queda declarada como
`LIMITATION: single-host` según §28. No se afirma universalidad de nada de lo que sigue.

---

## 0 · Condición que invalida parte del baseline

```
BLOCKED — escritor concurrente no gobernado sobre el mismo árbol
```

Antigravity (pid 11232, vivo desde 13:18) mantiene **12 descriptores** sobre el repositorio y
escribe en él. Medido:

| observación | evidencia |
|---|---|
| `docs/diagrams/*.drawio` regenerado 3 veces durante la sesión | 26.779 B (13:23) → 51.681 B (14:48) → 97.831 B (15:00) → reescrito 15:27:54 |
| `scripts/mutate_probe.py` — fichero creado por esta sesión — modificado por un tercero | mtime 15:27:51; el cambio (`from core.proc import TEXT_IO`, `**TEXT_IO`) no lo escribió esta sesión |
| una mutación restaurada reapareció en el árbol | la sonda verificó sha256 **en proceso** tras restaurar; `git diff` mostró la mutación después |

Hipótesis alternativas descartadas por medición:

- *¿un hook reescribe?* — los únicos hooks son el guardián y una comprobación de uid;
  `core/guard.py` tiene **0** llamadas `write_text`/`write_bytes`.
- *¿la sonda no restauró?* — su comprobación sha256 pasó; el fichero estaba restaurado en ese
  instante. Dos observaciones que sólo un tercer escritor reconcilia.

**Consecuencia:** §16 (reproducibility), §3 (baseline) y §42 (`artifact alterado`) no son
demostrables mientras el escritor concurrente siga activo. No se declara `PASS` sobre nada que
dependa de la estabilidad del árbol.

---

## 1 · Inventario ejecutado

### 1.1 Pruebas — 487, clasificadas

```
python3 refuto.py selftest          →  487/487 OK (skipped=1), 138 s
```

| suite | pruebas | qué fija |
|---|---:|---|
| unit | 369 | módulos en aislamiento |
| selftest | 72 | el juez se prueba a sí mismo (4 casos por puerta) |
| adversarial | 27 | ataques al juez |
| contract | 19 | el contrato de `Result` |

Diez ficheros concentran el 70 %: `test_session` (45), `test_gates` (44), `test_plataforma`
(35), `test_portabilidad` (29), `test_govern` (27), `test_provider` (27), `test_attacks` (27),
`test_policy` (24), `test_gates_nuevas` (22), `test_ciclo` (20).

**Qué NO cubren, medido:**

| eje | medición | estado |
|---|---|---|
| aislamiento de `$HOME` | corregido esta sesión; antes 7 fallos con `$HOME` hostil | `PASS` |
| dobles/mocks | **3** apariciones de `mock`/`patch` en 31 ficheros | suite de alta fidelidad, alta sensibilidad al entorno |
| red | 0 llamadas reales (17 usos de `offline=True`) | `PASS` |
| binarios externos | referencian `claude, codex, gemini, kiro, node, opencode` | `LIMITATION: host-dependent` |
| root / no-root | ninguna prueba distingue | `NOT_RUN` |
| filesystem de sólo lectura | ninguna prueba lo construye | `NOT_RUN` |
| tabla de procesos inaccesible | añadida esta sesión (`mock.patch`) | `PASS` |
| segunda máquina | no existe | `BLOCKED` (§28) |

### 1.2 Cobertura semántica — sonda de mutación

```
python3 scripts/mutate_probe.py     →  6/6 MUERTAS
```

Seis caminos de falso aseguramiento del catálogo de §42, inyectados en el juez:

| id | propiedad atacada | resultado |
|---|---|---|
| M1 | un resultado con hallazgos no puede aprobar | `MUERTA` |
| M2 | `NOT_APPLICABLE` exige motivo escrito | `MUERTA` |
| M3 | sólo existen los estados del vocabulario | `MUERTA` |
| M4 | `BLOCKED` no permite integrar | `MUERTA` |
| M5 | `NOT_EXECUTABLE` no permite integrar | `MUERTA` |
| M6 | el guardián deniega la escritura protegida | `MUERTA` |

> **Aquel 6/6 era `INCONCLUSIVE`, no un dato.** La sonda carecía de control negativo: no se
> había demostrado que supiera informar `VIVA`, y una mutación que rompiera el import habría
> hecho fallar todo contándose como `MUERTA` sin mérito de las pruebas.

**Calibrada el 2026-09-22 (H-07 cerrado).** Se añadieron dos controles y un clasificador:

| control | qué demuestra | resultado |
|---|---|---|
| `NC1` cambio semánticamente nulo (un comentario) | la sonda **sabe** informar `VIVA`; no mata por costumbre | `VIVA` ✓ |
| `NC2` sintaxis rota | distingue muerte **estructural** de **semántica** | `MUERTA_ESTRUCTURAL` ✓ |

`MUERTA_ESTRUCTURAL` es un estado nuevo y no cuenta como evidencia: el módulo dejó de
importarse y las pruebas murieron en el vestíbulo sin comprobar nada. Sin controles conformes,
la sonda declara el resultado completo `INCONCLUSIVE` y sale con código distinto de cero.

Re-medición individual verificada: `M4`, `M5` y `M4+M5` en secuencia → `MUERTA` semántica, sha
del fichero idéntico antes y después, 0 cambios en git.

### 1.3 Superficie expuesta

- **CLI** — 24 comandos; anidados en `policy` (7), `lock` (5), `memory` (4), `bind` (3),
  `environments` (2).
- **Puertas** — 13, todas con `THRESHOLD` declarado.
- **Adaptadores** — `ADAPTERS = {claude, codex, gemini, kiro, opencode}`.
- **Dialectos del guardián** — `{antigravity, claude, gemini, kiro, opencode}`.
- **Roles** — 22 en 9 grupos.
- **Código** — `core/` 42 ficheros / 10.581 líneas · `refuto.py` 1.698 · `tests/` 5.401 ·
  `gates/` 1.346 · `adapters/` 936 · `scripts/` 454.

### 1.4 Guardián — verificado en ejecución (E4)

Bloqueó dos operaciones no provocadas durante esta sesión: `rm -rf` (regla de rechazo) y una
escritura en `.harness/memory/`. Frontera de escritura medida en proceso con
`core.policy.decide_write`:

```
gates/**  .harness/**  harness.manifest.json   → deny
core/ tests/ schemas/ docs/ adapters/ refuto.py → allow
```

---

## 2 · Matriz de huecos frente a la Definition of Complete

`E` = nivel de evidencia (E0 dicho · E1 documentado · E2 reproducible · E3 probado · E4 observado).

| # | capacidad (§) | qué existe hoy, medido | estado | E |
|---|---|---|---|---|
| H-01 | **Run model (§7)** | `core/run.py::Run` con 11 campos y `StepResult` con 14. No representa `Agent`, `Capability`, `Tool`, `Skill`, `MCP`, `Approval`, `Evaluation` como entidades | `PARTIAL` | E3 |
| H-02 | **Split-brain de `run` (§24)** | **dos** familias: `.harness/state/run_*.json` (`core/run.py`) y `.harness/evidence/<id>.json` (`core/evidence.py`). Dos eventos terminales distintos: `run/finish` y `run/complete`. `Run` lleva además `context_run_id`: **tres** espacios de identidad | `FAIL` | E4 |
| H-03 | **Event model (§8)** | **8** tipos emitidos (`agent/run`, `run/finish`, `run/complete`, `session/open,error,close`, `policy/decision`). §8 exige ~35. En el ledger real: 3 tipos, 117 eventos | `PARTIAL` | E4 |
| H-04 | **Capability contract (§9)** | `AgentSpec` declara rutas de configuración y `speaks_acp: **bool**`. Un booleano no puede expresar `UNKNOWN`: «no lo comprobamos» y «no lo soporta» colapsan en `False` — el fallo exacto que §9 prohíbe. `declared` es un dict libre con nivel de evidencia (`"evidence": "D"`) | `PARTIAL` | E3 |
| H-05 | **Adapter conformance (§10)** | no existe suite uniforme. `compile_policy` medido: sólo `gemini` y `kiro` emiten hook dinámico desde la compilación | `NOT_RUN` | E4 |
| H-06 | **Environment assurance (§11)** | `harness.environment/v1` captura OS, usuario, credenciales, CI, herramientas con versión. **Faltan**: uid/gid, root, contenedor, `PATH`, escribibilidad del filesystem, red. Ninguna prueba declara precondiciones de entorno | `PARTIAL` | E4 |
| H-07 | **Auto-falsación (§34)** | `tests/adversarial/` (27) ataca al juez. No existe `tests/falsification/`. La sonda de mutación no tiene control negativo | `PARTIAL` | E3 |
| H-08 | **Contratos (§30)** | **20** identificadores `harness.*/v1` declarados en código; **2** publicados como esquema validable (`manifest`, `roles`). 18 formatos de cable versionados por cadena, sin contrato comprobable | `FAIL` | E4 |
| H-09 | **Forensics (§15)** | `refuto evidence`, `status`, `context`. No hay `run show/inspect/explain/diff/replay/reproduce` | `NOT_RUN` | E2 |
| H-10 | **Replay / reproducibilidad (§16)** | `core/lock.py` ancla origen por commit + sha256 por fichero. No cubre versión de agente, identificador de modelo, huella de entorno, hash de entrada. No distingue REPLAY de REPRODUCE | `PARTIAL` | E3 |
| H-11 | **Evaluation plane (§11/§17)** | no existe `eval/` ni `refuto eval` | `NOT_RUN` | — |
| H-12 | **Durable execution (§19)** | `core/run.py` tiene `resumable()` y `refuto resume`. No hay `pause/cancel/retry/recover` ni estados `WAITING_APPROVAL`/`RECOVERABLE` | `PARTIAL` | E2 |
| H-13 | **Resource governance (§20)** | `budget_usd` por paso y `cost_usd` en `StepResult`. Sin límites de CPU/RAM/disco/tiempo/tool-calls, sin eventos de violación | `PARTIAL` | E2 |
| H-14 | **Multi-agent / fleet (§21)** | G-FLEET existe. No hay `parent_run_id`/`child_run_id` ni ciclo de vida de subagente | `PARTIAL` | E2 |
| H-15 | **Human governance (§22)** | `core/humanreview.py`, G-HUMAN con 5 revisiones exigidas. Falta identidad verificable, ámbito y expiración | `PARTIAL` | E3 |
| H-16 | **Observabilidad (§23)** | ninguna integración OTel. Evidencia y telemetría no están separadas porque sólo existe evidencia | `NOT_RUN` | — |
| H-17 | **Docs como contrato (§25)** | `scripts/check_wiring.py` comprueba CLI/puertas/roles/adapters. No comprueba que la documentación describa el runtime actual | `PARTIAL` | E2 |
| H-18 | **Diagramas como evidencia (§26)** | `docs/diagrams/*.drawio` generado por un agente externo, rotulado «Medición Empírica 2026-09-22», con al menos una fila **falsa**: declara que Gemini CLI no tiene guardián cableado cuando `compile_policy` emite `.gemini/hooks/harness-guard.json` | `FAIL` | E4 |
| H-19 | **Canal de memoria contradictorio** | el informe de sesión declara `.harness/memory/**` escribible; la capa personal de Claude Code lo deniega sin excepción. Un agente que siga el informe pierde su memoria creyendo que la guardó | `FAIL` | E4 |
| H-20 | **Artefactos de proceso (§38)** | 1 de 13 presentes (`ARCHITECTURE.md`). `docs/research/` existe con 4 estudios | `PARTIAL` | E4 |
| H-21 | **Gates nuevos (§29)** | `gates/**` está **denegado por política** para este agente, por diseño: «un agente que edita lo que lo evalúa no está aprobando: está moviendo la puerta» | `BLOCKED` | E4 |

### Recuento

```
FAIL        5   (H-02, H-08, H-18, H-19, y G-SECURITY preexistente)
PARTIAL    11
NOT_RUN     4
BLOCKED     2   (H-21 por política · §28 segunda máquina)
INCONCLUSIVE 1  (sonda de mutación sin control negativo)
```

```
DEFINITION OF COMPLETE: NO ALCANZADA
CRITICAL GAPS ≠ 0
```

---

## 3 · Lo que este baseline NO puede afirmar

- Que el árbol medido sea el árbol actual — hay un escritor concurrente (§0).
- Que las 487 pruebas pasen en otra máquina — sólo hay una (§28).
- Que 6/6 mutaciones muertas signifique cobertura semántica suficiente — falta el control
  negativo (§1.2).
- Que `G-SECURITY` esté en rojo por un defecto: sus 21 hallazgos están en las credenciales
  **sintéticas** del propio repositorio, y `trivy` no pudo descargar su base → esa parte es
  `BLOCKED`, no verde.
