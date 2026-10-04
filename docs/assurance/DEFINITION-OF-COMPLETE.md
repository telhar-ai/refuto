# Definition of Complete — matriz viva

> Estados permitidos, y sólo éstos: `PASS` `FAIL` `BLOCKED` `NOT_EXECUTABLE` `NOT_APPLICABLE`
> `NOT_RUN`. Un punto con diseño y sin implementación es `NOT_RUN`, nunca `PASS`.
>
> Una capacidad es `PASS` únicamente si tiene las diez: contrato · implementación ·
> integración · prueba positiva · prueba negativa/falsación · evidencia reproducible ·
> documentación que describe el comportamiento real · sin contradecir otros contratos ·
> ejecutable desde entorno limpio · estado verificable después.

**Medición base:** `e28249c` + árbol sucio · Darwin 25.4.0 arm64 · Python 3.14.6 · usuario sin
privilegios (no root) · CI no · 2026-09-22.

```
503/503 pruebas pasan (skipped=1)   ·   stdlib_only PASS   schemas PASS
wiring PASS   compileall PASS   tree_sentinel PASS (0 cambios ajenos)
```

| # | Capacidad | Contrato | Impl. | Test | Falsación | Integr. | Evid. | Doc | **Estado** | Bloqueo / siguiente acción |
|---|---|:--:|:--:|:--:|:--:|:--:|:--:|:--:|---|---|
| 1 | canonical run model | parcial | parcial | sí | sí | parcial | sí | sí | `NOT_RUN` | identidad tipada hecha; faltan los campos de §7 (`attempt`, `principal`, `capabilities`, `policy_digest`, `source_lock`) |
| 2 | canonical event model | no | no | no | no | no | no | diseño | `NOT_RUN` | `docs/contracts/EVENT-MODEL.md` es diseño; 8 tipos emitidos de ~35 |
| 3 | canonical evidence model | sí | sí | sí | sí | sí | sí | sí | `PASS` **acotado** | **revisado 2026-09-23.** El artefacto era editable y `refuto status` reportaba el veredicto falsificado; el diario conservaba la verdad y nadie los comparaba. Ahora: cadena de huellas + reconciliación artefacto↔diario + `INCONCLUSIVE`. Es tamper-EVIDENCIA; truncar la cola sin ancla publicada queda `NOT_PROVEN`. Falta el grafo causal de §10 |
| 4 | capability contracts | no | no | no | no | no | no | no | `NOT_RUN` | `AgentSpec.speaks_acp` es `bool`: no puede expresar `UNKNOWN` |
| 5 | adapter conformance | no | no | no | no | no | no | no | `NOT_RUN` | no existe suite uniforme |
| 6 | policy enforcement | sí | sí | sí | sí | sí | sí | sí | `PASS` **acotado** | **revisado 2026-09-23.** El `PASS` anterior estaba mal acotado: cubría el canal `Write` y no el de órdenes. `Write gates/base.py` daba deny y `Bash echo x > gates/base.py` daba allow sobre la misma ruta (E4, en vivo). Cerrado para las escrituras DEMOSTRABLES (`core/effects.py`, producto cartesiano 18×10 en `test_efectos_cruzados.py`). `I6` en su forma fuerte —el agente no puede escribir al juez— es **`NOT_PROVEN`** y no es demostrable en esta frontera: ver ADR-0013. Lo que se afirma es `I6'` |
| 6b | root of trust de la política | sí | sí | sí | sí | sí | sí | sí | `PASS` | la monotonía era relativa y el hijo elegía el padre; ahora toda cadena se compone con la línea base del motor. Vaciar lo protegido es **inexpresable**, no sólo detectable |
| 7 | environment assurance | parcial | parcial | sí | sí | parcial | sí | sí | `NOT_RUN` | `$HOME` cerrado; faltan uid/root/contenedor/FS-RO/red |
| 8 | security assurance | parcial | sí | sí | no | sí | sí | parcial | `FAIL` | G-SECURITY rojo: 21 hallazgos sobre credenciales sintéticas; `trivy` no descargó su BD → esa parte `BLOCKED` |
| 9 | resource governance | no | parcial | no | no | no | no | no | `NOT_RUN` | sólo `budget_usd`/`cost_usd` por paso |
| 10 | durable execution | parcial | parcial | sí | no | parcial | no | no | `NOT_RUN` | hay `resume`/`resumable`; faltan pause/cancel/retry/recover y `WAITING_APPROVAL` |
| 11 | recovery | parcial | sí | sí | sí | no | sí | sí | `NOT_RUN` | probado sólo en la sonda de mutación, no en el motor |
| 12 | multi-agent lifecycle | no | no | no | no | no | no | no | `NOT_RUN` | sin `parent_run_id`/`root_run_id` |
| 13 | human governance | parcial | sí | sí | no | sí | sí | parcial | `NOT_RUN` | G-HUMAN existe; falta identidad verificable, ámbito y expiración |
| 14 | evaluation engine | no | no | no | no | no | no | no | `NOT_RUN` | no existe `eval/` ni `refuto eval` |
| 15 | adversarial evaluation | parcial | sí | sí | sí | sí | sí | sí | `NOT_RUN` | 27 ataques + sonda calibrada; falta el catálogo de 15 de §6 |
| 16 | replay | no | no | no | no | no | no | no | `NOT_RUN` | `lock` ancla origen; no cubre agente/modelo/entorno/entrada |
| 17 | reproducibility | parcial | parcial | sí | sí | no | sí | sí | `BLOCKED` | una sola máquina (§28) |
| 18 | forensic inspection | no | no | no | no | no | no | no | `NOT_RUN` | sin `run show/inspect/explain/diff` |
| 19 | observability | no | no | no | no | no | no | diseño | `NOT_RUN` | decisión tomada: OTel como *mapeo*, no como modelo |
| 20 | provenance | parcial | sí | sí | no | sí | sí | parcial | `NOT_RUN` | `provenance()` existe; falta forma in-toto con `subject[].digest` |
| 21 | documentation consistency | parcial | sí | sí | no | sí | sí | sí | `NOT_RUN` | `check_wiring` cubre CLI/puertas/roles/adapters, no doc↔runtime |
| 22 | deployment verification | no | no | no | no | no | no | no | `NOT_RUN` | CI nunca ha corrido en verde en remoto |
| 23 | cross-machine verification | — | — | — | — | — | — | sí | `BLOCKED` | sólo existe una máquina · `LIMITATION: single-host` |
| 24 | self-verification | parcial | sí | sí | sí | sí | sí | sí | `NOT_RUN` | `selftest` + contrato + wiring; falta `harness verify` de §35 |
| 25 | self-falsification | sí | sí | sí | sí | sí | sí | sí | `NOT_RUN` | sonda calibrada con testigos; falta `tests/falsification/` |
| 26 | no split-brain state | sí | sí | sí | sí | sí | sí | sí | **`PASS`** | identidad tipada + `latest_verification`; ADR unificados en `docs/decisions/` |
| 27 | no unresolved critical contradiction | — | — | — | — | — | — | — | `FAIL` | quedan 3: ADR-0009/0010/0011 «aceptados» con 0 implementación (declarado en el índice), G-SECURITY, G-PR |

## Recuento

```
PASS          2   (6 policy enforcement · 26 no split-brain)
FAIL          3   (8 security · 27 contradicciones · más G-PR fuera de esta matriz)
BLOCKED       2   (17 reproducibility · 23 cross-machine)  — externos al repositorio
NOT_RUN      20
```

```
CRITICAL GAPS ≠ 0        →  NO se declara COMPLETE
```

## Cómo se rehace esta matriz

Ninguna celda es una opinión. Las órdenes que la producen:

```sh
python3 refuto.py --verbose selftest          # 503/503
python3 scripts/check_stdlib_only.py
python3 scripts/check_schemas.py
python3 scripts/check_wiring.py
python3 scripts/mutate_probe.py --porque      # sonda calibrada, con testigos
python3 scripts/tree_sentinel.py snapshot --out /tmp/a.json
python3 refuto.py verify                      # 13 puertas
python3 refuto.py status                      # misma identidad que verify
```

Y para los tres ADR decididos sin implementar:

```sh
for t in CanonicalEvent git_tree_hash policy_hash EvidenceGraph TrustBoundary; do
  printf '%-18s %s\n' "$t" "$(grep -rl "$t" core adapters gates refuto.py tests schemas | wc -l)"
done
```

Mientras esa cuenta dé 0, los puntos 1, 2, 3 y 19 no pueden pasar de `NOT_RUN`.
